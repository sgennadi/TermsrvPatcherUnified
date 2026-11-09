using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Explicit, one-shot, administrator-approved Apply executor. Task Scheduler
/// launches the protected copy as LocalSystem in session 0, so a disconnected
/// or logged-off RDP GUI cannot terminate the in-flight DLL transaction.
/// The worker never reads replacement bytes or an executable path from the job.
/// </summary>
internal static class IsolatedApplyExecutor
{
    internal const string WorkerArgument = "--isolated-apply-worker";
    private const string TaskPrefix = "TermsrvPatcherUnified-Apply-";
    private const string ExecutableName = "TermsrvPatcherUnified.exe";
    private const string RequestName = "request.json";
    private const string StatusName = "status.json";
    private const string LockName = "started.lock";

    internal static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TermsrvPatcherUnified.Secure", "Executor");

    internal sealed record Request(string Id, string OriginalSha256, string FileVersion,
        string ProfileId, string ExeSha256);
    internal sealed record Status(string Id, string State, string Details, string Utc);

    internal static bool TryNormalizeId(string? input, out string id)
    {
        id = "";
        if (input is null || !Guid.TryParseExact(input, "N", out var uuid) ||
            input.Length != 32 || !input.All(Uri.IsHexDigit))
            return false;
        id = uuid.ToString("N");
        return id.Equals(input, StringComparison.OrdinalIgnoreCase);
    }

    internal static string Queue(PatchPlan preview)
    {
        ArgumentNullException.ThrowIfNull(preview);
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess ||
            !SystemInfo.IsAdministrator() || !NsudoDevilModeScope.IsBundled)
            throw new UnauthorizedAccessException(
                "Independent Apply requires elevation and verified embedded NSudo x64.");
        if (preview.IsManual || preview.State != PatchState.Ready ||
            preview.PatchedBytes is null)
            throw new InvalidOperationException(
                "Independent Apply accepts only an automatic Ready preview.");
        var os = SystemInfo.Read();
        if (!os.Supported ||
            !Path.GetFullPath(preview.FilePath).Equals(Path.GetFullPath(os.DllPath),
                StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Only the installed, supported client DLL may be changed.");
        // Recompute before queueing; no stale, imported or user-edited plans.
        using var engine = new TermsrvEngine(null);
        var fresh = engine.Inspect();
        if (fresh.State != PatchState.Ready || fresh.IsManual ||
            !SamePreview(preview, fresh))
            throw new InvalidOperationException(
                "Installed DLL or trusted automatic signature changed. Run Check DLL again.");
        NsudoDevilModeScope.Preflight();

        // Every path containing an executable, job request or result is
        // admin/SYSTEM-owned with a protected DACL, never user-writable.
        string parent = Path.GetDirectoryName(Root)!;
        NsudoDevilModeScope.EnsurePrivateDirectory(parent);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);

        string id = Guid.NewGuid().ToString("N");
        string dir = JobDirectory(id);
        NsudoDevilModeScope.EnsurePrivateDirectory(dir);
        string sourceExe = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot identify the running EXE.");
        if (!Path.GetExtension(sourceExe).Equals(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Independent Apply requires the packaged EXE.");
        string sourceSha = SystemInfo.Sha256(File.ReadAllBytes(sourceExe));
        string stagedExe = Path.Combine(dir, ExecutableName);
        File.Copy(sourceExe, stagedExe, overwrite: false);
        if (!SystemInfo.Sha256(File.ReadAllBytes(stagedExe))
                .Equals(sourceSha, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Staged protected executor failed SHA-256 verification.");
        // The worker ignores arbitrary paths and replacement data entirely.
        // Its request references only expected original SHA and exact profile.
        var request = new Request(id, fresh.OriginalSha256, fresh.FileVersion,
            fresh.ProfileId, sourceSha);
        File.WriteAllText(Path.Combine(dir, RequestName),
            JsonSerializer.Serialize(request));
        WriteStatus(dir, new Status(id, "Queued",
            "Approved automatic Apply with mandatory backup.", DateTimeOffset.UtcNow.ToString("O")));

        // Register an admin/SYSTEM-only task. A scheduled trigger in one minute
        // recovers a crash between registration and immediate Run().
        // The worker's CreateNew execution lock makes the operation at-most-once.
        RegisterAndStartTask(id, stagedExe);
        return id;
    }

    internal static int RunWorker(string? input)
    {
        if (!TryNormalizeId(input, out var id)) return 2;
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is null ||
            !identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid))
            return 3;
        string dir = JobDirectory(id);
        // Only access an already-created, administrator-controlled job folder.
        if (!Directory.Exists(dir) || !Directory.Exists(Root)) return 4;
        NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
        NsudoDevilModeScope.EnsurePrivateDirectory(dir);

        try
        {
            // Never execute a scheduled job twice, including after a Task
            // Scheduler retry or a stale trigger.
            using var once = new FileStream(Path.Combine(dir, LockName),
                FileMode.CreateNew, FileAccess.Write, FileShare.None);
            once.WriteByte(1);
            once.Flush(flushToDisk: true);
            try
            {
                var req = JsonSerializer.Deserialize<Request>(
                    File.ReadAllText(Path.Combine(dir, RequestName)))
                    ?? throw new InvalidDataException("Invalid scheduled request.");
                if (!string.Equals(req.Id, id, StringComparison.Ordinal) ||
                    req.OriginalSha256.Length != 64 ||
                    !req.OriginalSha256.All(Uri.IsHexDigit) ||
                    req.ExeSha256.Length != 64 || !req.ExeSha256.All(Uri.IsHexDigit) ||
                    req.FileVersion.Length is < 1 or > 128 ||
                    req.ProfileId.Length is < 1 or > 256)
                    throw new InvalidDataException("Scheduled request metadata is invalid.");
                var stagedExe = Path.Combine(dir, ExecutableName);
                if (!SystemInfo.Sha256(File.ReadAllBytes(stagedExe))
                        .Equals(req.ExeSha256, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Protected executor bytes changed.");
                // This is a separate system-process read, after RDP GUI exit.
                // It must reconstruct the trusted plan from the current file.
                using var engine = new TermsrvEngine(null);
                var plan = engine.Inspect();
                if (plan.State == PatchState.AlreadyPatched)
                {
                    WriteStatus(dir, new Status(id, "AlreadyPatched",
                        "No change required; current DLL already contains a trusted replacement.",
                        DateTimeOffset.UtcNow.ToString("O")));
                    return 0;
                }
                if (plan.IsManual || plan.State != PatchState.Ready ||
                    !plan.OriginalSha256.Equals(req.OriginalSha256, StringComparison.OrdinalIgnoreCase) ||
                    !plan.ProfileId.Equals(req.ProfileId, StringComparison.Ordinal) ||
                    !plan.FileVersion.Equals(req.FileVersion, StringComparison.Ordinal))
                    throw new InvalidOperationException("DLL drift or a different signature invalidated the job.");
                // No user-supplied path, no direct write and no no-backup option.
                WriteStatus(dir, new Status(id, "Running",
                    "System executor is applying the verified plan.", DateTimeOffset.UtcNow.ToString("O")));
                engine.Apply(plan, createBackup: true);
                var after = File.ReadAllBytes(plan.FilePath);
                if (!SystemInfo.Sha256(after).Equals(SystemInfo.Sha256(plan.PatchedBytes!),
                    StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Post-transaction DLL checksum mismatch.");
                WriteStatus(dir, new Status(id, "Succeeded",
                    "Protected write and RDP service recovery returned successfully.",
                    DateTimeOffset.UtcNow.ToString("O")));
                return 0;
            }
            catch (Exception ex)
            {
                // Preserve a durable local error type but never upload its
                // free-form message or raw system details.
                AuditLog.Append("Isolated Apply failed: " + ex.GetType().Name);
                WriteStatus(dir, new Status(id, "Failed", ex.GetType().Name,
                    DateTimeOffset.UtcNow.ToString("O")));
                return 5;
            }
        }
        catch (IOException) when (File.Exists(Path.Combine(dir, LockName)))
        {
            // At-most-once latch. An in-progress or terminal job must not
            // run again just because a scheduled trigger fires.
            return 0;
        }
        finally
        {
            try { DeleteScheduledTask(id); }
            catch { /* A stale one-shot task is harmless: lock prevents re-execution. */ }
        }
    }

    internal static Status? ReadLatestStatus()
    {
        if (!Directory.Exists(Root)) return null;
        try
        {
            NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
            NsudoDevilModeScope.EnsurePrivateDirectory(Root);
            foreach (string dir in Directory.EnumerateDirectories(Root, "job-*",
                         SearchOption.TopDirectoryOnly)
                         .OrderByDescending(Directory.GetCreationTimeUtc).Take(10))
            {
                string file = Path.Combine(dir, StatusName);
                if (!File.Exists(file)) continue;
                var result = JsonSerializer.Deserialize<Status>(File.ReadAllText(file));
                if (result is not null && TryNormalizeId(result.Id, out _)) return result;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   JsonException or InvalidOperationException)
        {
            return null;
        }
        return null;
    }

    private static bool SamePreview(PatchPlan a, PatchPlan b)
        => a.OriginalSha256.Equals(b.OriginalSha256, StringComparison.OrdinalIgnoreCase) &&
           a.ProfileId.Equals(b.ProfileId, StringComparison.Ordinal) &&
           a.FileVersion.Equals(b.FileVersion, StringComparison.Ordinal) &&
           a.Edits.Count == b.Edits.Count &&
           a.Edits.Zip(b.Edits).All(pair =>
               pair.First.Offset == pair.Second.Offset &&
               pair.First.Expected.SequenceEqual(pair.Second.Expected) &&
               pair.First.Replacement.SequenceEqual(pair.Second.Replacement));

    private static string JobDirectory(string id)
    {
        if (!TryNormalizeId(id, out var normalized))
            throw new InvalidDataException("Invalid executor job ID.");
        return Path.Combine(Root, "job-" + normalized);
    }

    private static void WriteStatus(string dir, Status status)
    {
        string final = Path.Combine(dir, StatusName);
        string temp = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllText(temp, JsonSerializer.Serialize(status));
            File.Move(temp, final, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static void RegisterAndStartTask(string id, string stagedExe)
    {
        string taskName = TaskPrefix + id;
        object? service = null, folder = null, definition = null, registered = null;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service")
                ?? throw new PlatformNotSupportedException("Windows Task Scheduler is unavailable.");
            service = Activator.CreateInstance(type)
                ?? throw new InvalidOperationException("Task Scheduler creation failed.");
            dynamic scheduler = service;
            scheduler.Connect();
            folder = scheduler.GetFolder(@"\");
            definition = scheduler.NewTask(0);
            dynamic task = definition;
            task.RegistrationInfo.Description =
                "One-time protected termsrv.dll Apply, independent of RDP sessions.";
            task.Principal.UserId = "SYSTEM";
            task.Principal.LogonType = 5; // TASK_LOGON_SERVICE_ACCOUNT
            task.Principal.RunLevel = 1;  // TASK_RUNLEVEL_HIGHEST
            task.Settings.Hidden = true;
            task.Settings.Enabled = true;
            task.Settings.AllowDemandStart = true;
            task.Settings.ExecutionTimeLimit = "PT10M";
            task.Settings.DisallowStartIfOnBatteries = false;
            task.Settings.StopIfGoingOnBatteries = false;
            dynamic trigger = task.Triggers.Create(1); // TASK_TRIGGER_TIME
            trigger.StartBoundary = DateTime.Now.AddMinutes(1).ToString(
                "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
            trigger.Enabled = true;
            dynamic action = task.Actions.Create(0); // TASK_ACTION_EXEC
            action.Path = stagedExe;
            action.Arguments = WorkerArgument + " " + id;
            action.WorkingDirectory = Path.GetDirectoryName(stagedExe)!;
            // Task security descriptor grants control only to SYSTEM and
            // Administrators; no standard user can change the task action.
            registered = ((dynamic)folder).RegisterTaskDefinition(taskName, definition,
                2, "SYSTEM", null, 5, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
            try { ((dynamic)registered).Run(null); }
            catch
            {
                try { ((dynamic)folder).DeleteTask(taskName, 0); } catch { }
                throw;
            }
        }
        finally
        {
            foreach (var o in new[] { registered, definition, folder, service })
                if (o is not null && Marshal.IsComObject(o))
                    Marshal.FinalReleaseComObject(o);
        }
    }

    private static void DeleteScheduledTask(string id)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service");
        if (type is null) return;
        object? service = null, folder = null;
        try
        {
            service = Activator.CreateInstance(type);
            if (service is null) return;
            dynamic scheduler = service;
            scheduler.Connect();
            folder = scheduler.GetFolder(@"\");
            ((dynamic)folder).DeleteTask(TaskPrefix + id, 0);
        }
        finally
        {
            if (folder is not null && Marshal.IsComObject(folder)) Marshal.FinalReleaseComObject(folder);
            if (service is not null && Marshal.IsComObject(service)) Marshal.FinalReleaseComObject(service);
        }
    }
}
