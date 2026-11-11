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
    internal const string RevertWorkerArgument = "--isolated-revert-worker";
    internal const string ProbeArgument = "--isolated-executor-qa";
    internal const string ProbeWorkerArgument = "--isolated-executor-probe-worker";
    private const string TaskPrefix = "TermsrvPatcherUnified-Apply-";
    private const string ExecutableName = "TermsrvPatcherUnified.exe";
    private const string RequestName = "request.json";
    private const string RevertRequestName = "revert-request.json";
    private const string StatusName = "status.json";
    private const string ReportOfferedName = "report-offered.flag";
    private const string ReportDeliveredName = "report-delivered.flag";
    private const string LockName = "started.lock";

    internal static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TermsrvPatcherUnified.Secure", "Executor");

    internal sealed record Request(string Id, string OriginalSha256, string ExpectedPatchedSha256,
        string FileVersion, string ProfileId, string ExeSha256, bool CreateBackup = true);
    internal sealed record RevertRequest(string Id, string OriginalSha256, string CurrentSha256,
        string FileVersion, string ProfileId, string RecoverySource, string ExeSha256);
    // Optional field preserves compatibility with statuses written by older versions.
    // Only the explicit one-shot SYSTEM Apply worker includes reviewed metadata.
    internal sealed record Status(string Id, string State, string Details, string Utc,
        SuccessfulFixMetadata? Report = null);
    internal sealed record ProbeRequest(string Id, string ExeSha256);

    internal static bool TryNormalizeId(string? input, out string id)
    {
        id = "";
        if (input is null || !Guid.TryParseExact(input, "N", out var uuid) ||
            input.Length != 32 || !input.All(Uri.IsHexDigit))
            return false;
        id = uuid.ToString("N");
        return id.Equals(input, StringComparison.OrdinalIgnoreCase);
    }

    internal static string Queue(PatchPlan preview, bool createBackup = true)
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
        if (fresh.PatchedBytes is null)
            throw new InvalidOperationException("Automatic preview has no verified output bytes.");
        // Refuse another concurrent RDP-disrupting job until its result is known.
        var last = ReadLatestStatus();
        if (last?.State is "Queued" or "Running")
            throw new InvalidOperationException("A protected SYSTEM job is already queued/running.");

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
        var request = new Request(id, fresh.OriginalSha256,
            SystemInfo.Sha256(fresh.PatchedBytes), fresh.FileVersion,
            fresh.ProfileId, sourceSha, createBackup);
        File.WriteAllText(Path.Combine(dir, RequestName),
            JsonSerializer.Serialize(request));
        WriteStatus(dir, new Status(id, "Queued",
            createBackup ? "Approved Apply with full backup and recovery journal." :
            "Approved Apply without full backup; protected recovery journal mandatory.",
            DateTimeOffset.UtcNow.ToString("O")));

        // Register an admin/SYSTEM-only task. A scheduled trigger in one minute
        // recovers a crash between registration and immediate Run().
        // The worker's CreateNew execution lock makes the operation at-most-once.
        try
        {
            RegisterAndStartTask(id, stagedExe);
            return id;
        }
        catch (Exception ex)
        {
            // Task Scheduler can fail before launching or after submitting.
            // Do not claim a guaranteed start or rollback; leave a visible
            // uncertain state and do not retry without operator inspection.
            WriteStatus(dir, new Status(id, "Unconfirmed",
                ex.GetType().Name + ": Task Scheduler did not confirm launch.",
                DateTimeOffset.UtcNow.ToString("O")));
            throw;
        }
    }

    internal static string QueueRevert(AutomaticRevertPlan approved)
    {
        ArgumentNullException.ThrowIfNull(approved);
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess ||
            !SystemInfo.IsAdministrator() || !NsudoDevilModeScope.IsBundled)
            throw new UnauthorizedAccessException(
                "Independent Revert requires elevation and embedded NSudo x64.");
        if (!AutomaticRevertSafety.SameApproval(approved, AutomaticRevertSafety.Inspect()))
            throw new InvalidOperationException(
                "No exact verified recovery record for this DLL. Run Check again.");
        NsudoDevilModeScope.Preflight();
        if (ReadLatestStatus()?.State is "Queued" or "Running")
            throw new InvalidOperationException("Another protected job is already queued or running.");

        NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
        string id = Guid.NewGuid().ToString("N");
        string dir = JobDirectory(id);
        NsudoDevilModeScope.EnsurePrivateDirectory(dir);
        string sourceExe = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot determine the packaged EXE.");
        if (!Path.GetExtension(sourceExe).Equals(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Independent Revert requires a standalone EXE.");
        string sha = SystemInfo.Sha256(File.ReadAllBytes(sourceExe));
        string staged = Path.Combine(dir, ExecutableName);
        File.Copy(sourceExe, staged, overwrite: false);
        if (!SystemInfo.Sha256(File.ReadAllBytes(staged))
                .Equals(sha, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Protected Revert executor SHA-256 mismatch.");
        // The request carries only expected hashes, version and profile.
        // The worker reconstructs the original bytes from trusted local storage.
        var req = new RevertRequest(id, approved.OriginalSha256,
            approved.InstalledSha256, approved.FileVersion, approved.ProfileId,
            approved.RecoverySource, sha);
        File.WriteAllText(Path.Combine(dir, RevertRequestName),
            JsonSerializer.Serialize(req));
        WriteStatus(dir, new Status(id, "Queued",
            "Revert queued independently of the RDP GUI.", DateTimeOffset.UtcNow.ToString("O")));
        try
        {
            RegisterAndStartTask(id, staged, RevertWorkerArgument);
            return id;
        }
        catch (Exception ex)
        {
            WriteStatus(dir, new Status(id, "Unconfirmed",
                "Revert scheduler launch unconfirmed: " + ex.GetType().Name,
                DateTimeOffset.UtcNow.ToString("O")));
            throw;
        }
    }

    /// <summary>
    /// Truly non-destructive Windows Task Scheduler integration check.
    /// Stages the same EXE and executes the same COM task-registration path,
    /// but the worker only attests SYSTEM + Session 0 and returns; it never
    /// opens a system DLL or stops a Windows service.
    /// </summary>
    internal static int RunSchedulerProbe()
    {
        if (!OperatingSystem.IsWindows() || !SystemInfo.IsAdministrator()) return 10;
        var id = Guid.NewGuid().ToString("N");
        var parent = Path.GetDirectoryName(Root)!;
        NsudoDevilModeScope.EnsurePrivateDirectory(parent);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
        var directory = JobDirectory(id);
        NsudoDevilModeScope.EnsurePrivateDirectory(directory);
        string source = Environment.ProcessPath
            ?? throw new InvalidOperationException("Self-contained EXE not detected.");
        if (!Path.GetExtension(source).Equals(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Probe requires published Windows EXE.");
        var sha = SystemInfo.Sha256(File.ReadAllBytes(source));
        var staged = Path.Combine(directory, ExecutableName);
        File.Copy(source, staged, overwrite: false);
        if (!SystemInfo.Sha256(File.ReadAllBytes(staged)).Equals(sha, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Probe staging checksum mismatch.");
        File.WriteAllText(Path.Combine(directory, "probe-request.json"),
            JsonSerializer.Serialize(new ProbeRequest(id, sha)));
        WriteStatus(directory, new Status(id, "ProbeQueued", "Safe scheduler probe",
            DateTimeOffset.UtcNow.ToString("O")));
        RegisterAndStartTask(id, staged, ProbeWorkerArgument);
        for (int i = 0; i < 90; i++)
        {
            Thread.Sleep(TimeSpan.FromSeconds(1));
            var status = JsonSerializer.Deserialize<Status>(
                File.ReadAllText(Path.Combine(directory, StatusName)));
            if (status is null || !status.Id.Equals(id, StringComparison.Ordinal)) return 12;
            if (status.State == "ProbeSucceeded")
            {
                Console.WriteLine("PASS: Task Scheduler launched protected EXE under SYSTEM in session 0; no DLL or service touched.");
                return 0;
            }
            if (status.State == "Failed") return 13;
        }
        Console.Error.WriteLine("FAIL: one-shot SYSTEM Task Scheduler probe timed out, no success assumed.");
        return 14;
    }

    internal static int RunProbeWorker(string? input)
    {
        if (!TryNormalizeId(input, out var id)) return 2;
        if (!IsSystemSessionZero()) return 3;
        var dir = JobDirectory(id);
        if (!Directory.Exists(dir)) return 4;
        NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
        NsudoDevilModeScope.EnsurePrivateDirectory(dir);
        try
        {
            using var once = new FileStream(Path.Combine(dir, LockName),
                FileMode.CreateNew, FileAccess.Write, FileShare.None);
            var request = JsonSerializer.Deserialize<ProbeRequest>(
                File.ReadAllText(Path.Combine(dir, "probe-request.json")))
                ?? throw new InvalidDataException("Probe request missing.");
            if (request.Id != id || request.ExeSha256 is null ||
                request.ExeSha256.Length != 64 || !request.ExeSha256.All(Uri.IsHexDigit) ||
                !SystemInfo.Sha256(File.ReadAllBytes(Path.Combine(dir, ExecutableName)))
                    .Equals(request.ExeSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Probe executable or ID mismatch.");
            WriteStatus(dir, new Status(id, "ProbeSucceeded", "SYSTEM Session 0 attested",
                DateTimeOffset.UtcNow.ToString("O")));
            return 0;
        }
        catch (Exception e)
        {
            AuditLog.Append("SYSTEM probe failed: " + e.GetType().Name);
            WriteStatus(dir, new Status(id, "Failed", e.GetType().Name,
                DateTimeOffset.UtcNow.ToString("O")));
            return 5;
        }
        finally
        {
            try { DeleteScheduledTask(id); } catch { }
        }
    }

    internal static int RunWorker(string? input)
    {
        if (!TryNormalizeId(input, out var id)) return 2;
        if (!IsSystemSessionZero()) return 3;
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
                    req.OriginalSha256 is null || req.OriginalSha256.Length != 64 ||
                    !req.OriginalSha256.All(Uri.IsHexDigit) ||
                    req.ExpectedPatchedSha256 is null || req.ExpectedPatchedSha256.Length != 64 ||
                    !req.ExpectedPatchedSha256.All(Uri.IsHexDigit) ||
                    req.ExeSha256 is null || req.ExeSha256.Length != 64 ||
                    !req.ExeSha256.All(Uri.IsHexDigit) ||
                    req.FileVersion is null || req.ProfileId is null ||
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
                    if (!plan.ProfileId.Equals(req.ProfileId, StringComparison.Ordinal) ||
                        !plan.FileVersion.Equals(req.FileVersion, StringComparison.Ordinal) ||
                        !SystemInfo.Sha256(File.ReadAllBytes(plan.FilePath))
                            .Equals(req.ExpectedPatchedSha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Already-patched DLL does not match expected job output.");
                    WriteStatus(dir, new Status(id, "AlreadyPatched",
                        "Current DLL already contains the exact authorized replacement hash.",
                        DateTimeOffset.UtcNow.ToString("O")));
                    return 0;
                }
                if (plan.IsManual || plan.State != PatchState.Ready ||
                    !plan.OriginalSha256.Equals(req.OriginalSha256, StringComparison.OrdinalIgnoreCase) ||
                    !plan.ProfileId.Equals(req.ProfileId, StringComparison.Ordinal) ||
                    !plan.FileVersion.Equals(req.FileVersion, StringComparison.Ordinal) ||
                    plan.PatchedBytes is null ||
                    !SystemInfo.Sha256(plan.PatchedBytes)
                        .Equals(req.ExpectedPatchedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("DLL drift or a different signature invalidated the job.");
                // No user-supplied path, no direct write and no no-backup option.
                WriteStatus(dir, new Status(id, "Running",
                    "System executor is applying the verified plan.", DateTimeOffset.UtcNow.ToString("O")));
                engine.Apply(plan, createBackup: req.CreateBackup);
                var after = File.ReadAllBytes(plan.FilePath);
                if (!SystemInfo.Sha256(after).Equals(req.ExpectedPatchedSha256,
                    StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Post-transaction DLL checksum mismatch.");
                // Persist bounded, validated metadata before announcing success.
                // GUI may be destroyed when TermService restarts during RDP Apply.
                // Optional reporting metadata failure must never reclassify Apply
                // or rerun a completed protected DLL transaction.
                SuccessfulFixMetadata? report = null;
                try
                {
                    report = SuccessfulFixMetadata.FromSuccessfulApply(
                        engine.EnvironmentInfo(), plan);
                }
                catch (Exception reportError) when (reportError is
                    InvalidDataException or InvalidOperationException or IOException or
                    UnauthorizedAccessException or ArgumentException)
                {
                    AuditLog.Append("One-shot Apply report evidence unavailable: " +
                                    reportError.GetType().Name);
                }
                WriteStatus(dir, new Status(id, "Succeeded",
                    "Protected write and RDP service recovery returned successfully.",
                    DateTimeOffset.UtcNow.ToString("O"), report));
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

    internal static int RunRevertWorker(string? input)
    {
        if (!TryNormalizeId(input, out var id)) return 2;
        if (!IsSystemSessionZero()) return 3;
        string dir = JobDirectory(id);
        if (!Directory.Exists(dir) || !Directory.Exists(Root)) return 4;
        NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
        NsudoDevilModeScope.EnsurePrivateDirectory(dir);
        try
        {
            using var once = new FileStream(Path.Combine(dir, LockName),
                FileMode.CreateNew, FileAccess.Write, FileShare.None);
            once.WriteByte(1);
            once.Flush(flushToDisk: true);
            try
            {
                var req = JsonSerializer.Deserialize<RevertRequest>(
                    File.ReadAllText(Path.Combine(dir, RevertRequestName)))
                    ?? throw new InvalidDataException("Invalid scheduled Revert request.");
                static bool ValidHash(string? value) =>
                    value is { Length: 64 } && value.All(Uri.IsHexDigit);
                if (req.Id != id || !ValidHash(req.OriginalSha256) ||
                    !ValidHash(req.CurrentSha256) || !ValidHash(req.ExeSha256) ||
                    req.FileVersion is null || req.ProfileId is null ||
                    req.FileVersion.Length is < 1 or > 128 ||
                    req.ProfileId.Length is < 1 or > 256 ||
                    req.RecoverySource is not ("Journal" or "TrustedBackup" or "System32Backup" or "ExactCatalog"))
                    throw new InvalidDataException("Untrusted Revert request metadata.");
                if (!SystemInfo.Sha256(File.ReadAllBytes(Path.Combine(dir, ExecutableName)))
                        .Equals(req.ExeSha256, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Revert worker EXE SHA-256 changed.");
                var approved = new AutomaticRevertPlan(req.OriginalSha256,
                    req.CurrentSha256, req.FileVersion, req.ProfileId, req.RecoverySource);
                if (!AutomaticRevertSafety.SameApproval(approved, AutomaticRevertSafety.Inspect()))
                    throw new InvalidOperationException(
                        "Source DLL or recovery evidence changed before Revert execution.");

                WriteStatus(dir, new Status(id, "Running",
                    "Revert worker restoring exact authenticated original.",
                    DateTimeOffset.UtcNow.ToString("O")));
                using var engine = new TermsrvEngine(null);
                engine.RevertAutomatic(approved);
                var os = SystemInfo.Read();
                if (!SystemInfo.Sha256(File.ReadAllBytes(os.DllPath))
                        .Equals(req.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Revert worker final SHA-256 mismatch.");
                WriteStatus(dir, new Status(id, "Succeeded",
                    "Revert finished and original DLL SHA-256 verified.",
                    DateTimeOffset.UtcNow.ToString("O")));
                return 0;
            }
            catch (Exception ex)
            {
                AuditLog.Append("Isolated Revert failed: " + ex.GetType().Name);
                WriteStatus(dir, new Status(id, "Failed",
                    "Revert failed: " + ex.GetType().Name,
                    DateTimeOffset.UtcNow.ToString("O")));
                return 5;
            }
        }
        catch (IOException) when (File.Exists(Path.Combine(dir, LockName)))
        {
            // Existing lock means this job has already started; never replay.
            return 0;
        }
        finally
        {
            try { DeleteScheduledTask(id); }
            catch { /* The one-shot lock blocks re-execution. */ }
        }
    }

    internal static bool IsSystemSessionZero()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is null ||
            !identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid))
            return false;
        using var process = Process.GetCurrentProcess();
        return process.SessionId == 0;
    }

    /// <summary>
    /// Stronger preflight for destructive Cleanup: inspect every job folder,
    /// not just the ten most recent. Unreadable/incomplete jobs fail closed.
    /// </summary>
    internal static bool AnyActiveJob()
    {
        if (!Directory.Exists(Root)) return false;
        try
        {
            NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
            NsudoDevilModeScope.EnsurePrivateDirectory(Root);
            int seen = 0;
            foreach (var dir in Directory.EnumerateDirectories(Root, "job-*",
                         SearchOption.TopDirectoryOnly))
            {
                if (++seen > 1024 ||
                    (File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                    return true;
                string path = Path.Combine(dir, StatusName);
                if (!File.Exists(path) ||
                    (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    return true;
                var status = JsonSerializer.Deserialize<Status>(File.ReadAllText(path));
                if (status is null || !TryNormalizeId(status.Id, out _) ||
                    status.State is "Queued" or "Running" or "Unconfirmed" or "ProbeQueued")
                    return true;
            }
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   JsonException or InvalidOperationException)
        {
            return true;
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

    /// <summary>
    /// Pure policy for attaching a self-reported success to a one-shot task:
    /// request, persisted success and CURRENT installed DLL SHA must agree.
    /// A queued or AlreadyPatched task cannot imply a newly completed Apply.
    /// </summary>
    internal static bool VerifiedReportMatches(Status? status, Request? request,
        string? installedSha256)
    {
        var record = status?.Report;
        if (status?.State != "Succeeded" || request is null || record is null ||
            !TryNormalizeId(status.Id, out var id) ||
            !string.Equals(request.Id, id, StringComparison.OrdinalIgnoreCase) ||
            request.OriginalSha256.Length != 64 ||
            request.ExpectedPatchedSha256.Length != 64 ||
            string.IsNullOrWhiteSpace(installedSha256) ||
            !string.Equals(installedSha256, request.ExpectedPatchedSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(record.OriginalSha256, request.OriginalSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(record.PatchedSha256, request.ExpectedPatchedSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(record.DllVersion, request.FileVersion,
                StringComparison.Ordinal) ||
            record.Mode != "automatic")
            return false;
        try { record.Validate(); return true; }
        catch (Exception ex) when (ex is InvalidDataException or
                                   ArgumentException or OverflowException)
        { return false; }
    }

    /// <summary>
    /// The persisted job is a USER-APPROVED one-shot Apply, never the
    /// unattended Windows-Update AutoReapply task. Read-only, fail-closed.
    /// </summary>
    internal static bool TryReadVerifiedReport(Status? status,
        out SuccessfulFixMetadata? report)
    {
        report = null;
        if (!SystemInfo.IsAdministrator() ||
            status?.State != "Succeeded" || status.Report is null ||
            !TryNormalizeId(status.Id, out var id))
            return false;
        try
        {
            NsudoDevilModeScope.EnsurePrivateDirectory(
                Path.GetDirectoryName(Root)!);
            NsudoDevilModeScope.EnsurePrivateDirectory(Root);
            string dir = JobDirectory(id);
            if (!Directory.Exists(dir) ||
                (File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                return false;
            NsudoDevilModeScope.EnsurePrivateDirectory(dir);
            string statusFile = Path.Combine(dir, StatusName);
            string requestFile = Path.Combine(dir, RequestName);
            if (!File.Exists(statusFile) || !File.Exists(requestFile) ||
                (File.GetAttributes(statusFile) & FileAttributes.ReparsePoint) != 0 ||
                (File.GetAttributes(requestFile) & FileAttributes.ReparsePoint) != 0 ||
                new FileInfo(statusFile).Length > 10000 ||
                new FileInfo(requestFile).Length > 3000)
                return false;
            var persisted = JsonSerializer.Deserialize<Status>(File.ReadAllText(statusFile));
            var request = JsonSerializer.Deserialize<Request>(File.ReadAllText(requestFile));
            if (persisted is null || request is null || persisted.Id != id ||
                !string.Equals(status.Utc, persisted.Utc, StringComparison.Ordinal))
                return false;

            var os = SystemInfo.Read();
            if (!os.Supported || os.DllVersion != persisted.Report?.DllVersion ||
                os.Name != persisted.Report.WindowsName ||
                os.DisplayVersion != persisted.Report.WindowsRelease ||
                os.Build != persisted.Report.WindowsBuild ||
                os.Ubr != persisted.Report.Ubr)
                return false;

            string installedHash = SystemInfo.Sha256(File.ReadAllBytes(os.DllPath));
            if (!VerifiedReportMatches(persisted, request, installedHash))
                return false;
            report = persisted.Report;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   JsonException or InvalidDataException or ArgumentException or
                                   InvalidOperationException or System.Security.SecurityException)
        {
            return false;
        }
    }

    /// <summary>
    /// A durable at-most-once UI OFFER, not an upload permission. The user
    /// still approves every report in the normal review/confirmation window.
    /// </summary>
    internal static bool TryClaimReportOffer(string id) =>
        TryCreateReportMarker(id, ReportOfferedName);

    internal static bool WasReportDelivered(string id) =>
        ReportMarkerExists(id, ReportDeliveredName);

    internal static bool TryMarkReportDelivered(string id) =>
        TryCreateReportMarker(id, ReportDeliveredName);

    private static bool ReportMarkerExists(string id, string marker)
    {
        if (!TryNormalizeId(id, out _)) return false;
        try
        {
            string dir = JobDirectory(id);
            return Directory.Exists(dir) &&
                (File.GetAttributes(dir) & FileAttributes.ReparsePoint) == 0 &&
                File.Exists(Path.Combine(dir, marker));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   ArgumentException) { return false; }
    }

    private static bool TryCreateReportMarker(string id, string marker)
    {
        if (!SystemInfo.IsAdministrator() || !TryNormalizeId(id, out _))
            return false;
        try
        {
            NsudoDevilModeScope.EnsurePrivateDirectory(
                Path.GetDirectoryName(Root)!);
            NsudoDevilModeScope.EnsurePrivateDirectory(Root);
            string dir = JobDirectory(id);
            if (!Directory.Exists(dir) ||
                (File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                return false;
            NsudoDevilModeScope.EnsurePrivateDirectory(dir);
            using var stream = new FileStream(Path.Combine(dir, marker),
                FileMode.CreateNew, FileAccess.Write, FileShare.None,
                1024, FileOptions.WriteThrough);
            byte[] timestamp = System.Text.Encoding.UTF8.GetBytes(
                DateTimeOffset.UtcNow.ToString("O"));
            stream.Write(timestamp);
            stream.Flush(flushToDisk: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   ArgumentException or System.Security.SecurityException)
        { return false; }
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

    private static void RegisterAndStartTask(string id, string stagedExe,
        string argument = WorkerArgument)
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
            // Never let Task Scheduler kill this process while TermService
            // is stopped: ServiceGuard itself bounds state transitions.
            task.Settings.ExecutionTimeLimit = "PT0S";
            task.Settings.DisallowStartIfOnBatteries = false;
            task.Settings.StopIfGoingOnBatteries = false;
            dynamic trigger = task.Triggers.Create(1); // TASK_TRIGGER_TIME
            trigger.StartBoundary = DateTime.Now.AddMinutes(1).ToString(
                "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
            trigger.Enabled = true;
            dynamic action = task.Actions.Create(0); // TASK_ACTION_EXEC
            action.Path = stagedExe;
            if (argument is not (WorkerArgument or RevertWorkerArgument or ProbeWorkerArgument))
                throw new InvalidOperationException("Unexpected protected task argument.");
            action.Arguments = argument + " " + id;
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
