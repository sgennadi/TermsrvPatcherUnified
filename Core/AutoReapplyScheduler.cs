using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Explicitly opted-in, machine-wide recurring Task Scheduler worker.
/// Its executable and state live in administrator/SYSTEM-owned ProgramData,
/// never in Desktop, Downloads or another ordinary-user writable directory.
/// The worker never accepts a DLL path, pattern or command line from its task.
/// </summary>
internal static class AutoReapplyScheduler
{
    internal const string WorkerArgument = "--auto-reapply-worker";
    internal const string TaskName = "TermsrvPatcherUnified-AutoReapply";
    private const string ExeName = "TermsrvPatcherUnified.exe";
    private const string StateName = "state.json";
    private const string Schema = "termsrv-auto-reapply/v1";
    // Windows Task Scheduler may add an extra ACE for the task principal
    // unless TASK_DONT_ADD_PRINCIPAL_ACE (0x10) is passed explicitly.
    internal const int CreateOrUpdateProtectedFlags = 0x06 | 0x10;
    private const string ProtectedTaskSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    internal static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TermsrvPatcherUnified.Secure", "AutoReapply");

    internal static string WorkerPath => Path.Combine(Root, ExeName);

    internal sealed record TaskState(bool Installed, bool Trusted, bool Enabled,
        string Message, bool Running = false, bool Repairable = false);
    private sealed record WorkerState(string SchemaId, string LastObservedSha256,
        string Result, string CheckedUtc, string RuntimeVersion);

    internal static bool NeedsInspection(string currentSha, string currentVersion,
        string lastSha, string? lastRuntimeVersion)
        => !currentSha.Equals(lastSha, StringComparison.OrdinalIgnoreCase) ||
           !currentVersion.Equals(lastRuntimeVersion, StringComparison.Ordinal);

    internal static bool HasProtectedTaskDacl(string? sddl)
    {
        if (string.IsNullOrWhiteSpace(sddl)) return false;
        int index = sddl.IndexOf("D:P", StringComparison.OrdinalIgnoreCase);
        if (index < 0) return false;
        int audit = sddl.IndexOf("S:", index, StringComparison.OrdinalIgnoreCase);
        string dacl = audit < 0 ? sddl[index..] : sddl[index..audit];
        var entries = Regex.Matches(dacl, @"\([^)]*\)");
        if (entries.Count < 2) return false;
        bool system = false;
        bool administrators = false;
        foreach (Match entry in entries)
        {
            var fields = entry.Value.Trim('(', ')').Split(';');
            if (fields.Length != 6 || !fields[0].Equals("A", StringComparison.Ordinal))
                return false; // Unexpected ACE or unsupported ACL format.
            var trustee = fields[5];
            if (trustee is "SY" or "S-1-5-18") system = true;
            else if (trustee is "BA" or "S-1-5-32-544") administrators = true;
            else return false; // Non-admin ACE can alter the scheduled action.
        }
        return system && administrators;
    }

    // Inspection and repair use the same exact identity gate. A foreign task
    // with this name must never be overwritten, deleted or ACL-repaired.
    private static bool HasExpectedTaskIdentity(dynamic task)
    {
        if ((int)task.Actions.Count != 1 ||
            (int)task.Principal.LogonType != 5 ||
            (int)task.Principal.RunLevel != 1 ||
            (int)task.Triggers.Count != 3)
            return false;
        string principal = Convert.ToString(task.Principal.UserId) ?? "";
        if (!principal.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
            !principal.Equals("S-1-5-18", StringComparison.OrdinalIgnoreCase) &&
            !principal.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase))
            return false;
        dynamic action = task.Actions.Item(1);
        string location = Convert.ToString(action.Path) ?? "";
        string arguments = Convert.ToString(action.Arguments) ?? "";
        string working = Convert.ToString(action.WorkingDirectory) ?? "";
        if (location.Length == 0 || working.Length == 0 ||
            !Path.GetFullPath(location).Equals(Path.GetFullPath(WorkerPath),
                StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFullPath(working).Equals(Path.GetFullPath(Root),
                StringComparison.OrdinalIgnoreCase) ||
            arguments != WorkerArgument) return false;

        dynamic evt = task.Triggers.Item(1);
        dynamic boot = task.Triggers.Item(2);
        dynamic daily = task.Triggers.Item(3);
        string subscription = Convert.ToString(evt.Subscription) ?? "";
        return (int)evt.Type == 0 && (int)boot.Type == 8 &&
            (int)daily.Type == 2 && (int)daily.DaysInterval == 1 &&
            subscription.Contains("Microsoft-Windows-WindowsUpdateClient/Operational",
                StringComparison.Ordinal) && subscription.Contains("EventID=19", StringComparison.Ordinal);
    }

    /// <summary>
    /// ACL-only repair, never a task replacement. Must be initiated by an
    /// elevated administrator who explicitly confirmed the proposed change.
    /// </summary>
    internal static void RepairTaskPermissions()
    {
        RequireAdministrator();
        var state = ReadStatus();
        if (!state.Repairable || !state.Installed || state.Trusted || state.Running)
            throw new UnauthorizedAccessException("Only our recognized, idle task is eligible for ACL repair.");
        object? service = null, folder = null, registered = null, definition = null;
        try
        {
            service = Connect();
            folder = ((dynamic)service).GetFolder(@"\");
            registered = ((dynamic)folder).GetTask(TaskName);
            definition = ((dynamic)registered).Definition;
            if ((int)((dynamic)registered).State == 4)
                throw new InvalidOperationException("Scheduled task is currently running; try repair after it finishes.");
            if (!HasExpectedTaskIdentity((dynamic)definition) ||
                !Directory.Exists(Root) || !File.Exists(WorkerPath) ||
                (File.GetAttributes(WorkerPath) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Scheduled task changed during ACL inspection.");
            NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
            NsudoDevilModeScope.EnsurePrivateDirectory(Root);
            string currentAcl = Convert.ToString(((dynamic)registered).GetSecurityDescriptor(4)) ?? "";
            if (HasProtectedTaskDacl(currentAcl)) return; // Already repaired.
            ((dynamic)registered).SetSecurityDescriptor(ProtectedTaskSddl, 0x10);
        }
        finally { ReleaseCom(definition, registered, folder, service); }
        var verified = ReadStatus();
        if (!verified.Trusted)
            throw new IOException("Windows Task Scheduler did not confirm the protected permissions.");
        AuditLog.Append("Protected Auto Reapply scheduled-task ACL repaired after administrator confirmation.");
    }

    // Some Windows Task Scheduler COM bindings surface a missing task as
    // FileNotFoundException (0x80070002), not COMException. Only the named
    // GetTask lookup may interpret this as 'not configured'. Other missing
    // files (including the protected worker) must still fail closed.
    internal static bool IsMissingTaskLookupError(Exception error)
    {
        if (error is not COMException && error is not FileNotFoundException)
            return false;
        return (uint)error.HResult is 0x80070002 or 0x8004130F;
    }

    internal static TaskState ReadStatus()
    {
        if (!OperatingSystem.IsWindows())
            return new(false, false, false, "Windows Task Scheduler unavailable.");
        object? service = null, folder = null, registered = null, definition = null, action = null;
        try
        {
            service = Connect();
            dynamic scheduler = service;
            folder = scheduler.GetFolder(@"\");
            try { registered = ((dynamic)folder).GetTask(TaskName); }
            catch (Exception error) when (IsMissingTaskLookupError(error))
            {
                return new(false, false, false,
                    "Scheduled task: Not configured (optional).");
            }
            definition = ((dynamic)registered).Definition;
            dynamic taskDef = definition;
            // Only a task with OUR expected action, SYSTEM identity, trigger
            // profile and protected worker is eligible for an ACL-only repair.
            if (!HasExpectedTaskIdentity(taskDef))
                return new(true, false, false,
                    "Task action, trigger schedule or identity differs from the protected profile. Manual review required.");
            if (!Directory.Exists(Root) || !File.Exists(WorkerPath) ||
                (File.GetAttributes(WorkerPath) & FileAttributes.ReparsePoint) != 0)
                return new(true, false, false, "Protected worker executable is missing or linked.");
            NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
            NsudoDevilModeScope.EnsurePrivateDirectory(Root);
            bool enabled = (bool)((dynamic)registered).Enabled;
            bool running = (int)((dynamic)registered).State == 4; // TASK_STATE_RUNNING
            string dacl = Convert.ToString(((dynamic)registered).GetSecurityDescriptor(4)) ?? "";
            if (!HasProtectedTaskDacl(dacl))
                return new(true, false, false,
                    running ? "Auto Reapply task is running with unverified permissions. Wait for completion."
                            : "Task permissions need repair. Only SYSTEM + Administrators may modify it.",
                    Running: running, Repairable: !running);
            return new(true, true, enabled,
                running ? "SYSTEM worker is running now; do not clean up its files." :
                enabled ? "Enabled. Checks after Windows Update and on startup."
                        : "Scheduled task is disabled.",
                running);
        }
        catch (Exception ex) when (ex is COMException or IOException or UnauthorizedAccessException or
                                   InvalidOperationException or ArgumentException or
                                   System.Security.SecurityException)
        {
            // Unknown state is NOT absence: registration and deletion must
            // fail closed rather than overwrite a task we could not inspect.
            return new(true, false, false, "Could not verify scheduled task (" + ex.GetType().Name + ").");
        }
        finally
        {
            ReleaseCom(action, definition, registered, folder, service);
        }
    }

    /// <summary>Perform a task-setup transaction only after an explicit user confirmation.</summary>
    internal static void Enable()
    {
        RequireAdministrator();
        var current = ReadStatus();
        if (current.Installed && !current.Trusted)
            throw new UnauthorizedAccessException("An unexpected scheduled task already uses this name. Refusing to overwrite it.");
        if (!SystemInfo.Read().Supported || !NsudoDevilModeScope.IsBundled)
            throw new InvalidOperationException("Automatic reapply requires supported Windows x64 and bundled NSudo.");
        NsudoDevilModeScope.Preflight();

        string source = Environment.ProcessPath ??
            throw new InvalidOperationException("Cannot locate the running application.");
        if (!Path.GetFileName(source).Equals(ExeName, StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(source))
            throw new InvalidOperationException("Enable this option from the packaged TermsrvPatcherUnified.exe.");

        EnsureRoot();
        UpdateProtectedWorker(source);
        // This is only an observation. The first scheduled run does NOT
        // reapply an unmodified DLL just because the option was enabled.
        string dll = SystemInfo.Read().DllPath;
        var existing = ReadWorkerState();
        if (!current.Installed || !current.Enabled || existing is null)
            SaveWorkerState(new WorkerState(Schema, HashFile(dll), "Armed",
                DateTimeOffset.UtcNow.ToString("O"), UpdateIntegration.Version));

        RegisterTask();
        var confirmed = ReadStatus();
        if (!confirmed.Trusted || !confirmed.Enabled)
            throw new IOException("Scheduled task registration could not be verified.");
        AuditLog.Append("Automatic post-update signature checking enabled by administrator.");
    }

    internal static void Disable()
    {
        RequireAdministrator();
        var state = ReadStatus();
        if (state.Installed && !state.Trusted)
            throw new UnauthorizedAccessException("Unrecognized task definition; not deleting it.");
        if (!state.Installed) return;
        if (state.Running)
            throw new InvalidOperationException(
                "The auto-reapply worker is currently running. Disable it after it finishes.");
        if (IsolatedApplyExecutor.AnyActiveJob())
            throw new InvalidOperationException("A protected Apply/Revert is pending or uncertain. Disable automation after it completes.");
        object? service = null, folder = null;
        try
        {
            service = Connect();
            folder = ((dynamic)service).GetFolder(@"\");
            ((dynamic)folder).DeleteTask(TaskName, 0);
        }
        finally { ReleaseCom(folder, service); }
        // The task is removed first; a still-running worker is not terminated.
        // The executable may be locked by that worker and is then left intact.
        if (File.Exists(WorkerPath))
        {
            try
            {
                if ((File.GetAttributes(WorkerPath) & FileAttributes.ReparsePoint) == 0)
                    File.Delete(WorkerPath);
            }
            catch (IOException) { }
        }
        AuditLog.Append("Automatic post-update task disabled by administrator.");
    }

    /// <summary>
    /// The updater may refresh an already-registered protected worker after
    /// successful EXE installation, without re-arming a disabled task.
    /// </summary>
    internal static void RefreshWorkerAfterSuccessfulUpdate(string newInstalledExe)
    {
        var state = ReadStatus();
        if (!state.Installed || !state.Trusted || !state.Enabled) return;
        EnsureRoot();
        UpdateProtectedWorker(newInstalledExe);
    }

    internal static int RunWorker()
    {
        if (!IsolatedApplyExecutor.IsSystemSessionZero())
            return 3;
        if (!Path.GetFullPath(Environment.ProcessPath ?? "").Equals(
                Path.GetFullPath(WorkerPath), StringComparison.OrdinalIgnoreCase))
            return 4;
        var configured = ReadStatus();
        if (!configured.Trusted || !configured.Enabled)
            return 5;
        if (IsolatedApplyExecutor.ReadLatestStatus()?.State is "Queued" or "Running")
            return 6;
        try
        {
            if (IsRebootPending()) return 7;
            using var engine = new TermsrvEngine(null);
            var os = engine.EnvironmentInfo();
            if (!os.Supported) return 8;
            string beforeSha = HashFile(os.DllPath);
            var saved = ReadWorkerState();
            if (saved is null)
            {
                // Missing/corrupted state must not authorize an unattended patch.
                SaveWorkerState(new WorkerState(Schema, beforeSha, "State recreated; no Apply",
                    DateTimeOffset.UtcNow.ToString("O"), UpdateIntegration.Version));
                return 9;
            }
            if (!NeedsInspection(beforeSha, UpdateIntegration.Version, saved.LastObservedSha256,
                    saved.RuntimeVersion))
                return 0;

            var plan = engine.Inspect();
            if (plan.State == PatchState.Ready && !plan.IsManual &&
                plan.OriginalSha256.Equals(beforeSha, StringComparison.OrdinalIgnoreCase) &&
                plan.PatchedBytes is not null)
            {
                // Every run performs a fresh exact-signature and file-hash check;
                // engine.Apply performs its own protected transaction and
                // creates a full backup plus a recovery journal.
                NsudoDevilModeScope.Preflight();
                engine.Apply(plan, createBackup: true);
                var verified = HashFile(os.DllPath);
                if (!verified.Equals(SystemInfo.Sha256(plan.PatchedBytes),
                        StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Scheduled Apply did not produce the verified DLL hash.");
                SaveWorkerState(new WorkerState(Schema, verified, "Applied verified automatic profile",
                    DateTimeOffset.UtcNow.ToString("O"), UpdateIntegration.Version));
                AuditLog.Append("Auto reapply after DLL change succeeded. Profile=" + plan.ProfileId);
                return 0;
            }
            // Unknown/ambiguous/unsupported files are never changed.
            // Record the observed hash to avoid repeatedly retrying the same
            // DLL with the same binary/pattern database on each scheduled run.
            SaveWorkerState(new WorkerState(Schema, beforeSha,
                "Skipped: " + plan.State, DateTimeOffset.UtcNow.ToString("O"),
                UpdateIntegration.Version));
            AuditLog.Append("Auto reapply skipped after DLL change: " + plan.State);
            return plan.State == PatchState.AlreadyPatched ? 0 : 10;
        }
        catch (Exception ex)
        {
            AuditLog.Append("Auto reapply failed safely: " + ex.GetType().Name);
            return 11;
        }
    }

    private static bool IsRebootPending()
    {
        using var servicing = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
        using var update = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
        return servicing is not null || update is not null;
    }

    private static void RegisterTask()
    {
        object? service = null, folder = null, definition = null, registered = null;
        try
        {
            service = Connect();
            dynamic scheduler = service;
            folder = scheduler.GetFolder(@"\");
            definition = scheduler.NewTask(0);
            dynamic task = definition;
            task.RegistrationInfo.Description =
                "Opt-in, protected post-Windows-Update termsrv.dll signature check. Exact matches only; full backup required.";
            task.Principal.UserId = "SYSTEM";
            task.Principal.LogonType = 5; // TASK_LOGON_SERVICE_ACCOUNT
            task.Principal.RunLevel = 1; // TASK_RUNLEVEL_HIGHEST
            task.Settings.Hidden = false;
            task.Settings.Enabled = true;
            task.Settings.AllowDemandStart = true;
            task.Settings.ExecutionTimeLimit = "PT0S";
            task.Settings.DisallowStartIfOnBatteries = false;
            task.Settings.StopIfGoingOnBatteries = false;
            task.Settings.StartWhenAvailable = true;
            task.Settings.MultipleInstances = 2; // Ignore new instances while running.
            dynamic eventTrigger = task.Triggers.Create(0); // TASK_TRIGGER_EVENT
            eventTrigger.Subscription =
                "<QueryList><Query Id=\"0\" Path=\"Microsoft-Windows-WindowsUpdateClient/Operational\">" +
                "<Select Path=\"Microsoft-Windows-WindowsUpdateClient/Operational\">" +
                "*[System[(EventID=19)]]</Select></Query></QueryList>";
            eventTrigger.Delay = "PT30M"; // Let Windows servicing finish first.
            eventTrigger.Enabled = true;
            dynamic bootTrigger = task.Triggers.Create(8); // TASK_TRIGGER_BOOT
            bootTrigger.Delay = "PT15M";
            bootTrigger.Enabled = true;
            // A daily check catches updates whose event was missed.
            dynamic daily = task.Triggers.Create(2); // TASK_TRIGGER_DAILY
            daily.StartBoundary = DateTime.Now.AddDays(1).Date.AddHours(3)
                .ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
            daily.DaysInterval = 1;
            daily.Enabled = true;

            dynamic action = task.Actions.Create(0); // TASK_ACTION_EXEC
            action.Path = WorkerPath;
            action.Arguments = WorkerArgument;
            action.WorkingDirectory = Root;
            registered = ((dynamic)folder).RegisterTaskDefinition(TaskName, definition,
                CreateOrUpdateProtectedFlags, "SYSTEM", null, 5, ProtectedTaskSddl);
            // Explicitly enforce the DACL after registration (Windows may
            // normalize a creation-time SDDL); never trust mere success HRESULT.
            ((dynamic)registered).SetSecurityDescriptor(ProtectedTaskSddl, 0x10);
        }
        finally { ReleaseCom(registered, definition, folder, service); }
    }

    private static void UpdateProtectedWorker(string source)
    {
        if (!Path.GetFileName(source).Equals(ExeName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Protected updater requires the expected EXE name.");
        if ((File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Source EXE must not be a filesystem link.");
        var originalHash = HashFile(source);
        if (File.Exists(WorkerPath))
        {
            if ((File.GetAttributes(WorkerPath) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Existing protected worker is a filesystem link.");
            if (HashFile(WorkerPath).Equals(originalHash, StringComparison.OrdinalIgnoreCase))
                return;
        }
        string stage = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".new");
        try
        {
            File.Copy(source, stage, overwrite: false);
            if (!HashFile(stage).Equals(originalHash, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Protected worker copy failed SHA-256 verification.");
            File.Move(stage, WorkerPath, overwrite: true);
            if (!HashFile(WorkerPath).Equals(originalHash, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Protected worker EXE hash mismatch after install.");
        }
        finally { if (File.Exists(stage)) File.Delete(stage); }
    }

    private static WorkerState? ReadWorkerState()
    {
        if (!Directory.Exists(Root)) return null;
        EnsureRoot();
        string path = Path.Combine(Root, StateName);
        if (!File.Exists(path)) return null;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Auto-reapply state is linked.");
        if (new FileInfo(path).Length > 4096) return null;
        try
        {
            var state = JsonSerializer.Deserialize<WorkerState>(File.ReadAllText(path));
            return state is { SchemaId: Schema } &&
                IsSha(state.LastObservedSha256) ? state : null;
        }
        catch (JsonException) { return null; }
    }

    private static void SaveWorkerState(WorkerState state)
    {
        EnsureRoot();
        string stage = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllText(stage, JsonSerializer.Serialize(state));
            File.Move(stage, Path.Combine(Root, StateName), overwrite: true);
        }
        finally { if (File.Exists(stage)) File.Delete(stage); }
    }

    private static bool IsSha(string? input) =>
        input is { Length: 64 } && input.All(Uri.IsHexDigit);

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static void EnsureRoot()
    {
        NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
    }

    private static void RequireAdministrator()
    {
        if (!OperatingSystem.IsWindows() || !SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Administrator elevation is required for the scheduled task.");
    }

    private static object Connect()
    {
        var type = Type.GetTypeFromProgID("Schedule.Service") ??
            throw new PlatformNotSupportedException("Task Scheduler COM is unavailable.");
        var service = Activator.CreateInstance(type) ??
            throw new InvalidOperationException("Task Scheduler COM could not initialize.");
        ((dynamic)service).Connect();
        return service;
    }

    private static void ReleaseCom(params object?[] objects)
    {
        foreach (var item in objects)
            if (item is not null && Marshal.IsComObject(item))
                Marshal.FinalReleaseComObject(item);
    }
}
