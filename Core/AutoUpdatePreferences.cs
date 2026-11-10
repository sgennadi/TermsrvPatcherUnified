using Microsoft.Win32;
using UniversalUpdater;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Machine-wide opt-in for automatic Stable release discovery. Does not grant
/// unattended installation: unsigned executables still need per-release
/// approval in the interactive updater window.
/// </summary>
internal static class AutoUpdatePreferences
{
    private const string RegistryPath = @"SOFTWARE\TermsrvPatcherUnified\Updates";
    private const string EnabledName = "AutoCheckStable";
    internal static readonly TimeSpan GuiInterval = TimeSpan.FromHours(4);

    internal static bool IsEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            return key?.GetValueKind(EnabledName) == RegistryValueKind.DWord &&
                   key.GetValue(EnabledName, null) is int setting && setting == 1;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or
                                   System.Security.SecurityException or
                                   IOException or ArgumentException)
        {
            return false; // Unknown must not opt in.
        }
    }

    internal static void SetEnabled(bool enabled)
    {
        if (!OperatingSystem.IsWindows() || !SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Administrator rights are required to set machine-wide automatic checks.");
        using var key = Registry.LocalMachine.CreateSubKey(RegistryPath, writable: true)
            ?? throw new IOException("Machine-wide update preference is unavailable.");
        key.SetValue(EnabledName, enabled ? 1 : 0, RegistryValueKind.DWord);
        if (key.GetValue(EnabledName, null) is not int saved ||
            saved != (enabled ? 1 : 0))
            throw new IOException("Update check preference could not be verified.");
        AuditLog.Append("Stable update automatic check " + (enabled ? "enabled" : "disabled") +
            ". Installation still requires an explicit confirmation.");
    }

    internal static string ReadScheduledSummary()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key is null) return "No scheduled update check recorded.";
            var utc = Convert.ToString(key.GetValue("LastCheckUtc", ""));
            var status = Convert.ToString(key.GetValue("LastCheckResult", ""));
            var version = Convert.ToString(key.GetValue("LastSeenStable", ""));
            if (string.IsNullOrWhiteSpace(utc) || string.IsNullOrWhiteSpace(status))
                return "No scheduled update check recorded.";
            return "Last scheduled Stable check: " + status +
                   (SemanticVersion.TryParse(version, out var ver) && !ver.IsPrerelease
                       ? " (" + ver + ")" : "") +
                   " at " + utc + " UTC. Open Updates for a fresh live check.";
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or
                                   System.Security.SecurityException or
                                   IOException or ArgumentException)
        {
            return "Scheduled check status inaccessible (" + ex.GetType().Name + ").";
        }
    }

    internal static bool IsScheduledCheckDue(DateTimeOffset? last,
        DateTimeOffset now) => last is null ||
            now < last.Value || now - last.Value >= TimeSpan.FromHours(24);

    // Only the already-trusted AutoReapply worker runs in SYSTEM Session 0.
    // It may read GitHub metadata when explicitly opted in, but NEVER stages,
    // downloads, replaces, launches an update, or modifies the task definition.
    internal static void CheckFromProtectedWorker()
    {
        if (!IsEnabled() || !IsolatedApplyExecutor.IsSystemSessionZero()) return;
        try
        {
            using var previous = Registry.LocalMachine.OpenSubKey(RegistryPath);
            var raw = Convert.ToString(previous?.GetValue("LastCheckUtc", ""));
            DateTimeOffset? last = DateTimeOffset.TryParse(raw,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed)
                ? parsed : null;
            if (!IsScheduledCheckDue(last, DateTimeOffset.UtcNow)) return;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or
                                   System.Security.SecurityException or
                                   IOException or ArgumentException)
        {
            AuditLog.Append("Scheduled update check time is unavailable: " + ex.GetType().Name);
            return; // Fail closed: no reason to make extra SYSTEM network requests.
        }
        string result = "CheckFailed";
        string version = "";
        try
        {
            using var client = new GitHubReleaseClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var release = client.CheckAsync(UpdateIntegration.Options(UpdateChannel.Stable),
                timeout.Token).GetAwaiter().GetResult();
            result = release is null ? "NoNewerStable" : "StableAvailable";
            version = release?.Version.ToString() ?? "";
        }
        catch (Exception ex)
        {
            // A network/check failure must NOT change the outcome of DLL maintenance.
            AuditLog.Append("Scheduled Stable release check failed (read-only): " + ex.GetType().Name);
        }
        finally
        {
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(RegistryPath, writable: true);
                if (key is not null && IsEnabled())
                {
                    key.SetValue("LastCheckUtc", DateTimeOffset.UtcNow.ToString("O"),
                        RegistryValueKind.String);
                    key.SetValue("LastCheckResult", result, RegistryValueKind.String);
                    key.SetValue("LastSeenStable", version, RegistryValueKind.String);
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or
                                       System.Security.SecurityException or
                                       IOException or ArgumentException)
            {
                AuditLog.Append("Scheduled Stable release status not stored: " + ex.GetType().Name);
            }
        }
    }

    internal static bool ShouldOffer(UpdateNotice notice, UpdateRelease? live,
        string? previouslyOffered, bool enabled, bool operationBusy) =>
        enabled && !operationBusy && !notice.IsCached &&
        notice.Status == UpdateNoticeStatus.Available && live is not null &&
        !live.Version.IsPrerelease &&
        live.Version.ToString() == notice.AvailableVersion &&
        live.Tag == "v" + live.Version &&
        !string.Equals(live.Version.ToString(), previouslyOffered, StringComparison.Ordinal);

    internal static string Label(bool enabled) => enabled
        ? "On: checks on startup and every 4 hours. New Stable installs require approval."
        : "Off: startup badge check only; no periodic checks.";
}
