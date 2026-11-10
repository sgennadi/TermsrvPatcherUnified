using Microsoft.Win32;
using System.IO;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Per-setting post-apply guidance, not a claim that an RDP client has
/// successfully negotiated the new effective policy.
/// </summary>
internal sealed record RdpFollowUpRow(
    string Setting, string Status, string RequiredAction);

internal sealed record RdpFollowUpReport(
    IReadOnlyList<RdpFollowUpRow> Rows, string Summary, bool ConnectionRetest);

internal static class RdpPostApply
{
    internal static RdpFollowUpReport Build(RdpStatus before, RdpStatus after,
        bool synchronizeFirewall)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        var rows = new List<RdpFollowUpRow>();
        Add("Remote Desktop",
            before.Enabled != after.Enabled,
            after.Enabled ? "Test a NEW remote connection; verify Firewall and policy."
                          : "New remote sign-ins may be blocked. Verify from console.");
        Add("Network Level Authentication",
            before.NetworkLevelAuthentication != after.NetworkLevelAuthentication,
            "Reconnect to verify the new authentication requirement.");
        Add("One session per user",
            before.OneSessionPerUser != after.OneSessionPerUser,
            "Verify behavior at the next user sign-in; current sessions may remain.");
        rows.Add(new RdpFollowUpRow(
            "RDP Firewall rules",
            synchronizeFirewall ? "Verified local transaction" : "Not changed",
            synchronizeFirewall
                ? "Test access from another computer; domain Firewall policy may override."
                : "No Firewall synchronization requested."));
        bool changed = before != after || synchronizeFirewall;
        return new(rows, changed
            ? "Saved and read back local settings. Check new connections and resultant policy. " +
              "No automatic gpupdate, TermService restart or Windows reboot was requested."
            : "No effective local change was requested. No service restart or reboot is required.",
            before.Enabled != after.Enabled ||
            before.NetworkLevelAuthentication != after.NetworkLevelAuthentication ||
            before.OneSessionPerUser != after.OneSessionPerUser ||
            synchronizeFirewall);

        void Add(string name, bool modified, string advice) =>
            rows.Add(new RdpFollowUpRow(name, modified ? "Local value changed" : "No local change",
                modified ? advice : "No action required for this setting."));
    }

    /// <summary>
    /// Reads the local RDP listener port. Its absence or invalid range is
    /// unknown, never interpreted as port 3389.
    /// </summary>
    internal static int? ReadLocalPort()
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
        if (key is null || !key.GetValueNames().Contains("PortNumber",
                StringComparer.OrdinalIgnoreCase) ||
            key.GetValueKind("PortNumber") != RegistryValueKind.DWord)
            return null;
        return InterpretPort(key.GetValue("PortNumber"));
    }

    internal static int? InterpretPort(object? value)
        => value is int n && n is >= 1 and <= 65535 ? n : null;

    internal static bool ListenerRestartRequired(int? previouslyObservedPort,
        int? nowObservedPort) =>
        previouslyObservedPort.HasValue && nowObservedPort.HasValue &&
        previouslyObservedPort.Value != nowObservedPort.Value;

    internal static (bool Success, int ExitCode) RefreshComputerPolicy()
    {
        if (!OperatingSystem.IsWindows() || !SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Refreshing computer Group Policy requires elevation.");
        // Keep the invocation fixed. Neither a path nor command arguments are
        // obtained from the UI, a task file, or a registry policy.
        string exe = Path.Combine(Environment.SystemDirectory, "gpupdate.exe");
        if (!File.Exists(exe) ||
            (File.GetAttributes(exe) & FileAttributes.ReparsePoint) != 0)
            throw new FileNotFoundException("Trusted local gpupdate.exe is unavailable.");

        using var op = OperationLock.Acquire();
        // /target:computer excludes user-policy changes, /wait:90 caps wait;
        // NEVER include /boot or /logoff. A GP client-side extension may still
        // require a later sign-in/restart, and a running RDP session may be affected.
        var result = CommandRunner.Run(exe, 115,
            "/target:computer", "/force", "/wait:90");
        AuditLog.Append("Explicit computer Group Policy refresh completed; code=" +
            result.ExitCode + ". No automatic boot/logoff was requested.");
        return (result.ExitCode == 0, result.ExitCode);
    }
}
