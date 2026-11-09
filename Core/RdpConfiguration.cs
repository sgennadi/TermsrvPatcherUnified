using Microsoft.Win32;

namespace TermsrvPatcherUnified.Core;

public sealed record RdpStatus(bool Enabled, bool NetworkLevelAuthentication, bool OneSessionPerUser);

public static class RdpConfiguration
{
    private const string TerminalKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string TcpKey = TerminalKey + @"\WinStations\RDP-Tcp";
    private const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    public static RdpStatus Read()
    {
        using var terminal = Registry.LocalMachine.OpenSubKey(TerminalKey)
            ?? throw new InvalidOperationException("Remote Desktop registry key not found.");
        using var tcp = Registry.LocalMachine.OpenSubKey(TcpKey)
            ?? throw new InvalidOperationException("Remote Desktop TCP registry key not found.");
        return new(Convert.ToInt32(terminal.GetValue("fDenyTSConnections", 1)) == 0,
            Convert.ToInt32(tcp.GetValue("UserAuthentication", 1)) == 1,
            Convert.ToInt32(terminal.GetValue("fSingleSessionPerUser", 1)) == 1);
    }

    public static void Save(bool enableRdp, bool enforceNla, bool oneSessionPerUser, bool syncFirewall)
    {
        if (!SystemInfo.IsAdministrator()) throw new UnauthorizedAccessException("Administrator rights required.");
        using var operation = OperationLock.Acquire();

        // Read the policy hints and snapshot ALL settings/firewall state before
        // any registry write. A conflicting policy would make Save misleading.
        RejectConflictingPolicies(enableRdp, enforceNla, oneSessionPerUser);
        using var terminal = Registry.LocalMachine.OpenSubKey(TerminalKey, writable: true)
            ?? throw new InvalidOperationException("Terminal Server registry key unavailable.");
        using var tcp = Registry.LocalMachine.OpenSubKey(TcpKey, writable: true)
            ?? throw new InvalidOperationException("RDP-Tcp registry key unavailable.");

        var changes = new List<RdpReversibleChange>
        {
            RdpSettingsTransaction.StageDword(terminal, "fDenyTSConnections", enableRdp ? 0 : 1),
            RdpSettingsTransaction.StageDword(terminal, "fSingleSessionPerUser", oneSessionPerUser ? 1 : 0),
            RdpSettingsTransaction.StageDword(tcp, "UserAuthentication", enforceNla ? 1 : 0)
        };
        if (syncFirewall)
            changes.AddRange(StageFirewall(enableRdp));

        try
        {
            RdpSettingsTransaction.Execute(changes);
        }
        catch (Exception error)
        {
            AuditLog.Append("RDP settings transaction failed: " + error.GetType().Name);
            throw;
        }

        AuditLog.Append($"RDP settings changed: enabled={enableRdp}, NLA={enforceNla}, singleUserSession={oneSessionPerUser}, firewall={syncFirewall}");
        OperationHistory.TryRecord("RdpSettings", "Success");
    }

    private static void RejectConflictingPolicies(bool enableRdp, bool enforceNla, bool oneSessionPerUser)
    {
        using var policy = Registry.LocalMachine.OpenSubKey(PolicyKey);
        if (policy is null) return;
        Check("fDenyTSConnections", enableRdp ? 0 : 1);
        Check("UserAuthentication", enforceNla ? 1 : 0);
        Check("fSingleSessionPerUser", oneSessionPerUser ? 1 : 0);

        void Check(string name, int desired)
        {
            if (!policy.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
                return;
            if (policy.GetValueKind(name) != RegistryValueKind.DWord ||
                policy.GetValue(name, null) is not int configured ||
                configured is not (0 or 1))
                throw new InvalidOperationException(
                    "Unrecognized Group Policy RDP value: " + name + ". No settings changed.");
            if (configured != desired)
                throw new InvalidOperationException(
                    "Group Policy conflicts with requested " + name +
                    ". Review RDP Health / applied GPO before changing local settings. No settings changed.");
        }
    }

    private static IReadOnlyList<RdpReversibleChange> StageFirewall(bool enabled)
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new InvalidOperationException("Windows Firewall policy COM object is unavailable.");
        dynamic policy = Activator.CreateInstance(type)
            ?? throw new InvalidOperationException("Cannot initialize Windows Firewall policy.");
        var changes = new List<RdpReversibleChange>();
        foreach (dynamic candidate in policy.Rules)
        {
            string? group = candidate.Grouping as string;
            if (group != "@FirewallAPI.dll,-28752" &&
                group != "@FirewallAPI.dll,-28852") continue;
            if ((int)candidate.Direction != 1) continue; // Inbound only.

            int profiles = (int)candidate.Profiles;
            // Enabling is restricted to Domain/Private; disabling also closes
            // existing public-profile RDP rules in the same recognized group.
            if (enabled && ((profiles & 3) == 0 || (profiles & 4) != 0)) continue;

            object rule = candidate;
            bool original = (bool)candidate.Enabled;
            changes.Add(new RdpReversibleChange(
                "RDP firewall inbound rule",
                () => ((dynamic)rule).Enabled = enabled,
                () => ((dynamic)rule).Enabled = original,
                () => (bool)((dynamic)rule).Enabled == enabled,
                () => (bool)((dynamic)rule).Enabled == original));
        }
        if (changes.Count == 0)
            throw new InvalidOperationException(
                "No eligible Windows Firewall RDP inbound rules were identified. " +
                "Refusing to save an unverified firewall configuration.");
        return changes;
    }
}
