using Microsoft.Win32;

namespace TermsrvPatcherUnified.Core;

public sealed record RdpStatus(bool Enabled, bool NetworkLevelAuthentication, bool OneSessionPerUser);

public static class RdpConfiguration
{
    private const string TerminalKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string TcpKey = TerminalKey + @"\WinStations\RDP-Tcp";

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
        using var terminal = Registry.LocalMachine.OpenSubKey(TerminalKey, writable: true)
            ?? throw new InvalidOperationException("Terminal Server registry key unavailable.");
        using var tcp = Registry.LocalMachine.OpenSubKey(TcpKey, writable: true)
            ?? throw new InvalidOperationException("RDP-Tcp registry key unavailable.");
        terminal.SetValue("fDenyTSConnections", enableRdp ? 0 : 1, RegistryValueKind.DWord);
        terminal.SetValue("fSingleSessionPerUser", oneSessionPerUser ? 1 : 0, RegistryValueKind.DWord);
        tcp.SetValue("UserAuthentication", enforceNla ? 1 : 0, RegistryValueKind.DWord);
        if (syncFirewall) SyncFirewall(enableRdp);
        AuditLog.Append($"RDP settings changed: enabled={enableRdp}, NLA={enforceNla}, singleUserSession={oneSessionPerUser}");
    }

    private static void SyncFirewall(bool enabled)
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new InvalidOperationException("Windows Firewall policy COM object is unavailable.");
        dynamic policy = Activator.CreateInstance(type)
            ?? throw new InvalidOperationException("Cannot initialize Windows Firewall policy.");
        foreach (dynamic rule in policy.Rules)
        {
            // Windows-independent resource IDs used by the original GUI implementation.
            string? grouping = rule.Grouping as string;
            if ((int)rule.Direction != 1) continue;
            if (grouping != "@FirewallAPI.dll,-28752" && grouping != "@FirewallAPI.dll,-28852") continue;
            // Enable only Domain/Private-only rules; when disabling RDP, switch off all RDP rules.
            int profiles = (int)rule.Profiles;
            if (!enabled || ((profiles & 3) != 0 && (profiles & 4) == 0))
                rule.Enabled = enabled;
        }
    }
}
