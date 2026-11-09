using Microsoft.Win32;
using System.ServiceProcess;
using System.Text;

namespace TermsrvPatcherUnified.Core;

/// <summary>Read-only evidence. A policy registry value is not proof GP has refreshed.</summary>
internal sealed record RdpPolicyEvidence(
    string Setting, string LocalValue, string PolicyValue, string Assessment, string Explanation);

internal sealed record RdpConfigurationReport(
    DateTimeOffset CheckedUtc, IReadOnlyList<RdpPolicyEvidence> Values,
    string TermServiceStatus, IReadOnlyList<string> Warnings)
{
    internal string AsText()
    {
        var builder = new StringBuilder();
        builder.AppendLine("Local RDP configuration and policy diagnostics — READ ONLY");
        builder.AppendLine("Checked UTC: " + CheckedUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        builder.AppendLine("TermService: " + TermServiceStatus);
        builder.AppendLine("A policy registry value may be pending Group Policy refresh.");
        builder.AppendLine("No registry, firewall, service, DLL or user-session changes were made.");
        foreach (var item in Values)
        {
            builder.AppendLine();
            builder.AppendLine(item.Setting + " | " + item.Assessment);
            builder.AppendLine("  Local: " + item.LocalValue + " | Policy: " + item.PolicyValue);
            builder.AppendLine("  " + item.Explanation);
        }
        foreach (var warning in Warnings) builder.AppendLine("NOTICE: " + warning);
        builder.AppendLine("Windows Firewall inbound RDP rule effectiveness is not verified here.");
        builder.AppendLine("Do not use this report to authorize a protected DLL change.");
        return builder.ToString();
    }
}

internal static class RdpPolicyDiagnostics
{
    private const string TerminalKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    internal static RdpPolicyEvidence Evaluate(
        string setting, int? local, int? policy, int minimum, int maximum,
        Func<int, string>? describe = null)
    {
        if (minimum > maximum) throw new ArgumentException("Invalid diagnostic bounds.");
        static string Display(int? value, Func<int, string>? formatter)
            => value.HasValue ? (formatter?.Invoke(value.Value) ?? value.Value.ToString(
                System.Globalization.CultureInfo.InvariantCulture)) : "(not configured or unreadable)";

        string localText = Display(local, describe);
        string policyText = Display(policy, describe);
        if (local.HasValue && (local.Value < minimum || local.Value > maximum) ||
            policy.HasValue && (policy.Value < minimum || policy.Value > maximum))
            return new(setting, localText, policyText, "Invalid value",
                "Value is outside the expected range. Configuration must be reviewed manually.");

        if (policy.HasValue && local.HasValue && policy != local)
            return new(setting, localText, policyText, "Policy differs",
                "A Group Policy value differs from the local setting; policy can override local configuration.");

        if (policy.HasValue)
            return new(setting, localText, policyText, "Policy configured",
                "A Group Policy registry value exists; confirm the applied result after policy refresh.");

        return new(setting, localText, policyText, local.HasValue ? "Local setting" : "Unavailable",
            local.HasValue ? "No corresponding policy registry value was found." :
                "The local value is absent or cannot be read. Do not assume a default is effective.");
    }

    internal static RdpConfigurationReport ReadLocal()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows registry is required for RDP diagnostics.");

        // Read-only handles; never OpenSubKey(writable:true), SetValue, or start services.
        using var terminal = Registry.LocalMachine.OpenSubKey(TerminalKey);
        using var tcp = Registry.LocalMachine.OpenSubKey(TerminalKey + @"\WinStations\RDP-Tcp");
        using var policy = Registry.LocalMachine.OpenSubKey(PolicyKey);

        var rows = new List<RdpPolicyEvidence>
        {
            Evaluate("Remote Desktop", ReadDword(terminal, "fDenyTSConnections"),
                ReadDword(policy, "fDenyTSConnections"), 0, 1,
                value => value == 0 ? "Enabled (0)" : "Disabled (1)"),
            Evaluate("Network Level Authentication", ReadDword(tcp, "UserAuthentication"),
                ReadDword(policy, "UserAuthentication"), 0, 1,
                value => value == 1 ? "Required (1)" : "Not required (0)"),
            Evaluate("One session per user", ReadDword(terminal, "fSingleSessionPerUser"),
                ReadDword(policy, "fSingleSessionPerUser"), 0, 1,
                value => value == 1 ? "On (1)" : "Off (0)"),
            Evaluate("RDP TCP port", ReadDword(tcp, "PortNumber"),
                ReadDword(policy, "PortNumber"), 1, 65535),
            Evaluate("RDP security layer", ReadDword(tcp, "SecurityLayer"),
                ReadDword(policy, "SecurityLayer"), 0, 2,
                value => value switch { 0 => "RDP security (0)", 1 => "Negotiate (1)",
                    2 => "TLS (2)", _ => "Unknown" }),
            Evaluate("Minimum encryption level", ReadDword(tcp, "MinEncryptionLevel"),
                ReadDword(policy, "MinEncryptionLevel"), 1, 4)
        };

        var warnings = new List<string>();
        foreach (var row in rows)
        {
            if (row.Assessment is "Policy differs" or "Invalid value")
                warnings.Add(row.Setting + ": " + row.Assessment + "; review the applied GPO.");
        }
        int? effectiveDeny = ReadDword(policy, "fDenyTSConnections") ??
                             ReadDword(terminal, "fDenyTSConnections");
        int? effectiveNla = ReadDword(policy, "UserAuthentication") ??
                            ReadDword(tcp, "UserAuthentication");
        if (effectiveDeny == 0 && effectiveNla == 0)
            warnings.Add("RDP appears enabled without required NLA. Review security policy.");
        if (effectiveDeny == 0 && tcp is null)
            warnings.Add("RDP-Tcp settings are inaccessible although RDP appears enabled.");

        string serviceStatus;
        try
        {
            using var service = new ServiceController("TermService");
            serviceStatus = service.Status.ToString();
        }
        catch (Exception ex) when (ex is InvalidOperationException or
                                   System.ComponentModel.Win32Exception or
                                   UnauthorizedAccessException)
        {
            serviceStatus = "Unavailable (" + ex.GetType().Name + ")";
        }
        if (effectiveDeny == 0 && serviceStatus != "Running")
            warnings.Add("TermService is not confirmed running; no service start was attempted.");
        return new(DateTimeOffset.UtcNow, rows, serviceStatus, warnings);
    }

    private static int? ReadDword(RegistryKey? key, string name)
    {
        if (key is null) return null;
        try
        {
            if (!key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase) ||
                key.GetValueKind(name) != RegistryValueKind.DWord)
                return null;
            return key.GetValue(name, null) is int value ? value : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException or ArgumentException)
        {
            return null; // Unreadable must never be shown as a safe default.
        }
    }
}
