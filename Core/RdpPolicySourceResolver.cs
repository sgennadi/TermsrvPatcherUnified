using System.Management;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Read-only Resultant Set of Policy lookup. A local HKLM\SOFTWARE\Policies
/// entry means "managed" even if WMI/RSoP has no accessible winning GPO.
/// An unknown or stale RSoP source is NEVER treated as permission to edit.
/// </summary>
internal sealed record RdpRsopRegistryEntry(
    string RegistryKey, string ValueName, string GpoId, uint Precedence);

internal sealed record RdpRsopGpoEntry(string Id, string GuidName, string DisplayName);

internal sealed record RdpPolicySource(
    string RegistryValue, string RegistryPath, string? GpoName, string? GpoId,
    bool Resolved, string Explanation)
{
    internal string Label => Resolved && !string.IsNullOrWhiteSpace(GpoName)
        ? GpoName
        : "GPO not identified";

    internal string Details => (Resolved && !string.IsNullOrWhiteSpace(GpoName)
            ? "Winning GPO: " + GpoName + (string.IsNullOrWhiteSpace(GpoId) ? "" : " [" + GpoId + "]")
            : "Winning GPO not identified. " + Explanation) +
        Environment.NewLine + "Controlled setting: " + RegistryPath;
}

internal static class RdpPolicySourceResolver
{
    internal const string TerminalPolicyPath =
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    // Read-only diagnostic mappings; only RdpLocalAdvancedSettings.Editable
    // controls which local DWORDs can actually be changed.
    private static readonly IReadOnlyDictionary<string, string> EvidenceValueNames =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Remote Desktop"] = "fDenyTSConnections",
            ["Network Level Authentication"] = "UserAuthentication",
            ["One session per user"] = "fSingleSessionPerUser",
            ["RDP TCP port"] = "PortNumber",
            ["RDP security layer"] = "SecurityLayer",
            ["Minimum encryption level"] = "MinEncryptionLevel",
            ["Always request password"] = "fPromptForPassword",
            ["Disable clipboard redirection"] = "fDisableClip",
            ["Disable drive redirection"] = "fDisableCdm",
            ["Disable printer redirection"] = "fDisableCpm",
            ["Disable COM port redirection"] = "fDisableCcm",
            ["Idle session limit"] = "MaxIdleTime",
            ["Active session time limit"] = "MaxConnectionTime",
            ["Disconnected session time limit"] = "MaxDisconnectionTime",
            ["Automatic reconnection disabled"] = "fDisableAutoReconnect",
            ["TCP/UDP transport policy"] = "SelectTransport"
        };

    internal static string? ValueForSetting(string? displayName) =>
        displayName is not null && EvidenceValueNames.TryGetValue(displayName, out var value)
            ? value : null;

    private static readonly Regex GpoGuidRegex = new(
        @"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    internal static string NormalizeRegistryKey(string? value)
    {
        string p = (value ?? "").Trim().Replace('/', '\\').Trim('\\');
        foreach (string prefix in new[] {
            @"\Registry\Machine\", @"HKEY_LOCAL_MACHINE\", @"HKLM\",
            @"MACHINE\" })
            if (p.StartsWith(prefix.TrimStart('\\'), StringComparison.OrdinalIgnoreCase))
                return p[prefix.TrimStart('\\').Length..].Trim('\\');
        return p;
    }

    internal static bool IsPolicyPresent(string valueName)
    {
        if (!EvidenceValueNames.Values.Contains(valueName, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("Not an approved RDP policy registry value.", nameof(valueName));
        using var policy = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services");
        return policy is not null &&
            policy.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase);
    }

    private static string? CanonicalGuid(string? value)
    {
        var match = GpoGuidRegex.Match(value ?? "");
        return match.Success && Guid.TryParse(match.Value, out var parsed)
            ? parsed.ToString("B") : null;
    }

    /// <summary>
    /// Matching requires the *exact* HKLM policy key, exact value name,
    /// RSoP precedence 1, and a matching RSOP_GPO ID or GUID. A different
    /// policy with a similar name or lower precedence is not attributed.
    /// </summary>
    internal static RdpPolicySource Resolve(
        string valueName, IEnumerable<RdpRsopRegistryEntry> settings,
        IEnumerable<RdpRsopGpoEntry> gpos)
    {
        if (string.IsNullOrWhiteSpace(valueName) ||
            !EvidenceValueNames.Values.Contains(valueName, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("Only allowlisted RDP policy settings can be resolved.",
                nameof(valueName));

        string registryPath = TerminalPolicyPath + "\\" + valueName;
        string target = NormalizeRegistryKey(TerminalPolicyPath);
        var winner = settings.FirstOrDefault(row =>
            row.Precedence == 1 &&
            string.Equals(row.ValueName, valueName, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(NormalizeRegistryKey(row.RegistryKey), target,
                StringComparison.OrdinalIgnoreCase));
        if (winner is null)
            return new(valueName, registryPath, null, null, false,
                "No matching winning RSoP registry entry (or RSoP logging may be unavailable).");

        var matchGuid = CanonicalGuid(winner.GpoId);
        var gpo = gpos.FirstOrDefault(row =>
            !string.IsNullOrWhiteSpace(winner.GpoId) &&
            string.Equals(row.Id, winner.GpoId, StringComparison.OrdinalIgnoreCase) ||
            matchGuid is not null &&
            (string.Equals(CanonicalGuid(row.Id), matchGuid, StringComparison.OrdinalIgnoreCase) ||
             string.Equals(CanonicalGuid(row.GuidName), matchGuid, StringComparison.OrdinalIgnoreCase)));

        if (gpo is null || string.IsNullOrWhiteSpace(gpo.DisplayName))
            return new(valueName, registryPath, null, matchGuid ?? winner.GpoId, false,
                "Matching RSoP rule found, but the GPO display name is unavailable.");
        return new(valueName, registryPath, gpo.DisplayName, matchGuid ?? winner.GpoId,
            true, "Winning RSoP entry with precedence 1.");
    }

    internal static RdpPolicySource ReadWinning(string valueName)
    {
        string registryPath = TerminalPolicyPath + "\\" + valueName;
        if (!OperatingSystem.IsWindows())
            return new(valueName, registryPath, null, null, false,
                "RSoP is available only on Windows.");
        try
        {
            var scope = new ManagementScope(@"\\.\root\RSOP\Computer");
            scope.Options.Timeout = TimeSpan.FromSeconds(8);
            scope.Connect();
            using var rules = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT registryKey, valueName, GPOID, precedence FROM RSOP_RegistryPolicySetting"));
            using var found = rules.Get();
            var selected = new List<RdpRsopRegistryEntry>();
            foreach (ManagementBaseObject row in found)
            {
                using (row)
                {
                    string key = Convert.ToString(row["registryKey"]) ?? "";
                    string name = Convert.ToString(row["valueName"]) ?? "";
                    if (!string.Equals(name, valueName, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(NormalizeRegistryKey(key),
                            NormalizeRegistryKey(TerminalPolicyPath), StringComparison.OrdinalIgnoreCase))
                        continue;
                    selected.Add(new(key, name, Convert.ToString(row["GPOID"]) ?? "",
                        Convert.ToUInt32(row["precedence"] ?? uint.MaxValue)));
                }
            }
            if (selected.All(row => row.Precedence != 1))
                return Resolve(valueName, selected, []);
            using var gpoQuery = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT id, guidName, name FROM RSOP_GPO"));
            using var gpoResult = gpoQuery.Get();
            var gpos = new List<RdpRsopGpoEntry>();
            foreach (ManagementBaseObject gpo in gpoResult)
            {
                using (gpo)
                    gpos.Add(new(
                        Convert.ToString(gpo["id"]) ?? "",
                        Convert.ToString(gpo["guidName"]) ?? "",
                        Convert.ToString(gpo["name"]) ?? ""));
            }
            return Resolve(valueName, selected, gpos);
        }
        catch (Exception ex) when (ex is ManagementException or COMException or
                                   UnauthorizedAccessException or
                                   System.Security.SecurityException or
                                   InvalidOperationException or
                                   System.ComponentModel.Win32Exception)
        {
            return new(valueName, registryPath, null, null, false,
                "Windows RSoP/WMI unavailable (" + ex.GetType().Name + "). " +
                "Use gpresult /scope computer /h report.html or GPMC Group Policy Results.");
        }
    }
}
