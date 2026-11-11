using Microsoft.Win32;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Local firewall evidence only. COM (active rules) is preferred; CIM and
/// registry are explicitly labelled LIMITED read-only fallbacks. No network
/// reachability or remote sign-in is attempted.
/// </summary>
internal sealed record RdpFirewallRule(
    string Name, string Group, string Service, int Direction, int Protocol,
    string LocalPorts, int Profiles, bool Enabled, bool Allow, string RemoteScope);

internal sealed record RdpFirewallEvidence(RdpDoctorLevel Level, string Summary, string Details);

internal static class RdpFirewallInspector
{
    private const string LocalRuleKey =
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    internal static bool PortIncludes(string? list, int port)
    {
        if (port is < 1 or > 65535 || string.IsNullOrWhiteSpace(list)) return false;
        foreach (var raw in list.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (raw.Equals("Any", StringComparison.OrdinalIgnoreCase) || raw == "*") return true;
            if (int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n == port)
                return true;
            var bounds = raw.Split('-', 2, StringSplitOptions.TrimEntries);
            if (bounds.Length == 2 &&
                int.TryParse(bounds[0], NumberStyles.None, CultureInfo.InvariantCulture, out int start) &&
                int.TryParse(bounds[1], NumberStyles.None, CultureInfo.InvariantCulture, out int end) &&
                start is >= 1 and <= 65535 && end is >= 1 and <= 65535 &&
                start <= port && port <= end) return true;
        }
        return false; // RPC, dynamic, malformed or unrecognised port syntax.
    }

    internal static bool IsBuiltinOrServiceRule(RdpFirewallRule rule) =>
        RdpSecurityInspector.IsRdpRuleGroup(rule.Group) ||
        rule.Service.Equals("TermService", StringComparison.OrdinalIgnoreCase) ||
        rule.Name.StartsWith("RemoteDesktop-UserMode-In-", StringComparison.OrdinalIgnoreCase);

    internal static RdpFirewallEvidence Assess(int? configuredPort, int activeProfiles,
        IReadOnlyList<RdpFirewallRule> rules, bool partial)
    {
        // Strictly evaluate a known configured port; never assume 3389.
        var port = configuredPort is > 0 and <= 65535 ? configuredPort : null;
        var relevant = rules.Where(x => x.Direction == 1 && x.Protocol == 6 &&
            (IsBuiltinOrServiceRule(x) || (port.HasValue &&
              PortIncludes(x.LocalPorts, port.Value) &&
              !x.LocalPorts.Equals("Any", StringComparison.OrdinalIgnoreCase) &&
              x.LocalPorts != "*"))).Take(48).ToArray();

        var details = new StringBuilder()
            .AppendLine("Windows Firewall COM inbound TCP rule metadata (read only).")
            .AppendLine("Active profiles: " + RdpSecurityInspector.DescribeProfiles(activeProfiles))
            .AppendLine("Configured RDP TCP port: " + (port?.ToString(CultureInfo.InvariantCulture) ?? "Unavailable"))
            .AppendLine("Candidate TCP rules: " + relevant.Length +
                        (partial ? " (partial rule enumeration)" : ""))
            .AppendLine("RDP-related and explicit port matches only; this is not proof of effective access.");

        foreach (var rule in relevant.Take(32))
        {
            details.AppendLine()
                .AppendLine("Rule: " + Clip(rule.Name))
                .AppendLine("  Type: " + (IsBuiltinOrServiceRule(rule) ? "RDP group/service" : "Custom port candidate"))
                .AppendLine("  Enabled: " + (rule.Enabled ? "Yes" : "No") +
                    "; Action: " + (rule.Allow ? "Allow" : "Block"))
                .AppendLine("  Protocol: TCP; Local ports: " + Clip(rule.LocalPorts))
                .AppendLine("  Profiles: " + RdpSecurityInspector.DescribeProfiles(rule.Profiles) +
                    "; Active intersection: " + (ProfileIntersects(rule.Profiles, activeProfiles) ? "Yes" : "No"))
                .AppendLine("  Remote scope: " + Clip(rule.RemoteScope));
        }

        details.AppendLine()
            .AppendLine("GPO/MDM precedence, all possible blocking rules, third-party filters,")
            .AppendLine("service ownership, client IP scope and external connectivity are NOT verified.");

        if (port is null || activeProfiles == 0)
            return new(RdpDoctorLevel.Unknown,
                "Active firewall profiles or configured RDP TCP port unavailable.", details.ToString());

        var applicable = relevant.Where(x => x.Enabled &&
            ProfileIntersects(x.Profiles, activeProfiles) &&
            PortIncludes(x.LocalPorts, port.Value)).ToArray();
        int blocks = applicable.Count(x => !x.Allow);
        int allows = applicable.Count(x => x.Allow);
        if (blocks > 0)
            return new(RdpDoctorLevel.Attention,
                blocks + " enabled inbound TCP Block candidate(s) match the configured RDP port. Effective filtering is not proved.",
                details.ToString());
        if (partial)
            return new(RdpDoctorLevel.Unknown,
                "Firewall rule enumeration was incomplete; effective inbound rules cannot be assessed.",
                details.ToString());
        if (allows > 0)
            return new(RdpDoctorLevel.Ok,
                allows + " enabled inbound TCP Allow candidate(s) match port " + port.Value +
                " and the active profile (local rule metadata only).",
                details.ToString());
        return new(RdpDoctorLevel.Attention,
            "No matching active inbound TCP Allow rule was found for configured port " + port.Value +
            ". Custom, managed or third-party filters may still apply.",
            details.ToString());
    }

    private static bool ProfileIntersects(int ruleProfiles, int activeProfiles) =>
        activeProfiles != 0 &&
        (ruleProfiles == int.MaxValue || ruleProfiles == 0 ||
         (ruleProfiles & activeProfiles) != 0);

    private static string Clip(string? value, int length = 100) =>
        string.IsNullOrEmpty(value) ? "(none)" :
        (value.Length > length ? value[..length] + "..." : value)
            .Replace('\r', ' ').Replace('\n', ' ');

    internal static RdpFirewallEvidence ReadLocal(int? configuredPort)
    {
        if (!OperatingSystem.IsWindows())
            return new(RdpDoctorLevel.Unknown, "Firewall inspection requires Windows.",
                "Not inspected on this platform.");
        string comError;
        try { return ReadCom(configuredPort); }
        catch (Exception ex) when (IsInspectionError(ex))
        {
            comError = ex.GetType().Name;
        }

        // The Windows NetSecurity CIM provider can show known RDP rules even
        // when classic Firewall COM is blocked, but port/address filters are
        // separate objects. Never label this limited fallback Verified.
        try { return ReadCimFallback(comError, configuredPort); }
        catch (Exception ex) when (IsInspectionError(ex))
        {
            return ReadRegistryFallback(comError, ex.GetType().Name, configuredPort);
        }
    }

    private static bool IsInspectionError(Exception ex) =>
        ex is COMException or UnauthorizedAccessException or
        System.Security.SecurityException or IOException or
        InvalidOperationException or NotSupportedException or
        System.ComponentModel.Win32Exception or
        System.Management.ManagementException or
        Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or
        ArgumentException or InvalidCastException or
        System.Reflection.TargetInvocationException;

    private static RdpFirewallEvidence ReadCom(int? configuredPort)
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new NotSupportedException("Windows Firewall COM not registered.");
        object instance = Activator.CreateInstance(type)
            ?? throw new InvalidOperationException("Windows Firewall COM unavailable.");
        try
        {
            dynamic policy = instance;
            int profiles = (int)policy.CurrentProfileTypes;
            var rules = new List<RdpFirewallRule>(48);
            bool partial = false;
            int examined = 0;
            foreach (dynamic rule in policy.Rules)
            {
                if (++examined > 4096) { partial = true; break; }
                try
                {
                    int direction = (int)rule.Direction;
                    if (direction != 1) continue;
                    string group = Convert.ToString((object?)rule.Grouping) ?? "";
                    string service = Convert.ToString((object?)rule.ServiceName) ?? "";
                    string name = Convert.ToString((object?)rule.Name) ?? "";
                    int protocol = (int)rule.Protocol;
                    if (protocol != 6) continue;
                    string ports = Convert.ToString((object?)rule.LocalPorts) ?? "";
                    bool known = RdpSecurityInspector.IsRdpRuleGroup(group) ||
                        service.Equals("TermService", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("RemoteDesktop-UserMode-In-", StringComparison.OrdinalIgnoreCase);
                    if (!known && (!configuredPort.HasValue ||
                         !PortIncludes(ports, configuredPort.Value) ||
                         ports.Equals("Any", StringComparison.OrdinalIgnoreCase) || ports == "*"))
                        continue;

                    rules.Add(new(name, group, service, direction, protocol, ports,
                        (int)rule.Profiles, (bool)rule.Enabled, (int)rule.Action == 1,
                        Convert.ToString((object?)rule.RemoteAddresses) ?? ""));
                    if (rules.Count >= 48) { partial = true; break; }
                }
                catch (Exception ex) when (IsInspectionError(ex))
                {
                    partial = true;
                }
            }
            return Assess(configuredPort, profiles, rules, partial);
        }
        finally
        {
            if (Marshal.IsComObject(instance)) Marshal.FinalReleaseComObject(instance);
        }
    }

    private static RdpFirewallEvidence ReadCimFallback(string comError, int? port)
    {
        var details = new StringBuilder()
            .AppendLine("Classic Firewall COM failed: " + comError)
            .AppendLine("Fallback: root/StandardCimv2 MSFT_NetFirewallRule (read only, limited).")
            .AppendLine("No port/address filter association or verified ActiveStore was read.");
        using var searcher = new ManagementObjectSearcher(
            @"\\.\root\StandardCimv2",
            "SELECT InstanceID, DisplayName, RuleGroup, Direction, Enabled, Action, Profiles " +
            "FROM MSFT_NetFirewallRule WHERE Direction = 1");
        searcher.Options.Timeout = TimeSpan.FromSeconds(10);
        using var results = searcher.Get();
        int inspected = 0, found = 0;
        foreach (ManagementObject item in results)
        {
            using (item)
            {
                if (++inspected > 4096) break;
                string id = Convert.ToString(item["InstanceID"]) ?? "";
                string group = Convert.ToString(item["RuleGroup"]) ?? "";
                if (!RdpSecurityInspector.IsRdpRuleGroup(group) &&
                    !id.StartsWith("RemoteDesktop-UserMode-In-", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (++found > 24) break;
                details.AppendLine("  " + Clip(id) + " | Enabled=" +
                    Clip(Convert.ToString(item["Enabled"])) + " | Action=" +
                    Clip(Convert.ToString(item["Action"])) + " | Profiles=" +
                    Clip(Convert.ToString(item["Profiles"])));
            }
        }
        details.AppendLine("RDP rule candidates: " + found +
            ". CIM metadata does not prove port matching or remote reachability.");
        return new(RdpDoctorLevel.Unknown,
            "Firewall COM unavailable; limited CIM rule metadata inspected (port " +
            (port?.ToString(CultureInfo.InvariantCulture) ?? "unknown") + " not verified).",
            details.ToString());
    }

    private static RdpFirewallEvidence ReadRegistryFallback(string comError, string cimError, int? port)
    {
        var details = new StringBuilder()
            .AppendLine("Firewall COM unavailable: " + comError)
            .AppendLine("Firewall CIM unavailable: " + cimError)
            .AppendLine("Fallback: read-only local persistent FirewallRules registry snapshot.");
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LocalRuleKey);
            foreach (string name in new[] { "RemoteDesktop-UserMode-In-TCP", "RemoteDesktop-UserMode-In-UDP" })
            {
                string? raw = key?.GetValue(name) as string;
                if (raw is null) { details.AppendLine(name + ": not present"); continue; }
                var parts = raw.Split('|', StringSplitOptions.RemoveEmptyEntries);
                string[] known = ["Active=", "Action=", "Dir=", "LPort=", "Profile="];
                string summary = string.Join("; ", parts
                    .Where(x => known.Any(prefix => x.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                    .Take(8).Select(x => Clip(x)));
                details.AppendLine(name + ": " + summary);
            }
        }
        catch (Exception ex) when (IsInspectionError(ex))
        {
            details.AppendLine("Registry fallback unavailable: " + ex.GetType().Name);
        }
        details.AppendLine("Registry is NOT the effective merged GPO/MDM/ActiveStore firewall policy.");
        return new(RdpDoctorLevel.Unknown,
            "Firewall policy inspection unavailable; limited local registry metadata only.",
            details.ToString());
    }
}
