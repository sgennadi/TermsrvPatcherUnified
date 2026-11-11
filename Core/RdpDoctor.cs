using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace TermsrvPatcherUnified.Core;

internal enum RdpDoctorLevel { Ok, Observed, Attention, Blocked, Unknown, Unavailable, NotTested }

internal enum RdpDoctorSocket { Unknown, NotListening, LoopbackOnly, Listening }

internal sealed record RdpDoctorFinding(
    string Area, RdpDoctorLevel Level, string Evidence, string Recommendation)
{
    public string Status => Level switch
    {
        RdpDoctorLevel.Ok => "Verified locally",
        RdpDoctorLevel.Observed => "Observed locally",
        RdpDoctorLevel.Attention => "Attention",
        RdpDoctorLevel.Blocked => "Blocker",
        RdpDoctorLevel.Unavailable => "Unavailable",
        RdpDoctorLevel.NotTested => "Not tested",
        _ => "Incomplete"
    };
}

internal sealed record RdpDoctorEvent(DateTimeOffset OccurredUtc,
    string Channel, int EventId, string Level)
{
    public string DateUtc => OccurredUtc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss");
}

internal sealed record RdpDoctorInputs(
    RdpConfigurationReport? Policy, RdpSecurityInspection? Security,
    int? LocalPort, RdpDoctorSocket LocalSocket,
    IReadOnlyList<RdpDoctorEvent> Events, IReadOnlyList<string> EventWarnings);

internal sealed record RdpDoctorReport(
    DateTimeOffset CheckedUtc, IReadOnlyList<RdpDoctorFinding> Findings,
    IReadOnlyList<RdpDoctorEvent> Events, IReadOnlyList<string> EventWarnings)
{
    // Available only to the local UI. This may include group names and certificate
    // metadata, so AsText() must NEVER serialize it or send it to reporting.
    internal RdpSecurityInspection? LocalSecurityDetails { get; init; }

    public int Blockers => Findings.Count(x => x.Level == RdpDoctorLevel.Blocked);
    public int AttentionCount => Findings.Count(x => x.Level == RdpDoctorLevel.Attention);
    public int UnknownCount => Findings.Count(x => x.Level == RdpDoctorLevel.Unknown);
    public int UnavailableCount => Findings.Count(x => x.Level == RdpDoctorLevel.Unavailable);
    public int NotTestedCount => Findings.Count(x => x.Level == RdpDoctorLevel.NotTested);
    public int LocalEvidenceCount => Findings.Count(x =>
        x.Level is RdpDoctorLevel.Ok or RdpDoctorLevel.Observed);

    public string Verdict => Blockers > 0
        ? "Local RDP blocker detected. Remote connectivity has NOT been tested."
        : AttentionCount > 0
            ? "Local issues need review. Remote connectivity has NOT been tested."
            : "No known local blockers from these checks. Remote connectivity is NOT verified.";

    internal string AsText()
    {
        // No account names, addresses, certificate subjects, raw event messages
        // or machine identifiers. Never upload this automatically.
        var sb = new StringBuilder()
            .AppendLine("RDP Doctor - read-only local diagnostic summary")
            .AppendLine("Checked UTC: " + CheckedUtc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
            .AppendLine("Verdict: " + Verdict)
            .AppendLine("Blockers: " + Blockers + "; attention: " + AttentionCount +
                        "; local evidence: " + LocalEvidenceCount +
                        "; unavailable: " + UnavailableCount +
                        "; incomplete: " + UnknownCount +
                        "; not tested: " + NotTestedCount)
            .AppendLine("IMPORTANT: local checks cannot prove external RDP reachability or licensing.");
        foreach (var x in Findings)
        {
            sb.AppendLine().AppendLine("[" + x.Status + "] " + x.Area)
                .AppendLine("Evidence: " + x.Evidence)
                .AppendLine("Next step: " + x.Recommendation);
        }
        sb.AppendLine().AppendLine("Recent event metadata (no account or network identifiers):");
        foreach (var ev in Events.Take(60))
            sb.AppendLine(ev.DateUtc + " UTC | " + ev.Channel + " | " +
                          ev.EventId + " | " + ev.Level);
        foreach (var warning in EventWarnings)
            sb.AppendLine("Event source: " + warning);
        sb.AppendLine("No registry, service, user session, certificate, firewall, or system DLL changed.");
        return sb.ToString();
    }
}

/// <summary>
/// RDP Doctor local-only assessment. Pure Analyze() accepts synthetic inputs
/// so no CI test needs to start TermService, open ports, or modify Windows.
/// </summary>
internal static class RdpDoctor
{
    internal static RdpDoctorReport ReadLocal()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows is required for RDP Doctor.");

        RdpConfigurationReport? policy = null;
        RdpSecurityInspection? security = null;
        int? port = null;
        RdpDoctorSocket socket = RdpDoctorSocket.Unknown;
        try { policy = RdpPolicyDiagnostics.ReadLocal(); }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or
                                   System.ComponentModel.Win32Exception or UnauthorizedAccessException or
                                   System.Security.SecurityException or ArgumentException)
        {
            // Unknown: a failed probe never becomes "enabled".
        }
        try
        {
            port = RdpPostApply.ReadLocalPort();
            if (port is > 0 and <= 65535)
                socket = ReadSocket(port.Value);
        }
        catch (Exception ex) when (ex is NetworkInformationException or
                                   InvalidOperationException or UnauthorizedAccessException or
                                   System.Security.SecurityException or ArgumentException)
        {
            socket = RdpDoctorSocket.Unknown;
        }
        try { security = RdpSecurityInspector.ReadLocal(port); }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or
                                   System.ComponentModel.Win32Exception or UnauthorizedAccessException or
                                   System.Security.SecurityException or ArgumentException or
                                   System.Runtime.InteropServices.COMException)
        {
            // Failed inspection is unavailable, never evidence of a healthy firewall.
        }
        var (events, warnings) = RdpDoctorEventReader.ReadRecent(TimeSpan.FromHours(24));
        return Analyze(new(policy, security, port, socket, events, warnings))
            with { LocalSecurityDetails = security };
    }

    internal static RdpDoctorSocket InspectSockets(int port, IEnumerable<IPEndPoint> endpoints)
    {
        if (port is < 1 or > 65535) return RdpDoctorSocket.Unknown;
        var relevant = endpoints.Where(x => x.Port == port).ToArray();
        if (relevant.Length == 0) return RdpDoctorSocket.NotListening;
        return relevant.Any(x => !IPAddress.IsLoopback(x.Address))
            ? RdpDoctorSocket.Listening : RdpDoctorSocket.LoopbackOnly;
    }

    private static RdpDoctorSocket ReadSocket(int port) =>
        InspectSockets(port, IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners());

    private static RdpPolicyEvidence? Setting(RdpConfigurationReport? report, string name) =>
        report?.Values.FirstOrDefault(x => x.Setting == name);

    private static string ConfiguredValue(RdpPolicyEvidence? row)
    {
        if (row is null || row.Assessment is "Invalid value" or "Unavailable")
            return "";
        return row.Assessment is "Policy differs" or "Policy configured"
            ? row.PolicyValue : row.LocalValue;
    }

    private static void Add(List<RdpDoctorFinding> findings, string area,
        RdpDoctorLevel level, string evidence, string recommendation) =>
        findings.Add(new(area, level, evidence, recommendation));

    internal static RdpDoctorReport Analyze(RdpDoctorInputs source)
    {
        var checks = new List<RdpDoctorFinding>();
        var service = source.Policy?.TermServiceStatus;
        if (service == "Running")
            Add(checks, "TermService", RdpDoctorLevel.Ok,
                "Service Control Manager reports Running.",
                "Continue with listener and network checks; service state alone is not connectivity proof.");
        else if (service is "Stopped" or "Paused" or "StopPending")
            Add(checks, "TermService", RdpDoctorLevel.Blocked,
                "Service Control Manager reports " + service + ".",
                "From an independent console, inspect service failures and Windows Event Viewer. Do not restart during an RDP-only session.");
        else
            Add(checks, "TermService", RdpDoctorLevel.Unknown,
                "Service status unavailable or transitional.",
                "Check TermService through services.msc or a local administrator console.");

        var remote = Setting(source.Policy, "Remote Desktop");
        string remoteValue = ConfiguredValue(remote);
        if (remoteValue.StartsWith("Disabled (", StringComparison.Ordinal))
            Add(checks, "RDP enabled setting", RdpDoctorLevel.Blocked,
                "Configuration says Disabled. Source: " + remote?.Assessment + ".",
                "Review fDenyTSConnections and controlling computer GPO. Only apply changes with a recovery path.");
        else if (remoteValue.StartsWith("Enabled (", StringComparison.Ordinal))
            Add(checks, "RDP enabled setting", remote?.Assessment == "Policy differs"
                ? RdpDoctorLevel.Attention : RdpDoctorLevel.Ok,
                "Configuration says Enabled. Source: " + remote?.Assessment +
                ". Effective GP refresh is not independently proved.",
                "Check computer GPO and verify a new RDP connection from another managed computer.");
        else
            Add(checks, "RDP enabled setting", RdpDoctorLevel.Unknown,
                "Enabled/disabled status could not be established.",
                "Check local fDenyTSConnections and applied computer GPO; missing values are not assumed enabled.");

        if (source.LocalPort is null)
            Add(checks, "RDP TCP listener", RdpDoctorLevel.Unknown,
                "Local listener port is missing or invalid.",
                "Inspect the RDP-Tcp PortNumber and policy; do not infer that port 3389 is active.");
        else
        {
            string port = source.LocalPort.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var (level, evidence, guidance) = source.LocalSocket switch
            {
                RdpDoctorSocket.Listening => (RdpDoctorLevel.Ok,
                    "Local TCP listener detected on configured port " + port +
                    " (owner and external reachability not verified).",
                    "From another managed host, test the authorized TCP connection and verify the listener process and Firewall scope."),
                RdpDoctorSocket.LoopbackOnly => (RdpDoctorLevel.Attention,
                    "Port " + port + " is listening only on local loopback addresses.",
                    "Review listener bindings and permitted addresses from the console; remote access is not established."),
                RdpDoctorSocket.NotListening => (RdpDoctorLevel.Blocked,
                    "No local TCP listening socket found for configured port " + port + ".",
                    "Inspect TermService, RDP listener bindings and event logs; avoid restarting service from RDP-only access."),
                _ => (RdpDoctorLevel.Unknown,
                    "Listening state could not be checked for configured port " + port + ".",
                    "Inspect local TCP listeners and confirm active port with an authorized independent test.")
            };
            Add(checks, "RDP TCP listener", level, evidence, guidance);
        }

        var nla = Setting(source.Policy, "Network Level Authentication");
        string nlaValue = ConfiguredValue(nla);
        if (nlaValue.StartsWith("Required (", StringComparison.Ordinal))
            Add(checks, "Network Level Authentication", RdpDoctorLevel.Ok,
                "NLA is configured as required (" + nla?.Assessment + ").",
                "If authentication still fails, inspect logon rights and client credential errors.");
        else if (nlaValue.StartsWith("Not required (", StringComparison.Ordinal))
            Add(checks, "Network Level Authentication", RdpDoctorLevel.Attention,
                "NLA is not required by the inspected setting.",
                "Review security requirements and apply a permitted NLA policy; do not disable authentication to troubleshoot.");
        else
            Add(checks, "Network Level Authentication", RdpDoctorLevel.Unknown,
                "NLA could not be verified.",
                "Inspect UserAuthentication in local RDP-Tcp settings and applied GPO.");

        var conflict = source.Policy?.Values.Where(x => x.Assessment is
            "Policy differs" or "Invalid value").ToArray() ?? [];
        if (conflict.Length > 0)
            Add(checks, "Policy conflicts / invalid values", RdpDoctorLevel.Attention,
                conflict.Length + " setting(s) differ from policy or have invalid values: " +
                string.Join(", ", conflict.Take(5).Select(x => x.Setting)) + ".",
                "Use Advanced > Remote Desktop > Policy sources to locate the winning GPO; do not override it blindly.");
        else if (source.Policy is not null)
            Add(checks, "Policy conflicts / invalid values", RdpDoctorLevel.Ok,
                "No obvious value conflicts among inspected RDP registry settings. RSoP/MDM not fully evaluated.",
                "If connectivity fails, verify the effective GPO and MDM configuration.");
        else
            Add(checks, "Policy conflicts / invalid values", RdpDoctorLevel.Unknown,
                "Registry or policy inventory unavailable.",
                "Check registry permissions and inspect gpresult / computer policy from an authorized console.");

        var blank = Setting(source.Policy, RdpPolicyDiagnostics.BlankPasswordSetting);
        if (blank?.LocalValue == "Restriction OFF")
            Add(checks, "Blank-password account restriction", RdpDoctorLevel.Attention,
                "Console-only restriction is OFF. This is a security risk, not proof of RDP logon.",
                "Require strong local passwords and review the Windows LSA policy; never disable NLA to make empty passwords work.");
        else if (blank?.LocalValue == "Restriction ON")
            Add(checks, "Blank-password account restriction", RdpDoctorLevel.Ok,
                "Local console-only restriction is ON (effective security GPO unknown).",
                "Keep the restriction. Other authentication requirements remain independent.");
        else
            Add(checks, "Blank-password account restriction", RdpDoctorLevel.Unknown,
                "LSA restriction could not be verified.",
                "Review LimitBlankPasswordUse locally and security GPO/MDM provenance.");

        var firewall = source.Security?.FirewallEvidence;
        if (firewall is not null)
            Add(checks, "Windows Firewall", firewall.Level, firewall.Summary,
                "Expand Technical evidence > Firewall to review the active profile, exact TCP port, " +
                "Allow/Block candidates and any COM/CIM/registry fallback. Never disable Firewall to troubleshoot.");
        else if (source.Security is null ||
                 string.IsNullOrWhiteSpace(source.Security.Firewall) ||
                 source.Security.Firewall.Contains("Unable to inspect", StringComparison.OrdinalIgnoreCase))
            Add(checks, "Windows Firewall", RdpDoctorLevel.Unavailable,
                "Inbound Firewall rule inspection unavailable.",
                "Run as administrator and inspect the local Firewall technical evidence; no rules are changed.");
        else
            Add(checks, "Windows Firewall", RdpDoctorLevel.Unknown,
                "Only unstructured local Firewall metadata is available; effective rules not established.",
                "Review active profile, inbound TCP port, enabled rules and source scope.");

        var rights = source.Security?.LogonRights ?? "";
        if (string.IsNullOrWhiteSpace(rights) ||
            rights.Contains("Unable to inspect", StringComparison.OrdinalIgnoreCase) ||
            rights.Contains("Rights status UNKNOWN", StringComparison.OrdinalIgnoreCase))
            Add(checks, "Remote interactive logon rights", RdpDoctorLevel.Unavailable,
                "Local LSA Allow/Deny rights could not be read.",
                "Review access to local LSA policy; actual account group membership cannot be inferred.");
        else if (rights.Contains("Not enumerated", StringComparison.OrdinalIgnoreCase) ||
                 rights.Contains("status UNKNOWN", StringComparison.OrdinalIgnoreCase))
            Add(checks, "Remote interactive logon rights", RdpDoctorLevel.Unknown,
                "LSA assignments were only partially enumerated.",
                "Check SeRemoteInteractiveLogonRight, SeDenyRemoteInteractiveLogonRight and failed LSA lookups.");
        else if (rights.Contains("Local applied LSA", StringComparison.Ordinal))
            Add(checks, "Remote interactive logon rights", RdpDoctorLevel.Observed,
                "Local Allow/Deny assignments read; nested groups and the actual user token NOT evaluated.",
                "Deny takes precedence. Compare the target account and nested group membership before attempting sign-in.");
        else
            Add(checks, "Remote interactive logon rights", RdpDoctorLevel.Unknown,
                "LSA evidence is incomplete; effective user permissions not established.",
                "Inspect LSA Allow/Deny rights and the effective user's token.");

        var certificate = source.Security?.Certificate ?? "";
        if (certificate.Contains("EXPIRED or not yet valid", StringComparison.Ordinal))
            Add(checks, "RDP TLS certificate", RdpDoctorLevel.Attention,
                "The locally located listener certificate is outside its validity dates.",
                "Inspect listener binding and trusted certificate; do not change TLS settings automatically.");
        else if (certificate.Contains("Within validity dates", StringComparison.Ordinal))
            Add(checks, "RDP TLS certificate", RdpDoctorLevel.Observed,
                "Bound certificate found and validity dates checked locally; active TLS handshake/trust NOT tested.",
                "Check trust chain, TermService private-key access and remote handshake if connections fail.");
        else if (string.IsNullOrWhiteSpace(certificate) ||
                 certificate.Contains("Unable to inspect", StringComparison.OrdinalIgnoreCase))
            Add(checks, "RDP TLS certificate", RdpDoctorLevel.Unavailable,
                "Certificate inspection unavailable.",
                "Check local certificate store permissions and RDP listener binding.");
        else
            Add(checks, "RDP TLS certificate", RdpDoctorLevel.Unknown,
                "Certificate metadata is incomplete or no listener binding was found.",
                "Check listener certificate, issuer trust, private-key permissions and remote TLS handshake.");

        var graphics = source.Security?.Graphics ?? "";
        if (graphics.Contains("RDP graphics ADMX", StringComparison.Ordinal))
            Add(checks, "Graphics / codec policy", RdpDoctorLevel.Observed,
                "GPU, AVC and WDDM policy metadata read locally; active codec negotiation NOT tested.",
                "Inspect graphics GPO only for reported performance problems, not as proof of connectivity.");
        else
            Add(checks, "Graphics / codec policy", RdpDoctorLevel.Unavailable,
                "GPU, AVC or WDDM policy inspection unavailable.",
                "Inspect local computer policy registry and applied GPO, if needed.");

        int eventErrors = source.Events.Count(x => x.Level is "Critical" or "Error");
        int eventWarnings = source.Events.Count(x => x.Level == "Warning");
        if (source.EventWarnings.Count > 0)
            Add(checks, "Windows RDP event logs", RdpDoctorLevel.Unknown,
                source.Events.Count > 0
                    ? "Some event channels were read, but one or more channels were unavailable."
                    : "One or more Windows RDP event channels were unavailable.",
                "Inspect individual Event Viewer channels; gaps cannot establish successful connections.");
        else if (eventErrors + eventWarnings > 0)
            Add(checks, "Windows RDP event logs", RdpDoctorLevel.Attention,
                "Last 24 hours: " + eventErrors + " error/critical and " +
                eventWarnings + " warning event(s), for correlation only.",
                "Correlate event IDs and UTC times with the user's independent connection attempt.");
        else
            Add(checks, "Windows RDP event logs", RdpDoctorLevel.Observed,
                source.Events.Count == 0
                    ? "Inspected event channels returned no sampled events in the last 24 hours."
                    : source.Events.Count + " recent informational event(s); no errors found in this bounded sample.",
                "A clean sample is not proof of connectivity. Correlate events with a separately tested RDP session.");

        Add(checks, "External client connection", RdpDoctorLevel.NotTested,
            "No TCP connection, TLS handshake, authentication or interactive logon from another host was attempted.",
            "From a separate authorized computer, test the configured port and normal RDP sign-in.");

        var sorted = checks.OrderBy(x => x.Level switch
        {
            RdpDoctorLevel.Blocked => 0,
            RdpDoctorLevel.Attention => 1,
            RdpDoctorLevel.Unavailable => 2,
            RdpDoctorLevel.Unknown => 3,
            RdpDoctorLevel.NotTested => 4,
            RdpDoctorLevel.Observed => 5,
            _ => 6
        }).ToArray();
        return new(DateTimeOffset.UtcNow, sorted, source.Events, source.EventWarnings);
    }
}
