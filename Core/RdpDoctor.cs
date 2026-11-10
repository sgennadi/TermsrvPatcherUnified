using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace TermsrvPatcherUnified.Core;

internal enum RdpDoctorLevel { Ok, Attention, Blocked, Unknown }

internal enum RdpDoctorSocket { Unknown, NotListening, LoopbackOnly, Listening }

internal sealed record RdpDoctorFinding(
    string Area, RdpDoctorLevel Level, string Evidence, string Recommendation)
{
    public string Status => Level switch
    {
        RdpDoctorLevel.Ok => "OK (local)",
        RdpDoctorLevel.Attention => "Attention",
        RdpDoctorLevel.Blocked => "Blocker",
        _ => "Unverified"
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
    public int Blockers => Findings.Count(x => x.Level == RdpDoctorLevel.Blocked);
    public int AttentionCount => Findings.Count(x => x.Level == RdpDoctorLevel.Attention);
    public int UnknownCount => Findings.Count(x => x.Level == RdpDoctorLevel.Unknown);

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
                        "; unverified: " + UnknownCount)
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
        try { security = RdpSecurityInspector.ReadLocal(); }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or
                                   System.ComponentModel.Win32Exception or UnauthorizedAccessException or
                                   System.Security.SecurityException or ArgumentException or
                                   System.Runtime.InteropServices.COMException)
        {
            // Per-source failure is unknown. Do not reveal local account names.
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
        var (events, warnings) = RdpDoctorEventReader.ReadRecent(TimeSpan.FromHours(24));
        return Analyze(new(policy, security, port, socket, events, warnings));
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

        var firewall = source.Security?.Firewall ?? "";
        if (string.IsNullOrWhiteSpace(firewall) ||
            firewall.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase) ||
            firewall.Contains("Unable to inspect", StringComparison.OrdinalIgnoreCase))
            Add(checks, "Windows Firewall", RdpDoctorLevel.Unknown,
                "Inbound RDP rule inspection unavailable.",
                "Inspect effective inbound rules, active network profile, port and source address restrictions.");
        else if (firewall.Contains("No built-in RDP inbound", StringComparison.OrdinalIgnoreCase) ||
                 firewall.Contains("No built-in RDP inbound rule", StringComparison.OrdinalIgnoreCase))
            Add(checks, "Windows Firewall", RdpDoctorLevel.Attention,
                "No built-in RDP inbound rule group detected. Custom rules might exist.",
                "Review effective Firewall rules and approved source scope. Do not disable Windows Firewall.");
        else
            Add(checks, "Windows Firewall", RdpDoctorLevel.Unknown,
                "Built-in rule metadata is available, but effective RDP access remains unverified.",
                "Check active profile intersection, enabled Allow rules, TCP port, address scope and upstream filters.");

        var rights = source.Security?.LogonRights ?? "";
        Add(checks, "Remote interactive logon rights", RdpDoctorLevel.Unknown,
            rights.Contains("Local applied LSA", StringComparison.Ordinal)
                ? "LSA Allow/Deny assignments were enumerated (user/group token and nested membership not evaluated)."
                : "Effective logon rights not verified.",
            "Inspect SeRemoteInteractiveLogonRight, SeDenyRemoteInteractiveLogonRight and effective group memberships. Deny takes precedence.");

        var certificate = source.Security?.Certificate ?? "";
        if (certificate.Contains("EXPIRED or not yet valid", StringComparison.Ordinal))
            Add(checks, "RDP TLS certificate", RdpDoctorLevel.Attention,
                "Certificate validity dates appear expired or not yet valid.",
                "Review the actual listener binding and trusted replacement certificate; no automatic certificate changes.");
        else
            Add(checks, "RDP TLS certificate", RdpDoctorLevel.Unknown,
                certificate.Contains("Within validity dates", StringComparison.Ordinal)
                    ? "Certificate is within its date window. TLS trust and active handshake not verified."
                    : "Certificate binding, trust or validity not independently established.",
                "Check RDP listener certificate, issuer trust, private-key permissions and remote TLS handshake.");

        Add(checks, "Graphics / codec policy", RdpDoctorLevel.Unknown,
            source.Security?.Graphics is null
                ? "GPU, AVC and WDDM policies could not be inspected."
                : "GPU, AVC and WDDM policy metadata was inspected; negotiated codec is unknown.",
            "Review graphics GPO only if users report poor visual performance. It is not a primary connectivity test.");

        int eventErrors = source.Events.Count(x => x.Level is "Critical" or "Error");
        int eventWarnings = source.Events.Count(x => x.Level == "Warning");
        if (source.EventWarnings.Count > 0)
            Add(checks, "Windows RDP event logs", RdpDoctorLevel.Unknown,
                "One or more event channels were unavailable or unreadable.",
                "Check channel accessibility in Event Viewer; missing logs cannot prove a healthy RDP session.");
        else if (eventErrors + eventWarnings > 0)
            Add(checks, "Windows RDP event logs", RdpDoctorLevel.Attention,
                "Last 24 hours: " + eventErrors + " error/critical and " +
                eventWarnings + " warning event(s). Events are clues, not diagnosed root causes.",
                "Review the event IDs and timestamps in the local table; correlate with the user's connection attempt.");
        else
            Add(checks, "Windows RDP event logs", RdpDoctorLevel.Unknown,
                source.Events.Count == 0 ? "No recent events found in the inspected channels." :
                    source.Events.Count + " recent informational event(s); no errors observed in sampled records.",
                "If a connection fails, reproduce with a timestamp and inspect all relevant channels and client logs.");

        Add(checks, "External client connection", RdpDoctorLevel.Unknown,
            "No remote TCP, TLS, credential or interactive logon attempt was performed.",
            "Use a different authorized computer to test the configured port and a normal RDP sign-in; compare timestamps with events.");

        var sorted = checks.OrderBy(x => x.Level switch
        {
            RdpDoctorLevel.Blocked => 0,
            RdpDoctorLevel.Attention => 1,
            RdpDoctorLevel.Unknown => 2,
            _ => 3
        }).ToArray();
        return new(DateTimeOffset.UtcNow, sorted, source.Events, source.EventWarnings);
    }
}
