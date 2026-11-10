using Microsoft.Win32;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Operator-only local RDP inspection. Never changes Windows configuration,
/// creates a policy, tests remote authentication, or adds diagnostics telemetry.
/// Access is deliberately bounded and every incomplete source is labelled.
/// </summary>
internal sealed record RdpSecurityInspection(
    DateTimeOffset CheckedUtc, string Firewall, string LogonRights,
    string Certificate, string Graphics);

internal static class RdpSecurityInspector
{
    private const string TerminalPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    private const string ListenerKey =
        @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

    internal static RdpSecurityInspection ReadLocal()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Local Windows security APIs are required.");
        return new(DateTimeOffset.UtcNow, SafeRead(ReadFirewall),
            SafeRead(ReadLogonRights), SafeRead(ReadCertificate), SafeRead(ReadGraphics));
    }

    private static string SafeRead(Func<string> inspect)
    {
        try { return inspect(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or
            UnauthorizedAccessException or System.Security.SecurityException or
            IOException or InvalidOperationException or NotSupportedException or
            COMException or System.Management.ManagementException or
            System.Security.Cryptography.CryptographicException or
            Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or
            InvalidCastException or ArgumentException or
            System.Reflection.TargetInvocationException)
        {
            return "Unable to inspect: " + ex.GetType().Name +
                ". Status UNKNOWN. No changes made.";
        }
    }

    internal static bool IsRdpRuleGroup(string? group) =>
        string.Equals(group, "@FirewallAPI.dll,-28752", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(group, "@FirewallAPI.dll,-28852", StringComparison.OrdinalIgnoreCase);

    private static string Clip(string? value, int limit = 132) =>
        value is null ? "(unknown)" : value.Length <= limit ? value : value[..limit] + "...";

    private static string ReadFirewall()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        if (type is null) return "Windows Firewall policy COM is unavailable. Status UNKNOWN.";
        object? instance = Activator.CreateInstance(type);
        if (instance is null) return "Could not open Windows Firewall policy. Status UNKNOWN.";
        var lines = new StringBuilder()
            .AppendLine("Windows Firewall COM / inbound RDP rule metadata (read-only).");
        int seen = 0, displayed = 0;
        try
        {
            dynamic policy = instance;
            int activeProfiles = (int)policy.CurrentProfileTypes;
            lines.AppendLine("Active Windows network profiles (COM): " +
                             DescribeProfiles(activeProfiles));
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    if (!IsRdpRuleGroup((string?)rule.Grouping) ||
                        (int)rule.Direction != 1) continue;
                    seen++;
                    if (displayed++ >= 36) continue;
                    int p = (int)rule.Protocol;
                    string protocol = p switch { 6 => "TCP", 17 => "UDP", _ => "IP " + p };
                    int profiles = (int)rule.Profiles;
                    string profileNames = DescribeProfiles(profiles);
                    string scope = Clip(Convert.ToString((object?)rule.RemoteAddresses));
                    lines.AppendLine()
                        .AppendLine("Rule: " + Clip(Convert.ToString((object?)rule.Name)))
                        .AppendLine("  Enabled: " + ((bool)rule.Enabled ? "Yes" : "No") +
                                    "; Action: " + ((int)rule.Action == 1 ? "Allow" : "Block") +
                                    "; Protocol: " + protocol)
                        .AppendLine("  Local ports: " + Clip(Convert.ToString((object?)rule.LocalPorts)) +
                                    "; Profiles: " + profileNames)
                        .AppendLine("  Active-profile intersection: " +
                            (profiles == int.MaxValue || (profiles & activeProfiles) != 0
                                ? "Yes (profile only; other restrictions unknown)"
                                : "No (rule not active on the current network profile)"))
                        .AppendLine("  Remote address scope: " + scope);
                }
                catch (Exception ex) when (ex is COMException or InvalidCastException or
                                           Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
                {
                    lines.AppendLine("One RDP firewall rule could not be fully inspected (" +
                        ex.GetType().Name + ").");
                }
            }
        }
        finally
        {
            if (Marshal.IsComObject(instance)) Marshal.FinalReleaseComObject(instance);
        }
        if (seen == 0)
            lines.AppendLine("No built-in RDP inbound rule group matched. This is NOT proof that RDP is blocked or allowed.");
        if (seen > 36) lines.AppendLine((seen - 36) + " additional RDP rules omitted for display safety.");
        lines.AppendLine("Rule presence/Enabled is NOT proof of an effective firewall decision. " +
                         "Active network profiles, GPO/MDM, other rules, IP scope, service binding, " +
                         "third-party filters and remote reachability are not verified.");
        return lines.ToString();
    }

    internal static string DescribeProfiles(int flags)
    {
        if (flags == int.MaxValue) return "All";
        var names = new List<string>();
        if ((flags & 1) != 0) names.Add("Domain");
        if ((flags & 2) != 0) names.Add("Private");
        if ((flags & 4) != 0) names.Add("Public");
        return names.Count == 0 ? "Unknown (" + flags + ")" : string.Join(", ", names);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        internal uint Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal uint Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaUnicodeString
    {
        internal ushort Length;
        internal ushort MaximumLength;
        internal IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaSidEntry { internal IntPtr Sid; }

    [DllImport("advapi32.dll")]
    private static extern uint LsaOpenPolicy(IntPtr systemName,
        ref LsaObjectAttributes objectAttributes, uint desiredAccess, out IntPtr policy);

    [DllImport("advapi32.dll")]
    private static extern uint LsaEnumerateAccountsWithUserRight(IntPtr policy,
        ref LsaUnicodeString userRight, out IntPtr buffer, out uint count);

    [DllImport("advapi32.dll")]
    private static extern uint LsaFreeMemory(IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policy);

    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(uint status);

    [DllImport("advapi32.dll")]
    private static extern uint GetLengthSid(IntPtr sid);

    private static string ReadLogonRights()
    {
        var attributes = new LsaObjectAttributes
        {
            Length = (uint)Marshal.SizeOf<LsaObjectAttributes>()
        };
        const uint lookupNamesAndRead = 0x00000800 | 0x00000001;
        uint opened = LsaOpenPolicy(IntPtr.Zero, ref attributes, lookupNamesAndRead, out var handle);
        if (opened != 0)
            return "LSA read access denied/unavailable (Win32 " +
                LsaNtStatusToWinError(opened) + "). Rights status UNKNOWN.";
        try
        {
            var lines = new StringBuilder()
                .AppendLine("Local applied LSA user-right assignments (read-only).");
            AppendRight("Allow log on through Remote Desktop Services",
                "SeRemoteInteractiveLogonRight", lines, handle);
            AppendRight("Deny log on through Remote Desktop Services",
                "SeDenyRemoteInteractiveLogonRight", lines, handle);
            lines.AppendLine()
                .AppendLine("Deny rights override allow rights. Group membership, nested " +
                    "groups, per-user tokens, GPO/MDM ownership and actual account sign-in " +
                    "are NOT evaluated. Account/group names appear only in this local UI.");
            return lines.ToString();
        }
        finally { LsaClose(handle); }
    }

    private static void AppendRight(string label, string right, StringBuilder output, IntPtr handle)
    {
        var text = Marshal.StringToHGlobalUni(right);
        try
        {
            var unicode = new LsaUnicodeString
            {
                Buffer = text,
                Length = checked((ushort)(right.Length * 2)),
                MaximumLength = checked((ushort)((right.Length + 1) * 2))
            };
            IntPtr buffer = IntPtr.Zero;
            uint count = 0;
            uint code = LsaEnumerateAccountsWithUserRight(handle, ref unicode, out buffer, out count);
            output.AppendLine().AppendLine(label + " (" + right + "):");
            try
            {
                if (code != 0)
                {
                    output.AppendLine("  Not enumerated (Win32 " +
                        LsaNtStatusToWinError(code) + "); status UNKNOWN.");
                    return;
                }
                if (count > 2048)
                {
                    output.AppendLine("  Abnormally large result; refusing unbounded enumeration.");
                    return;
                }
                if (count == 0 || buffer == IntPtr.Zero)
                {
                    output.AppendLine("  No assignments returned. This does NOT prove that every login is denied.");
                    return;
                }
                int perEntry = Marshal.SizeOf<LsaSidEntry>();
                for (int i = 0; i < count && i < 64; i++)
                {
                    var entry = Marshal.PtrToStructure<LsaSidEntry>(IntPtr.Add(buffer, checked(i * perEntry)));
                    if (entry.Sid == IntPtr.Zero) continue;
                    uint length = GetLengthSid(entry.Sid);
                    if (length is < 8 or > 68)
                    {
                        output.AppendLine("  Unreadable account SID.");
                        continue;
                    }
                    byte[] bytes = new byte[length];
                    Marshal.Copy(entry.Sid, bytes, 0, (int)length);
                    var sid = new SecurityIdentifier(bytes, 0);
                    try { output.AppendLine("  " + sid.Translate(typeof(NTAccount)).Value); }
                    catch (IdentityNotMappedException) { output.AppendLine("  " + sid.Value); }
                }
                if (count > 64)
                    output.AppendLine("  " + (count - 64) + " more identities hidden for display safety.");
            }
            finally { if (buffer != IntPtr.Zero) LsaFreeMemory(buffer); }
        }
        finally { Marshal.FreeHGlobal(text); }
    }

    internal static string NormalizeThumbprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        string normalized = value.Replace(" ", "", StringComparison.Ordinal)
            .Replace(":", "", StringComparison.Ordinal)
            .Replace("\u200e", "", StringComparison.Ordinal)
            .Replace("\u200f", "", StringComparison.Ordinal).Trim();
        return normalized.Length == 40 && normalized.All(Uri.IsHexDigit)
            ? normalized.ToUpperInvariant() : string.Empty;
    }

    private static string ReadCertificate()
    {
        string thumb = "";
        string origin = "No verified listener certificate binding";
        try
        {
            using var search = new ManagementObjectSearcher(
                @"\\.\root\CIMV2\TerminalServices",
                "SELECT TerminalName, SSLCertificateSHA1Hash FROM Win32_TSGeneralSetting");
            using var results = search.Get();
            foreach (ManagementObject item in results)
            {
                using (item)
                {
                    if (!string.Equals(Convert.ToString(item["TerminalName"]), "RDP-tcp",
                        StringComparison.OrdinalIgnoreCase)) continue;
                    thumb = NormalizeThumbprint(Convert.ToString(item["SSLCertificateSHA1Hash"]));
                    origin = "Win32_TSGeneralSetting (WMI)";
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or
                                   COMException or InvalidOperationException)
        {
            origin = "WMI unavailable (" + ex.GetType().Name + "), registry fallback";
        }
        if (thumb.Length == 0)
        {
            using var key = Registry.LocalMachine.OpenSubKey(ListenerKey);
            if (key?.GetValue("SSLCertificateSHA1Hash") is byte[] binary && binary.Length == 20)
            {
                thumb = Convert.ToHexString(binary);
                origin = "RDP-Tcp SSL certificate registry binding";
            }
        }
        var lines = new StringBuilder()
            .AppendLine("Local RDP TLS listener certificate (read-only)")
            .AppendLine("Listener binding source: " + origin);
        if (thumb.Length == 0)
        {
            lines.AppendLine("Configured certificate thumbprint unavailable. A managed or " +
                "automatically generated RDP certificate may still exist.")
                .AppendLine("Listener TLS handshake and client certificate trust NOT verified.");
            return lines.ToString();
        }
        lines.AppendLine("Configured thumbprint (SHA-1 identifier): " + thumb);
        foreach (var storeName in new[] { "Remote Desktop", "My" })
        {
            try
            {
                using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumb,
                    validOnly: false);
                if (found.Count == 0) continue;
                var certificate = found[0];
                bool datesValid = certificate.NotBefore.ToUniversalTime() <= DateTime.UtcNow &&
                                  certificate.NotAfter.ToUniversalTime() >= DateTime.UtcNow;
                lines.AppendLine("Found in LocalMachine\\" + storeName)
                    .AppendLine("Subject: " + Clip(certificate.Subject, 180))
                    .AppendLine("Issuer: " + Clip(certificate.Issuer, 180))
                    .AppendLine("Valid from (UTC): " + certificate.NotBefore.ToUniversalTime().ToString("u"))
                    .AppendLine("Valid to (UTC): " + certificate.NotAfter.ToUniversalTime().ToString("u"))
                    .AppendLine("Date window: " + (datesValid ? "Within validity dates" : "EXPIRED or not yet valid"))
                    .AppendLine("Self-issued: " + (certificate.Subject == certificate.Issuer ? "Yes" : "No"))
                    .AppendLine("Private key present (metadata): " + (certificate.HasPrivateKey ? "Yes" : "No"))
                    .AppendLine("Trust chain, key ACL for TermService and active TLS handshake NOT verified.");
                return lines.ToString();
            }
            catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or
                                       UnauthorizedAccessException)
            {
                lines.AppendLine("LocalMachine\\" + storeName + ": inaccessible (" +
                    ex.GetType().Name + ").");
            }
        }
        return lines.AppendLine("Bound certificate not found in inspected local stores. " +
            "The binding may be stale or managed elsewhere; active certificate UNKNOWN.").ToString();
    }

    internal static string DescribeGraphicsDword(string name, object? raw)
    {
        if (raw is null) return "Not configured (effective codec/driver unknown)";
        if (raw is not int value || value is not (0 or 1))
            return "Invalid/unexpected DWORD; review policy manually";
        return name switch
        {
            "bEnumerateHWBeforeSW" => value == 1
                ? "Hardware graphics GPU preference enabled" : "Hardware graphics GPU preference disabled",
            "AVCHardwareEncodePreferred" => value == 1
                ? "Prefer hardware H.264/AVC encoding" : "Software H.264/AVC encoding",
            "AVC444ModePreferred" => value == 1
                ? "Prefer AVC 444 when compatible" : "AVC 444 preference disabled",
            "fEnableWddmDriver" => value == 1
                ? "WDDM driver preference enabled" : "WDDM driver preference disabled",
            _ => "Unknown graphics policy"
        };
    }

    private static string ReadGraphics()
    {
        using var policy = Registry.LocalMachine.OpenSubKey(TerminalPolicy);
        var lines = new StringBuilder()
            .AppendLine("RDP graphics ADMX computer policy registry (read-only).");
        foreach (var (label, name) in new[] {
            ("Use hardware GPU for remote sessions", "bEnumerateHWBeforeSW"),
            ("H.264/AVC hardware encoding", "AVCHardwareEncodePreferred"),
            ("H.264/AVC 444 graphics mode", "AVC444ModePreferred"),
            ("WDDM display driver", "fEnableWddmDriver")
        })
        {
            object? raw = null;
            if (policy is not null && policy.GetValueNames().Contains(name,
                    StringComparer.OrdinalIgnoreCase))
                raw = policy.GetValueKind(name) == RegistryValueKind.DWord
                    ? policy.GetValue(name) : "INVALID_TYPE";
            lines.AppendLine(label + ": " + DescribeGraphicsDword(name, raw))
                .AppendLine("  " + @"HKLM\" + TerminalPolicy + "\\" + name);
        }
        lines.AppendLine("OS edition, GPU availability, applied GPO/MDM, actual " +
            "negotiated codec and remote client support are NOT verified. " +
            "WDDM policy changes can require a Windows restart.");
        return lines.ToString();
    }
}
