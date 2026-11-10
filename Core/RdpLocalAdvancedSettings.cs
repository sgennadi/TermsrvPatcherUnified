using Microsoft.Win32;
using System.Globalization;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Strict allow-list for local RDP-Tcp DWORD values. Group Policy settings and
/// arbitrary registry names are NEVER edited here. This is a GUI convenience,
/// not a way to bypass administrative policy or Windows authentication.
/// </summary>
internal sealed record RdpLocalSettingChoice(int Value, string Label);

internal sealed record RdpLocalSettingSpec(
    string Setting, string RegistryValue, int Minimum, int Maximum,
    bool ConsoleOnly, string Guidance, IReadOnlyList<RdpLocalSettingChoice> Choices)
{
    internal bool HasChoices => Choices.Count > 0;
}

internal static class RdpLocalAdvancedSettings
{
    private const string TcpKey =
        @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const string PolicyKey =
        @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    internal static readonly IReadOnlyList<RdpLocalSettingSpec> Editable =
    [
        new("RDP TCP port", "PortNumber", 1, 65535, true,
            "A listener-port change can require firewall changes and a later " +
            "TermService restart/reboot. Console access is required. " +
            "The program will NEVER restart the service automatically.", []),
        new("RDP security layer", "SecurityLayer", 0, 2, true,
            "TLS (2) is the preferred choice. Lower settings may weaken " +
            "transport security. A new connection and possibly restart are needed.",
            [new(2, "TLS only (2) — recommended"),
             new(1, "Negotiate (1)"),
             new(0, "RDP security (0) — insecure legacy")]),
        new("Minimum encryption level", "MinEncryptionLevel", 1, 4, true,
            "High (3) is recommended where supported. Legacy lower levels " +
            "weaken security; FIPS (4) requires compatible clients.",
            [new(3, "High (3) — recommended"),
             new(4, "FIPS compliant (4)"),
             new(2, "Client compatible (2)"),
             new(1, "Low (1) — insecure legacy")]),
        new("Always request password", "fPromptForPassword", 0, 1, false,
            "Controls the RDP listener's additional password-prompt preference. " +
            "Does not disable Windows sign-in authentication or create passwordless RDP.",
            [new(1, "Always prompt (1)"),
             new(0, "Allow credentials supplied by client (0)")]),
        new("Idle session limit", "MaxIdleTime", 0, int.MaxValue, false,
            "Value is milliseconds. 0 means unlimited. Existing RDP sessions " +
            "may not adopt a new limit until reconnecting.", []),
        new("Active session time limit", "MaxConnectionTime", 0, int.MaxValue, false,
            "Value is milliseconds. 0 means unlimited. A smaller limit may " +
            "terminate sessions; review before applying.", []),
        new("Disconnected session time limit", "MaxDisconnectionTime", 0, int.MaxValue, false,
            "Value is milliseconds. 0 means unlimited. A new value can change " +
            "how disconnected sessions are handled.", [])
    ];

    internal static RdpLocalSettingSpec? Find(string? setting) =>
        Editable.FirstOrDefault(spec => string.Equals(
            spec.Setting, setting, StringComparison.Ordinal));

    internal static int ParseValue(RdpLocalSettingSpec spec, string? input)
    {
        if (spec is null || !Editable.Contains(spec))
            throw new InvalidDataException("Not an approved local RDP option.");
        if (!int.TryParse(input, NumberStyles.None, CultureInfo.InvariantCulture,
                out var result) || result < spec.Minimum || result > spec.Maximum ||
            (spec.HasChoices && !spec.Choices.Any(choice => choice.Value == result)))
            throw new ArgumentOutOfRangeException(nameof(input),
                "Select an approved choice or a number in the allowed range.");
        return result;
    }

    internal static bool IsPolicyManaged(RdpLocalSettingSpec spec)
    {
        ValidateSpec(spec);
        using var policy = Registry.LocalMachine.OpenSubKey(PolicyKey);
        // Fail closed if the policy key or its values cannot be inspected;
        // the registry API propagates permission errors to the GUI.
        return policy is not null && policy.GetValueNames().Contains(
            spec.RegistryValue, StringComparer.OrdinalIgnoreCase);
    }

    internal static int? ReadLocal(RdpLocalSettingSpec spec)
    {
        ValidateSpec(spec);
        using var key = Registry.LocalMachine.OpenSubKey(TcpKey);
        if (key is null ||
            !key.GetValueNames().Contains(spec.RegistryValue, StringComparer.OrdinalIgnoreCase) ||
            key.GetValueKind(spec.RegistryValue) != RegistryValueKind.DWord ||
            key.GetValue(spec.RegistryValue, null) is not int value ||
            value < spec.Minimum || value > spec.Maximum)
            return null;
        return value;
    }

    internal static void SaveLocal(RdpLocalSettingSpec spec, int expected, int desired)
    {
        ValidateSpec(spec);
        if (!OperatingSystem.IsWindows() || !SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Administrator rights are required.");
        if (desired < spec.Minimum || desired > spec.Maximum ||
            (spec.HasChoices && !spec.Choices.Any(x => x.Value == desired)))
            throw new ArgumentOutOfRangeException(nameof(desired));
        // Changes which can sever the RDP session are console-only.
        if (spec.ConsoleOnly && InteractiveSessionDetector.Detect() != SessionKind.Console)
            throw new InvalidOperationException(
                "This connection or encryption setting requires a local/hypervisor console, not an RDP session.");
        using var operation = OperationLock.Acquire();
        if (IsPolicyManaged(spec))
            throw new InvalidOperationException(
                "Local change blocked by Group Policy. " +
                RdpPolicySourceResolver.ReadWinning(spec.RegistryValue).Details +
                Environment.NewLine + "No registry or GPO changes were made.");

        using var key = Registry.LocalMachine.OpenSubKey(TcpKey, writable: true)
            ?? throw new InvalidOperationException("The RDP listener registry key is unavailable.");
        if (!key.GetValueNames().Contains(spec.RegistryValue, StringComparer.OrdinalIgnoreCase) ||
            key.GetValueKind(spec.RegistryValue) != RegistryValueKind.DWord ||
            key.GetValue(spec.RegistryValue, null) is not int current ||
            current < spec.Minimum || current > spec.Maximum)
            throw new InvalidDataException("The selected local setting is missing or invalid.");
        if (current != expected)
            throw new InvalidOperationException(
                "The local setting changed while this editor was open. Reload and try again.");
        if (current == desired) return;
        if (IsPolicyManaged(spec))
            throw new InvalidOperationException("Group Policy was applied during the operation. " +
                RdpPolicySourceResolver.ReadWinning(spec.RegistryValue).Details +
                Environment.NewLine + "No local change made.");
        RdpSettingsTransaction.Execute([
            RdpSettingsTransaction.StageBoundedDword(
                key, spec.RegistryValue, desired, spec.Minimum, spec.Maximum)
        ]);
        AuditLog.Append("Verified local RDP option: " + spec.RegistryValue +
            ", modified; no gpupdate, service restart or reboot triggered.");
        OperationHistory.TryRecord("RdpSettings", "Success");
    }

    private static void ValidateSpec(RdpLocalSettingSpec spec)
    {
        if (spec is null || !Editable.Contains(spec))
            throw new InvalidDataException("This RDP registry name is not approved for local editing.");
    }
}
