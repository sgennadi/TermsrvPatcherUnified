using Microsoft.Win32;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Local security policy only. A domain GPO may override the registry value;
/// this class never claims that a remote login succeeds, and never edits a GPO.
/// </summary>
internal static class RdpBlankPasswordSecurity
{
    private const string LsaKey = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string ValueName = "LimitBlankPasswordUse";

    // True = prohibit remote blank-password authentication (recommended).
    // False = local policy permits it (high risk). Null = unavailable.
    internal static bool? Read()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LsaKey);
            if (key is null || !key.GetValueNames().Contains(ValueName,
                    StringComparer.OrdinalIgnoreCase) ||
                key.GetValueKind(ValueName) != RegistryValueKind.DWord)
                return null;
            return Interpret(key.GetValue(ValueName, null));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException or ArgumentException)
        {
            return null;
        }
    }

    internal static bool? Interpret(object? registryValue)
        => registryValue is int n && n is 0 or 1 ? n == 1 : null;

    internal static void SetRestricted(bool restricted)
    {
        if (!SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Administrator rights required.");
        using var operation = OperationLock.Acquire();
        using var key = Registry.LocalMachine.OpenSubKey(LsaKey, writable: true)
            ?? throw new InvalidOperationException("LSA security policy is unavailable.");
        if (!key.GetValueNames().Contains(ValueName, StringComparer.OrdinalIgnoreCase) ||
            key.GetValueKind(ValueName) != RegistryValueKind.DWord ||
            Interpret(key.GetValue(ValueName, null)) is null)
            throw new InvalidDataException(
                "Blank-password policy could not be verified. No setting changed.");

        // Re-use protected, audited read-back and verified rollback logic.
        RdpSettingsTransaction.Execute([
            RdpSettingsTransaction.StageDword(key, ValueName, restricted ? 1 : 0)
        ]);
        AuditLog.Append("Local blank-password restriction: " +
            (restricted ? "ENABLED" : "DISABLED BY EXPLICIT OPERATOR DECISION") +
            ". Domain policy may override this local setting.");
        OperationHistory.TryRecord("RdpSettings", "Success");
    }
}
