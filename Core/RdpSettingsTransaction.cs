using Microsoft.Win32;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// A complete preflight plan is constructed before the first change. The
/// transaction attempts to undo even the operation that threw, since a COM
/// setter or registry call may have changed state before returning an error.
/// </summary>
internal sealed record RdpReversibleChange(
    string Name, Action Apply, Action Rollback,
    Func<bool> IsApplied, Func<bool> IsRestored);

internal static class RdpSettingsTransaction
{
    internal static void Execute(IReadOnlyList<RdpReversibleChange> changes)
    {
        ArgumentNullException.ThrowIfNull(changes);
        var attempted = new List<RdpReversibleChange>(changes.Count);
        try
        {
            foreach (var change in changes)
            {
                attempted.Add(change); // Even a throwing setter may have changed state.
                change.Apply();
                if (!change.IsApplied())
                    throw new IOException(change.Name + ": read-back verification failed.");
            }
        }
        catch (Exception original)
        {
            var rollbackFailures = new List<Exception>();
            for (int i = attempted.Count - 1; i >= 0; i--)
            {
                var change = attempted[i];
                try
                {
                    change.Rollback();
                    if (!change.IsRestored())
                        throw new IOException("Rollback verification failed.");
                }
                catch (Exception rollback)
                {
                    rollbackFailures.Add(new InvalidOperationException(
                        change.Name + ": rollback failed or could not be verified.", rollback));
                }
            }
            if (rollbackFailures.Count != 0)
                throw new AggregateException(
                    "RDP settings change failed and rollback is INCOMPLETE. " +
                    "Use the local console and verify RDP registry and firewall state.",
                    new[] { original }.Concat(rollbackFailures));
            throw new InvalidOperationException(
                "RDP settings change failed; all attempted changes were rolled back and verified.",
                original);
        }
    }

    internal static RdpReversibleChange StageDword(
        RegistryKey key, string valueName, int newValue)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (newValue is not (0 or 1))
            throw new ArgumentOutOfRangeException(nameof(newValue));
        bool existed = key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase);
        int original = 0;
        if (existed)
        {
            if (key.GetValueKind(valueName) != RegistryValueKind.DWord ||
                key.GetValue(valueName, null) is not int existing ||
                existing is not (0 or 1))
                throw new InvalidDataException(
                    "Existing RDP setting has an unexpected registry type or value: " + valueName);
            original = existing;
        }

        bool EqualsCurrent(int value)
            => key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase) &&
               key.GetValueKind(valueName) == RegistryValueKind.DWord &&
               key.GetValue(valueName, null) is int actual && actual == value;

        bool Missing()
            => !key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase);

        int captured = original;
        return new RdpReversibleChange(
            valueName,
            () => key.SetValue(valueName, newValue, RegistryValueKind.DWord),
            () =>
            {
                if (existed) key.SetValue(valueName, captured, RegistryValueKind.DWord);
                else key.DeleteValue(valueName, throwOnMissingValue: false);
            },
            () => EqualsCurrent(newValue),
            () => existed ? EqualsCurrent(captured) : Missing());
    }
    /// <summary>
    /// Existing allowlisted DWORD only. Retains precise value and read-back
    /// rollback for advanced settings whose values are not limited to 0/1.
    /// Caller validates name, exact registry key, GPO and expected value.
    /// </summary>
    internal static RdpReversibleChange StageBoundedDword(
        RegistryKey key, string valueName, int newValue, int minimum, int maximum)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (minimum < 0 || maximum < minimum ||
            newValue < minimum || newValue > maximum)
            throw new ArgumentOutOfRangeException(nameof(newValue));
        if (!key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase) ||
            key.GetValueKind(valueName) != RegistryValueKind.DWord ||
            key.GetValue(valueName, null) is not int original ||
            original < minimum || original > maximum)
            throw new InvalidDataException(
                "Cannot stage an unknown, missing or invalid RDP DWORD: " + valueName);

        bool EqualsCurrent(int value)
            => key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase) &&
               key.GetValueKind(valueName) == RegistryValueKind.DWord &&
               key.GetValue(valueName, null) is int actual && actual == value;
        return new RdpReversibleChange(
            valueName,
            () => key.SetValue(valueName, newValue, RegistryValueKind.DWord),
            () => key.SetValue(valueName, original, RegistryValueKind.DWord),
            () => EqualsCurrent(newValue),
            () => EqualsCurrent(original));
    }

}
