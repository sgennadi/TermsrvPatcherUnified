namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Explains whether a read-only RDP diagnostic row has a supported local editor.
/// This is UI advisory evidence only; every actual writer re-checks Windows
/// privileges, policy conflicts and the current registry value at commit time.
/// </summary>
internal static class RdpRowEditStatus
{
    internal static RdpPolicyEvidence Annotate(
        RdpPolicyEvidence row, bool administrator, bool console,
        bool? policyManaged, bool validValue)
    {
        bool blank = row.Setting == RdpPolicyDiagnostics.BlankPasswordSetting;
        bool supported = blank || RdpLocalAdvancedSettings.Find(row.Setting) is not null;
        bool requiresConsole = !blank &&
            RdpLocalAdvancedSettings.Find(row.Setting)?.ConsoleOnly == true;

        if (!supported)
            return row with
            {
                CanEdit = false,
                PolicyLocked = row.Assessment is "Policy differs" or "Policy configured",
                EditStatus = row.Setting is "Remote Desktop" or
                    "Network Level Authentication" or "One session per user"
                    ? "Use main controls"
                    : row.Assessment is "Policy differs" or "Policy configured"
                        ? "GPO controlled"
                        : "View only (GPO / policy)"
            };
        if (policyManaged == true)
            return row with
            {
                CanEdit = false, PolicyLocked = true, EditStatus = "Blocked by GPO"
            };
        if (!blank && policyManaged is null)
            return row with
            {
                CanEdit = false, PolicyLocked = false,
                EditStatus = "Policy check unavailable"
            };
        if (!validValue)
            return row with
            {
                CanEdit = false, EditStatus = "Missing / invalid value"
            };
        if (!administrator)
            return row with
            {
                CanEdit = false, EditStatus = "Administrator required"
            };
        if (requiresConsole && !console)
            return row with
            {
                CanEdit = false, EditStatus = "Local / VM console only"
            };
        return row with
        {
            CanEdit = true,
            EditStatus = blank ? "Edit local LSA (GPO unverified)" : "Editable locally"
        };
    }
}
