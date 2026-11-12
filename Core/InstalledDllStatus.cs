namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Read-only display classification. A backup/Revert option is NEVER used in
/// place of a current-file classification. No write permission is granted by
/// this result; Apply/Revert still require independent protected preflight.
/// </summary>
internal enum InstalledDllKind { Patched, NotPatched, Unknown }

internal sealed record InstalledDllStatus(
    InstalledDllKind Kind, string Headline, string Evidence,
    string RevertHeadline, string RevertDetails,
    bool CanOfferAutomaticApply, bool CanOfferAutomaticRevert)
{
    internal static InstalledDllStatus FromEvidence(PatchPlan plan,
        AutomaticRevertPlan? recovery, bool recoveryInspectionFailed = false)
    {
        ArgumentNullException.ThrowIfNull(plan);

        // Never mix a recoverable DLL observed at an earlier SHA/version with
        // a new signature scan. Treat changes during the scan as unknown.
        bool recoveryMatches = recovery is not null &&
            recovery.InstalledSha256.Equals(plan.OriginalSha256,
                StringComparison.OrdinalIgnoreCase) &&
            recovery.FileVersion.Equals(plan.FileVersion, StringComparison.Ordinal);
        if (recovery is not null && !recoveryMatches)
            return Unknown("Signature check and recovery describe different DLL bytes or versions. Run Check again.",
                "Revert: UNAVAILABLE — stale or mismatched recovery evidence.");

        // A Ready (Find/original-side) signature plus a valid Revert claim
        // is contradictory. Do not enable either operation from this scan.
        if (plan.State == PatchState.Ready && recoveryMatches)
            return Unknown("Conflicting original and recovery evidence. No automatic action is permitted.",
                "Revert: UNAVAILABLE — inconsistent evidence.");

        bool patchedByCatalog = plan.State == PatchState.AlreadyPatched;
        bool patchedByRecovery = recoveryMatches &&
            plan.State is PatchState.Unknown or PatchState.Ambiguous;

        if (patchedByCatalog || patchedByRecovery)
        {
            string evidence = patchedByCatalog
                ? "Known replacement bytes were found in the current DLL (exact signature match). This does not verify remote RDP operation."
                : "A verified recovery source is bound to the exact current DLL SHA-256; automatic signature recognition alone was inconclusive.";
            if (recoveryMatches)
            {
                bool catalogOnly = recovery!.RecoverySource == "ExactCatalog";
                return new(InstalledDllKind.Patched, "DLL STATUS: PATCHED", evidence,
                    catalogOnly
                        ? "Revert: RECONSTRUCTION AVAILABLE (no original backup)"
                        : "Revert: AVAILABLE (verified recovery source)",
                    catalogOnly
                        ? "Catalog-based reconstruction cannot prove Microsoft-original DLL authenticity."
                        : "Recovery matches the current installed DLL hash. Revert still requires separate administrator confirmation.",
                    false, true);
            }
            return new(InstalledDllKind.Patched, "DLL STATUS: PATCHED", evidence,
                recoveryInspectionFailed
                    ? "Revert: NOT VERIFIED (recovery check failed)"
                    : "Revert: UNAVAILABLE (no verified recovery source)",
                "Patch detection is independent of the ability to restore. Never infer backup availability from matching signatures.",
                false, false);
        }

        if (plan.State == PatchState.Ready)
            return new(InstalledDllKind.NotPatched, "DLL STATUS: NOT PATCHED",
                "Known original-side Find bytes were found in the installed DLL. This is not proof of an authentic Microsoft binary.",
                "Revert: NOT NEEDED (known patch not detected)",
                recoveryInspectionFailed
                    ? "Recovery inspection failed; the current automatic Find signature was still checked independently."
                    : "Automatic Apply may be offered only after the normal administrator, signature and safety checks.",
                true, false);

        string reason = plan.State switch
        {
            PatchState.Ambiguous => "Overlapping, repeated or conflicting signatures; current status cannot be determined safely.",
            PatchState.Unsupported => "This Windows/DLL combination is unsupported by the automatic recognition path.",
            _ => "Neither a complete known original signature nor a complete known replacement signature was identified."
        };
        return Unknown(reason,
            recoveryInspectionFailed
                ? "Revert: NOT VERIFIED (recovery check failed)"
                : "Revert: UNAVAILABLE (no verified recovery for this DLL).");
    }

    private static InstalledDllStatus Unknown(string reason, string recovery) =>
        new(InstalledDllKind.Unknown, "DLL STATUS: UNKNOWN", reason, recovery,
            "No automatic modification or Revert is authorized by this status. Review Advanced signature evidence.",
            false, false);
}
