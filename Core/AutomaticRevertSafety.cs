using System.Diagnostics;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Compact Revert accepts only a SHA-256-bound protected recovery journal or
/// one administrator-controlled backup that reproduces the exact installed
/// patched DLL via an embedded, trusted automatic signature. Never guess from
/// Windows version, CRC32, filename or a near pattern match.
/// </summary>
internal sealed record AutomaticRevertPlan(string OriginalSha256,
    string InstalledSha256, string FileVersion, string ProfileId, string RecoverySource);

internal sealed record AutomaticRevertSnapshot(AutomaticRevertPlan Plan, byte[] OriginalBytes);

internal static class AutomaticRevertSafety
{
    internal static AutomaticRevertPlan? Inspect() => Resolve()?.Plan;

    internal static AutomaticRevertSnapshot? Resolve()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess ||
            !SystemInfo.IsAdministrator() || !NsudoDevilModeScope.IsBundled)
            return null;
        var os = SystemInfo.Read();
        if (!os.Supported || !File.Exists(os.DllPath)) return null;
        byte[] installed = File.ReadAllBytes(os.DllPath);
        PeSafety.ReadAmd64DllSections(installed);
        string currentHash = SystemInfo.Sha256(installed);

        // The authenticated journal is independent of the signature catalog.
        // It is deliberately keyed by the EXACT current (patched) file hash.
        // If Windows Update replaced this DLL, stale journals do not match.
        var journal = RecoveryJournalStore.LoadExact(installed, os.DllVersion);
        if (journal is not null)
        {
            if (journal.OriginalSha256.Equals(currentHash,
                    StringComparison.OrdinalIgnoreCase)) return null;
            return new AutomaticRevertSnapshot(new AutomaticRevertPlan(
                journal.OriginalSha256, currentHash, os.DllVersion,
                journal.ProfileId, "Journal"), journal.OriginalBytes);
        }

        // Compatibility with Preview.21 protected backups and the System32
        // .bak introduced in Preview.22. Each candidate must reproduce the
        // EXACT current patched DLL using a trusted embedded automatic profile.
        // A stale Windows Update backup can never authorize Revert.
        var candidates = new List<(string Source, byte[] Bytes)>();
        using (var engine = new TermsrvEngine(null))
        {
            var backups = engine.BackupsForCurrentVersion();
            // Several valid originals can exist after Windows servicing or a
            // previous Apply. Do NOT pick the newest by timestamp: compare
            // every bounded candidate against the entire installed DLL below.
            // If too many copies are present, require Advanced/manual review.
            if (backups.Count > 24) return null;
            foreach (string backup in backups)
                candidates.Add(("TrustedBackup", DllBackupStore.ReadVerified(
                    TermsrvEngine.BackupDirectory, backup,
                    os.DllVersion, installed.LongLength)));
        }
        var system32 = System32BackupStore.ReadVerified(os.DllVersion, installed.LongLength);
        if (system32 is not null)
            candidates.Add(("System32Backup", system32));
        var matches = new List<AutomaticRevertSnapshot>();
        foreach (var candidate in candidates)
        {
            var original = candidate.Bytes;
            string originalHash = SystemInfo.Sha256(original);
            if (originalHash.Equals(currentHash, StringComparison.OrdinalIgnoreCase))
                continue;
            var expected = PatchCatalog.Inspect(original, os.DllPath, os.DllVersion,
                originalHash, true, PatchCatalog.LoadAutomatic(), "x64", false,
                new AutomaticSelectionContext(os.Name, os.DisplayVersion, os.InstallationType));
            if (expected.State != PatchState.Ready || expected.IsManual ||
                expected.PatchedBytes is null || expected.Edits.Count == 0)
                continue;
            PeSafety.RequireExecutableEdits(original, expected.Edits);
            if (!SystemInfo.Sha256(expected.PatchedBytes)
                    .Equals(currentHash, StringComparison.OrdinalIgnoreCase))
                continue;
            matches.Add(new AutomaticRevertSnapshot(new AutomaticRevertPlan(
                originalHash, currentHash, os.DllVersion,
                expected.ProfileId, candidate.Source), original));
        }
        // Duplicate copies of identical originals are fine; two different
        // originals are never auto-selected. A backup's timestamp and .bak
        // filename do NOT authorize the choice.
        if (!HasUniqueOriginal(matches.Select(x => x.Plan.OriginalSha256)))
            return null;
        if (matches.Count > 0)
            return matches[0];

        // Last-resort source-free recovery. Only the fully fixed 13/19-byte
        // Windows 11 family may be reversed deterministically. A generic
        // wildcard signature, unknown Windows build, ambiguous candidate or
        // changed DLL is NOT enough to reconstruct missing source bytes.
        // This is not proof of an authentic Microsoft binary: UI requires
        // a second explicit, higher-risk approval before using this fallback.
        return ExactCatalogRevert.Inspect(os, installed);
    }

    // Keep this pure for synthetic Windows Update/ambiguous backup regressions.
    internal static bool HasUniqueOriginal(IEnumerable<string> matchedHashes) =>
        matchedHashes.Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(2).Count() <= 1;

    internal static bool SameApproval(AutomaticRevertPlan approved,
        AutomaticRevertPlan? current) =>
        current is not null &&
        approved.OriginalSha256.Equals(current.OriginalSha256,
            StringComparison.OrdinalIgnoreCase) &&
        approved.InstalledSha256.Equals(current.InstalledSha256,
            StringComparison.OrdinalIgnoreCase) &&
        approved.FileVersion.Equals(current.FileVersion, StringComparison.Ordinal) &&
        approved.ProfileId.Equals(current.ProfileId, StringComparison.Ordinal) &&
        approved.RecoverySource.Equals(current.RecoverySource, StringComparison.Ordinal);
}
