namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Emergency recovery ONLY when no prior original DLL or journal is available.
/// Reconstructing lost bytes is mathematically impossible if the original
/// signature contains wildcards. We therefore accept only fully fixed embedded
/// Windows 11 version-specific signatures and verify that reapplying the exact
/// same signature recreates the entire current DLL byte-for-byte.
/// This proves deterministic reversibility, NOT Microsoft catalog authenticity.
/// </summary>
internal static class ExactCatalogRevert
{
    internal static bool TryReverseGroups(ReadOnlySpan<byte> installed,
        IReadOnlyList<BytePattern> groups, out byte[] original,
        out PatchEdit[] reverseEdits)
    {
        original = [];
        reverseEdits = [];
        if (groups.Count is < 1 or > 16 ||
            groups.Any(g => g.Search.Any(b => !b.HasValue) ||
                            g.Replace.Length != g.Search.Length))
            return false;

        var found = new List<PatchEdit>();
        foreach (var group in groups)
        {
            // Must be precisely one replacement hit and no original hit.
            // A missing/duplicate/mixed pattern is never reversible by policy.
            var hits = BytePattern.FindOffsets(installed, group.Replace);
            if (hits.Count != 1 ||
                BytePattern.FindOffsets(installed, group.Search).Count != 0)
                return false;
            var expected = group.Search.Select(b => b!.Value).ToArray();
            found.Add(new PatchEdit(hits[0], group.Replace, expected));
        }
        found.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        for (int i = 1; i < found.Count; i++)
        {
            if (found[i].Offset < found[i - 1].Offset + found[i - 1].Expected.Length)
                return false;
        }
        byte[] candidate = installed.ToArray();
        foreach (var edit in found)
        {
            if (!candidate.AsSpan(edit.Offset, edit.Expected.Length).SequenceEqual(edit.Expected))
                return false;
            edit.Replacement.CopyTo(candidate, edit.Offset);
        }
        if (candidate.SequenceEqual(installed)) return false;
        original = candidate;
        reverseEdits = found.ToArray();
        return true;
    }

    internal static AutomaticRevertSnapshot? Inspect(WindowsDetails os, byte[] installed)
    {
        if (!os.Supported ||
            !os.Name.Equals("Windows 11", StringComparison.OrdinalIgnoreCase) ||
            !os.InstallationType.Equals("Client", StringComparison.OrdinalIgnoreCase))
            return null;
        PeSafety.ReadAmd64DllSections(installed);
        var catalog = PatchCatalog.LoadAutomatic();
        var context = new AutomaticSelectionContext(
            os.Name, os.DisplayVersion, os.InstallationType);
        string installedHash = SystemInfo.Sha256(installed);
        // A specific 13-byte replacement can also contain the 12-byte
        // generic replacement as a prefix. The ordinary forward inspector
        // may label such patched bytes Ambiguous, although reconstructing the
        // unique specific ORIGINAL and comparing its full re-applied output
        // is unambiguous. Do not use the patched-file state as proof.
        var matches = new List<AutomaticRevertSnapshot>();
        foreach (var profile in catalog)
        {
            bool expectedFamily = os.DisplayVersion.ToUpperInvariant() switch
            {
                "24H2" => profile.Label.StartsWith(
                    "Windows 11 24H2 family", StringComparison.Ordinal),
                "25H2" or "26H2" => profile.Label.Equals(
                    "Windows 11 25H2 / 26H2 alternate layout", StringComparison.Ordinal),
                _ => false
            };
            if (!expectedFamily || profile.Groups.Any(group =>
                    group.Search.Any(b => !b.HasValue)))
                continue;
            if (!TryReverseGroups(installed, profile.Groups,
                    out var original, out var changes))
                continue;
            PeSafety.RequireExecutableEdits(installed, changes);
            // Independently inspect the reconstructed original with ALL
            // embedded patterns and the OS-aware priority rules. The exact
            // reconstructed output must equal the complete installed file.
            var ready = PatchCatalog.Inspect(original, os.DllPath, os.DllVersion,
                SystemInfo.Sha256(original), true, catalog, "x64", false, context);
            if (ready.State != PatchState.Ready ||
                ready.PatchedBytes is null ||
                !ready.PatchedBytes.SequenceEqual(installed) ||
                !ready.ProfileId.Equals(profile.Label, StringComparison.Ordinal))
                continue;
            matches.Add(new AutomaticRevertSnapshot(new AutomaticRevertPlan(
                SystemInfo.Sha256(original), installedHash, os.DllVersion,
                profile.Label, "ExactCatalog"), original));
        }
        // Multiple candidate originals must never be guessed between.
        return matches.Count == 1 ? matches[0] : null;
    }
}
