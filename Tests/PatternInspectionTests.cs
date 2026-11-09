using System.IO;
using System.Buffers.Binary;
using TermsrvPatcherUnified.Core;

internal static class PatternInspectionTests
{
    private static int checks;
    private static void Verify(bool condition, string message)
    {
        checks++;
        if (!condition) throw new InvalidOperationException("Pattern evidence QA: " + message);
    }

    private static byte[] SamplePe()
    {
        var bytes = new byte[0x600];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3C, 4), 0x80);
        new byte[] { (byte)'P', (byte)'E', 0, 0 }.CopyTo(bytes, 0x80);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x84, 2), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x86, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x94, 2), 0xF0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x96, 2), 0x2000);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x98, 2), 0x20B);
        int section = 0x80 + 24 + 0xF0;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(section + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(section + 20, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(section + 36, 4), 0x60000020);
        bytes.AsSpan(0x200, 0x200).Fill(0xFA);
        return bytes;
    }

    internal static int Run()
    {
        byte[] dll = SamplePe();
        new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(dll, 0x230);
        var named = PatchCatalog.Manual("11 22 33 44", "AA BB CC DD") with
        {
            Label = "Windows 11 26H2 (26300.9711)",
            Source = "Synthetic CI fixture"
        };
        var os = new WindowsDetails("Windows 11", "26H2", 26300, 9711, "Client",
            true, "synthetic.dll", "10.0.26100.8115");

        var knownCatalog = PatchCatalog.LoadAutomatic();
        Verify(knownCatalog.Count == 3 && knownCatalog.All(p =>
               p.Architecture == "x64" && p.Groups.Count == 1),
            "embedded automatic catalog has all three expected x64 groups");
        var expectedLengths = new[] { 12, 13, 19 };
        for (int i = 0; i < knownCatalog.Count; i++)
        {
            var group = knownCatalog[i].Groups.Single();
            Verify(group.Search.Length == expectedLengths[i] &&
                   group.Replace.Length == expectedLengths[i],
                "automatic Find and Replace byte lengths exactly agree for family " + (i + 1));
        }
        var displayedCatalog = SignatureInspector.Analyze(dll, knownCatalog);
        foreach (var row in displayedCatalog.Rows)
        {
            Verify(row.FindByteCount == row.ReplaceByteCount &&
                   row.AlignedFindHex.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                       .All(x => x.Length == 2) &&
                   row.AlignedPair.Contains("  Find:    ") &&
                   row.AlignedPair.Contains("  Replace: "),
                "every automatic group displays Find/Replace in aligned two-character cells");
        }
        Verify(knownCatalog[0].Groups[0].Search[7] == 0x84 &&
               displayedCatalog.Rows[0].AlignedFindHex.Contains("0F 84 ?? ?? ?? 00"),
            "the Generic opcode 84 is fixed, with exactly three variable displacement bytes");

        var validManual = ManualPatternValidator.Check("39 81 3C 06 00 00 0F 84 * * * 00",
            "B8 00 01 00 00 89 81 38 06 00 00 90");
        Verify(validManual.IsValid && validManual.GroupCount == 1 &&
               validManual.Message.Contains("12 Find/Replace byte pairs"),
            "valid Generic Find and Replace validate without a system operation");
        var unequalManual = ManualPatternValidator.Check("11 22 33 44",
            "AA BB CC");
        Verify(!unequalManual.IsValid &&
               unequalManual.Message.Contains("Find has 4 byte(s), Replace has 3"),
            "unequal Manual fields give precise lengths without throwing or logging an operation");
        Verify(!ManualPatternValidator.Check("11 22 33 44", "").IsValid &&
               !ManualPatternValidator.Check("", "AA BB CC DD").IsValid,
            "incomplete manual fields are handled by editor validation");
        Verify(!ManualPatternValidator.Check("11 22 33 44 | 55 66 77 88",
            "AA BB CC DD").IsValid,
            "manual group count mismatches are diagnosed");
        Verify(!ManualPatternValidator.Check("11 22 33 44", "AA BB ?? DD").IsValid,
            "manual Replace refuses wildcard bytes");

        var report = SignatureInspector.Analyze(dll, [named]);
        Verify(report.Rows.Count == 1, "each catalog group is visible");
        Verify(report.Rows[0].State == "Exact original match", "exact Find marked");
        Verify(report.Rows[0].FindOffsets == "0x00000230", "Find offset retained");
        Verify(report.Rows[0].ReplaceHits == "0", "absent Replace is explicit");
        Verify(report.AsText().Contains("Find:") && report.AsText().Contains("Replace:"),
            "actual Find and Replace signatures printed");

        byte[] replaced = (byte[])dll.Clone();
        new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }.CopyTo(replaced, 0x230);
        var after = SignatureInspector.Analyze(replaced, [named]).Rows.Single();
        Verify(after.State == "Exact replacement match", "Replace-only distinguished");
        Verify(after.ReplaceOffsets == "0x00000230", "Replace offset shown");

        byte[] collided = (byte[])dll.Clone();
        new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }.CopyTo(collided, 0x260);
        var conflict = SignatureInspector.Analyze(collided, [named]).Rows.Single();
        Verify(conflict.State.Contains("Conflict"), "simultaneous Find and Replace conflict shown");
        Verify(conflict.FindHits == "1" && conflict.ReplaceHits == "1", "both hits counted");

        byte[] duplicate = (byte[])dll.Clone();
        new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(duplicate, 0x260);
        var repeated = SignatureInspector.Analyze(duplicate, [named]).Rows.Single();
        Verify(repeated.State.Contains("repeated"), "repeated signature is ambiguous");
        Verify(repeated.FindHits == "2", "multiple offsets counted");

        // Reproduce the diagnostic shape of Windows 11 26H2 build 26300.9711:
        // an old generic mask and a longer 25H2/26H2 mask both match, but
        // at DIFFERENT offsets. The mismatch is between profiles, not inside
        // a single repeated signature. These are synthetic bytes only.
        byte[] crossBytes = (byte[])dll.Clone();
        new byte[] { 0x55, 0x66, 0x77, 0x88, 0x99 }.CopyTo(crossBytes, 0x290);
        var genericProfile = named with { Label = "Windows 10 / older generic family" };
        var specificProfile = PatchCatalog.Manual(
            "55 66 77 88 99", "90 91 92 93 94") with
            { Label = "Windows 11 25H2 / 26H2 alternate layout" };
        var missingProfile = PatchCatalog.Manual("C1 C2 C3 C4", "70 71 72 73") with
            { Label = "Windows 11 24H2 family" };
        PatchProfile[] catalog = [genericProfile, missingProfile, specificProfile];
        var crossReport = SignatureInspector.Analyze(crossBytes, catalog);
        Verify(crossReport.CompleteProfileCount == 2 &&
               crossReport.DistinctCandidateTargetCount == 2 &&
               crossReport.ConflictingProfileCount == 0,
            "two distinct full profile matches are not misclassified as duplicates within one profile");
        Verify(crossReport.AmbiguityReason.Contains("MULTIPLE DISTINCT") &&
               crossReport.Summary.Contains("0 conflicting profile(s)"),
            "exactly explain cross-profile ambiguity with zero within-profile collisions");
        Verify(crossReport.Profiles.Count == 3 &&
               crossReport.Profiles[0].Offsets == "0x00000230" &&
               crossReport.Profiles[1].Classification.Contains("Incomplete") &&
               crossReport.Profiles[2].Offsets == "0x00000290",
            "list each family and real byte offset, even for an absent family");
        Verify(crossReport.Profiles[2].FixedBytes > crossReport.Profiles[0].FixedBytes &&
               crossReport.AmbiguityReason.Contains("longer pattern alone is not sufficient"),
            "longer version-specific pattern is only a candidate, never an automatic selection");
        Verify(crossReport.AsText().Contains("Per-profile classification:") &&
               crossReport.AsText().Contains("0x00000290"),
            "read-only report shows individual profile evidence before group details");
        var automaticPlan = PatchCatalog.Inspect(crossBytes, "fake.dll", "10.0.26100.8115",
            SystemInfo.Sha256(crossBytes), true, catalog);
        Verify(automaticPlan.State == PatchState.Ambiguous &&
               automaticPlan.PatchedBytes is null && automaticPlan.Edits.Count == 0,
            "two independent exact patterns still block automatic modification");
        var repeatedReport = SignatureInspector.Analyze(duplicate, [named]);
        Verify(repeatedReport.DistinctCandidateTargetCount == 0 &&
               repeatedReport.ConflictingProfileCount == 1 &&
               repeatedReport.AmbiguityReason.Contains("WITHIN-PROFILE"),
            "repeated bytes inside one pattern are classified separately");
        var equivalentReport = SignatureInspector.Analyze(dll, [
            named, named with { Label = "second label, identical target" }
        ]);
        Verify(equivalentReport.CompleteProfileCount == 2 &&
               equivalentReport.DistinctCandidateTargetCount == 1 &&
               !equivalentReport.AmbiguityReason.Contains("MULTIPLE DISTINCT"),
            "two labels for identical byte edits are not falsely counted as independent targets");
        var checkedCrossPlan = new PatchPlan(PatchState.Ambiguous, "Two candidate families", "",
            "fake.dll", "10.0.26100.8115", SystemInfo.Sha256(crossBytes), [], null);
        var verifiedCross = VerifiedSignatureSnapshot.Capture(
            crossBytes, checkedCrossPlan, catalog);
        var exportedCross = SignatureEvidenceExport.Build(
            new WindowsDetails("Windows 11", "26H2", 26300, 9711,
                "Client", true, "fake.dll", "10.0.26100.8115"),
            checkedCrossPlan, verifiedCross);
        Verify(exportedCross.Contains("Distinct candidate target sets: 2") &&
               exportedCross.Contains("MULTIPLE DISTINCT") &&
               exportedCross.Contains("0x00000230") &&
               exportedCross.Contains("0x00000290"),
            "locally exported evidence explains two distinct exact locations");

        // Exact regression fixture for a reported Windows 11 26H2 pattern shape.
        // The bytes are synthetic, not a copy of the user's DLL. The embedded
        // catalog's generic and alternate-layout patterns occupy distinct
        // offsets, 0x6D20A and 0xA6896, exactly as reported by the operator.
        var upstream = PatchCatalog.LoadAutomatic();
        byte[] reportedShape = new byte[0xA6896 + 0x100];
        Array.Fill(reportedShape, (byte)0xFA);
        void AddOriginal(PatchProfile profile, int at)
        {
            var group = profile.Groups.Single();
            for (int i = 0; i < group.Search.Length; i++)
                reportedShape[at + i] = group.Search[i] ?? (byte)0x73;
        }
        AddOriginal(upstream[0], 0x6D20A);
        AddOriginal(upstream[2], 0xA6896);
        var reportedInspection = SignatureInspector.Analyze(reportedShape, upstream);
        Verify(reportedInspection.CompleteProfileCount == 2 &&
               reportedInspection.DistinctCandidateTargetCount == 2 &&
               reportedInspection.ConflictingProfileCount == 0,
            "reported 26H2 situation is two distinct exact profile matches, not duplicate bytes");
        Verify(reportedInspection.Rows[0].FindOffsets == "0x0006D20A" &&
               reportedInspection.Rows[1].State == "Not found" &&
               reportedInspection.Rows[2].FindOffsets == "0x000A6896",
            "the exact two reported candidate offsets and absent 24H2 pattern remain visible");
        Verify(reportedInspection.Profiles[0].FixedBytes == 9 &&
               reportedInspection.Profiles[2].FixedBytes == 19,
            "generic nine-fixed-byte mask and specific nineteen-fixed-byte mask are distinguished");
        var reportedPlan = PatchCatalog.Inspect(reportedShape, "synthetic.dll",
            "10.0.26100.8115", SystemInfo.Sha256(reportedShape), true, upstream);
        Verify(reportedPlan.State == PatchState.Ambiguous &&
               reportedPlan.Edits.Count == 0 &&
               reportedPlan.PatchedBytes is null,
            "reported signature combination must remain blocked from automatic Apply");
        // With trusted Windows 11 26H2 context, select the alternate-specific
        // pattern at the operator's original location. The generic is ignored.
        var resolvedReportPlan = PatchCatalog.Inspect(reportedShape, "synthetic.dll",
            "10.0.26100.8115", SystemInfo.Sha256(reportedShape), true, upstream,
            selectionContext: new AutomaticSelectionContext("Windows 11", "26H2", "Client"));
        Verify(resolvedReportPlan.State == PatchState.Ready &&
               resolvedReportPlan.Edits.Count == 1 &&
               resolvedReportPlan.Edits[0].Offset == 0xA6896,
            "on 26H2, two reported matching profiles resolve to specific-target preview");
        Verify(resolvedReportPlan.PatchedBytes is not null &&
               resolvedReportPlan.PatchedBytes.AsSpan(0x6D20A, 12).SequenceEqual(
                   reportedShape.AsSpan(0x6D20A, 12)),
            "the real-report generic-location bytes stay unchanged in the automatic preview");
        var afterReportedPreview = PatchCatalog.Inspect(
            resolvedReportPlan.PatchedBytes!, "synthetic.dll", "10.0.26100.8115",
            SystemInfo.Sha256(resolvedReportPlan.PatchedBytes!), true, upstream,
            selectionContext: new AutomaticSelectionContext("Windows 11", "26H2", "Client"));
        Verify(afterReportedPreview.State == PatchState.AlreadyPatched &&
               afterReportedPreview.Edits.Single().Offset == 0xA6896,
            "after selecting specific profile, original generic hit is not applied a second time");


        // Regression: old generic pattern accidentally treated opcode 84 as
        // a wildcard. JE/JZ near jump is 0F 84 followed by four rel32 bytes,
        // of which this catalog variant fixes only the final 00.
        var genericMask = upstream[0].Groups.Single().Search;
        Verify(genericMask.Length == 12 && genericMask[6] == 0x0F &&
               genericMask[7] == 0x84 && genericMask[8] is null &&
               genericMask[9] is null && genericMask[10] is null &&
               genericMask[11] == 0,
            "generic pattern fixes JE/JZ opcode 84 and only wildcards three displacement bytes");
        var genericFixture = Enumerable.Repeat((byte)0xFA, 128).ToArray();
        new byte[] { 0x39, 0x81, 0x3C, 0x06, 0, 0, 0x0F, 0x84,
                     0x12, 0x34, 0x56, 0 }.CopyTo(genericFixture, 20);
        Verify(BytePattern.FindOffsets(genericFixture, genericMask).SequenceEqual([20]),
            "generic JE/JZ mask finds a valid varying rel32 displacement");
        var wrongConditionalJump = (byte[])genericFixture.Clone();
        wrongConditionalJump[27] = 0x85; // JNE/JNZ differs from JE/JZ.
        Verify(BytePattern.FindOffsets(wrongConditionalJump, genericMask).Count == 0,
            "0F 85 no longer falsely matches the generic 0F 84 signature");
        var wrongDisplacementHigh = (byte[])genericFixture.Clone();
        wrongDisplacementHigh[31] = 0x20;
        Verify(BytePattern.FindOffsets(wrongDisplacementHigh, genericMask).Count == 0,
            "this catalog variant requires final displacement byte 00, not 20");

        // Trusted OS-aware automatic selection: a 26H2-specific exact match
        // wins over a separate older generic fallback, without editing both.
        // Use a valid synthetic PE with both signatures in an executable section.
        var selectionBytes = SamplePe();
        void PutOriginal(byte[] destination, PatchProfile rule, int offset)
        {
            var find = rule.Groups.Single().Search;
            for (int i = 0; i < find.Length; i++)
                destination[offset + i] = find[i] ?? (byte)0x34;
        }
        PutOriginal(selectionBytes, upstream[0], 0x230);
        PutOriginal(selectionBytes, upstream[2], 0x290);
        var context26 = new AutomaticSelectionContext("Windows 11", "26H2", "Client");
        var chosen = PatchCatalog.Inspect(selectionBytes, "test.dll", "10.0.26100.8115",
            SystemInfo.Sha256(selectionBytes), true, upstream,
            selectionContext: context26);
        Verify(chosen.State == PatchState.Ready &&
               chosen.Edits.Count == 1 && chosen.Edits[0].Offset == 0x290 &&
               chosen.ProfileId.Contains("25H2 / 26H2"),
            "26H2 specific exact signature wins over simultaneously matched generic fallback");
        Verify(chosen.PatchedBytes is not null &&
               chosen.PatchedBytes.AsSpan(0x230, 12).SequenceEqual(
                   selectionBytes.AsSpan(0x230, 12)) &&
               !chosen.PatchedBytes.AsSpan(0x290, 19).SequenceEqual(
                   selectionBytes.AsSpan(0x290, 19)),
            "selected preview patches only the specific target; generic bytes stay untouched");
        PeSafety.RequireExecutableEdits(selectionBytes, chosen.Edits);
        Verify(chosen.Description.Contains("specific profile over") &&
               !chosen.IsManual, "automatic profile priority is explicit in result details");

        var afterSpecific = PatchCatalog.Inspect(chosen.PatchedBytes!, "test.dll",
            "10.0.26100.8115", SystemInfo.Sha256(chosen.PatchedBytes!), true, upstream,
            selectionContext: context26);
        Verify(afterSpecific.State == PatchState.AlreadyPatched &&
               afterSpecific.Edits.Count == 1 &&
               afterSpecific.Edits[0].Offset == 0x290,
            "after a specific-profile replacement, generic original hit is not patched again");

        var unknownContext = new AutomaticSelectionContext("Windows 11", "27H2", "Client");
        var unknownChoice = PatchCatalog.Inspect(selectionBytes, "test.dll",
            "10.0.26100.8115", SystemInfo.Sha256(selectionBytes), true, upstream,
            selectionContext: unknownContext);
        Verify(unknownChoice.State == PatchState.Ambiguous &&
               unknownChoice.PatchedBytes is null && unknownChoice.Edits.Count == 0,
            "unrecognized Windows version does not guess a specific-profile priority");
        var offlineChoice = PatchCatalog.Inspect(selectionBytes, "test.dll",
            "10.0.26100.8115", SystemInfo.Sha256(selectionBytes), true, upstream);
        Verify(offlineChoice.State == PatchState.Ambiguous,
            "offline DLL without a matching installed-OS context remains ambiguous");
        var manualChoice = PatchCatalog.Inspect(selectionBytes, "test.dll",
            "10.0.26100.8115", SystemInfo.Sha256(selectionBytes), true, upstream,
            manual: true, selectionContext: context26);
        Verify(manualChoice.State == PatchState.Ambiguous,
            "manual mode never inherits automatic selection precedence");

        var onlyGeneric = (byte[])selectionBytes.Clone();
        upstream[2].Groups.Single().Search
            .Select((x, i) => i).ToList()
            .ForEach(i => onlyGeneric[0x290 + i] = 0xFA);
        var genericChoice = PatchCatalog.Inspect(onlyGeneric, "test.dll",
            "10.0.26100.8115", SystemInfo.Sha256(onlyGeneric), true, upstream,
            selectionContext: context26);
        Verify(genericChoice.State == PatchState.Ready &&
               genericChoice.Edits.Single().Offset == 0x230,
            "a single verified generic candidate remains eligible when specific does not match");
        var fakeRules = new[]
        {
            upstream[0],
            new PatchProfile(upstream[2].Label, "x64", upstream[2].Groups,
                "Imported manual file")
        };
        var untrustedChoice = PatchCatalog.Inspect(selectionBytes, "test.dll",
            "10.0.26100.8115", SystemInfo.Sha256(selectionBytes), true, fakeRules,
            selectionContext: context26);
        Verify(untrustedChoice.State == PatchState.Ambiguous &&
               untrustedChoice.PatchedBytes is null,
            "imported labels cannot impersonate the trusted embedded specific profile");

        var fragment = ManualFragmentSearch.SearchBytes(dll, "1122");
        Verify(fragment.Hits.Count == 1 && fragment.Hits[0].Offset == 0x230,
            "two-byte compact HEX fragment found");
        Verify(fragment.Hits[0].ActualHex == "11 22", "actual bytes printed");
        Verify(fragment.Hits[0].Context.Contains("[11 22]"), "surrounding bytes printed");
        var fullWildcard = new BytePattern("11 ?? 33 44", "AA BB CC DD");
        Verify(BytePattern.FindOffsets(dll, fullWildcard.Search).Single() == 0x230,
            "manual full Find and incremental viewer both support ?? as one-byte wildcard");
        var wildcard = ManualFragmentSearch.SearchBytes(dll, "11 ?? 33");
        Verify(wildcard.Hits.Count == 1 && wildcard.Hits[0].ActualHex == "11 22 33",
            "wildcard reveals actual unknown byte");
        var typing = ManualFragmentSearch.SearchBytes(dll, "11 22 3");
        Verify(typing.Hits.Count == 1 && typing.Summary.Contains("incomplete nibble"),
            "partial entry works without guessing the unfinished byte");
        var frequent = ManualFragmentSearch.SearchBytes(dll, "FA FA");
        Verify(frequent.Hits.Count == ManualFragmentSearch.MaximumShown &&
            frequent.Summary.Contains("showing the first"), "broad output is capped");
        Verify(ManualFragmentSearch.SearchBytes(dll, "* *").Hits.Count == 0,
            "all-wildcard preview suppressed");
        Verify(ManualFragmentSearch.SearchBytes(dll, "11").Hits.Count == 0,
            "single-byte preview suppressed");
        bool badFormat = false;
        try { ManualFragmentSearch.SearchBytes(dll, "GG 33"); }
        catch (FormatException) { badFormat = true; }
        Verify(badFormat, "malformed HEX is not interpreted as a partial match");

        var hexFrame = HexViewport.Build(dll, 0x230, 4, [1, 3]);
        Verify(hexFrame.Rows.Count > 1 && hexFrame.HighlightedCount == 4,
            "selected pattern is displayed in bounded 16-column HEX lines");
        var marked = hexFrame.Rows.SelectMany(row => row.Bytes)
            .Where(cell => cell.Highlight != HexByteHighlight.None).ToArray();
        Verify(marked.Select(cell => cell.Offset).SequenceEqual(
            new[] { 0x230, 0x231, 0x232, 0x233 }),
            "actual byte offsets, not row-relative positions, are highlighted");
        Verify(marked[0].IsFixedMatch && marked[1].IsWildcardMatch &&
            marked[2].IsFixedMatch && marked[3].IsWildcardMatch,
            "wildcard bytes highlighted differently from fixed mask bytes");
        Verify(hexFrame.AsText().Contains("ADDRESS") &&
            hexFrame.AsText().Contains("11 22 33 44"),
            "human-readable HEX viewer includes addresses and real bytes");
        var crossRow = HexViewport.Build(dll, 0x23F, 4, [1]);
        Verify(crossRow.HighlightedCount == 4 &&
            crossRow.Rows.SelectMany(row => row.Bytes).Count(c => c.IsWildcardMatch) == 1,
            "selection crossing a 16-byte boundary remains highlighted");
        var edge = HexViewport.Build(new byte[35], 34, 1, rowsBefore: 0, rowsAfter: 0);
        Verify(edge.Rows.Count == 1 && edge.Rows.Single().Bytes.Count == 3,
            "end-of-file partial row never reads beyond the file");
        bool refused = false;
        try { HexViewport.Build(dll, dll.Length - 1, 4); }
        catch (ArgumentOutOfRangeException) { refused = true; }
        Verify(refused, "out-of-bounds match selection is rejected");
        refused = false;
        try { HexViewport.Build(dll, 0x230, 4, [4]); }
        catch (ArgumentOutOfRangeException) { refused = true; }
        Verify(refused, "out-of-bounds wildcard selection is rejected");
        var actualWildcard = ManualFragmentSearch.SearchBytes(dll, "11 ?? 33").Hits.Single();
        Verify(actualWildcard.Length == 3 &&
            actualWildcard.MaskHex == "11 ?? 33" &&
            actualWildcard.WildcardPositions.SequenceEqual([1]),
            "manual Find mask keeps wildcard positions and actual-byte length");
        Verify(actualWildcard.Address == "0x00000230", "manual matched offset has HEX address");

        var imported = ImportedCatalogInspector.Inspect(dll, os.DllVersion, os, [named]);
        Verify(imported.Results.Count == 1 && imported.ExactMatches == 1,
            "all-import scan enumerates the exact matching entry");
        Verify(imported.SuggestedIndex == 0,
            "unique valid match and compatible OS is suggested, but never applied");
        Verify(imported.Results[0].WindowsHint.StartsWith("Match:") &&
            imported.Results[0].OsBuildHint.StartsWith("Match:"),
            "Windows release and OS build hints shown");
        Verify(imported.Results[0].DllVersionHint.StartsWith("Different:"),
            "Windows build and DLL build are compared separately");
        Verify(imported.Results[0].Offsets.Contains("0x00000230"),
            "imported exact match offset visible");

        var wrongOs = named with { Label = "Windows 10 22H2 (19045.1111)" };
        var mismatched = ImportedCatalogInspector.Inspect(dll, os.DllVersion, os, [wrongOs]);
        Verify(mismatched.ExactMatches == 1 && mismatched.SuggestedIndex is null,
            "mismatched OS hints prevent automatic suggestion despite byte match");
        var versionOnly = named with
        {
            Groups = [new BytePattern("51 52 53 54", "DE AD BE EF")]
        };
        var noBytes = ImportedCatalogInspector.Inspect(dll, os.DllVersion, os, [versionOnly]);
        Verify(noBytes.VersionHintMatches == 1 && noBytes.SuggestedIndex is null,
            "matching version without matching bytes never authorizes a patch");
        var duplicated = ImportedCatalogInspector.Inspect(dll, os.DllVersion, os, [named, named]);
        Verify(duplicated.ExactMatches == 2 && duplicated.SuggestedIndex is null,
            "two exact profiles are not auto-selected");
        var badPe = new byte[dll.Length];
        new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(badPe, 0x230);
        var unsupported = ImportedCatalogInspector.Inspect(badPe, os.DllVersion, os, [named]);
        Verify(unsupported.ExactMatches == 0 && unsupported.SuggestedIndex is null,
            "matching bytes in malformed PE cannot suggest Apply");
        // Snapshot and export must be bound to the *same* file hash as
        // the engine's preview. These tests never modify a real Windows DLL.
        var originalHash = SystemInfo.Sha256(dll);
        var evidencePlan = new PatchPlan(PatchState.Ambiguous, "conflicting signatures", "",
            @"C:\Users\SensitiveUser\termsrv.dll", os.DllVersion, originalHash, [], null);
        var evidence = VerifiedSignatureSnapshot.Capture(dll, evidencePlan, [named]);
        Verify(evidence.Sha256 == originalHash, "captured evidence matches plan hash");
        Verify(evidence.Inspection.Rows.Count == 1 &&
            evidence.Inspection.Rows[0].FindOffsets == "0x00000230",
            "captured profile and offsets originate from verified bytes");

        var reportText = SignatureEvidenceExport.Build(os, evidencePlan, evidence);
        Verify(reportText.StartsWith("termsrv-signature-evidence/v1", StringComparison.Ordinal),
            "report has a versioned read-only schema");
        Verify(reportText.Contains("Automatic result: Ambiguous") &&
               reportText.Contains("Find mask: 11 22 33 44") &&
               reportText.Contains("Replace signature: AA BB CC DD"),
            "report shows the exact catalog signatures and status");
        Verify(reportText.Contains("0x00000230") && reportText.Contains(originalHash),
            "report includes bound hash and matching offset");
        Verify(!reportText.Contains(@"C:\Users\SensitiveUser", StringComparison.Ordinal) &&
               !reportText.Contains("SensitiveUser", StringComparison.Ordinal),
            "report excludes the absolute DLL path and user profile");
        Verify(!reportText.Contains("localhost", StringComparison.OrdinalIgnoreCase),
            "report excludes host identity");

        var tamperedPlan = evidencePlan with { OriginalSha256 = new string('a', 64) };
        bool mismatchRejected = false;
        try { VerifiedSignatureSnapshot.Capture(dll, tamperedPlan, [named]); }
        catch (InvalidOperationException) { mismatchRejected = true; }
        Verify(mismatchRejected, "mismatched engine preview and second file read are rejected");

        bool corruptRejected = false;
        evidence.Bytes[0x230] ^= 0x01;
        try { SignatureEvidenceExport.Build(os, evidencePlan, evidence); }
        catch (InvalidDataException) { corruptRejected = true; }
        Verify(corruptRejected, "report refuses mutated cached evidence");
        evidence.Bytes[0x230] ^= 0x01;

        string testRoot = Path.Combine(Path.GetTempPath(),
            "termsrv-evidence-qa-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testRoot);
        try
        {
            string sampleFile = Path.Combine(testRoot, "mock-termsrv.dll");
            File.WriteAllBytes(sampleFile, dll);
            evidence.RequireCurrentFile(sampleFile);
            Verify(File.ReadAllBytes(sampleFile).SequenceEqual(dll),
                "read-only snapshot inspection never writes the source");
            var alternative = (byte[])dll.Clone();
            alternative[0x230] ^= 0x01;
            File.WriteAllBytes(sampleFile, alternative);
            bool staleRejected = false;
            try { evidence.RequireCurrentFile(sampleFile); }
            catch (InvalidOperationException) { staleRejected = true; }
            Verify(staleRejected, "file change after preview disables evidence reuse");

            string savedFile = Path.Combine(testRoot, "evidence.txt");
            SignatureEvidenceExport.SaveNew(reportText, savedFile);
            Verify(File.ReadAllText(savedFile).Contains(originalHash),
                "explicit local text export preserves report");
            bool overwriteRejected = false;
            try { SignatureEvidenceExport.SaveNew(reportText, savedFile); }
            catch (IOException) { overwriteRejected = true; }
            Verify(overwriteRejected, "export never overwrites an existing report");
            bool extensionRejected = false;
            try
            {
                SignatureEvidenceExport.SaveNew(reportText,
                    Path.Combine(testRoot, "evidence.dll"));
            }
            catch (ArgumentException) { extensionRejected = true; }
            Verify(extensionRejected, "export rejects a target DLL extension");
        }
        finally
        {
            Directory.Delete(testRoot, recursive: true);
        }

        var untrustedNamed = named with
        {
            Label = @"Windows 11 C:\Users\SensitiveUser\termsrv.dll"
        };
        var untrustedEvidence = VerifiedSignatureSnapshot.Capture(
            dll, evidencePlan, [untrustedNamed]);
        var sanitizedReport = SignatureEvidenceExport.Build(
            os, evidencePlan, untrustedEvidence);
        Verify(!sanitizedReport.Contains("SensitiveUser") &&
               sanitizedReport.Contains("Group 1: (unavailable)"),
            "unsafe catalog labels are redacted before report export");

        Console.WriteLine("PASS: " + checks +
            " read-only signature, partial HEX, OS/DLL version and Check all imported assertions.");
        return checks;
    }
}
