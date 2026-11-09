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
