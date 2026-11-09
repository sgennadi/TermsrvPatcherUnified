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
        Console.WriteLine("PASS: " + checks +
            " read-only signature, partial HEX, OS/DLL version and Check all imported assertions.");
        return checks;
    }
}
