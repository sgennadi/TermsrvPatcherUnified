using System.Diagnostics;
using System.Text;

namespace TermsrvPatcherUnified.Core;

public sealed record ScanHit(string Kind, int Offset, string Context);
public sealed record ScanReport(string FileName, string FileVersion, string Sha256,
    PatchState AutomaticState, string AutomaticProfile, IReadOnlyList<ScanHit> Hits,
    IReadOnlyList<SimilarSignature> Similar, string Explanation)
{
    public string AsText()
    {
        var s = new StringBuilder();
        s.AppendLine("TermsrvPatcher Unified - read-only DLL inspection");
        s.AppendLine($"Name: {FileName}");
        s.AppendLine($"File version: {FileVersion}");
        s.AppendLine($"SHA-256: {Sha256}");
        s.AppendLine($"Automatic status: {AutomaticState}");
        s.AppendLine($"Matched profile: {AutomaticProfile}");
        s.AppendLine(Explanation);
        if (Similar.Count > 0)
        {
            s.AppendLine("Near matches (READ-ONLY; not validated patches):");
            foreach (var similar in Similar)
                s.AppendLine($"  0x{similar.Offset:X8}  {similar.Profile}, group {similar.GroupNumber}: " +
                    $"{similar.MatchedBytes}/{similar.FixedBytes} fixed bytes match; " +
                    $"different pattern indexes [{string.Join(", ", similar.DifferentByteIndexes)}]");
        }
        foreach (var hit in Hits)
            s.AppendLine($"{hit.Kind} at 0x{hit.Offset:X8}: {hit.Context}");
        s.AppendLine("Candidate offsets are informational only; no patch bytes have been generated.");
        return s.ToString();
    }
}

public static class DllScanner
{
    private static readonly (string Name, string Signature)[] Markers = [
        ("Legacy compare", "39 81 3C 06 00 00 0F"),
        ("24H2 compare", "8B 81 38 06 00 00 39 81"),
        ("Alternate layout", "44 8B 87 3C 06 00 00 44"),
        ("Counter reference", "38 06 00 00"),
    ];

    public static ScanReport Scan(string path, string? userSignature)
    {
        var dll = File.ReadAllBytes(path);
        var hash = SystemInfo.Sha256(dll);
        string version = FileVersionInfo.GetVersionInfo(path).FileVersion ?? "Unknown";
        var automatic = PatchCatalog.Inspect(dll, path, version, hash, true,
            PatchCatalog.LoadAutomatic());
        var hits = new List<ScanHit>();
        IReadOnlyList<SimilarSignature> similar = automatic.State is PatchState.Unknown or PatchState.Ambiguous
            ? NearMatchFinder.Find(dll, PatchCatalog.LoadAutomatic())
            : Array.Empty<SimilarSignature>();
        foreach (var (name, signature) in Markers)
        {
            var parsed = BytePattern.ParseFind(signature);
            foreach (int offset in BytePattern.FindOffsets(dll, parsed, maxResults: 12))
                hits.Add(new ScanHit(name, offset, Context(dll, offset, parsed.Length)));
        }
        if (!string.IsNullOrWhiteSpace(userSignature))
        {
            var parsed = BytePattern.ParseFind(userSignature);
            if (parsed.Length < 4 || parsed.All(x => !x.HasValue))
                throw new FormatException("Search requires at least four tokens and one fixed hexadecimal byte.");
            foreach (int offset in BytePattern.FindOffsets(dll, parsed, maxResults: 128))
                hits.Add(new ScanHit("Manual search", offset, Context(dll, offset, parsed.Length)));
        }
        var explanation = automatic.State is PatchState.Unknown or PatchState.Ambiguous
            ? "No uniquely verified automatic match. Nearby byte sequences are hints, not safe replacement instructions."
            : "Automatic inspection completed. The listed offsets remain informational.";
        return new ScanReport(Path.GetFileName(path), version, hash, automatic.State,
            automatic.ProfileId, hits, similar, explanation);
    }

    private static string Context(byte[] dll, int offset, int length)
    {
        int start = Math.Max(0, offset - 16);
        int end = Math.Min(dll.Length, offset + length + 16);
        string left = Convert.ToHexString(dll.AsSpan(start, offset - start));
        string center = Convert.ToHexString(dll.AsSpan(offset, length));
        string right = Convert.ToHexString(dll.AsSpan(offset + length, end - offset - length));
        return $"{Spaced(left)} [{Spaced(center)}] {Spaced(right)}".Trim();
    }

    private static string Spaced(string hex) =>
        string.Join(" ", Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2)));
}
