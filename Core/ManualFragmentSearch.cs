using System.Text;

namespace TermsrvPatcherUnified.Core;

public sealed record ManualFragmentHit(
    int Group, int Offset, string ActualHex, string Context,
    int Length, string MaskHex, IReadOnlyList<int> WildcardPositions)
{
    public string Address => "0x" + Offset.ToString("X8");
}

public sealed record ManualFragmentReport(
    IReadOnlyList<ManualFragmentHit> Hits, string Summary)
{
    public string AsText()
    {
        var b = new StringBuilder();
        b.AppendLine("Manual fragment lookup — READ ONLY");
        b.AppendLine(Summary);
        foreach (var hit in Hits)
        {
            b.AppendLine("Group " + hit.Group + ", offset 0x" + hit.Offset.ToString("X8") +
                         ", actual " + hit.ActualHex);
            b.AppendLine("  " + hit.Context);
        }
        b.AppendLine("No replacement is inferred, proposed or applied.");
        return b.ToString();
    }
}

public sealed record ManualFragmentSnapshot(
    byte[] Bytes, ManualFragmentReport Report);

/// <summary>
/// Read-only incremental Find-field lookup. Accepts short or compact partial HEX;
/// a trailing incomplete nibble is ignored until it forms a complete byte.
/// This path is deliberately separate from verified manual Apply.
/// </summary>
public static class ManualFragmentSearch
{
    public const int MaximumShown = 24;
    private const int MaximumInputChars = 2048;
    private const int MaximumPatternBytes = 96;
    private const long MaximumFileSize = 64L * 1024 * 1024;

    private sealed record Query(int GroupNumber, byte?[] Bytes, bool Incomplete);

    public static ManualFragmentReport SearchFile(string path, string input)
        => SearchFileSnapshot(path, input).Report;

    public static ManualFragmentSnapshot SearchFileSnapshot(string path, string input)
    {
        var queries = Parse(input);
        if (queries.Count == 0)
            return new([], new([], "Enter two or more complete fixed HEX bytes, e.g. 44 8B."));
        if (queries.All(q => q.Bytes.Count(x => x.HasValue) < 2))
            return new([], new([], "Enter at least two complete fixed bytes. " +
                "A one-byte or all-wildcard pattern is too broad for live lookup."));
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("The inspected DLL is not available.");
        if (info.Length is < 1 or > MaximumFileSize)
            throw new InvalidDataException("Selected file size is outside the read-only 64 MB limit.");
        byte[] bytes = File.ReadAllBytes(path);
        return new(bytes, SearchBytes(bytes, input, queries));
    }

    public static ManualFragmentReport SearchBytes(byte[] file, string input)
    {
        ArgumentNullException.ThrowIfNull(file);
        return SearchBytes(file, input, Parse(input));
    }

    private static ManualFragmentReport SearchBytes(byte[] file, string input,
        IReadOnlyList<Query> queries)
    {
        if (queries.Count == 0)
            return new([], "Type two or more complete HEX bytes to see matching actual DLL bytes.");
        var hits = new List<ManualFragmentHit>(MaximumShown);
        int skippedGroups = 0;
        bool truncated = false;
        bool unfinished = queries.Any(q => q.Incomplete);
        foreach (var query in queries)
        {
            // The live preview is intentionally more permissive than a patch signature,
            // but it refuses overly broad one-byte or wildcard-only searches.
            if (query.Bytes.Count(x => x.HasValue) < 2)
            {
                skippedGroups++;
                continue;
            }
            int remaining = MaximumShown - hits.Count;
            if (remaining <= 0)
            {
                truncated = true;
                break;
            }
            var offsets = BytePattern.FindOffsets(file, query.Bytes, remaining + 1);
            if (offsets.Count > remaining) truncated = true;
            foreach (int offset in offsets.Take(remaining))
            {
                int size = query.Bytes.Length;
                int left = Math.Max(0, offset - 12);
                int end = Math.Min(file.Length, offset + size + 12);
                var actual = file.AsSpan(offset, size);
                var before = file.AsSpan(left, offset - left);
                var after = file.AsSpan(offset + size, end - offset - size);
                hits.Add(new ManualFragmentHit(query.GroupNumber, offset,
                    Spaced(actual), Spaced(before) + " [" + Spaced(actual) + "] " + Spaced(after),
                    size,
                    string.Join(" ", query.Bytes.Select(x => x.HasValue ? x.Value.ToString("X2") : "??")),
                    query.Bytes.Select((x, i) => x.HasValue ? -1 : i)
                        .Where(x => x >= 0).ToArray()));
            }
        }
        string count = truncated ? "At least " + (hits.Count + 1) : hits.Count.ToString();
        string summary = count + " matching location(s)" +
            (truncated ? " (showing the first " + MaximumShown + ")" : "") +
            ". Actual file bytes are shown in brackets; '??' / '*' stand for any one byte." +
            (unfinished ? " Trailing incomplete nibble ignored while typing." : "") +
            (skippedGroups > 0 ? " " + skippedGroups + " broad/unfinished group(s) omitted." : "") +
            " This is a read-only suggestion; Check manual pattern is still required.";
        return new(hits, summary);
    }

    private static List<Query> Parse(string input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (input.Length > MaximumInputChars)
            throw new FormatException("HEX input is too long for an interactive lookup.");
        var parts = input.Split('|');
        if (parts.Length > 8)
            throw new FormatException("Live lookup supports at most eight Find groups.");
        var result = new List<Query>();
        for (int group = 0; group < parts.Length; group++)
        {
            var bytes = new List<byte?>();
            bool incomplete = false;
            var tokens = parts[group].Split(
                [' ', '\t', '\r', '\n', ',', '-', ';', ':'],
                StringSplitOptions.RemoveEmptyEntries);
            foreach (var token in tokens)
            {
                if (token is "*" or "??")
                {
                    bytes.Add(null);
                    continue;
                }
                if (token.Length > 2 * MaximumPatternBytes ||
                    token.Any(c => !Uri.IsHexDigit(c)))
                    throw new FormatException("Find must contain hexadecimal pairs, * or ??. " +
                        "Use complete bytes (e.g. 8B 81), not half-byte wildcards.");
                for (int n = 0; n + 1 < token.Length; n += 2)
                    bytes.Add(Convert.ToByte(token.Substring(n, 2), 16));
                if (token.Length % 2 != 0)
                    incomplete = true;
                if (bytes.Count > MaximumPatternBytes)
                    throw new FormatException("Each interactive Find group may contain at most 96 bytes.");
            }
            if (bytes.Count > 0 || incomplete)
                result.Add(new Query(group + 1, bytes.ToArray(), incomplete));
        }
        return result;
    }

    private static string Spaced(ReadOnlySpan<byte> span)
        => string.Join(" ", Convert.ToHexString(span).Chunk(2)
            .Select(two => new string(two)));
}
