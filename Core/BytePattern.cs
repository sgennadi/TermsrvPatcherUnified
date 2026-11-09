namespace TermsrvPatcherUnified.Core;

// Pure byte signatures. A '*' in a find pattern means exactly one arbitrary byte.
public sealed class BytePattern
{
    public byte?[] Search { get; }
    public byte[] Replace { get; }

    public BytePattern(string find, string replace)
    {
        Search = ParseFind(find);
        Replace = ParseReplace(replace);
        if (Search.Length < 4 || Search.Length != Replace.Length)
            throw new ArgumentException("Find and replace must contain the same number of bytes (at least four).");
        if (Search.All(x => !x.HasValue))
            throw new ArgumentException("An all-wildcard search pattern is not allowed.");
    }

    public static byte?[] ParseFind(string text)
    {
        var tokens = Tokens(text);
        if (tokens.Length < 1) throw new FormatException("Search pattern cannot be empty.");
        try { return tokens.Select(t => t is "*" or "??" ? (byte?)null : ParseHexByte(t)).ToArray(); }
        catch (Exception e) when (e is FormatException or OverflowException)
        { throw new FormatException("Search must be hexadecimal bytes separated by spaces, or '*' / '??' for one byte.", e); }
    }

    public static byte[] ParseReplace(string text)
    {
        try { return Tokens(text).Select(ParseHexByte).ToArray(); }
        catch (Exception e) when (e is FormatException or OverflowException)
        { throw new FormatException("Replacement must contain hexadecimal bytes only.", e); }
    }

    private static string[] Tokens(string text) => text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

    private static byte ParseHexByte(string token)
    {
        if (token.Length != 2 || !Uri.IsHexDigit(token[0]) || !Uri.IsHexDigit(token[1]))
            throw new FormatException($"Invalid hexadecimal byte '{token}'. Use exactly two hex digits.");
        return Convert.ToByte(token, 16);
    }

    public static IReadOnlyList<int> FindOffsets(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte?> pattern, int maxResults = 2)
    {
        var hits = new List<int>();
        if (pattern.Length == 0 || bytes.Length < pattern.Length || maxResults <= 0) return hits;
        int anchor = 0;
        while (anchor < pattern.Length && !pattern[anchor].HasValue) anchor++;
        if (anchor == pattern.Length) return hits;
        var end = bytes.Length - pattern.Length;
        for (int offset = 0; offset <= end; offset++)
        {
            if (bytes[offset + anchor] != pattern[anchor]!.Value) continue;
            int i;
            for (i = 0; i < pattern.Length; i++)
                if (pattern[i].HasValue && bytes[offset + i] != pattern[i]!.Value) break;
            if (i == pattern.Length)
            {
                hits.Add(offset);
                if (hits.Count >= maxResults) break;
            }
        }
        return hits;
    }

    public static IReadOnlyList<int> FindOffsets(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> pattern, int maxResults = 2)
    {
        var hits = new List<int>();
        if (pattern.Length == 0 || bytes.Length < pattern.Length || maxResults <= 0) return hits;
        int from = 0;
        while (from <= bytes.Length - pattern.Length)
        {
            int found = bytes[from..].IndexOf(pattern);
            if (found < 0) break;
            var absolute = from + found;
            hits.Add(absolute);
            if (hits.Count >= maxResults) break;
            from = absolute + 1;
        }
        return hits;
    }
}
