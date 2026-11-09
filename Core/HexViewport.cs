namespace TermsrvPatcherUnified.Core;

/// <summary>
/// A bounded, read-only 16-byte-wide memory view for a selected pattern hit.
/// Built from the same inspected DLL snapshot that produced the search result.
/// No disassembly, executable loading, file writes or replacement inference.
/// </summary>
public enum HexByteHighlight { None, FixedMatch, WildcardMatch }

public sealed record HexViewportByte(
    int Offset, string Hex, char Ascii, HexByteHighlight Highlight)
{
    public bool IsFixedMatch => Highlight == HexByteHighlight.FixedMatch;
    public bool IsWildcardMatch => Highlight == HexByteHighlight.WildcardMatch;
}

public sealed record HexViewportRow(
    string Address, IReadOnlyList<HexViewportByte> Bytes);

public sealed record HexViewportFrame(
    int Offset, int Length, IReadOnlyList<HexViewportRow> Rows)
{
    public int HighlightedCount => Rows.Sum(row => row.Bytes.Count(x =>
        x.Highlight is not HexByteHighlight.None));

    public string AsText()
    {
        var result = new System.Text.StringBuilder();
        result.AppendLine("ADDRESS     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | DUMP");
        foreach (var row in Rows)
        {
            result.Append(row.Address).Append("  ");
            for (int i = 0; i < 16; i++)
                result.Append(i < row.Bytes.Count ? row.Bytes[i].Hex : "  ").Append(' ');
            result.Append("| ");
            foreach (var item in row.Bytes) result.Append(item.Ascii);
            result.AppendLine();
        }
        return result.ToString();
    }
}

public static class HexViewport
{
    public const int BytesPerRow = 16;
    public const int DefaultRowsBefore = 9;
    public const int DefaultRowsAfter = 12;
    public const int MaxRows = 65;

    public static HexViewportFrame Build(ReadOnlySpan<byte> data, int offset, int length,
        IReadOnlyList<int>? wildcardIndices = null, int rowsBefore = DefaultRowsBefore,
        int rowsAfter = DefaultRowsAfter)
    {
        if (data.IsEmpty || offset < 0 || length < 1 ||
            (long)offset + length > data.Length)
            throw new ArgumentOutOfRangeException(nameof(offset), "Selected match must fit the DLL snapshot.");
        if (rowsBefore < 0 || rowsAfter < 0 || rowsBefore + rowsAfter + 1 > MaxRows)
            throw new ArgumentOutOfRangeException(nameof(rowsBefore),
                "HEX viewport must remain small and responsive.");

        HashSet<int> wildcards = wildcardIndices is null ? [] : new(wildcardIndices);
        if (wildcards.Any(i => i < 0 || i >= length))
            throw new ArgumentOutOfRangeException(nameof(wildcardIndices));
        int selectedRow = offset / BytesPerRow;
        int last = (data.Length - 1) / BytesPerRow;
        int firstRow = Math.Max(0, selectedRow - rowsBefore);
        int lastRow = Math.Min(last,
            Math.Max(selectedRow + rowsAfter,
                (offset + length - 1) / BytesPerRow));
        // A 96-byte Find may cross several lines; keep the full highlight in view.
        if (lastRow - firstRow + 1 > MaxRows)
            lastRow = firstRow + MaxRows - 1;

        var lines = new List<HexViewportRow>(lastRow - firstRow + 1);
        for (int row = firstRow; row <= lastRow; row++)
        {
            int start = row * BytesPerRow;
            int count = Math.Min(BytesPerRow, data.Length - start);
            var cells = new HexViewportByte[count];
            for (int index = 0; index < count; index++)
            {
                int absolute = start + index;
                byte value = data[absolute];
                int relative = absolute - offset;
                HexByteHighlight highlight = relative is >= 0 && relative < length
                    ? wildcards.Contains(relative) ? HexByteHighlight.WildcardMatch :
                        HexByteHighlight.FixedMatch : HexByteHighlight.None;
                cells[index] = new(absolute, value.ToString("X2"),
                    value is >= 32 and <= 126 ? (char)value : '.',
                    highlight);
            }
            lines.Add(new HexViewportRow(start.ToString("X8"), cells));
        }
        return new HexViewportFrame(offset, length, lines);
    }
}
