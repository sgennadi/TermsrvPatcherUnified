using System.Buffers.Binary;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Strict executable-section bounds validation. Protected system operations
/// remain AMD64-only; offline file inspection supports both PE32/x86 and
/// PE32+/AMD64 without executing or loading the candidate DLL.
/// </summary>
public static class PeSafety
{
    public sealed record Section(int Start, int Length, bool Executable);
    public sealed record DllLayout(string Architecture, IReadOnlyList<Section> Sections);

    public static IReadOnlyList<Section> ReadAmd64DllSections(ReadOnlySpan<byte> file)
    {
        var layout = ReadOfflineDllSections(file);
        if (layout.Architecture != "x64")
            throw new InvalidDataException("Protected system DLL operations require AMD64.");
        return layout.Sections;
    }

    public static DllLayout ReadOfflineDllSections(ReadOnlySpan<byte> file)
    {
        if (file.Length < 0x100 || file[0] != (byte)'M' || file[1] != (byte)'Z')
            throw new InvalidDataException("Not a valid PE file: missing DOS header.");
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(file.Slice(0x3C, 4));
        if (peOffset < 0x40 || (long)peOffset + 26 > file.Length ||
            !file.Slice(peOffset, 4).SequenceEqual(new byte[] { (byte)'P', (byte)'E', 0, 0 }))
            throw new InvalidDataException("Not a valid PE file: invalid PE header offset or signature.");
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 4, 2));
        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 6, 2));
        ushort optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 20, 2));
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 22, 2));
        string architecture = machine switch
        {
            0x8664 => "x64",
            0x014c => "x86",
            _ => throw new InvalidDataException("Only PE32 x86 or PE32+ AMD64 DLLs may be inspected.")
        };
        if ((characteristics & 0x2000) == 0)
            throw new InvalidDataException("Selected PE file is not marked as a DLL.");
        if (sectionCount is 0 or > 96 || optionalSize < 2 ||
            (long)peOffset + 24 + optionalSize + sectionCount * 40L > file.Length)
            throw new InvalidDataException("PE section table is invalid or truncated.");
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 24, 2));
        if (magic != (architecture == "x64" ? 0x20B : 0x10B))
            throw new InvalidDataException("PE optional-header type does not match machine architecture.");
        int sectionOffset = peOffset + 24 + optionalSize;
        var sections = new List<Section>();
        for (int index = 0; index < sectionCount; index++)
        {
            int at = sectionOffset + index * 40;
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(file.Slice(at + 16, 4));
            uint start = BinaryPrimitives.ReadUInt32LittleEndian(file.Slice(at + 20, 4));
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(file.Slice(at + 36, 4));
            if (size == 0) continue;
            if (start > file.Length || (ulong)start + size > (ulong)file.Length)
                throw new InvalidDataException("PE section extends beyond the file boundary.");
            sections.Add(new Section((int)start, (int)size, (flags & 0x20000000) != 0));
        }
        if (!sections.Any(s => s.Executable))
            throw new InvalidDataException("PE file has no executable section.");
        return new DllLayout(architecture, sections);
    }

    public static void RequireExecutableEdits(ReadOnlySpan<byte> file, IEnumerable<PatchEdit> edits)
        => RequireInExecutableSections(ReadAmd64DllSections(file).Where(s => s.Executable), edits);

    public static void RequireOfflineExecutableEdits(ReadOnlySpan<byte> file,
        IEnumerable<PatchEdit> edits, string architecture)
    {
        var layout = ReadOfflineDllSections(file);
        if (!layout.Architecture.Equals(architecture, StringComparison.Ordinal))
            throw new InvalidDataException("Selected profile architecture does not match DLL PE architecture.");
        RequireInExecutableSections(layout.Sections.Where(s => s.Executable), edits);
    }

    private static void RequireInExecutableSections(IEnumerable<Section> executableSections,
        IEnumerable<PatchEdit> edits)
    {
        var executable = executableSections.ToArray();
        foreach (var edit in edits)
        {
            if (edit.Offset < 0 || edit.Expected.Length < 1 ||
                !executable.Any(s => edit.Offset >= s.Start &&
                    (long)edit.Offset + edit.Expected.Length <= (long)s.Start + s.Length))
                throw new InvalidDataException($"Patch offset 0x{edit.Offset:X8} is not inside executable DLL code.");
        }
    }
}
