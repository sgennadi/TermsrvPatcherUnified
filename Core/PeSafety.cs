using System.Buffers.Binary;

namespace TermsrvPatcherUnified.Core;

// Deliberately small, read-only PE header validator for protected-file writes.
// It rejects a signature found in a resource, overlay, or other non-executable region.
public static class PeSafety
{
    public sealed record Section(int Start, int Length, bool Executable);

    public static IReadOnlyList<Section> ReadAmd64DllSections(ReadOnlySpan<byte> file)
    {
        if (file.Length < 0x100 || file[0] != (byte)'M' || file[1] != (byte)'Z')
            throw new InvalidDataException("Not a valid PE file: missing DOS header.");
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(file.Slice(0x3C, 4));
        if (peOffset < 0x40 || (long)peOffset + 24 > file.Length ||
            !file.Slice(peOffset, 4).SequenceEqual(new byte[] { (byte)'P', (byte)'E', 0, 0 }))
            throw new InvalidDataException("Not a valid PE file: invalid PE header offset or signature.");
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 4, 2));
        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 6, 2));
        ushort optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 20, 2));
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 22, 2));
        if (machine != 0x8664 || (characteristics & 0x2000) == 0)
            throw new InvalidDataException("Only a 64-bit AMD64 Windows DLL can be modified.");
        if (sectionCount is 0 or > 96 || optionalSize < 2 ||
            (long)peOffset + 24 + optionalSize + sectionCount * 40L > file.Length)
            throw new InvalidDataException("PE section table is invalid or truncated.");
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(file.Slice(peOffset + 24, 2));
        if (magic != 0x20B) throw new InvalidDataException("PE optional header is not PE32+.");
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
        return sections;
    }

    public static void RequireExecutableEdits(ReadOnlySpan<byte> file, IEnumerable<PatchEdit> edits)
    {
        var executable = ReadAmd64DllSections(file).Where(s => s.Executable).ToArray();
        foreach (var edit in edits)
        {
            if (edit.Offset < 0 || edit.Expected.Length < 1 ||
                !executable.Any(s => edit.Offset >= s.Start &&
                    (long)edit.Offset + edit.Expected.Length <= (long)s.Start + s.Length))
                throw new InvalidDataException($"Patch offset 0x{edit.Offset:X8} is not inside executable DLL code.");
        }
    }
}
