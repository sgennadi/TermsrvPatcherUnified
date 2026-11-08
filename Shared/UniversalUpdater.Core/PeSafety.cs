using System.Text;

namespace UniversalUpdater;

/// <summary>Portable PE machine validation; does not execute the downloaded file.</summary>
public static class PeSafety
{
    public static void ValidateArchitecture(string exePath, string architecture)
    {
        var expected = architecture switch
        {
            "win-x86" => (ushort)0x014c,
            "win-x64" => (ushort)0x8664,
            "win-arm64" => (ushort)0xaa64,
            _ => throw new InvalidDataException("Unsupported PE architecture.")
        };
        using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length < 0x86) throw new InvalidDataException("Executable is too short to contain a PE header.");
        using var reader = new BinaryReader(stream, Encoding.ASCII);
        if (reader.ReadUInt16() != 0x5a4d) throw new InvalidDataException("Executable has no DOS MZ header.");
        stream.Position = 0x3c;
        var peOffset = reader.ReadInt32();
        if (peOffset < 0x40 || peOffset > stream.Length - 6)
            throw new InvalidDataException("Executable has an invalid PE offset.");
        stream.Position = peOffset;
        if (reader.ReadUInt32() != 0x00004550 || reader.ReadUInt16() != expected)
            throw new InvalidDataException("Downloaded executable architecture does not match the host.");
    }
}
