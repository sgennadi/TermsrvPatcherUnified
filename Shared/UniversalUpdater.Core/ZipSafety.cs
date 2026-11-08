using System.IO.Compression;

namespace UniversalUpdater;

/// <summary>Strict, side-effect-free ZIP manifest validation before extraction.</summary>
public static class ZipSafety
{
    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public static bool IsSafeRelativeEntry(string? entry)
    {
        if (string.IsNullOrWhiteSpace(entry) || entry.Length > 260 ||
            entry.StartsWith('/') || entry.EndsWith(' ') || entry.Contains('\\') || entry.Contains(':') ||
            entry.Any(char.IsControl)) return false;
        var normalized = entry.EndsWith('/') ? entry[..^1] : entry;
        if (normalized.Length == 0) return false;
        foreach (var part in normalized.Split('/'))
        {
            if (part.Length == 0 || part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.') ||
                part.Any(c => c is '<' or '>' or '"' or '|' or '?' or '*')) return false;
            var baseName = part.Split('.', 2)[0];
            if (ReservedDeviceNames.Contains(baseName)) return false;
        }
        return true;
    }

    public static void Validate(string archivePath, UpdateAssetRule rule, long maxExpandedBytes)
    {
        using var zip = ZipFile.OpenRead(archivePath);
        ValidateEntries(zip.Entries, rule, maxExpandedBytes);
    }

    public static void ValidateEntries(
        IReadOnlyCollection<ZipArchiveEntry> entries, UpdateAssetRule rule, long maxExpandedBytes)
    {
        if (entries.Count is < 1 or > 2048 || maxExpandedBytes < 1)
            throw new InvalidDataException("Unexpected archive entry count or expansion limit.");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var expectedSingle = rule.SingleExecutableName;
        var allowed = new HashSet<string>(rule.AllowedZipEntries ?? [], StringComparer.OrdinalIgnoreCase);
        long total = 0;
        var files = 0;
        foreach (var entry in entries)
        {
            string path = entry.FullName;
            if (!IsSafeRelativeEntry(path))
                throw new InvalidDataException("ZIP contains an unsafe path.");
            if (!seen.Add(path.TrimEnd('/')))
                throw new InvalidDataException("ZIP contains duplicate or case-colliding entries.");
            var unixType = (entry.ExternalAttributes >> 16) & 0xF000;
            if (unixType is not (0 or 0x8000 or 0x4000))
                throw new InvalidDataException("ZIP contains a link or unsupported file type.");
            bool directory = path.EndsWith('/');
            if (directory)
            {
                if (entry.Length != 0 || unixType == 0x8000)
                    throw new InvalidDataException("Invalid ZIP directory entry.");
                if (rule.Kind == PackageKind.SingleExeZip)
                    throw new InvalidDataException("Single EXE packages cannot include directories.");
                if (!allowed.Any(x => x.StartsWith(path, StringComparison.OrdinalIgnoreCase)))
                    throw new InvalidDataException("Unexpected ZIP directory.");
                continue;
            }
            files++;
            if (entry.Length < 1 || entry.Length > maxExpandedBytes - total)
                throw new InvalidDataException("ZIP expansion exceeds configured limit.");
            if (entry.CompressedLength > 0 && entry.Length / entry.CompressedLength > 10000)
                throw new InvalidDataException("ZIP compression ratio exceeds safety limit.");
            total += entry.Length;
            if (rule.Kind == PackageKind.SingleExeZip)
            {
                if (!string.Equals(path, expectedSingle, StringComparison.Ordinal))
                    throw new InvalidDataException("Single EXE ZIP contains an unexpected file.");
            }
            else if (rule.Kind is PackageKind.PluginZip or PackageKind.GenericZip)
            {
                if (!allowed.Contains(path))
                    throw new InvalidDataException("ZIP contains a file outside the explicit allowlist.");
            }
            else throw new InvalidDataException("The package format cannot be staged as a ZIP.");
        }
        if (rule.Kind == PackageKind.SingleExeZip && files != 1)
            throw new InvalidDataException("Single EXE ZIP must contain exactly one executable.");
        if (rule.Kind is PackageKind.PluginZip or PackageKind.GenericZip && files == 0)
            throw new InvalidDataException("Release package has no files.");
    }
}
