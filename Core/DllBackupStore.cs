using System.Diagnostics;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Validates persistent backups independently of the elevated protected-write path.
/// Callers must still enforce administrator approval and the exact system-DLL target.
/// A disabled backup does not create a directory or write any file.
/// </summary>
internal static class DllBackupStore
{
    private const string Prefix = "termsrv-";

    internal static string? Save(
        string directory, string fileVersion, byte[] original,
        string expectedSha256, bool createBackup)
    {
        if (!createBackup) return null;
        ArgumentNullException.ThrowIfNull(original);
        if (original.Length == 0) throw new InvalidDataException("Empty original DLL.");
        var backupName = FileName(fileVersion, expectedSha256);
        if (!SystemInfo.Sha256(original).Equals(expectedSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Original DLL checksum changed before backup.");
        var root = Path.GetFullPath(directory);
        Directory.CreateDirectory(root);
        RejectLinkedParents(root);
        var backup = Path.Combine(root, backupName);
        if (File.Exists(backup))
        {
            RejectLinkedFile(backup);
            if (!SystemInfo.Sha256(File.ReadAllBytes(backup)).Equals(expectedSha256,
                    StringComparison.OrdinalIgnoreCase))
                throw new IOException("Existing backup has an invalid checksum; it was not overwritten.");
            return backup;
        }

        // A unique temporary file and atomic, no-overwrite rename avoid partial
        // backups. Existing backups are never replaced by new bytes.
        var temporary = backup + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 65536, FileOptions.WriteThrough))
            {
                stream.Write(original);
                stream.Flush(flushToDisk: true);
            }
            if (!SystemInfo.Sha256(File.ReadAllBytes(temporary)).Equals(expectedSha256,
                    StringComparison.OrdinalIgnoreCase))
                throw new IOException("Written backup failed SHA-256 verification.");
            RejectLinkedParents(root);
            File.Move(temporary, backup, overwrite: false);
            RejectLinkedFile(backup);
            return backup;
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    internal static byte[] ReadVerified(
        string directory, string candidate, string installedVersion, long installedLength)
    {
        if (installedLength < 1) throw new InvalidDataException("Installed DLL is empty.");
        var root = Path.GetFullPath(directory);
        var file = Path.GetFullPath(candidate);
        // Direct children only. A directory prefix check by itself is insufficient.
        if (!Path.GetDirectoryName(file)!.Equals(root, StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(file) || !Path.GetExtension(file).Equals(".dll", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Select a backup directly inside the application's backup folder.");
        RejectLinkedParents(root);
        RejectLinkedFile(file);
        // Windows uses side-by-side MUI resources for some system-file version
        // strings. Those resources are unavailable after backup renaming, so
        // GetVersionInfo(backup) may differ from GetVersionInfo(System32 DLL).
        // Save records the original version in the canonical checksum name.
        var filename = Path.GetFileName(file);
        var expectedVersionPrefix = FileName(installedVersion, new string('0', 64))[..^68];
        if (!filename.StartsWith(expectedVersionPrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Backup DLL version or name does not match the installed DLL.");
        var bytes = File.ReadAllBytes(file);
        if (bytes.LongLength != installedLength)
            throw new InvalidOperationException("Backup length differs from installed DLL.");
        var computedSha = SystemInfo.Sha256(bytes);
        // SHA-256 detects corruption and the canonical name binds the version
        // recorded at backup time. It does not authenticate arbitrary files from
        // an untrusted writable directory: keep backups administrator-controlled.
        if (!Path.GetFileName(file).Equals(FileName(installedVersion, computedSha),
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("Backup filename, version or SHA-256 is invalid.");
        PeSafety.ReadAmd64DllSections(bytes);
        return bytes;
    }

    internal static IReadOnlyList<string> ListVerified(
        string directory, string installedVersion, long installedLength)
    {
        if (!Directory.Exists(directory)) return [];
        RejectLinkedParents(Path.GetFullPath(directory));
        var found = new List<string>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.dll",
                     SearchOption.TopDirectoryOnly))
        {
            try
            {
                _ = ReadVerified(directory, file, installedVersion, installedLength);
                found.Add(file);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or
                                       InvalidOperationException or UnauthorizedAccessException)
            {
                // Never offer a tampered, version-mismatched or linked backup in the UI.
            }
        }
        return found.OrderByDescending(File.GetCreationTimeUtc).ToArray();
    }

    private static string FileName(string version, string sha)
    {
        if (string.IsNullOrWhiteSpace(version) || version.Length > 128 ||
            !sha.All(Uri.IsHexDigit) || sha.Length != 64)
            throw new InvalidDataException("Invalid backup DLL version or SHA-256.");
        var safeVersion = string.Concat(version.Select(
            c => char.IsLetterOrDigit(c) || c == '.' ? c : '_'));
        return Prefix + safeVersion + "-" + sha.ToLowerInvariant() + ".dll";
    }

    private static void RejectLinkedParents(string directory)
    {
        for (var p = new DirectoryInfo(directory); p is not null; p = p.Parent)
        {
            if ((p.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Backup directory must not use filesystem links.");
        }
    }

    private static void RejectLinkedFile(string file)
    {
        if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Backup file must not be a filesystem link.");
    }
}
