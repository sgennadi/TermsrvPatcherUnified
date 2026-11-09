using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;

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

    /// <summary>
    /// Production-only guard. A checksum named by an attacker is not proof that
    /// its file is an authentic original DLL. Require the application state root
    /// AND the backup directory to be controlled only by trusted administrators.
    /// No ACLs are repaired automatically: legacy/untrusted locations fail closed.
    /// </summary>
    internal static void RequireTrustedLocation(string directory, bool create)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("NTFS backup trust requires Windows.");
        var root = Path.GetFullPath(directory);
        var parent = Path.GetDirectoryName(root)
            ?? throw new InvalidOperationException("Backup directory has no application state root.");
        if (create && !Directory.Exists(parent)) CreateProtectedDirectory(parent);
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("The backup parent directory does not exist.");
        RejectLinkedParents(parent);
        RequireTrustedAcl(parent);
        if (create && !Directory.Exists(root)) CreateProtectedDirectory(root);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException("The backup directory does not exist.");
        RejectLinkedParents(root);
        RequireTrustedAcl(root);
    }

    private static void CreateProtectedDirectory(string path)
    {
        if (!SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Administrator permission is required to create protected backup storage.");
        // CreateDirectory(DirectorySecurity, ...) applies the protected DACL at
        // directory creation, before untrusted accounts can plant backup files.
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.SetOwner(administrators);
        foreach (var sid in new[] { administrators, system })
            acl.AddAccessRule(new FileSystemAccessRule(
                sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        FileSystemAclExtensions.CreateDirectory(acl, path);
    }

    private static void RequireTrustedAcl(string path)
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var trustedInstaller = new SecurityIdentifier(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        using var identity = WindowsIdentity.GetCurrent();
        var current = identity.User;
        var elevated = SystemInfo.IsAdministrator();
        var acl = new DirectoryInfo(path).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        // Existing application state may be owned by the elevated administrator
        // who created it, rather than by the Administrators group.
        bool ownerIsCurrentElevatedAdmin = elevated && current is not null &&
                                           owner is not null && owner.Equals(current);
        if (owner is null ||
            (!owner.Equals(administrators) && !owner.Equals(system) &&
             !owner.Equals(trustedInstaller) && !ownerIsCurrentElevatedAdmin))
            throw new UnauthorizedAccessException(
                "Backup storage owner is not a trusted administrator; restore is blocked.");

        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true,
                     typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                !UpdateInstallBridge.HasMutatingRights(rule.FileSystemRights))
                continue;
            if (rule.IdentityReference is not SecurityIdentifier sid)
                throw new UnauthorizedAccessException("Unknown writable backup ACL entry.");
            // CREATOR OWNER applies to future objects; InheritOnly does not
            // grant access to this directory itself.
            if (sid.Equals(new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null)) &&
                rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
                continue;
            if (sid.Equals(administrators) || sid.Equals(system) ||
                sid.Equals(trustedInstaller) ||
                (ownerIsCurrentElevatedAdmin && current is not null && sid.Equals(current)))
                continue;
            throw new UnauthorizedAccessException(
                "Backup directory grants modification rights to an untrusted account.");
        }
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
