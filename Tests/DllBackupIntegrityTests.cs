using System.Diagnostics;
using System.IO;
using TermsrvPatcherUnified.Core;

/// <summary>
/// A real Windows DLL is copied to a disposable user-temp directory.
/// No SYSTEM32 writes, no service calls, no NSudo library loading.
/// </summary>
internal static class DllBackupIntegrityTests
{
    internal static int Run()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("DLL backup QA requires Windows.");
        var liveDll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "termsrv.dll");
        if (!File.Exists(liveDll))
            throw new FileNotFoundException("Real DLL required for backup test.", liveDll);

        var source = File.ReadAllBytes(liveDll);
        var version = FileVersionInfo.GetVersionInfo(liveDll).FileVersion
            ?? throw new InvalidDataException("The Windows DLL lacks version metadata.");
        var sourceHash = SystemInfo.Sha256(source);
        var folder = Path.Combine(Path.GetTempPath(),
            "Termsrv-DllBackup-Tests-" + Guid.NewGuid().ToString("N"));
        var backupDir = Path.Combine(folder, "backups");
        var expectedProtectedRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "TermsrvPatcherUnified.Secure");
        var expectedProtectedBackups = Path.Combine(expectedProtectedRoot, "Backups");
        // The old audit directory may be writable by ordinary users.
        // It must never be used as a source of trusted Restore bytes.

        var assertions = 0;

        void Check(bool condition, string reason)
        {
            assertions++;
            if (!condition) throw new Exception("Backup QA failed: " + reason);
        }

        void Refuses<T>(Action action, string reason) where T : Exception
        {
            bool threw = false;
            try { action(); }
            catch (T) { threw = true; }
            Check(threw, reason);
        }

        try
        {
            // Path-only checks are safe without administrative rights; the
            // protected storage itself is never created in this QA run.
            Check(TermsrvEngine.BackupDirectory.Equals(expectedProtectedBackups,
                    StringComparison.OrdinalIgnoreCase),
                "protected backups use their own ProgramData state root");
            Check(!Path.GetFullPath(TermsrvEngine.BackupDirectory).StartsWith(
                    Path.GetFullPath(AuditLog.Root).TrimEnd(Path.DirectorySeparatorChar) +
                    Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase),
                "protected backups are not children of the writable audit root");
            Check(TermsrvEngine.LegacyBackupDirectory.Equals(
                    Path.Combine(AuditLog.Root, "Backups"),
                    StringComparison.OrdinalIgnoreCase),
                "legacy backup location is identified but never auto-trusted");
            // No-backup mode MUST NOT create even a backup directory.
            Check(DllBackupStore.Save(backupDir, version, source, sourceHash,
                createBackup: false) is null, "disabled backup returns null");
            Check(!Directory.Exists(backupDir), "disabled backup writes nothing");

            var saved = DllBackupStore.Save(backupDir, version, source, sourceHash,
                createBackup: true) ?? throw new Exception("Backup was not saved.");
            Check(File.Exists(saved), "enabled backup saves the original DLL");
            Check(SystemInfo.Sha256(File.ReadAllBytes(saved)) == sourceHash,
                "persisted backup SHA-256 matches untouched system DLL");

            var initialTime = File.GetLastWriteTimeUtc(saved);
            Check(DllBackupStore.Save(backupDir, version, source, sourceHash,
                    createBackup: true) == saved && File.GetLastWriteTimeUtc(saved) == initialTime,
                "a second Apply keeps the existing verified backup intact");
            var restoredBytes = DllBackupStore.ReadVerified(backupDir, saved,
                version, source.LongLength);
            Check(restoredBytes.AsSpan().SequenceEqual(source),
                "verified Restore recovers exact original bytes and SHA-256");
            Check(DllBackupStore.ListVerified(backupDir, version, source.LongLength)
                    .SequenceEqual([saved], StringComparer.OrdinalIgnoreCase),
                "Restore list displays only verified matching backup");
            Refuses<InvalidOperationException>(
                () => DllBackupStore.ReadVerified(backupDir, saved,
                    "0.0.0.0", source.LongLength),
                "reject a backup whose version differs from installed DLL");
            Refuses<InvalidOperationException>(
                () => DllBackupStore.ReadVerified(backupDir, saved,
                    version, source.LongLength + 1),
                "reject a backup whose size differs from installed DLL");

            // A valid set of DLL bytes must not be selected from a .txt file.
            var wrongExtension = Path.Combine(backupDir,
                Path.GetFileNameWithoutExtension(saved) + ".txt");
            File.Copy(saved, wrongExtension);
            Refuses<InvalidOperationException>(
                () => DllBackupStore.ReadVerified(backupDir, wrongExtension,
                    version, source.LongLength),
                "reject a backup with an unrelated file extension");

            var unrelatedFolder = Path.Combine(folder, "unrelated");
            Directory.CreateDirectory(unrelatedFolder);
            var outsideFile = Path.Combine(unrelatedFolder, Path.GetFileName(saved));
            File.Copy(saved, outsideFile);
            Refuses<InvalidOperationException>(
                () => DllBackupStore.ReadVerified(backupDir, outsideFile,
                    version, source.LongLength),
                "reject a DLL outside the backup directory");

            var nested = Path.Combine(backupDir, "subdirectory");
            Directory.CreateDirectory(nested);
            var nestedFile = Path.Combine(nested, Path.GetFileName(saved));
            File.Copy(saved, nestedFile);
            Refuses<InvalidOperationException>(
                () => DllBackupStore.ReadVerified(backupDir, nestedFile,
                    version, source.LongLength),
                "reject a nested backup even if it has the right hash");

            var corruptedBytes = (byte[])source.Clone();
            corruptedBytes[^1] ^= 0x5A;
            File.WriteAllBytes(saved, corruptedBytes);
            Refuses<IOException>(
                () => DllBackupStore.ReadVerified(backupDir, saved,
                    version, source.LongLength),
                "reject a tampered backup whose filename still claims original hash");
            Refuses<IOException>(
                () => DllBackupStore.Save(backupDir, version, source,
                    sourceHash, createBackup: true),
                "never overwrite a corrupted backup without administrator investigation");
            Check(DllBackupStore.ListVerified(backupDir, version, source.LongLength).Count == 0,
                "Restore list hides corrupted backup");
            Check(DllBackupStore.Save(backupDir, version, source,
                    sourceHash, createBackup: false) is null,
                "no-backup mode never rewrites a corrupt or existing backup");

            File.Delete(saved);
            var repaired = DllBackupStore.Save(backupDir, version,
                source, sourceHash, createBackup: true);
            Check(saved == repaired, "a fresh backup can be created after manual removal");
            Check(DllBackupStore.ReadVerified(backupDir, saved, version,
                    source.LongLength).AsSpan().SequenceEqual(source),
                "freshly created backup restores exact original DLL bytes");

            // Forged filename containing the right digest but wrong prefix must not
            // become an eligible Restore source.
            var forged = Path.Combine(backupDir, "unknown-" + sourceHash + ".dll");
            File.Copy(saved, forged);
            Refuses<InvalidOperationException>(
                () => DllBackupStore.ReadVerified(backupDir, forged,
                    version, source.LongLength),
                "reject an unrecognized backup file name");
            Check(DllBackupStore.ListVerified(backupDir, version, source.LongLength)
                    .SequenceEqual([saved], StringComparer.OrdinalIgnoreCase),
                "Restore list includes verified backup only");

            if (SystemInfo.IsAdministrator())
            {
                // A normal user-temp folder may inherit permissive rights:
                // explicitly create an admin-controlled test root and child.
                var user = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
                var admin = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                var localSystem = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                var privateAcl = new System.Security.AccessControl.DirectorySecurity();
                privateAcl.SetAccessRuleProtection(true, false);
                privateAcl.SetOwner(user);
                foreach (var sid in new[] { admin, localSystem })
                    privateAcl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        sid, System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                        System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None,
                        System.Security.AccessControl.AccessControlType.Allow));
                new DirectoryInfo(folder).SetAccessControl(privateAcl);
                new DirectoryInfo(backupDir).SetAccessControl(privateAcl);
                DllBackupStore.RequireTrustedLocation(backupDir, create: false);
                Check(true, "protected administrator-owned backup folder passes ACL gate");

                // Exercise the actual ProgramData inheritance boundary, but
                // use a unique QA-only directory, never the application folder.
                var programDataProbe = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "TermsrvBackup-QA-" + Guid.NewGuid().ToString("N"));
                try
                {
                    var programDataBackups = Path.Combine(programDataProbe, "Backups");
                    DllBackupStore.RequireTrustedLocation(programDataBackups, create: true);
                    Check(Directory.Exists(programDataBackups),
                        "first-use ProgramData backup storage is created with a protected ACL");
                }
                finally
                {
                    if (Directory.Exists(programDataProbe))
                        Directory.Delete(programDataProbe, recursive: true);
                }

                // Reproduce the reported real-world failure: a legacy
                // application state root inherits a user-writable ACE. A
                // protected child must NOT be created inside that root.
                var unsafeParent = Path.Combine(folder, "unsafe-parent");
                Directory.CreateDirectory(unsafeParent);
                var unsafeParentInfo = new DirectoryInfo(unsafeParent);
                unsafeParentInfo.SetAccessControl(privateAcl);
                var inheritedAcl = unsafeParentInfo.GetAccessControl();
                inheritedAcl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null),
                    System.Security.AccessControl.FileSystemRights.Modify,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));
                unsafeParentInfo.SetAccessControl(inheritedAcl);
                var unsafeChild = Path.Combine(unsafeParent, "Backups");
                Refuses<UnauthorizedAccessException>(
                    () => DllBackupStore.RequireTrustedLocation(unsafeChild, create: true),
                    "user-writable existing parent is refused without bypassing ACL checks");
                Check(!Directory.Exists(unsafeChild),
                    "rejecting an unsafe parent does not create a child backup directory");

                var unsafeDir = Path.Combine(folder, "unsafe-backups");
                Directory.CreateDirectory(unsafeDir);
                var unsafeInfo = new DirectoryInfo(unsafeDir);
                unsafeInfo.SetAccessControl(privateAcl);
                var unsafeAcl = unsafeInfo.GetAccessControl();
                unsafeAcl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.WorldSid, null),
                    System.Security.AccessControl.FileSystemRights.Modify,
                    System.Security.AccessControl.InheritanceFlags.None,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));
                unsafeInfo.SetAccessControl(unsafeAcl);
                Refuses<UnauthorizedAccessException>(
                    () => DllBackupStore.RequireTrustedLocation(unsafeDir, create: false),
                    "writable untrusted ACE prevents protected Backup and Restore");
            }
            else
                Console.WriteLine("SKIP: NTFS ACL trust checks require elevated runner.");

            Console.WriteLine("PASS: " + assertions + " real-DLL-copy backup/Restore checks; " +
                "default-off/no folder, enabled SHA-256, idempotence, wrong version/size/path, " +
                "tampering rejection, no overwrite, verified Restore and filtering.");
            Console.WriteLine("LIMIT: no protected Windows DLL writes or TermService changes.");
            return assertions;
        }
        finally
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
        }
    }
}
