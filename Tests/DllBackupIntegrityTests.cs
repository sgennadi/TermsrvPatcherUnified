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
