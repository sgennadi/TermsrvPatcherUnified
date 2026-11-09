using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// The opt-in FULL backup copy is a sibling of the installed termsrv.dll.
/// A per-machine DPAPI-authenticated index binds that copy to the exact original
/// hash/version. Windows updates never cause Check to write anything: only an
/// explicitly approved Apply of a fresh, trusted Ready original updates .bak.
/// Old copies are archived BEFORE replacement; unindexed copies are archived
/// separately and never promoted into trusted Restore candidates.
/// </summary>
internal static class System32BackupStore
{
    private static readonly byte[] Entropy = SHA256.HashData(
        Encoding.UTF8.GetBytes("TermsrvPatcherUnified/system32-bak-index/v1"));

    private sealed record Index(string Schema, string Sha256, string FileVersion,
        int FileLength, string CreatedUtc);

    private static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TermsrvPatcherUnified.Secure", "System32Backup");

    private static string IndexPath => Path.Combine(Root, "index.dpapi");

    internal static string BackupPath => SystemInfo.Read().DllPath + ".bak";

    internal static bool NeedsRefresh(string expectedOriginalSha, string? existingSha)
        => !expectedOriginalSha.Equals(existingSha, StringComparison.OrdinalIgnoreCase);

    private static bool IsSha(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static void EnsureRoot()
    {
        NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
    }

    private static Index? ReadIndex()
    {
        if (!Directory.Exists(Root)) return null;
        EnsureRoot();
        if (!File.Exists(IndexPath)) return null;
        if ((File.GetAttributes(IndexPath) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("System32 backup index is linked.");
        byte[] sealedIndex = File.ReadAllBytes(IndexPath);
        if (sealedIndex.Length is < 40 or > 16384)
            throw new InvalidDataException("System32 backup index is invalid.");
        byte[] clear = ProtectedData.Unprotect(
            sealedIndex, Entropy, DataProtectionScope.LocalMachine);
        var result = JsonSerializer.Deserialize<Index>(clear)
            ?? throw new InvalidDataException("System32 backup index is unreadable.");
        if (result.Schema != "termsrv-system32-bak/v1" ||
            !IsSha(result.Sha256) ||
            result.FileVersion is null || result.FileVersion.Length is < 1 or > 128 ||
            result.FileLength is < 1 or > 50_000_000)
            throw new InvalidDataException("System32 backup index metadata is invalid.");
        return result;
    }

    private static void WriteIndex(string sourceHash, string version, int length)
    {
        EnsureRoot();
        var record = new Index("termsrv-system32-bak/v1", sourceHash, version,
            length, DateTimeOffset.UtcNow.ToString("O"));
        byte[] encoded = ProtectedData.Protect(
            JsonSerializer.SerializeToUtf8Bytes(record), Entropy,
            DataProtectionScope.LocalMachine);
        string temp = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var f = new FileStream(temp, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 8192, FileOptions.WriteThrough))
            {
                f.Write(encoded);
                f.Flush(flushToDisk: true);
            }
            File.Move(temp, IndexPath, overwrite: true);
            var verified = ReadIndex()
                ?? throw new IOException("System32 backup index not persisted.");
            if (!verified.Sha256.Equals(sourceHash, StringComparison.OrdinalIgnoreCase) ||
                verified.FileVersion != version || verified.FileLength != length)
                throw new IOException("System32 backup index read-back mismatch.");
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static void RejectLinkAndWritableAcl(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("System32 backup cannot be a filesystem link.");
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var installer = new SecurityIdentifier(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        var security = new FileInfo(path).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                !UpdateInstallBridge.HasMutatingRights(rule.FileSystemRights))
                continue;
            if (rule.IdentityReference is not SecurityIdentifier sid ||
                (!sid.Equals(admins) && !sid.Equals(system) && !sid.Equals(installer)))
                throw new UnauthorizedAccessException(
                    "System32 backup grants write access to an untrusted account.");
        }
    }

    private static void ArchiveOld(byte[] old, string originalSha, string version,
        bool indexed)
    {
        string folder = Path.Combine(Root,
            indexed ? "PreviousWindowsVersions" : "UnverifiedPreviousCopies");
        NsudoDevilModeScope.EnsurePrivateDirectory(folder);
        string safeVersion = new string(version.Select(c =>
            char.IsAsciiLetterOrDigit(c) || c == '.' ? c : '_').ToArray());
        string path = Path.Combine(folder,
            "termsrv-" + safeVersion + "-" + originalSha + ".dll");
        if (!File.Exists(path))
        {
            using var f = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 65536, FileOptions.WriteThrough);
            f.Write(old);
            f.Flush(flushToDisk: true);
        }
        else if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Previous-version archive is linked.");
        if (!SystemInfo.Sha256(File.ReadAllBytes(path))
                .Equals(originalSha, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Cannot verify old .bak archive. Existing .bak retained.");
    }

    internal static void SyncBeforeApply(PatchPlan plan, byte[] source)
    {
        if (plan.State != PatchState.Ready || plan.IsManual ||
            plan.PatchedBytes is null || !SystemInfo.IsAdministrator())
            throw new InvalidOperationException("System32 backup requires an approved automatic Apply.");
        var os = SystemInfo.Read();
        if (!Path.GetFullPath(plan.FilePath)
                .Equals(Path.GetFullPath(os.DllPath), StringComparison.OrdinalIgnoreCase) ||
            !plan.FileVersion.Equals(os.DllVersion, StringComparison.Ordinal) ||
            !SystemInfo.Sha256(source).Equals(plan.OriginalSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !SystemInfo.Sha256(File.ReadAllBytes(os.DllPath)).Equals(plan.OriginalSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("System32 backup can only copy this exact original DLL.");

        EnsureRoot();
        string backup = BackupPath;
        var priorIndex = ReadIndex();
        byte[]? oldBytes = null;
        string? oldHash = null;
        if (File.Exists(backup))
        {
            RejectLinkAndWritableAcl(backup);
            oldBytes = File.ReadAllBytes(backup);
            oldHash = SystemInfo.Sha256(oldBytes);
            if (priorIndex is not null &&
                (!priorIndex.Sha256.Equals(oldHash, StringComparison.OrdinalIgnoreCase) ||
                 priorIndex.FileLength != oldBytes.Length))
                throw new IOException("Existing .bak differs from the protected index: manual review required.");
        }
        else if (priorIndex is not null)
        {
            // A missing .bak after Windows servicing is not proof of corruption;
            // allow recreating from the current exact Ready original.
            oldBytes = null;
        }

        if (!NeedsRefresh(plan.OriginalSha256, oldHash))
        {
            if (priorIndex is null || priorIndex.FileVersion != plan.FileVersion)
                WriteIndex(plan.OriginalSha256, plan.FileVersion, source.Length);
            return;
        }

        if (oldBytes is not null && oldHash is not null)
        {
            // Preserve previous build BEFORE replacement. An unindexed backup
            // is archived as UNVERIFIED and never offered as trusted Restore.
            ArchiveOld(oldBytes, oldHash,
                priorIndex?.FileVersion ?? "unknown", indexed: priorIndex is not null);
        }

        // This stage is the only extra System32 write. Do it BEFORE any RDP
        // service is stopped. Refuse the Apply if creating the .bak fails.
        string stage = backup + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var scope = NsudoDevilModeScope.Enter())
            {
                using (var file = new FileStream(stage, FileMode.CreateNew,
                           FileAccess.Write, FileShare.None, 65536,
                           FileOptions.WriteThrough))
                {
                    file.Write(source);
                    file.Flush(flushToDisk: true);
                }
                if (!SystemInfo.Sha256(File.ReadAllBytes(stage)).Equals(
                        plan.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Staged System32 backup hash mismatch.");
                File.Move(stage, backup, overwrite: true);
            }
            RejectLinkAndWritableAcl(backup);
            if (!SystemInfo.Sha256(File.ReadAllBytes(backup)).Equals(
                    plan.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("System32 .bak SHA-256 verification failed.");
            // Only publish the new trusted index AFTER the new .bak is verified.
            WriteIndex(plan.OriginalSha256, plan.FileVersion, source.Length);
        }
        finally
        {
            if (File.Exists(stage))
            {
                try { using var scope = NsudoDevilModeScope.Enter(); File.Delete(stage); }
                catch { /* Do not hide the original failure. */ }
            }
        }
        if (!SystemInfo.Sha256(File.ReadAllBytes(os.DllPath)).Equals(
                plan.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Installed DLL changed while preparing System32 backup.");
    }

    internal static byte[]? ReadVerified(string currentVersion, long currentLength)
    {
        if (!OperatingSystem.IsWindows() || !SystemInfo.IsAdministrator())
            return null;
        Index? index = ReadIndex();
        if (index is null || index.FileVersion != currentVersion ||
            index.FileLength != currentLength || !File.Exists(BackupPath))
            return null;
        RejectLinkAndWritableAcl(BackupPath);
        byte[] bytes = File.ReadAllBytes(BackupPath);
        if (bytes.LongLength != currentLength ||
            !SystemInfo.Sha256(bytes).Equals(index.Sha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("System32 .bak has changed since approved original backup.");
        PeSafety.ReadAmd64DllSections(bytes);
        return bytes;
    }
}
