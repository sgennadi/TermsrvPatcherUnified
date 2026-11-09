using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Small DPAPI-protected, per-DLL recovery journal. It stores only modified byte
/// spans, never another full DLL. An exact patched-file SHA-256 is required
/// before replay: old journals MUST NOT change a Windows-updated DLL.
/// The directory is admin/SYSTEM-only; DPAPI LocalMachine also authenticates
/// the encrypted record. It is NOT a replacement for an offline VM snapshot.
/// </summary>
internal static class RecoveryJournalStore
{
    private static readonly byte[] Entropy =
        SHA256.HashData(Encoding.UTF8.GetBytes("TermsrvPatcherUnified/recovery-journal/v1"));

    internal static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TermsrvPatcherUnified.Secure", "Recovery");

    internal sealed record Change(int Offset, byte[] Original, byte[] Replacement);
    internal sealed record Journal(string Schema, string OriginalSha256,
        string PatchedSha256, string FileVersion, string ProfileId,
        int Length, Change[] Changes);
    internal sealed record Verified(string OriginalSha256, string PatchedSha256,
        string FileVersion, string ProfileId, byte[] OriginalBytes);

    private static bool IsSha(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static string PathForPatchedHash(string sha)
    {
        if (!IsSha(sha)) throw new InvalidDataException("Invalid recovery hash.");
        return Path.Combine(Root, "journal-" + sha.ToLowerInvariant() + ".dpapi");
    }

    internal static void SaveBeforeApply(PatchPlan plan, byte[] original)
    {
        if (plan.State != PatchState.Ready || plan.IsManual ||
            plan.PatchedBytes is null || plan.Edits.Count == 0 ||
            original.Length != plan.PatchedBytes.Length ||
            !SystemInfo.Sha256(original).Equals(plan.OriginalSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only an exact automatic plan can create a recovery journal.");

        var rebuilt = (byte[])original.Clone();
        foreach (var edit in plan.Edits)
        {
            if (edit.Offset < 0 || edit.Expected.Length == 0 ||
                edit.Expected.Length != edit.Replacement.Length ||
                edit.Offset > original.Length - edit.Expected.Length ||
                !original.AsSpan(edit.Offset, edit.Expected.Length).SequenceEqual(edit.Expected))
                throw new InvalidDataException("Recovery journal edit does not match the original DLL.");
            edit.Replacement.CopyTo(rebuilt, edit.Offset);
        }
        if (!rebuilt.SequenceEqual(plan.PatchedBytes))
            throw new InvalidDataException("Recovery journal expected patched bytes differ.");

        string newHash = SystemInfo.Sha256(plan.PatchedBytes);
        var journal = new Journal("termsrv-recovery/v1", plan.OriginalSha256, newHash,
            plan.FileVersion, plan.ProfileId, original.Length,
            plan.Edits.Select(e =>
                new Change(e.Offset, (byte[])e.Expected.Clone(), (byte[])e.Replacement.Clone()))
                .ToArray());
        string parent = Path.GetDirectoryName(Root)!;
        NsudoDevilModeScope.EnsurePrivateDirectory(parent);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
        string file = PathForPatchedHash(newHash);
        if (File.Exists(file))
        {
            // An existing entry can only be reused if it independently
            // reconstructs exactly this original; never overwrite it.
            var prior = LoadExact(plan.PatchedBytes, plan.FileVersion)
                ?? throw new InvalidDataException("Existing recovery journal failed validation.");
            if (!prior.OriginalSha256.Equals(plan.OriginalSha256,
                    StringComparison.OrdinalIgnoreCase) ||
                !prior.ProfileId.Equals(plan.ProfileId, StringComparison.Ordinal) ||
                !prior.OriginalBytes.SequenceEqual(original))
                throw new InvalidDataException("Existing recovery journal conflicts with proposed Apply.");
            return;
        }
        byte[] encrypted = ProtectedData.Protect(
            JsonSerializer.SerializeToUtf8Bytes(journal), Entropy,
            DataProtectionScope.LocalMachine);
        try
        {
            using var stream = new FileStream(file, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 8192, FileOptions.WriteThrough);
            stream.Write(encrypted);
            stream.Flush(flushToDisk: true);
        }
        catch (IOException) when (File.Exists(file))
        {
            // Another writer won: validate the already persisted journal.
            var persisted = LoadExact(plan.PatchedBytes, plan.FileVersion)
                ?? throw new InvalidDataException("Concurrent recovery journal is unreadable.");
            if (!persisted.OriginalBytes.SequenceEqual(original) ||
                !persisted.ProfileId.Equals(plan.ProfileId, StringComparison.Ordinal))
                throw new InvalidDataException("Concurrent recovery journal is different.");
        }
        // Verify the final ciphertext really decrypts back to our source.
        var confirmed = LoadExact(plan.PatchedBytes, plan.FileVersion)
            ?? throw new IOException("Persisted recovery journal cannot be verified.");
        if (!confirmed.OriginalBytes.SequenceEqual(original) ||
            !confirmed.ProfileId.Equals(plan.ProfileId, StringComparison.Ordinal))
            throw new IOException("Persisted recovery journal original bytes mismatch.");
    }

    internal static Verified? LoadExact(byte[] current, string fileVersion)
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess ||
            !SystemInfo.IsAdministrator()) return null;
        if (current.Length == 0 || !Directory.Exists(Root)) return null;

        // Fail closed on an untrusted pre-existing directory, even for Check.
        NsudoDevilModeScope.EnsurePrivateDirectory(Path.GetDirectoryName(Root)!);
        NsudoDevilModeScope.EnsurePrivateDirectory(Root);
        string currentSha = SystemInfo.Sha256(current);
        string path = PathForPatchedHash(currentSha);
        if (!File.Exists(path)) return null;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Recovery journal must not be a filesystem link.");
        byte[] ciphertext = File.ReadAllBytes(path);
        if (ciphertext.Length is < 40 or > 131072)
            throw new InvalidDataException("Recovery journal has invalid size.");
        byte[] clear = ProtectedData.Unprotect(
            ciphertext, Entropy, DataProtectionScope.LocalMachine);
        var record = JsonSerializer.Deserialize<Journal>(clear)
            ?? throw new InvalidDataException("Recovery journal is invalid.");
        if (record.Schema != "termsrv-recovery/v1" ||
            record.Changes is null || record.Changes.Length is < 1 or > 32 ||
            record.Length != current.Length ||
            !record.FileVersion.Equals(fileVersion, StringComparison.Ordinal) ||
            record.ProfileId is null || record.ProfileId.Length is < 1 or > 256 ||
            !IsSha(record.OriginalSha256) || !IsSha(record.PatchedSha256) ||
            !record.PatchedSha256.Equals(currentSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Recovery journal metadata mismatch.");

        byte[] restored = (byte[])current.Clone();
        int lastEnd = 0;
        foreach (var change in record.Changes.OrderBy(c => c.Offset))
        {
            if (change.Original is null || change.Replacement is null ||
                change.Offset < lastEnd || change.Offset < 0 ||
                change.Original.Length is < 1 or > 128 ||
                change.Original.Length != change.Replacement.Length ||
                change.Offset > current.Length - change.Original.Length ||
                !current.AsSpan(change.Offset, change.Replacement.Length)
                    .SequenceEqual(change.Replacement))
                throw new InvalidDataException("Recovery journal changed spans are invalid.");
            change.Original.CopyTo(restored, change.Offset);
            lastEnd = change.Offset + change.Original.Length;
        }
        if (!SystemInfo.Sha256(restored).Equals(record.OriginalSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Recovery journal cannot reconstruct the original SHA-256.");
        PeSafety.ReadAmd64DllSections(restored);
        return new Verified(record.OriginalSha256, currentSha,
            record.FileVersion, record.ProfileId, restored);
    }
}
