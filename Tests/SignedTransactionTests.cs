using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.IO.Compression;
using System.Security.Cryptography;
using TermsrvPatcherUnified.Core;
using UniversalUpdater;

internal static class SignedTransactionTests
{
    internal static int Run(string zip, string pin, string version)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "tpu-signed-transaction-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var candidate = Path.Combine(root, "candidate", "TermsrvPatcherUnified.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(candidate)!);
            using (var archive = ZipFile.OpenRead(Path.GetFullPath(zip)))
            {
                if (archive.Entries.Count != 1 || archive.Entries[0].FullName != "TermsrvPatcherUnified.exe")
                    throw new InvalidDataException("Signed updater ZIP must contain one EXE.");
                archive.Entries[0].ExtractToFile(candidate);
            }
            if (!ReleaseSignatureVerifier.VerifyWithPin(candidate, pin, out var reason))
                throw new Exception("Candidate signer rejected: " + reason);
            var candidateHash = Hash(candidate);
            foreach (var failProbe in new[] { false, true })
            {
                var name = failProbe ? "rollback" : "success";
                var dir = Path.Combine(root, name);
                Directory.CreateDirectory(dir);
                var target = Path.Combine(dir, "TermsrvPatcherUnified.exe");
                // Old installation is a disposable synthetic x64 PE; new payload is genuinely signed.
                // This exercises the transaction but not the privileged production helper.
                // A distinct disposable old x64 PE is required: the transaction rejects
                // same-version/same-hash replay before invoking its health probe.
                File.WriteAllBytes(target, OldX64Fixture());
                var oldHash = Hash(target);
                var rule = new UpdateAssetRule("win-x64", "TermsrvPatcherUnified-update-win-x64.zip",
                    PackageKind.SingleExeZip, "TermsrvPatcherUnified.exe");
                var options = new UpdateOptions
                {
                    ProductId = "SignedTransactionQA" + name,
                    Repository = "sgennadi/TermsrvPatcherUnified",
                    InstalledVersion = "0.1.0-preview.1",
                    Architecture = "win-x64",
                    Channel = UpdateChannel.Prerelease,
                    StateDirectory = Path.Combine(root, name + "-state"),
                    Assets = [rule]
                };
                var stagedDir = Path.Combine(options.StateDirectory!, options.ProductId, "staging", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(stagedDir);
                var staged = Path.Combine(stagedDir, "TermsrvPatcherUnified.exe");
                File.Copy(candidate, staged);
                var stagedZip = Path.Combine(stagedDir, rule.AssetName);
                File.Copy(zip, stagedZip);
                var releaseVersion = SemanticVersion.Parse(version);
                var release = new UpdateRelease(options.Repository, releaseVersion,
                    "v" + version, "https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v" + version,
                    "Signed transaction QA", null, rule,
                    new Uri("https://github.com/sgennadi/TermsrvPatcherUnified/releases/download/v" + version + "/" + rule.AssetName),
                    new FileInfo(stagedZip).Length, Hash(stagedZip));
                var package = new StagedPackage(release, stagedZip, Hash(stagedZip), staged, candidateHash);
                var probes = 0;
                var result = new PortableExeTransaction().ApplyManualAsync(options, package,
                    dir, "TermsrvPatcherUnified.exe", explicitlyApproved: true, (installed, cancellationToken) =>
                    {
                        probes++;
                        return Task.FromResult(ReleaseSignatureVerifier.VerifyWithPin(installed, pin, out _) &&
                            Hash(installed) == candidateHash && !failProbe);
                    }).GetAwaiter().GetResult();
                var state = new UpdateStateStore(options).Read();
                if (probes != 1 || Hash(target) != (failProbe ? oldHash : candidateHash))
                    throw new Exception("Signed transaction target digest or health probe count is incorrect for " + name + ".");
                if (failProbe)
                {
                    if (result.Success || !result.RolledBack || !state.FailureHold ||
                        state.LastResultCode != "INSTALL_FAILED_RESTORED")
                        throw new Exception("Signed transaction rollback failed.");
                }
                else if (!result.Success || result.RolledBack || state.FailureHold ||
                         state.LastResultCode != "INSTALL_OK" || !File.Exists(target + ".bak") ||
                         Hash(target + ".bak") != oldHash)
                    throw new Exception("Signed transaction backup/commit failed.");
            }
            Console.WriteLine("PASS: signed archive transaction, backup, failed-probe rollback and signer check.");
            Console.WriteLine("LIMIT: synthetic old PE; no elevated helper or two-version signed upgrade exercised.");
            return 0;
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static byte[] OldX64Fixture()
    {
        var bytes = new byte[4096];
        bytes[0] = 0x4d;
        bytes[1] = 0x5a;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3c, 4), 0x80);
        bytes[0x80] = 0x50;
        bytes[0x81] = 0x45;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x84, 2), 0x8664);
        bytes[0x200] = 0x42;
        return bytes;
    }

    private static string Hash(string path) =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
}
