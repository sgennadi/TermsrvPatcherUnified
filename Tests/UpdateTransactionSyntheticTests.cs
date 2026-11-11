using System.IO;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using UniversalUpdater;
using TermsrvPatcherUnified.Core;

internal static class UpdateTransactionSyntheticTests
{
    internal static int Run()
    {
        if (!OperatingSystem.IsWindows())
            return 0; // CI runs on windows-2025; File.Replace is tested there.

        var stable = SemanticVersion.Parse("1.0.3");
        var preview = SemanticVersion.Parse("1.0.3-preview.1");
        if (!GitHubReleaseClient.MatchesChannel(UpdateChannel.Stable, false, stable) ||
            GitHubReleaseClient.MatchesChannel(UpdateChannel.Stable, true, stable) ||
            GitHubReleaseClient.MatchesChannel(UpdateChannel.Stable, false, preview) ||
            !GitHubReleaseClient.MatchesChannel(UpdateChannel.Prerelease, true, preview) ||
            GitHubReleaseClient.MatchesChannel(UpdateChannel.Prerelease, false, stable) ||
            GitHubReleaseClient.MatchesChannel(UpdateChannel.Prerelease, true, stable) ||
            GitHubReleaseClient.MatchesChannel(UpdateChannel.Prerelease, false, preview))
            throw new Exception("Stable/Preview channel isolation failed: only matching GitHub flag plus SemVer may pass.");
        Console.WriteLine("PASS: Preview and Stable channels reject cross-channel and incorrectly labelled releases.");

        // Regression: an older Preview cannot replace installed newer Stable.
        // This is the same version gate as the GUI staging and SYSTEM helper.
        var versionCases = new (string Installed, string Offered, bool Allowed)[]
        {
            ("1.0.5", "1.0.5-preview.5", false),
            ("1.0.5", "1.0.5-preview.99", false),
            ("1.0.6", "1.0.5-preview.99", false),
            ("1.0.5", "1.0.4", false),
            ("1.0.5", "1.0.5", false),
            ("1.0.5-preview.5", "1.0.5", true),
            ("1.0.5-preview.4", "1.0.5-preview.5", true),
            ("1.0.5", "1.0.6-preview.1", true) // explicit newer Preview only
        };
        foreach (var test in versionCases)
        {
            bool allowed = UpdateInstallBridge.IsUpgradeCandidate(
                SemanticVersion.Parse(test.Offered), test.Installed);
            if (allowed != test.Allowed)
                throw new Exception("Update downgrade guard failed for " +
                    test.Installed + " -> " + test.Offered);
        }
        Console.WriteLine("PASS: Stable downgrade guard and deliberate upgrade SemVer matrix.");

        RunOneCase(failHealthProbe: false);
        RunOneCase(failHealthProbe: true);
        Console.WriteLine("PASS: transactional update replaced a disposable EXE and recovered from a rejected health probe.");
        return 2;
    }

    private static void RunOneCase(bool failHealthProbe)
    {
        var root = Path.Combine(Path.GetTempPath(),
            "Termsrv-Updater-Synthetic-" + Guid.NewGuid().ToString("N"));
        try
        {
            var installation = Path.Combine(root, "installed");
            Directory.CreateDirectory(installation);
            const string exeName = "TermsrvPatcherUnified.exe";
            var target = Path.Combine(installation, exeName);
            var originalBytes = FakeX64Executable(0x12);
            var nextBytes = FakeX64Executable(0x34);
            File.WriteAllBytes(target, originalBytes);

            var rule = new UpdateAssetRule("win-x64",
                "TermsrvPatcherUnified-update-win-x64.zip",
                PackageKind.SingleExeZip, exeName);
            var options = new UpdateOptions
            {
                ProductId = "TermsrvUpdaterSynthetic",
                Repository = "sgennadi/TermsrvPatcherUnified",
                InstalledVersion = "0.1.0-preview.12",
                Architecture = "win-x64",
                Channel = UpdateChannel.Prerelease,
                StateDirectory = Path.Combine(root, "state"),
                Assets = [rule]
            };
            var stageDir = Path.Combine(options.StateDirectory!,
                options.ProductId, "staging", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(stageDir);
            var stagedExe = Path.Combine(stageDir, exeName);
            File.WriteAllBytes(stagedExe, nextBytes);
            var archive = Path.Combine(stageDir, rule.AssetName);
            File.WriteAllBytes(archive, Encoding.ASCII.GetBytes(
                "Synthetic test only: this is not a downloadable release ZIP."));
            var archiveHash = Sha(archive);
            var stagedExeHash = Sha(stagedExe);
            var nextVersion = SemanticVersion.Parse("0.1.0-preview.13");
            var release = new UpdateRelease(options.Repository, nextVersion,
                "v0.1.0-preview.13",
                "https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v0.1.0-preview.13",
                "Synthetic transactional test", null, rule,
                new Uri("https://github.com/sgennadi/TermsrvPatcherUnified/releases/download/v0.1.0-preview.13/TermsrvPatcherUnified-update-win-x64.zip"),
                new FileInfo(archive).Length, archiveHash);
            var package = new StagedPackage(release, archive, archiveHash,
                stagedExe, stagedExeHash);

            var callbackCount = 0;
            var result = new PortableExeTransaction().ApplyManualAsync(
                options, package, installation, exeName,
                explicitlyApproved: true,
                (exe, _) =>
                {
                    callbackCount++;
                    if (!string.Equals(Path.GetFullPath(exe), target,
                        StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Health probe target is not the installed EXE.");
                    return Task.FromResult(!failHealthProbe);
                }).GetAwaiter().GetResult();

            if (callbackCount != 1)
                throw new Exception("Transactional update did not run exactly one health probe.");
            var installedHash = Sha(target);
            var state = new UpdateStateStore(options).Read();
            if (failHealthProbe)
            {
                if (result.Success || !result.RolledBack ||
                    !string.Equals(installedHash, Sha(originalBytes),
                        StringComparison.OrdinalIgnoreCase) ||
                    !state.FailureHold || state.LastResultCode != "INSTALL_FAILED_RESTORED")
                    throw new Exception("Failure-probe rollback did not restore the original EXE and hold updates.");
            }
            else
            {
                var backupPath = target + ".bak";
                if (!result.Success || result.RolledBack ||
                    !string.Equals(installedHash, Sha(nextBytes),
                        StringComparison.OrdinalIgnoreCase) ||
                    !File.Exists(backupPath) ||
                    !string.Equals(Sha(backupPath), Sha(originalBytes),
                        StringComparison.OrdinalIgnoreCase) ||
                    state.FailureHold || state.LastResultCode != "INSTALL_OK")
                    throw new Exception("Successful transactional update did not retain a verified backup.");
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] FakeX64Executable(byte marker)
    {
        var bytes = new byte[4096];
        bytes[0] = 0x4D;
        bytes[1] = 0x5A;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3C, 4), 0x80);
        bytes[0x80] = 0x50;
        bytes[0x81] = 0x45;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x84, 2), 0x8664);
        bytes[0x200] = marker;
        return bytes;
    }

    private static string Sha(string path) =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    private static string Sha(byte[] bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));
}
