using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using UniversalUpdater;

/// <summary>
/// Exercises actual published single-file EXEs and the shared EXE transaction.
/// Uses disposable temp files only. Never touches termsrv.dll, RDP or Program Files.
/// </summary>
internal static class PublishedUpgradeTests
{
    private const string ExeName = "TermsrvPatcherUnified.exe";
    private const string AssetName = "TermsrvPatcherUnified-update-win-x64.zip";
    private const string Repository = "sgennadi/TermsrvPatcherUnified";

    internal static int Run(string oldZip, string newZip, string oldVersion, string newVersion)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (SemanticVersion.Parse(newVersion) <= SemanticVersion.Parse(oldVersion))
            throw new InvalidDataException("Upgrade requires a newer candidate version.");
        var root = Path.Combine(Path.GetTempPath(),
            "Termsrv-PublishedUpgrade-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            var oldExe = ExtractOne(oldZip, Path.Combine(root, "old"));
            var newExe = ExtractOne(newZip, Path.Combine(root, "new"));
            PeSafety.ValidateArchitecture(oldExe, "win-x64");
            PeSafety.ValidateArchitecture(newExe, "win-x64");
            var oldSha = Hash(oldExe);
            var newSha = Hash(newExe);
            if (oldSha == newSha ||
                !Probe(oldExe, oldVersion).GetAwaiter().GetResult() ||
                !Probe(newExe, newVersion).GetAwaiter().GetResult() ||
                Probe(newExe, oldVersion).GetAwaiter().GetResult() ||
                Probe(oldExe, newVersion).GetAwaiter().GetResult())
                throw new Exception("Released EXE identities or offline version probes are wrong.");

            RunCase(root, "success", oldExe, newExe, newZip, oldVersion, newVersion,
                oldSha, newSha, rejectProbe: false);
            RunCase(root, "rollback", oldExe, newExe, newZip, oldVersion, newVersion,
                oldSha, newSha, rejectProbe: true);
            RunTamper(root, oldExe, newExe, newZip, oldVersion, newVersion, oldSha, newSha);
            Console.WriteLine("PASS: real published EXEs, offline probes, backup, upgrade, " +
                "probe-failure rollback, previous backup retention and staged tamper rejection.");
            Console.WriteLine("LIMIT: disposable file tests only, not a live Program Files updater or DLL patch.");
            return 3;
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static string ExtractOne(string zipPath, string directory)
    {
        using var archive = ZipFile.OpenRead(Path.GetFullPath(zipPath));
        if (archive.Entries.Count != 1 || archive.Entries[0].FullName != ExeName ||
            archive.Entries[0].Length < 4096)
            throw new InvalidDataException("Release update ZIP must have exactly one x64 EXE.");
        Directory.CreateDirectory(directory);
        var output = Path.Combine(directory, ExeName);
        using (var entry = archive.Entries[0].Open())
        using (var target = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            entry.CopyTo(target);
        return output;
    }

    private static (UpdateOptions Options, StagedPackage Package, string Directory, string Target)
        Stage(string root, string caseName, string oldExe, string newExe, string releaseZip,
            string oldVersion, string newVersion, string newSha)
    {
        var installDir = Path.Combine(root, caseName, "installed");
        Directory.CreateDirectory(installDir);
        var target = Path.Combine(installDir, ExeName);
        File.Copy(oldExe, target);
        var rule = new UpdateAssetRule("win-x64", AssetName, PackageKind.SingleExeZip, ExeName);
        var options = new UpdateOptions
        {
            ProductId = "TermsrvPublishedUpgradeQA",
            Repository = Repository,
            Architecture = "win-x64",
            InstalledVersion = oldVersion,
            Channel = UpdateChannel.Prerelease,
            StateDirectory = Path.Combine(root, caseName, "state"),
            Assets = [rule]
        };
        var stagingDir = Path.Combine(options.StateDirectory!, options.ProductId,
            "staging", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stagingDir);
        var stagedExe = Path.Combine(stagingDir, ExeName);
        var stagedArchive = Path.Combine(stagingDir, AssetName);
        File.Copy(newExe, stagedExe);
        File.Copy(releaseZip, stagedArchive);
        var archiveSha = Hash(stagedArchive);
        var tag = "v" + newVersion;
        var release = new UpdateRelease(Repository, SemanticVersion.Parse(newVersion),
            tag, "https://github.com/" + Repository + "/releases/tag/" + tag,
            "Published EXE regression", null, rule,
            new Uri("https://github.com/" + Repository + "/releases/download/" + tag + "/" + AssetName),
            new FileInfo(stagedArchive).Length, archiveSha);
        var package = new StagedPackage(release, stagedArchive, archiveSha, stagedExe, newSha);
        return (options, package, installDir, target);
    }

    private static void RunCase(string root, string caseName, string oldExe, string newExe,
        string releaseZip, string oldVersion, string newVersion, string oldSha, string newSha,
        bool rejectProbe)
    {
        var x = Stage(root, caseName, oldExe, newExe, releaseZip, oldVersion, newVersion, newSha);
        var originalBackup = System.Text.Encoding.ASCII.GetBytes("Existing backup checkpoint.");
        if (rejectProbe) File.WriteAllBytes(x.Target + ".bak", originalBackup);
        int probes = 0;
        var result = new PortableExeTransaction().ApplyManualAsync(
            x.Options, x.Package, x.Directory, ExeName, explicitlyApproved: true,
            async (installed, ct) =>
            {
                probes++;
                if (Path.GetFullPath(installed) != x.Target || Hash(installed) != newSha ||
                    !await Probe(installed, newVersion, ct))
                    throw new Exception("Installed new EXE is invalid or failed real probe.");
                return !rejectProbe; // Force a second-stage health failure for rollback.
            }).GetAwaiter().GetResult();
        if (probes != 1) throw new Exception("Expected exactly one health probe.");
        var state = new UpdateStateStore(x.Options).Read();
        if (rejectProbe)
        {
            if (result.Success || !result.RolledBack || Hash(x.Target) != oldSha ||
                !state.FailureHold || state.LastResultCode != "INSTALL_FAILED_RESTORED" ||
                !File.Exists(x.Target + ".bak") ||
                !File.ReadAllBytes(x.Target + ".bak").SequenceEqual(originalBackup) ||
                !Probe(x.Target, oldVersion).GetAwaiter().GetResult())
                throw new Exception("Failed health probe did not restore EXE and prior backup.");
        }
        else
        {
            if (!result.Success || result.RolledBack || Hash(x.Target) != newSha ||
                !File.Exists(x.Target + ".bak") || Hash(x.Target + ".bak") != oldSha ||
                state.FailureHold || state.LastResultCode != "INSTALL_OK" ||
                !Probe(x.Target, newVersion).GetAwaiter().GetResult())
                throw new Exception("Real EXE upgrade, backup or final probe failed.");
        }
    }

    private static void RunTamper(string root, string oldExe, string newExe, string releaseZip,
        string oldVersion, string newVersion, string oldSha, string newSha)
    {
        var x = Stage(root, "tampered", oldExe, newExe, releaseZip,
            oldVersion, newVersion, newSha);
        using (var staged = new FileStream(x.Package.ExtractedExecutablePath!,
                   FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            staged.Position = 256;
            int old = staged.ReadByte();
            staged.Position = 256;
            staged.WriteByte((byte)(old ^ 0x01));
        }
        bool blocked = false;
        try
        {
            _ = new PortableExeTransaction().ApplyManualAsync(
                x.Options, x.Package, x.Directory, ExeName, explicitlyApproved: true,
                (_, _) => throw new Exception("Tampered EXE reached health probe"))
                .GetAwaiter().GetResult();
        }
        catch (InvalidDataException) { blocked = true; }
        if (!blocked || Hash(x.Target) != oldSha || File.Exists(x.Target + ".bak"))
            throw new Exception("Updater did not reject tampered staging before replace.");
    }

    private static async Task<bool> Probe(string file, string version,
        CancellationToken cancellation = default)
    {
        using var p = Process.Start(new ProcessStartInfo(file)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "--update-probe", version }
        }) ?? throw new InvalidOperationException("Cannot run offline EXE probe.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(35));
        try { await p.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            return false;
        }
        return p.ExitCode == 0;
    }

    private static string Hash(string file)
    {
        using var input = File.OpenRead(file);
        return Convert.ToHexStringLower(SHA256.HashData(input));
    }
}
