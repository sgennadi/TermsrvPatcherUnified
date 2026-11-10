using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using UniversalUpdater;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Manual self-update: run a protected copy of the CURRENT executable after
/// the GUI exits. The shared transaction replaces the target, probes the new
/// executable and rolls it back if the health probe fails.
/// </summary>
internal static class UpdateInstallBridge
{
    internal const string HelperArgument = "--update-helper";
    internal const string ProbeArgument = "--update-probe";
    internal const string ExecutableName = "TermsrvPatcherUnified.exe";
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private sealed record Job(
        string TargetPath, string TargetSha256, int ParentProcessId,
        DateTimeOffset CreatedUtc, string CandidateVersion, string CandidateTag,
        string CandidateAssetUrl, long CandidateAssetSize,
        string ArchivePath, string ArchiveSha256,
        string ExtractedExePath, string ExtractedExeSha256,
        UpdateChannel Channel);

    internal static bool CanInstall(out string reason)
    {
        if (!OperatingSystem.IsWindows() ||
            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture !=
                System.Runtime.InteropServices.Architecture.X64)
        {
            reason = "Manual update requires Windows x64.";
            return false;
        }
        if (!SystemInfo.IsAdministrator())
        {
            reason = "Restart as administrator to install updates.";
            return false;
        }
        if (Environment.ProcessPath is not { } current ||
            !string.Equals(Path.GetFileName(current), ExecutableName,
                StringComparison.OrdinalIgnoreCase) || !File.Exists(current))
        {
            reason = "Install is available only in the packaged TermsrvPatcherUnified.exe.";
            return false;
        }
        if (!IsSafePortableInstallTarget(current, out reason))
            return false;
        reason = "";
        return true;
    }

    private const System.Security.AccessControl.FileSystemRights MutatingRights =
        System.Security.AccessControl.FileSystemRights.WriteData |
        System.Security.AccessControl.FileSystemRights.AppendData |
        System.Security.AccessControl.FileSystemRights.WriteExtendedAttributes |
        System.Security.AccessControl.FileSystemRights.WriteAttributes |
        System.Security.AccessControl.FileSystemRights.Delete |
        System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles |
        System.Security.AccessControl.FileSystemRights.ChangePermissions |
        System.Security.AccessControl.FileSystemRights.TakeOwnership;

    internal static bool HasMutatingRights(System.Security.AccessControl.FileSystemRights rights) =>
        (rights & MutatingRights) != 0;

    // Portable releases run from a user-selected local folder. The elevated
    // helper stays in administrator-owned ProgramData and validates the
    // original EXE hash, downloaded archive, staged EXE and post-install
    // probe. Desktop/Downloads are valid; redirects and network targets are
    // not silently followed.
    internal static bool IsSafePortableInstallTarget(string path, out string reason)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) ||
                !Path.IsPathFullyQualified(path) ||
                path.StartsWith(@"\\", StringComparison.Ordinal) ||
                !Path.GetFileName(path).Equals(ExecutableName,
                    StringComparison.OrdinalIgnoreCase))
            {
                reason = "Select a local TermsrvPatcherUnified.exe, not a network or redirected file.";
                return false;
            }
            var full = Path.GetFullPath(path);
            if (!File.Exists(full))
            {
                reason = "Application executable is missing.";
                return false;
            }
            var driveRoot = Path.GetPathRoot(full) ??
                throw new IOException("Cannot determine the target drive.");
            var type = new DriveInfo(driveRoot).DriveType;
            if (type is not (DriveType.Fixed or DriveType.Removable))
            {
                reason = "Automatic EXE replacement requires a local fixed or USB drive.";
                return false;
            }
            if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("EXE is a filesystem link.");
            for (DirectoryInfo? dir = new DirectoryInfo(Path.GetDirectoryName(full)!);
                 dir is not null; dir = dir.Parent)
            {
                if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Installation folder or ancestor is a filesystem link.");
            }
            reason = "";
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or
                                   UnauthorizedAccessException or NotSupportedException or
                                   System.Security.SecurityException)
        {
            reason = "Cannot safely update this local EXE: " + ex.GetType().Name +
                ". Use a regular local folder without junctions or symlinks.";
            return false;
        }
    }

    private static string ProtectedRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "TermsrvPatcherUnified.NativeProtected");

    private static string UpdaterRoot => Path.Combine(ProtectedRoot, "Updater");

    private static string CreatePrivateJobDirectory()
    {
        NsudoDevilModeScope.EnsurePrivateDirectory(ProtectedRoot);
        NsudoDevilModeScope.EnsurePrivateDirectory(UpdaterRoot);
        var directory = Path.Combine(UpdaterRoot, Guid.NewGuid().ToString("N"));
        NsudoDevilModeScope.EnsurePrivateDirectory(directory);
        return directory;
    }

    private static void VerifyPrivateJobDirectory(string directory)
    {
        var name = Path.GetFileName(directory);
        if (!Guid.TryParseExact(name, "N", out _) ||
            !string.Equals(Path.GetFullPath(directory),
                Path.Combine(UpdaterRoot, name), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected updater helper directory.");
        NsudoDevilModeScope.EnsurePrivateDirectory(ProtectedRoot);
        NsudoDevilModeScope.EnsurePrivateDirectory(UpdaterRoot);
        NsudoDevilModeScope.EnsurePrivateDirectory(directory);
    }

    /// <summary>
    /// Called ONLY after a successful live GitHub check and an explicit
    /// confirmation acknowledging that preview binaries are unsigned.
    /// </summary>
    internal static async Task PrepareAndLaunchAsync(UpdateChannel channel,
        UpdateRelease release, IProgress<UpdateProgress>? progress, CancellationToken token)
    {
        if (!CanInstall(out var reason)) throw new InvalidOperationException(reason);
        var options = UpdateIntegration.Options(channel);
        if (release.Repository != options.Repository || release.Rule.Architecture != "win-x64" ||
            release.Rule.Kind != PackageKind.SingleExeZip ||
            release.Rule.AssetName != "TermsrvPatcherUnified-update-win-x64.zip" ||
            release.Rule.SingleExecutableName != ExecutableName ||
            release.Version <= SemanticVersion.Parse(options.InstalledVersion))
            throw new InvalidDataException("The live release does not match this updater.");
        if (new UpdateStateStore(options).Read().FailureHold)
            throw new InvalidOperationException("A previous failed update requires administrator review.");

        using var downloader = new UpdateDownloader();
        var stage = await downloader.StageAsync(options, release, progress, token);
        token.ThrowIfCancellationRequested();

        var target = Path.GetFullPath(Environment.ProcessPath!);
        var targetSha = await ShaAsync(target, token);
        var directory = CreatePrivateJobDirectory();
        var helper = Path.Combine(directory, ExecutableName);

        // The downloaded EXE is NEVER used as an elevated updater helper.
        File.Copy(target, helper, overwrite: false);
        if (!string.Equals(await ShaAsync(helper, token), targetSha,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Trusted helper copy changed during preparation.");

        var job = new Job(target, targetSha, Environment.ProcessId, DateTimeOffset.UtcNow,
            release.Version.ToString(), release.Tag, release.AssetUrl.AbsoluteUri,
            release.SizeBytes, stage.ArchivePath, stage.ArchiveSha256,
            stage.ExtractedExecutablePath ?? throw new InvalidDataException("No staged EXE."),
            stage.ExtractedExecutableSha256 ?? throw new InvalidDataException("No staged EXE hash."),
            channel);
        var jobPath = Path.Combine(directory, "update-job.json");
        await File.WriteAllTextAsync(jobPath, JsonSerializer.Serialize(job, Json), token);
        token.ThrowIfCancellationRequested();

        using var helperProcess = Process.Start(new ProcessStartInfo(helper)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = directory,
            ArgumentList = { HelperArgument, jobPath }
        }) ?? throw new IOException("Could not start the verified updater helper.");
        AuditLog.Append("Manual updater accepted an approved release: " + release.Version);
    }

    internal static int Probe(string expectedVersion)
    {
        // Offline start check. No DLL modification, NSudo hooks, or RDP access.
        if (!string.Equals(expectedVersion, UpdateIntegration.Version, StringComparison.Ordinal) ||
            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture !=
                System.Runtime.InteropServices.Architecture.X64 ||
            !NsudoDevilModeScope.IsBundled) return 5;
        try
        {
            // Exercise embedded pattern resources without touching the Windows DLL.
            return PatchCatalog.LoadAutomatic().Count == 3 ? 0 : 5;
        }
        catch { return 5; }
    }

    internal static int RunHelper(string jobFile)
    {
        // Do not block a captured WPF SynchronizationContext in OnStartup.
        try { return Task.Run(() => RunHelperAsync(jobFile)).GetAwaiter().GetResult(); }
        catch (Exception ex)
        {
            AuditLog.Append("Updater helper failed: " + ex.GetType().Name);
            return 6;
        }
    }

    private static async Task<int> RunHelperAsync(string jobFile)
    {
        // The helper intentionally runs from the protected ProgramData cache,
        // not from Program Files. Validate the helper's protected folder below,
        // and check the actual TARGET installation path separately.
        if (!OperatingSystem.IsWindows() ||
            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture !=
                System.Runtime.InteropServices.Architecture.X64 || !SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Updater helper requires elevated Windows x64.");
        var helperPath = Path.GetFullPath(Environment.ProcessPath!);
        var directory = Path.GetDirectoryName(helperPath)!;
        var expectedJob = Path.Combine(directory, "update-job.json");
        if (!string.Equals(Path.GetFullPath(jobFile), expectedJob,
                StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Updater requires its protected job file.");
        VerifyPrivateJobDirectory(directory);
        var inProgress = Path.Combine(directory, "update-job.running");
        File.Move(expectedJob, inProgress); // Single-use job, no replay.
        var job = JsonSerializer.Deserialize<Job>(await File.ReadAllTextAsync(inProgress))
            ?? throw new InvalidDataException("Update job is incomplete.");
        var age = DateTimeOffset.UtcNow - job.CreatedUtc;
        if (age < TimeSpan.Zero || age > TimeSpan.FromMinutes(15))
            throw new InvalidDataException("Update job expired.");
        if (!IsSafePortableInstallTarget(job.TargetPath, out var targetReason))
            throw new UnauthorizedAccessException("Updater target path failed local safety checks: " + targetReason);
        if (!Path.IsPathFullyQualified(job.TargetPath) ||
            !string.Equals(job.TargetPath, Path.GetFullPath(job.TargetPath),
                StringComparison.Ordinal) ||
            !string.Equals(Path.GetFileName(job.TargetPath), ExecutableName,
                StringComparison.OrdinalIgnoreCase) ||
            !ValidSha(job.TargetSha256) || !ValidSha(job.ArchiveSha256) ||
            !ValidSha(job.ExtractedExeSha256) || job.ParentProcessId <= 0 ||
            job.ParentProcessId == Environment.ProcessId)
            throw new InvalidDataException("Update job is not valid.");
        if (!string.Equals(await ShaAsync(helperPath, CancellationToken.None),
                job.TargetSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Updater helper is not the current installed version.");

        var options = UpdateIntegration.Options(job.Channel);
        var next = SemanticVersion.Parse(job.CandidateVersion);
        if (next <= SemanticVersion.Parse(options.InstalledVersion) ||
            (job.CandidateTag != "v" + job.CandidateVersion &&
             job.CandidateTag != job.CandidateVersion) ||
            job.CandidateAssetUrl !=
                $"https://github.com/{options.Repository}/releases/download/{job.CandidateTag}/TermsrvPatcherUnified-update-win-x64.zip" ||
            job.CandidateAssetSize is < 1 or > 536870912)
            throw new InvalidDataException("Update does not match the pinned GitHub release.");

        // Wait for the original GUI's executable file mapping to be released.
        try
        {
            using var parent = Process.GetProcessById(job.ParentProcessId);
            if (!parent.WaitForExit(90000))
                throw new TimeoutException("Application did not exit for replacement.");
        }
        catch (ArgumentException) { /* The parent already exited. */ }

        if (!File.Exists(job.TargetPath) ||
            !string.Equals(await ShaAsync(job.TargetPath, CancellationToken.None),
                job.TargetSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Original EXE changed before installation.");
        var rule = options.Assets.Single();
        var release = new UpdateRelease(options.Repository, next, job.CandidateTag,
            $"https://github.com/{options.Repository}/releases/tag/{job.CandidateTag}",
            "", null, rule, new Uri(job.CandidateAssetUrl),
            job.CandidateAssetSize, job.ArchiveSha256);
        var staged = new StagedPackage(release, job.ArchivePath, job.ArchiveSha256,
            job.ExtractedExePath, job.ExtractedExeSha256);
        var transaction = new PortableExeTransaction();
        var installDir = Path.GetDirectoryName(job.TargetPath)!;
        var result = await transaction.ApplyManualAsync(options, staged,
            installDir, ExecutableName, explicitlyApproved: true,
            async (exe, ct) => await ProbeInstalledAsync(exe, job.CandidateVersion, ct));
        AuditLog.Append("EXE replacement result: " + result.Summary);
        if (result.Success)
        {
            try
            {
                // Keep the explicitly enabled SYSTEM worker in sync with the
                // newly installed, verified EXE rather than launching the
                // original Desktop/Downloads executable as SYSTEM.
                AutoReapplyScheduler.RefreshWorkerAfterSuccessfulUpdate(job.TargetPath);
            }
            catch (Exception error)
            {
                AuditLog.Append("Verified EXE updated; auto-reapply worker refresh needs review: " +
                    error.GetType().Name);
            }
        }
        try { File.Delete(inProgress); } catch (IOException) { }

        if (result.Success || result.RolledBack)
            Process.Start(new ProcessStartInfo(job.TargetPath)
            {
                UseShellExecute = true,
                WorkingDirectory = installDir
            });
        return result.Success ? 0 : 7;
    }

    private static async Task<bool> ProbeInstalledAsync(string exe, string version,
        CancellationToken cancellationToken)
    {
        using var process = Process.Start(new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true,
            ArgumentList = { ProbeArgument, version }
        });
        if (process is null) return false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            return false;
        }
        return process.ExitCode == 0;
    }

    private static bool ValidSha(string value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static async Task<string> ShaAsync(string file, CancellationToken token)
    {
        await using var source = new FileStream(file, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(source, token));
    }
}
