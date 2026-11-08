using System.Security.Cryptography;

namespace UniversalUpdater;

/// <summary>
/// Manual, transactional single-EXE replacement. Must run from a trusted helper after
/// the target process exits; no arbitrary command execution, UAC bypass or auto-install.
/// </summary>
public sealed class PortableExeTransaction
{
    public async Task<UpdateInstallResult> ApplyManualAsync(
        UpdateOptions options,
        StagedPackage staged,
        string trustedInstallDirectory,
        string trustedExecutableFileName,
        bool explicitlyApproved,
        Func<string, CancellationToken, Task<bool>> healthProbe,
        CancellationToken cancellationToken = default)
    {
        if (!explicitlyApproved)
            throw new UnauthorizedAccessException("Manual installation requires an explicit operator decision.");
        ArgumentNullException.ThrowIfNull(healthProbe);
        options.Validate();
        if (staged.Release.Rule.Kind is not (PackageKind.SingleExeZip or PackageKind.DirectExe) ||
            staged.Release.Rule.Architecture != options.Architecture ||
            staged.Release.Repository != options.Repository ||
            staged.Release.Version <= SemanticVersion.Parse(options.InstalledVersion) ||
            (staged.Release.Rule.Kind == PackageKind.DirectExe
                ? staged.Release.Rule.AssetName : staged.Release.Rule.SingleExecutableName) != trustedExecutableFileName ||
            !options.Assets.Any(rule => rule == staged.Release.Rule) ||
            staged.ExtractedExecutablePath is null || staged.ExtractedExecutableSha256 is null ||
            !IsSha(staged.ExtractedExecutableSha256) || !IsSha(staged.ArchiveSha256))
            throw new InvalidDataException("Invalid or ineligible staged single EXE package.");

        if (!Path.IsPathFullyQualified(trustedInstallDirectory) ||
            !UpdateOptions.IsSafeFileName(trustedExecutableFileName))
            throw new InvalidDataException("Trusted installation path is invalid.");
        var installDir = Path.GetFullPath(trustedInstallDirectory);
        if (!Directory.Exists(installDir))
            throw new DirectoryNotFoundException("The application install directory does not exist.");
        RejectReparsePoint(installDir);
        var target = Path.Combine(installDir, trustedExecutableFileName);
        if (!File.Exists(target))
            throw new FileNotFoundException("Cannot update an application that is not installed.");
        RejectReparsePoint(target);

        var stageFile = Path.GetFullPath(staged.ExtractedExecutablePath);
        var stagingRoot = Path.GetFullPath(UpdateStateStore.GetStagingRoot(options));
        var expectedParent = Path.GetDirectoryName(stageFile)!;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!string.Equals(Path.GetDirectoryName(expectedParent), stagingRoot, comparison) ||
            !Path.GetFileName(stageFile).Equals(trustedExecutableFileName, StringComparison.Ordinal))
            throw new InvalidDataException("The executable is not inside an approved staging folder.");
        RejectReparsePoint(expectedParent);
        RejectReparsePoint(stageFile);
        var actualStageHash = await UpdateDownloader.HashFileAsync(stageFile, cancellationToken);
        if (!actualStageHash.Equals(staged.ExtractedExecutableSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Staged executable changed after validation.");
        PeSafety.ValidateArchitecture(stageFile, options.Architecture);
        if (!string.Equals(await UpdateDownloader.HashFileAsync(staged.ArchivePath, cancellationToken),
                staged.Release.Sha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(staged.ArchiveSha256, staged.Release.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Release archive changed since it was verified.");

        var state = new UpdateStateStore(options);
        if (state.Read().FailureHold)
            throw new InvalidOperationException("Installation blocked by existing failure/rollback hold.");

        // Same path across users/sessions: lock prevents concurrent manual and scheduled replacement.
        await using var gate = new FileStream(Path.Combine(installDir, ".universalupdater.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        cancellationToken.ThrowIfCancellationRequested();
        if (state.Read().FailureHold)
            throw new InvalidOperationException("Another update has activated a failure hold.");
        RejectReparsePoint(target);
        if (string.Equals(await UpdateDownloader.HashFileAsync(target, cancellationToken),
                actualStageHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The same executable version is already installed.");
        var id = Guid.NewGuid().ToString("N");
        string next = Path.Combine(installDir, $".{trustedExecutableFileName}.{id}.new");
        string backup = target + ".bak";
        string priorBackup = backup + ".prior-" + id;
        string restore = Path.Combine(installDir, $".{trustedExecutableFileName}.{id}.restore");
        bool movedPriorBackup = false;
        bool replaced = false;
        try
        {
            File.Copy(stageFile, next, overwrite: false);
            if (!string.Equals(await UpdateDownloader.HashFileAsync(next, cancellationToken),
                    actualStageHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Pre-install file verification failed.");
            if (File.Exists(backup))
            {
                RejectReparsePoint(backup);
                File.Move(backup, priorBackup);
                movedPriorBackup = true;
            }
            File.Replace(next, target, backup, ignoreMetadataErrors: false);
            replaced = true;
            // Host must check the actual installed file and run a meaningful application self-test.
            bool healthy = await healthProbe(target, cancellationToken);
            if (!healthy) throw new InvalidOperationException("Post-install self-test did not pass.");
            if (!string.Equals(await UpdateDownloader.HashFileAsync(target, CancellationToken.None),
                    actualStageHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Installed executable digest differs from staged digest.");

            var s = state.Read();
            s.Phase = UpdatePhase.Healthy;
            s.LastInstalledUtc = DateTimeOffset.UtcNow;
            s.LastResultCode = "INSTALL_OK";
            s.LastSeenVersion = staged.Release.Version.ToString();
            state.Write(s);
            if (movedPriorBackup) TryDelete(priorBackup);
            TryRecordHistory(options, "INSTALL", options.InstalledVersion,
                staged.Release.Version.ToString(), "INSTALL_OK");
            return new UpdateInstallResult(true, false, "INSTALL_OK");
        }
        catch (Exception)
        {
            // The new version must never be called healthy if post-install checks failed.
            bool restored = !replaced;
            if (replaced)
            {
                try
                {
                    if (!File.Exists(backup)) throw new IOException("Missing rollback checkpoint.");
                    File.Copy(backup, restore, overwrite: false);
                    File.Replace(restore, target, null, ignoreMetadataErrors: false);
                    restored = true;
                }
                catch (Exception rollbackException) when (rollbackException is IOException or UnauthorizedAccessException)
                {
                    restored = false; // Keep all backups for technician recovery.
                }
            }
            if (restored && movedPriorBackup && File.Exists(priorBackup))
            {
                try { File.Move(priorBackup, backup, overwrite: true); }
                catch (IOException) { restored = false; }
                catch (UnauthorizedAccessException) { restored = false; }
            }
            // Hold survives any failed apply, even if the previous EXE was fully restored.
            state.Hold(restored ? "INSTALL_FAILED_RESTORED" : "ROLLBACK_REQUIRES_ATTENTION");
            TryRecordHistory(options, "INSTALL", options.InstalledVersion,
                staged.Release.Version.ToString(), restored ? "INSTALL_FAILED_RESTORED" : "ROLLBACK_REQUIRES_ATTENTION");
            return new UpdateInstallResult(false, replaced && restored,
                restored ? "INSTALL_FAILED_RESTORED" : "ROLLBACK_REQUIRES_ATTENTION");
        }
        finally
        {
            TryDelete(next);
            TryDelete(restore);
            // Never delete priorBackup on failure: it may be the last good checkpoint.
        }
    }

    private static void TryRecordHistory(UpdateOptions options, string action, string previous,
        string next, string result)
    {
        try { new UpdateHistoryStore(options).Append(options.ProductId, action, previous, next, result); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Updater paths must not be filesystem links.");
    }
    private static bool IsSha(string? text) => text is { Length: 64 } && text.All(Uri.IsHexDigit);
    private static void TryDelete(string file)
    {
        try { if (File.Exists(file)) File.Delete(file); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
