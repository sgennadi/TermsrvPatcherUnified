namespace UniversalUpdater;

/// <summary>Explicit local rollback to a prior .bak; never runs as an unattended downgrade.</summary>
public sealed class ManualRollbackService
{
    public async Task<UpdateInstallResult> RollbackAsync(
        UpdateOptions options, string trustedInstallDirectory, string trustedExecutableName,
        bool explicitlyApproved, Func<string, CancellationToken, Task<bool>> healthProbe,
        CancellationToken cancellationToken = default)
    {
        if (!explicitlyApproved)
            throw new UnauthorizedAccessException("A manual rollback requires explicit confirmation.");
        ArgumentNullException.ThrowIfNull(healthProbe);
        options.Validate();
        if (!Path.IsPathFullyQualified(trustedInstallDirectory) ||
            !UpdateOptions.IsSafeFileName(trustedExecutableName) ||
            !trustedExecutableName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Invalid local rollback destination.");
        var root = Path.GetFullPath(trustedInstallDirectory);
        var target = Path.Combine(root, trustedExecutableName);
        var backup = target + ".bak";
        if (!File.Exists(target) || !File.Exists(backup))
            throw new FileNotFoundException("A previous executable checkpoint is not available.");
        RejectLink(root); RejectLink(target); RejectLink(backup);
        // A failure hold must not prevent a deliberate recovery operation.
        await using var gate = new FileStream(Path.Combine(root, ".universalupdater.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        cancellationToken.ThrowIfCancellationRequested();
        RejectLink(target); RejectLink(backup);
        PeSafety.ValidateArchitecture(backup, options.Architecture);
        var id = Guid.NewGuid().ToString("N");
        var candidate = Path.Combine(root, $".{trustedExecutableName}.{id}.rollback");
        var snapshot = Path.Combine(root, $".{trustedExecutableName}.{id}.snapshot");
        var restore = Path.Combine(root, $".{trustedExecutableName}.{id}.restore");
        bool replaced = false;
        bool restored = false;
        var state = new UpdateStateStore(options);
        try
        {
            File.Copy(backup, candidate, overwrite: false);
            File.Replace(candidate, target, snapshot, ignoreMetadataErrors: false);
            replaced = true;
            if (!await healthProbe(target, cancellationToken))
                throw new InvalidOperationException("Rolled-back application did not pass its self-test.");
            // Preserve the replaced newer executable in .bak (one-generation undo).
            File.Move(snapshot, backup, overwrite: true);
            state.Hold("MANUAL_ROLLBACK");
            TryRecordHistory(options, "ROLLBACK", "MANUAL_ROLLBACK");
            return new UpdateInstallResult(true, true, "MANUAL_ROLLBACK");
        }
        catch (Exception)
        {
            if (replaced && File.Exists(snapshot))
            {
                try
                {
                    File.Copy(snapshot, restore, overwrite: false);
                    File.Replace(restore, target, null, ignoreMetadataErrors: false);
                    restored = true;
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            state.Hold(restored || !replaced ? "ROLLBACK_ABORTED" : "ROLLBACK_REQUIRES_ATTENTION");
            TryRecordHistory(options, "ROLLBACK", restored || !replaced ? "ROLLBACK_ABORTED" : "ROLLBACK_REQUIRES_ATTENTION");
            return new UpdateInstallResult(false, false,
                restored || !replaced ? "ROLLBACK_ABORTED" : "ROLLBACK_REQUIRES_ATTENTION");
        }
        finally
        {
            TryDelete(candidate);
            TryDelete(restore);
            // Preserve snapshot on incomplete recovery for a technician to inspect.
            if (replaced && restored) TryDelete(snapshot);
        }
    }
    private static void TryRecordHistory(UpdateOptions options, string operation, string result)
    {
        try { new UpdateHistoryStore(options).Append(options.ProductId, operation, "", "", result); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
    private static void RejectLink(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Rollback paths must be real files/directories.");
    }
    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
