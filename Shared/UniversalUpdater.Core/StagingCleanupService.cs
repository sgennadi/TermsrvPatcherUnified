using System.Text.RegularExpressions;

namespace UniversalUpdater;

/// <summary>
/// Bounded cleaning of old updater-owned UUID staging directories only.
/// Never deletes unknown names, a rollback checkpoint, history or files outside staging.
/// A failure hold preserves all staging for inspection. Use dry-run first.
/// </summary>
public sealed record StagingCleanupResult(
    int Scanned, int Eligible, int Deleted, int Skipped,
    bool Held, bool DryRun);

public static class StagingCleanupService
{
    private const int MaximumDirectoriesPerRun = 128;
    private const int MaximumNodesPerDirectory = 4096;
    private static readonly Regex UuidDirectory = new(@"\A[0-9a-f]{32}\z",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250));

    public static StagingCleanupResult Run(UpdateOptions options,
        TimeSpan retention, bool dryRun = true, DateTimeOffset? nowUtc = null)
    {
        options.Validate();
        if (retention < TimeSpan.FromDays(1) || retention > TimeSpan.FromDays(365))
            throw new ArgumentOutOfRangeException(nameof(retention));
        var state = new UpdateStateStore(options).Read();
        if (state.FailureHold)
            return new StagingCleanupResult(0, 0, 0, 0, true, dryRun);

        var root = UpdateStateStore.GetStagingRoot(options);
        if (!Directory.Exists(root))
            return new StagingCleanupResult(0, 0, 0, 0, false, dryRun);
        var info = new DirectoryInfo(root);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Staging root must not be a filesystem link.");

        var cutoff = (nowUtc ?? DateTimeOffset.UtcNow).UtcDateTime - retention;
        int scanned = 0, eligible = 0, deleted = 0, skipped = 0;
        foreach (var candidate in info.EnumerateDirectories().Take(MaximumDirectoriesPerRun))
        {
            scanned++;
            if (!UuidDirectory.IsMatch(candidate.Name) ||
                !IsOldSafeTree(candidate, cutoff))
            {
                skipped++;
                continue;
            }
            eligible++;
            if (dryRun) continue;
            try
            {
                candidate.Delete(recursive: true);
                deleted++;
            }
            catch (IOException) { skipped++; }
            catch (UnauthorizedAccessException) { skipped++; }
        }
        return new StagingCleanupResult(scanned, eligible, deleted, skipped, false, dryRun);
    }

    private static bool IsOldSafeTree(DirectoryInfo root, DateTime cutoff)
    {
        try
        {
            var stack = new Stack<DirectoryInfo>();
            stack.Push(root);
            var nodes = 0;
            while (stack.Count > 0)
            {
                var directory = stack.Pop();
                if (++nodes > MaximumNodesPerDirectory ||
                    (directory.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    directory.LastWriteTimeUtc > cutoff)
                    return false;
                foreach (var child in directory.EnumerateFileSystemInfos())
                {
                    if (++nodes > MaximumNodesPerDirectory ||
                        (child.Attributes & FileAttributes.ReparsePoint) != 0 ||
                        child.LastWriteTimeUtc > cutoff)
                        return false;
                    if (child is DirectoryInfo subdirectory) stack.Push(subdirectory);
                }
            }
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
}
