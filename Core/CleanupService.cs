using System.IO;
using UniversalDiagnostics;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Explicitly authorized application-data cleanup. Never alters installed
/// termsrv.dll, Windows event logs, Windows Update history or external reports.
/// </summary>
internal static class CleanupService
{
    internal sealed record Options(bool Backups, bool LocalReports, bool ScheduledTask);

    internal static string Preview(Options options)
    {
        var groups = new List<string>();
        if (options.Backups)
            groups.Add("All application-owned DLL backups, System32 termsrv.dll.bak, and encrypted recovery journals (Revert may become unavailable)");
        if (options.LocalReports)
            groups.Add("Application operation log, local history, health baseline, reviewed diagnostic queue and completed worker records");
        if (options.ScheduledTask)
            groups.Add("The TermsrvPatcherUnified-AutoReapply scheduled task and its protected worker/state");
        if (groups.Count == 0) return "Nothing selected.";
        return string.Join(Environment.NewLine, groups.Select(g => "  • " + g)) +
            Environment.NewLine + Environment.NewLine +
            "Not included: live DLL, Windows Event Logs, system restore, updater rollback state, exported files outside application folders.";
    }

    internal static string Clean(Options options)
    {
        if (!options.Backups && !options.LocalReports && !options.ScheduledTask)
            throw new InvalidOperationException("Select at least one cleanup category.");
        if (!OperatingSystem.IsWindows() || !SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Administrator rights required for Cleanup.");
        if (IsolatedApplyExecutor.AnyActiveJob() ||
            AutoReapplyScheduler.ReadStatus().Running)
            throw new InvalidOperationException(
                "A SYSTEM worker is pending, running or unconfirmed. Finish it before Cleanup.");
        using var gate = OperationLock.Acquire();
        if (IsolatedApplyExecutor.AnyActiveJob() ||
            AutoReapplyScheduler.ReadStatus().Running)
            throw new InvalidOperationException(
                "A SYSTEM worker started while Cleanup was preparing; no files were removed.");
        int removed = 0;

        // Task removal is explicit and independent from ordinary data cleanup.
        // Delete it before its worker files, so no scheduled restart points to a missing EXE.
        if (options.ScheduledTask)
        {
            AutoReapplyScheduler.Disable();
            removed += DeleteTree(AutoReapplyScheduler.Root, protectedRoot: true);
        }

        if (options.Backups)
        {
            var bak = System32BackupStore.BackupPath;
            if (File.Exists(bak))
            {
                if ((File.GetAttributes(bak) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("System32 backup is a filesystem link; cleanup refused.");
                // Only this exact fixed .bak path is ever eligible for elevated deletion.
                using var elevated = NsudoDevilModeScope.Enter();
                File.Delete(bak);
                removed++;
            }
            removed += DeleteTree(TermsrvEngine.BackupDirectory, protectedRoot: true);
            removed += DeleteTree(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TermsrvPatcherUnified.Secure", "System32Backup"), protectedRoot: true);
            removed += DeleteTree(RecoveryJournalStore.Root, protectedRoot: true);
            removed += DeleteTree(TermsrvEngine.LegacyBackupDirectory, protectedRoot: false);
        }

        if (options.LocalReports)
        {
            removed += DeleteFile(Path.Combine(AuditLog.Root, "operations.log"));
            removed += DeleteTree(Path.GetDirectoryName(OperationHistory.LocalFile)!,
                protectedRoot: false);
            removed += DeleteTree(Path.GetDirectoryName(DllHealthMonitor.LocalBaselineFile)!,
                protectedRoot: false);
            var queue = UniversalDiagnosticsEmbedded.QueueDirectory(DiagnosticsBridge.Project);
            var userRoot = Path.GetFullPath(Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData)).TrimEnd(Path.DirectorySeparatorChar);
            if (!Path.GetFullPath(queue).StartsWith(
                userRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Diagnostics queue is not inside the local profile.");
            removed += DeleteTree(queue, protectedRoot: false);
            // Completed one-shot task records are application-owned. Never delete
            // files from an untrusted or active executor directory.
            removed += DeleteTree(IsolatedApplyExecutor.Root, protectedRoot: true);
        }
        // Do not append to the removed operations.log: that would immediately
        // recreate files that the user requested to clear.
        return $"Cleanup completed: {removed} application file(s) or folder(s) removed. " +
            "Windows event logs and external files were untouched.";
    }

    private static int DeleteFile(string file)
    {
        if (!File.Exists(file)) return 0;
        CheckUnlinked(file, directory: false);
        File.Delete(file);
        return 1;
    }

    private static int DeleteTree(string directory, bool protectedRoot)
    {
        if (!Directory.Exists(directory)) return 0;
        CheckUnlinked(directory, directory: true);
        if (protectedRoot)
        {
            string parent = Path.GetDirectoryName(directory) ??
                throw new IOException("Protected directory has no parent.");
            NsudoDevilModeScope.EnsurePrivateDirectory(parent);
            NsudoDevilModeScope.EnsurePrivateDirectory(directory);
        }
        int remainingBudget = 8192;
        return DeleteDirectoryRecursive(directory, ref remainingBudget);
    }

    private static int DeleteDirectoryRecursive(string directory, ref int remainingBudget)
    {
        CheckUnlinked(directory, directory: true);
        if (--remainingBudget <= 0)
            throw new IOException("Cleanup item limit exceeded. No further files removed.");
        int removed = 0;
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory, "*",
                     SearchOption.TopDirectoryOnly))
        {
            bool isFolder = (File.GetAttributes(entry) & FileAttributes.Directory) != 0;
            CheckUnlinked(entry, isFolder);
            if (isFolder)
                removed += DeleteDirectoryRecursive(entry, ref remainingBudget);
            else
            {
                File.Delete(entry);
                removed++;
            }
        }
        Directory.Delete(directory, recursive: false);
        return removed + 1;
    }

    private static void CheckUnlinked(string path, bool directory)
    {
        var info = File.GetAttributes(path);
        if ((info & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Cleanup refuses filesystem links or junctions: " + Path.GetFileName(path));
        if (((info & FileAttributes.Directory) != 0) != directory)
            throw new IOException("Unexpected cleanup entry type: " + Path.GetFileName(path));
        var ancestor = directory ? new DirectoryInfo(path) :
            new DirectoryInfo(Path.GetDirectoryName(path)!);
        for (; ancestor is not null; ancestor = ancestor.Parent)
            if ((ancestor.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Cleanup refuses a linked ancestor directory.");
    }
}
