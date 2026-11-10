using System.Windows;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

/// <summary>Explicitly reviewed app-data cleanup. No silent or automatic removal.</summary>
public partial class CleanupWindow : Window
{
    private bool running;

    public CleanupWindow()
    {
        InitializeComponent();
        var task = AutoReapplyScheduler.ReadStatus();
        CleanupTaskStatus.Text = task.Installed
            ? "Current task: " + (task.Trusted ? task.Message : "UNRECOGNIZED; cannot be removed automatically")
            : "No Auto Reapply task is currently configured.";
        CleanupTaskCheck.IsEnabled = !task.Installed || task.Trusted;
        Render();
    }

    private CleanupService.Options Selected => new(
        CleanupBackupsCheck.IsChecked == true,
        CleanupReportsCheck.IsChecked == true,
        CleanupTaskCheck.IsChecked == true);

    private void SelectionChanged(object sender, RoutedEventArgs e) => Render();

    private void Render()
    {
        if (CleanupExecuteButton is null || CleanupPreview is null) return;
        var selected = Selected;
        CleanupExecuteButton.IsEnabled = !running &&
            (selected.Backups || selected.LocalReports || selected.ScheduledTask);
        CleanupPreview.Text = CleanupService.Preview(selected);
    }

    private async void Execute_Click(object sender, RoutedEventArgs e)
    {
        if (running) return;
        var selected = Selected;
        if (!selected.Backups && !selected.LocalReports && !selected.ScheduledTask) return;
        if (selected.Backups && ModernMessageDialog.Show(this,
                "This removes all application-managed DLL backups and protected recovery journals, " +
                "including the System32 .bak. If the installed DLL is patched, Revert may become impossible. " +
                "Windows servicing or an original DLL copy may be required. Continue?",
                "Delete recovery options?", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        if (selected.ScheduledTask && ModernMessageDialog.Show(this,
                "Remove the persistent Auto Reapply Task Scheduler job as well? " +
                "After removal, Windows Update will no longer trigger automatic checking.",
                "Remove the scheduled task?", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        if (ModernMessageDialog.Show(this,
                "Remove the selected TermsrvPatcherUnified files now?\n\n" +
                CleanupService.Preview(selected) +
                "\n\nThis action cannot be undone.",
                "Confirm Cleanup", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        running = true;
        CleanupBackupsCheck.IsEnabled = false;
        CleanupReportsCheck.IsEnabled = false;
        CleanupTaskCheck.IsEnabled = false;
        Render();
        try
        {
            var result = await Task.Run(() => CleanupService.Clean(selected));
            ModernMessageDialog.Show(this, result, "Cleanup finished",
                MessageBoxButton.OK, MessageBoxImage.Information);
            DialogResult = true;
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Cleanup", ex);
            ModernMessageDialog.Show(this,
                "Cleanup was not completed. Some selected files may already have been removed.\n\n" +
                ex.GetType().Name + ": " + ex.Message,
                "Cleanup needs review", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            running = false;
            CleanupBackupsCheck.IsEnabled = true;
            CleanupReportsCheck.IsEnabled = true;
            var status = AutoReapplyScheduler.ReadStatus();
            CleanupTaskCheck.IsEnabled = !status.Installed || status.Trusted;
            Render();
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
