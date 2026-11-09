using System.Windows;
using System.Windows.Threading;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

/// <summary>
/// Compact first-run view when a trusted automatic plan is available.
/// The actual Apply is executed in a separate one-shot SYSTEM process.
/// Closing this window never cancels an already scheduled operation.
/// </summary>
public partial class QuickApplyWindow : Window
{
    private PatchPlan? plan;
    private readonly DispatcherTimer statusTimer;
    private bool checking;
    private bool queued;
    private string? activeJobId;

    public QuickApplyWindow()
    {
        InitializeComponent();
        statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        statusTimer.Tick += (_, _) => RefreshJobStatus();
        Closed += (_, _) => statusTimer.Stop();
        Loaded += async (_, _) =>
        {
            statusTimer.Start();
            await CheckAsync();
        };
    }

    internal void SetInitialPlan(PatchPlan checkedPlan)
    {
        // This is a display hint. Both console Apply and the isolated
        // scheduled worker independently re-check the DLL before writing.
        plan = checkedPlan;
    }

    private async Task CheckAsync()
    {
        if (checking || queued) return;
        checking = true;
        QuickApplyButton.IsEnabled = false;
        QuickCheckButton.IsEnabled = false;
        QuickStatusText.Text = "Checking installed DLL...";
        QuickHelpText.Text = "Comparing full exact signatures and SHA-256.";
        try
        {
            var result = await Task.Run(() =>
            {
                using var engine = new TermsrvEngine(null);
                var os = engine.EnvironmentInfo();
                var candidate = engine.Inspect();
                return (os, candidate);
            });
            plan = result.candidate;
            QuickSystemText.Text = result.os.Display;
            QuickDllText.Text = "termsrv.dll " + result.os.DllVersion;
            bool authorized = plan.State == PatchState.Ready &&
                !plan.IsManual && result.os.Supported &&
                SystemInfo.IsAdministrator() && NsudoDevilModeScope.IsBundled;
            QuickApplyButton.IsEnabled = authorized;
            QuickStatusText.Text = authorized ? "Ready to apply" :
                plan.State == PatchState.AlreadyPatched ? "Already patched" :
                "Automatic Apply unavailable";
            var session = InteractiveSessionDetector.Detect();
            QuickHelpText.Text = authorized
                ? (session == SessionKind.Console
                    ? "Local console: normal protected Apply with backup."
                    : "RDP or uncertain session: protected SYSTEM task, independent of this window.")
                : "No eligible single-target automatic plan. Open Advanced to see details.";
        }
        catch (Exception e)
        {
            plan = null;
            QuickApplyButton.IsEnabled = false;
            QuickStatusText.Text = "Automatic check could not complete";
            QuickHelpText.Text = e.GetType().Name + ". Open Advanced for diagnostics.";
        }
        finally
        {
            checking = false;
            QuickCheckButton.IsEnabled = !queued;
            RefreshJobStatus();
        }
    }

    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (checking || queued || plan?.State != PatchState.Ready ||
            !SystemInfo.IsAdministrator() || !NsudoDevilModeScope.IsBundled)
            return;

        var initialMode = InteractiveSessionDetector.Detect();
        string executionText = initialMode == SessionKind.Console
            ? "LOCAL CONSOLE: Apply will run normally in the elevated GUI."
            : "RDP / UNCONFIRMED: Apply will run as an independent one-shot SYSTEM task.";
        var approval = MessageBox.Show(this,
            "Apply the verified automatic patch with a mandatory protected backup?\n\n" +
            executionText + "\n\n" +
            "Remote Desktop services can restart during Apply. Retain a VM snapshot " +
            "or local console recovery access and follow applicable Windows licensing.",
            "Confirm protected Apply", MessageBoxButton.YesNo,
            MessageBoxImage.Warning, MessageBoxResult.No);
        if (approval != MessageBoxResult.Yes) return;

        checking = true;
        QuickApplyButton.IsEnabled = false;
        QuickCheckButton.IsEnabled = false;
        try
        {
            // Re-evaluate IMMEDIATELY before dispatch, not at startup.
            // Unknown is handled like RDP to avoid terminating a fragile session.
            var mode = InteractiveSessionDetector.Detect();
            if (mode == SessionKind.Console)
            {
                QuickStatusText.Text = "Applying from the local console...";
                var approvedPlan = plan;
                await Task.Run(() =>
                {
                    using var engine = new TermsrvEngine(null);
                    var fresh = engine.Inspect();
                    if (fresh.State != PatchState.Ready ||
                        fresh.OriginalSha256 != approvedPlan.OriginalSha256 ||
                        fresh.ProfileId != approvedPlan.ProfileId ||
                        fresh.FileVersion != approvedPlan.FileVersion)
                        throw new InvalidOperationException("DLL changed since check. Run Check again.");
                    engine.Apply(fresh, createBackup: true);
                });
                plan = null;
                QuickStatusText.Text = "Apply completed and verified";
                QuickHelpText.Text = "Local console operation succeeded. Use Check to verify DLL state.";
                QuickCancelButton.Content = "Close";
                return;
            }

            QuickStatusText.Text = "Starting the protected SYSTEM task...";
            string id = await Task.Run(() => IsolatedApplyExecutor.Queue(plan));
            activeJobId = id;
            queued = true;
            QuickStatusText.Text = "Queued independently of RDP";
            QuickHelpText.Text = "Job " + id[..8] +
                " was accepted by Task Scheduler. Wait for Running or Succeeded status. " +
                "Closing this window does not cancel the task.";
            QuickCancelButton.Content = "Close";
            statusTimer.Start();
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Protected Apply", ex);
            QuickStatusText.Text = "Apply failed or did not start";
            QuickHelpText.Text = ex.GetType().Name + ": " + ex.Message;
            MessageBox.Show(this,
                "Protected Apply did not complete successfully.\n" + ex.Message,
                "Protected Apply", MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            checking = false;
            QuickCheckButton.IsEnabled = !queued;
            if (!queued && plan is { State: PatchState.Ready })
                QuickApplyButton.IsEnabled = SystemInfo.IsAdministrator() &&
                                             NsudoDevilModeScope.IsBundled;
        }
    }

    private void RefreshJobStatus()
    {
        if (checking) return;
        var status = IsolatedApplyExecutor.ReadLatestStatus();
        if (status is null || activeJobId is not null &&
            !status.Id.Equals(activeJobId, StringComparison.OrdinalIgnoreCase)) return;
        // Only a persistent terminal record authorizes claiming success.
        if (status.State is "Queued" or "Running")
        {
            queued = true;
            QuickApplyButton.IsEnabled = false;
            QuickCheckButton.IsEnabled = false;
            QuickCancelButton.Content = "Close";
            QuickStatusText.Text = status.State == "Running"
                ? "SYSTEM executor is running" : "Protected operation queued";
            QuickHelpText.Text = "You may disconnect RDP. Reopen the application to see the final result.";
            return;
        }
        if (!queued) return;
        queued = false;
        QuickCheckButton.IsEnabled = true;
        QuickStatusText.Text = status.State switch
        {
            "Succeeded" => "Apply completed and verified",
            "AlreadyPatched" => "Already patched",
            "Failed" => "Apply failed",
            _ => "Check job status in Advanced"
        };
        QuickHelpText.Text = status.State == "Failed"
            ? "Local failure type: " + status.Details + ". Check operations.log and RDP health."
            : status.Details;
        QuickCancelButton.Content = "Close";
    }

    private async void Check_Click(object sender, RoutedEventArgs e) => await CheckAsync();

    private void Advanced_Click(object sender, RoutedEventArgs e)
    {
        // Change the application owner before closing the quick window:
        // OnMainWindowClose must not terminate the new Advanced window.
        var advanced = new MainWindow();
        Application.Current.MainWindow = advanced;
        advanced.Show();
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();
}
