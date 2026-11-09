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
        // The plan is a display hint; CheckAsync will independently re-check
        // before the first Apply, and Queue() checks it again.
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
            QuickHelpText.Text = authorized
                ? "One verified signature. Backup is mandatory; the task runs independently of RDP."
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

        var approval = MessageBox.Show(this,
            "Apply the verified automatic patch with a mandatory protected backup?\n\n" +
            "The separate SYSTEM executor may stop Remote Desktop services and disconnect " +
            "this RDP session. It continues independently of this window, but a VM snapshot " +
            "or local console recovery is still recommended. Confirm only where permitted by " +
            "the applicable Windows license.",
            "Confirm independent Apply", MessageBoxButton.YesNo,
            MessageBoxImage.Warning, MessageBoxResult.No);
        if (approval != MessageBoxResult.Yes) return;

        checking = true;
        QuickApplyButton.IsEnabled = false;
        QuickCheckButton.IsEnabled = false;
        QuickStatusText.Text = "Preparing protected SYSTEM executor...";
        try
        {
            string id = await Task.Run(() => IsolatedApplyExecutor.Queue(plan));
            queued = true;
            QuickStatusText.Text = "Queued independently of RDP";
            QuickHelpText.Text = "Job " + id[..8] +
                " is running under SYSTEM. You may close this window. " +
                "Reopen the app to inspect the result.";
            QuickCancelButton.Content = "Close";
            statusTimer.Start();
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Independent Apply", ex);
            QuickStatusText.Text = "Apply was not started";
            QuickHelpText.Text = ex.GetType().Name + ": " + ex.Message;
            MessageBox.Show(this,
                "No protected job was confirmed.\n" + ex.Message,
                "Independent Apply not started", MessageBoxButton.OK,
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
        if (status is null) return;
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
