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
    private AutomaticRevertPlan? revertPlan;
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
        QuickRevertButton.IsEnabled = false;
        QuickCheckButton.IsEnabled = false;
        QuickNoBackupCheck.IsEnabled = false;
        QuickStatusText.Text = "Checking installed DLL...";
        QuickHelpText.Text = "Comparing full exact signatures and SHA-256.";
        try
        {
            var result = await Task.Run(() =>
            {
                using var engine = new TermsrvEngine(null);
                var os = engine.EnvironmentInfo();
                var candidate = engine.Inspect();
                AutomaticRevertPlan? recovery = null;
                try { recovery = AutomaticRevertSafety.Inspect(); }
                catch (Exception ex)
                {
                    // Recovery metadata may be damaged by an OS update or
                    // security tool. Never let it authorize Revert or block
                    // a separate, read-only automatic signature Check.
                    AuditLog.Append("Compact Revert eligibility unavailable: " + ex.GetType().Name);
                }
                return (os, candidate, recovery);
            });
            plan = result.candidate;
            revertPlan = result.recovery;
            QuickSystemText.Text = result.os.Display;
            QuickDllText.Text = "termsrv.dll " + result.os.DllVersion;
            bool authorized = plan.State == PatchState.Ready &&
                !plan.IsManual && result.os.Supported &&
                SystemInfo.IsAdministrator() && NsudoDevilModeScope.IsBundled;
            QuickApplyButton.IsEnabled = authorized;
            QuickRevertButton.IsEnabled = revertPlan is not null &&
                SystemInfo.IsAdministrator() && NsudoDevilModeScope.IsBundled;
            QuickStatusText.Text = authorized ? "Ready to apply" :
                revertPlan?.RecoverySource == "ExactCatalog"
                    ? "Revert by known signature (no original backup)" :
                revertPlan is not null ? "Verified original available for Revert" :
                plan.State == PatchState.AlreadyPatched ? "Already patched" :
                "Automatic Apply unavailable";
            var session = InteractiveSessionDetector.Detect();
            QuickHelpText.Text = authorized
                ? (session == SessionKind.Console
                    ? "Local console: direct protected Apply. Full backup is optional."
                    : "RDP or uncertain session: one-shot SYSTEM task, independent of the window.")
                : revertPlan is not null
                    ? revertPlan.RecoverySource == "ExactCatalog"
                        ? "NO BACKUP/JOURNAL: bytes reconstructible from fixed catalog; " +
                          "not proof of a genuine Microsoft original. Review before Revert."
                        : (session == SessionKind.Console
                            ? "Original SHA-256 verified against protected recovery."
                            : "Protected Revert will continue under SYSTEM after RDP disconnect.")
                    : plan.State == PatchState.AlreadyPatched
                        ? "No safe saved source or reversible fixed signature. " +
                          "Use Advanced and Windows SFC/DISM recovery; Revert disabled."
                        : "No verified one-click action. Open Advanced for details.";
        }
        catch (Exception e)
        {
            plan = null;
            revertPlan = null;
            QuickApplyButton.IsEnabled = false;
            QuickRevertButton.IsEnabled = false;
            QuickStatusText.Text = "Automatic check could not complete";
            QuickHelpText.Text = e.GetType().Name + ". Open Advanced for diagnostics.";
        }
        finally
        {
            checking = false;
            QuickCheckButton.IsEnabled = !queued;
            QuickNoBackupCheck.IsEnabled = !queued;
            RefreshJobStatus();
        }
    }

    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (checking || queued || plan?.State != PatchState.Ready ||
            !SystemInfo.IsAdministrator() || !NsudoDevilModeScope.IsBundled)
            return;

        bool createFullBackup = QuickNoBackupCheck.IsChecked != true;
        var initialMode = InteractiveSessionDetector.Detect();
        string executionText = initialMode == SessionKind.Console
            ? "LOCAL CONSOLE: Apply will run normally in the elevated GUI."
            : "RDP / UNCONFIRMED: Apply will run as an independent one-shot SYSTEM task.";
        var approval = MessageBox.Show(this,
            "Apply the verified automatic patch?\n\n" +
            (createFullBackup
                ? "Full backup ON: create/refresh System32 termsrv.dll.bak and protected archived copy.\n"
                : "Full backup OFF: no new DLL .bak / ProgramData copy. Authenticated recovery journal REQUIRED.\n") +
            executionText + "\n\n" +
            "Remote Desktop services can restart during Apply. Retain a VM snapshot " +
            "or local console recovery access and follow applicable Windows licensing.",
            "Confirm protected Apply", MessageBoxButton.YesNo,
            MessageBoxImage.Warning, MessageBoxResult.No);
        if (approval != MessageBoxResult.Yes) return;
        if (!createFullBackup && MessageBox.Show(this,
                "Do not create backup is selected. The encrypted recovery journal stores only the " +
                "original changed bytes. If Windows Update replaces this DLL or the local DPAPI " +
                "machine keys are lost, automatic Revert will be unavailable. " +
                "Continue WITHOUT a full DLL backup?",
                "Confirm no full backup", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;

        checking = true;
        QuickApplyButton.IsEnabled = false;
        QuickRevertButton.IsEnabled = false;
        QuickCheckButton.IsEnabled = false;
        QuickNoBackupCheck.IsEnabled = false;
        try
        {
            // Re-evaluate IMMEDIATELY before dispatch, not at startup.
            // Unknown is handled like RDP to avoid terminating a fragile session.
            var mode = InteractiveSessionDetector.Detect();
            if ((initialMode == SessionKind.Console) != (mode == SessionKind.Console))
                throw new InvalidOperationException(
                    "Session type changed after confirmation. Check the DLL and approve again.");
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
                    engine.Apply(fresh, createBackup: createFullBackup);
                });
                plan = null;
                QuickStatusText.Text = "Apply completed and verified";
                QuickHelpText.Text = "Local console operation succeeded. Use Check to verify DLL state.";
                QuickCancelButton.Content = "Close";
                return;
            }

            QuickStatusText.Text = "Starting the protected SYSTEM task...";
            string id = await Task.Run(() => IsolatedApplyExecutor.Queue(plan, createFullBackup));
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
            QuickNoBackupCheck.IsEnabled = !queued;
            if (!queued && plan is { State: PatchState.Ready })
                QuickApplyButton.IsEnabled = SystemInfo.IsAdministrator() &&
                                             NsudoDevilModeScope.IsBundled;
            if (!queued && revertPlan is not null)
                QuickRevertButton.IsEnabled = SystemInfo.IsAdministrator() &&
                                              NsudoDevilModeScope.IsBundled;
        }
    }

    private async void Revert_Click(object sender, RoutedEventArgs e)
    {
        if (checking || queued || revertPlan is null ||
            !SystemInfo.IsAdministrator() || !NsudoDevilModeScope.IsBundled)
            return;
        var approved = revertPlan;
        var initialMode = InteractiveSessionDetector.Detect();
        string route = initialMode == SessionKind.Console
            ? "Local console: Revert runs as a protected transaction."
            : "RDP/unknown session: Revert runs as a separate SYSTEM Session 0 task.";
        bool sourceFree = approved.RecoverySource == "ExactCatalog";
        string operation = sourceFree
            ? "EMERGENCY BYTE RECONSTRUCTION (NO BACKUP/JOURNAL). " +
              "This only reverses a unique fixed embedded signature. " +
              "The resulting SHA-256 is calculated, NOT compared to an authentic Microsoft original."
            : "Restore the original termsrv.dll using verified " + approved.RecoverySource + " evidence.";
        if (MessageBox.Show(this,
                operation + "\n\nThis temporarily stops RDP and may disconnect remote users.\n\n" +
                route + "\n\nResult SHA-256: " + approved.OriginalSha256[..16] +
                "...\n\nRetain VM console access and an independent recovery option.",
                sourceFree ? "Confirm emergency reconstruction" : "Confirm Revert",
                MessageBoxButton.YesNo, MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        if (sourceFree && MessageBox.Show(this,
                "There is NO authenticated backup or recovery journal. " +
                "Matching fixed bytes is not proof that other DLL bytes are original. " +
                "For fully authenticated Windows recovery, use SFC / DISM and a local console. " +
                "Proceed with an unverified, catalog-based reconstruction ONLY on " +
                "an isolated, recoverable machine?",
                "Second confirmation: no original source",
                MessageBoxButton.YesNo, MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        checking = true;
        QuickApplyButton.IsEnabled = false;
        QuickRevertButton.IsEnabled = false;
        QuickCheckButton.IsEnabled = false;
        QuickNoBackupCheck.IsEnabled = false;
        try
        {
            var mode = InteractiveSessionDetector.Detect();
            if ((initialMode == SessionKind.Console) != (mode == SessionKind.Console))
                throw new InvalidOperationException(
                    "Windows session type changed after confirmation. Check and approve Revert again.");
            if (mode == SessionKind.Console)
            {
                QuickStatusText.Text = "Restoring exact original DLL from local console...";
                await Task.Run(() =>
                {
                    using var engine = new TermsrvEngine(null);
                    engine.RevertAutomatic(approved);
                });
                revertPlan = null;
                plan = null;
                QuickStatusText.Text = sourceFree
                    ? "Catalog reconstruction completed; result SHA-256 verified"
                    : "Revert completed and original SHA-256 verified";
                QuickHelpText.Text = sourceFree
                    ? "Authenticity of Windows DLL is NOT established. Validate using Windows servicing tools."
                    : "Protected original restored. Use Check to refresh state.";
                QuickCancelButton.Content = "Close";
                return;
            }
            QuickStatusText.Text = "Queuing protected SYSTEM Revert...";
            string id = await Task.Run(() => IsolatedApplyExecutor.QueueRevert(approved));
            activeJobId = id;
            queued = true;
            QuickStatusText.Text = "Revert queued independently of RDP";
            QuickHelpText.Text = "Job " + id[..8] +
                " accepted by Task Scheduler. Closing this window cannot cancel it. " +
                "Reopen the app to view a verified final status.";
            QuickCancelButton.Content = "Close";
            statusTimer.Start();
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Protected Revert", ex);
            QuickStatusText.Text = "Revert failed or could not start";
            QuickHelpText.Text = ex.GetType().Name + ". Open Advanced for diagnostics.";
            MessageBox.Show(this, "Protected Revert did not complete:\n" + ex.Message,
                "Protected Revert", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            checking = false;
            QuickCheckButton.IsEnabled = !queued;
            QuickNoBackupCheck.IsEnabled = !queued;
            if (!queued && revertPlan is not null)
                QuickRevertButton.IsEnabled = true;
        }
    }

    private void BackupOptionChanged(object sender, RoutedEventArgs e)
    {
        if (QuickBackupInfoText is null) return;
        QuickBackupInfoText.Text = QuickNoBackupCheck.IsChecked == true
            ? "No full DLL backup. A small DPAPI-protected recovery journal is still required."
            : "Full backup ON: verified System32 .bak plus protected archived original.";
    }

    private void RefreshJobStatus()
    {
        if (checking) return;
        var status = IsolatedApplyExecutor.ReadLatestStatus();
        if (status is null || activeJobId is not null &&
            !status.Id.Equals(activeJobId, StringComparison.OrdinalIgnoreCase)) return;
        // Only a persistent terminal record authorizes claiming success.
        bool isRevert = status.Details.Contains("Revert", StringComparison.OrdinalIgnoreCase);
        if (status.State is "Queued" or "Running")
        {
            queued = true;
            QuickApplyButton.IsEnabled = false;
            QuickRevertButton.IsEnabled = false;
            QuickCheckButton.IsEnabled = false;
            QuickNoBackupCheck.IsEnabled = false;
            QuickCancelButton.Content = "Close";
            QuickStatusText.Text = status.State == "Running"
                ? (isRevert ? "SYSTEM Revert is running" : "SYSTEM Apply is running")
                : (isRevert ? "Revert queued" : "Apply queued");
            QuickHelpText.Text = "You may disconnect RDP. Reopen the application to see the final result.";
            return;
        }
        if (!queued) return;
        queued = false;
        QuickCheckButton.IsEnabled = true;
        QuickNoBackupCheck.IsEnabled = true;
        QuickStatusText.Text = status.State switch
        {
            "Succeeded" => isRevert ? "Revert completed and verified" : "Apply completed and verified",
            "AlreadyPatched" => "Already patched",
            "Failed" => isRevert ? "Revert failed" : "Apply failed",
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
