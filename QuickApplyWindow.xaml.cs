using System.Windows;
using System.Windows.Threading;
using System.Windows.Media;
using TermsrvPatcherUnified.Core;
using UniversalUpdater;

namespace TermsrvPatcherUnified;

/// <summary>
/// Compact first-run view when a trusted automatic plan is available.
/// The actual Apply is executed in a separate one-shot SYSTEM process.
/// Closing this window never cancels an already scheduled operation.
/// </summary>
public partial class QuickApplyWindow : Window
{
    private PatchPlan? plan;
    private PatchPlan? completedAppliedPlan;
    private AutomaticRevertPlan? revertPlan;
    private readonly DispatcherTimer statusTimer;
    private bool checking;
    private bool queued;
    private string? activeJobId;
    private bool autoTaskLoading;
    private bool autoTaskChanging;
    private string? promptedJobId;
    private bool autoUpdateLoading;
    private bool autoUpdateChanging;
    private readonly UpdateIntegration updates = new();
    private readonly AutoUpdateGuiCoordinator autoUpdateCoordinator;

    public QuickApplyWindow()
    {
        InitializeComponent();
        Title = "TermsrvPatcherUnified " + UpdateIntegration.Version;
        QuickVersionText.Text = UpdateIntegration.Version + "   •   Remote Desktop maintenance";
        autoUpdateCoordinator = new AutoUpdateGuiCoordinator(this, updates,
            () => IsActive && !checking && !queued && !autoTaskChanging && !autoUpdateChanging);
        Loaded += (_, _) => WindowLayout.FitToWorkArea(this);
        statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        statusTimer.Tick += (_, _) => RefreshJobStatus();
        Closed += (_, _) => { statusTimer.Stop(); autoUpdateCoordinator.Dispose(); updates.Dispose(); };
        foreach (var channel in new[] { UpdateChannel.Stable, UpdateChannel.Prerelease })
            updates.Get(channel).NoticeChanged += (_, _) =>
                Dispatcher.BeginInvoke(RefreshUpdateIndicator);
        RefreshUpdateIndicator();
        Loaded += async (_, _) =>
        {
            statusTimer.Start();
            ReadAutoUpdateSetting();
            autoUpdateCoordinator.Start();
            await RefreshAutoReapplyAsync();
            await CheckAsync();
            _ = StartupUpdatesAsync();
        };
    }

    internal void SetBackupPreference(bool createFullBackup)
        => QuickNoBackupCheck.IsChecked = !createFullBackup;

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
        QuickStatusText.Foreground = new SolidColorBrush(Color.FromRgb(11, 46, 90));
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
            // A verified recovery source is a GOOD result, even when the
            // installed DLL is already patched. Do not color it like a failure.
            QuickStatusText.Foreground = revertPlan is not null &&
                revertPlan.RecoverySource != "ExactCatalog"
                ? new SolidColorBrush(Color.FromRgb(11, 135, 76))
                : plan.State == PatchState.AlreadyPatched &&
                  revertPlan?.RecoverySource != "ExactCatalog"
                    ? new SolidColorBrush(Color.FromRgb(185, 28, 28))
                    : new SolidColorBrush(Color.FromRgb(11, 46, 90));
            BackupOptionChanged(this, new RoutedEventArgs());
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
            QuickStatusText.Foreground = new SolidColorBrush(Color.FromRgb(185, 28, 28));
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
        var approval = ModernMessageDialog.Show(this,
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
        if (!createFullBackup && ModernMessageDialog.Show(this,
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
                completedAppliedPlan = approvedPlan;
                plan = null;
                QuickStatusText.Text = "Apply completed and verified";
                QuickHelpText.Text = "Local console operation succeeded. Use Check to verify DLL state.";
                QuickStatusText.Foreground = new SolidColorBrush(Color.FromRgb(11, 135, 76));
                QuickShareReportButton.Visibility = Visibility.Visible;
                QuickCancelButton.Content = "Close";
                Dispatcher.BeginInvoke(new Action(OfferReportAfterSuccessfulApply));
                return;
            }

            QuickStatusText.Text = "Starting the protected SYSTEM task...";
            string id = await Task.Run(() => IsolatedApplyExecutor.Queue(plan, createFullBackup));
            completedAppliedPlan = plan;
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
            QuickStatusText.Foreground = new SolidColorBrush(Color.FromRgb(185, 28, 28));
            QuickHelpText.Text = ex.GetType().Name + ": " + ex.Message;
            ModernMessageDialog.Show(this,
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
        if (ModernMessageDialog.Show(this,
                operation + "\n\nThis temporarily stops RDP and may disconnect remote users.\n\n" +
                route + "\n\nResult SHA-256: " + approved.OriginalSha256[..16] +
                "...\n\nRetain VM console access and an independent recovery option.",
                sourceFree ? "Confirm emergency reconstruction" : "Confirm Revert",
                MessageBoxButton.YesNo, MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        if (sourceFree && ModernMessageDialog.Show(this,
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
                // Green means authenticated recovery success; a catalog-based
                // reconstruction is not proof of an authentic Windows original.
                QuickStatusText.Foreground = sourceFree
                    ? new SolidColorBrush(Color.FromRgb(160, 92, 14))
                    : new SolidColorBrush(Color.FromRgb(11, 135, 76));
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
            QuickStatusText.Foreground = new SolidColorBrush(Color.FromRgb(185, 28, 28));
            QuickHelpText.Text = ex.GetType().Name + ". Open Advanced for diagnostics.";
            ModernMessageDialog.Show(this, "Protected Revert did not complete:\n" + ex.Message,
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
        if (QuickBackupInfoText is null || QuickNoBackupCheck is null) return;
        bool verifiedBackup = revertPlan?.RecoverySource is "System32Backup" or "TrustedBackup";
        bool verifiedJournal = revertPlan?.RecoverySource == "Journal";
        QuickBackupInfoText.Text = verifiedBackup
            ? "Verified original DLL backup available for Revert."
            : verifiedJournal
                ? "Verified protected recovery journal available for Revert."
                : QuickNoBackupCheck.IsChecked == true
                    ? "Next Apply: no full backup, protected recovery journal still required."
                    : "Next Apply: full backup selected (not yet verified on disk).";
        QuickBackupInfoText.Foreground = verifiedBackup || verifiedJournal
            ? new SolidColorBrush(Color.FromRgb(11, 135, 76))
            : new SolidColorBrush(Color.FromRgb(100, 116, 139));
    }

    private void RefreshJobStatus()
    {
        if (checking) return;
        var status = IsolatedApplyExecutor.ReadLatestStatus();
        if (status is null || activeJobId is not null &&
            !status.Id.Equals(activeJobId, StringComparison.OrdinalIgnoreCase)) return;
        // Only a persistent terminal record authorizes claiming success.
        bool isRevert = status.Details.Contains("Revert", StringComparison.OrdinalIgnoreCase);
        // This is an audit/status record, not proof of current DLL health.
        // Reopening the GUI after RDP logoff still displays the most recent
        // SYSTEM worker result, even when no in-memory queued flag survives.
        QuickLastJobText.Text = status.State is
            ("Queued" or "Running" or "Succeeded" or "AlreadyPatched" or
             "Failed" or "Unconfirmed")
            ? "Last " + (isRevert ? "Revert" : "Apply") + " task " + status.Id[..8] +
              ": " + status.State + " (recorded; Check confirms current DLL)."
            : "";
        QuickLastJobText.Foreground = status.State == "Succeeded"
            ? new SolidColorBrush(Color.FromRgb(11, 135, 76))
            : status.State == "Failed"
                ? new SolidColorBrush(Color.FromRgb(185, 28, 28))
                : new SolidColorBrush(Color.FromRgb(100, 116, 139));
        QuickShareReportButton.Visibility = status.State == "Succeeded" && !isRevert &&
            completedAppliedPlan is not null
            ? Visibility.Visible : Visibility.Collapsed;
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
        QuickStatusText.Foreground = status.State == "Succeeded"
            ? new SolidColorBrush(Color.FromRgb(11, 135, 76))
            : status.State == "Failed"
                ? new SolidColorBrush(Color.FromRgb(185, 28, 28))
                : new SolidColorBrush(Color.FromRgb(11, 46, 90));
        QuickCancelButton.Content = "Close";
        if (status.State == "Succeeded" && !isRevert &&
            activeJobId is not null &&
            status.Id.Equals(activeJobId, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(promptedJobId, status.Id, StringComparison.OrdinalIgnoreCase))
        {
            promptedJobId = status.Id;
            Dispatcher.BeginInvoke(new Action(OfferReportAfterSuccessfulApply));
        }
    }

    private void OfferReportAfterSuccessfulApply()
    {
        if (!IsLoaded || completedAppliedPlan is not
            { State: PatchState.Ready, PatchedBytes: not null } completedPlan)
            return;
        try
        {
            // A previous successful job is not proof that the same DLL remains
            // installed; compare the complete hash before offering its report.
            using var engine = new TermsrvEngine(null);
            var os = engine.EnvironmentInfo();
            string actualHash = SystemInfo.Sha256(File.ReadAllBytes(os.DllPath));
            if (!string.Equals(actualHash, SystemInfo.Sha256(completedPlan.PatchedBytes),
                    StringComparison.OrdinalIgnoreCase))
            {
                QuickHelpText.Text = "DLL changed since Apply; report unavailable.";
                QuickShareReportButton.Visibility = Visibility.Collapsed;
                return;
            }
            var metadata = SuccessfulFixMetadata.FromSuccessfulApply(os, completedPlan);
            if (new SuccessfulFixWindow(metadata) { Owner = this }.ShowDialog() == true)
                QuickShareReportButton.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            AuditLog.Append("Unified completed-Apply report unavailable: " +
                            ex.GetType().Name);
            QuickHelpText.Text = "Could not prepare the combined report. " +
                                 "No information was uploaded automatically.";
        }
    }

    private void ShareReport_Click(object sender, RoutedEventArgs e)
        => OfferReportAfterSuccessfulApply();

    private async void Check_Click(object sender, RoutedEventArgs e) => await CheckAsync();


    private async Task RefreshAutoReapplyAsync()
    {
        if (autoTaskChanging) return;
        var state = await Task.Run(AutoReapplyScheduler.ReadStatus);
        autoTaskLoading = true;
        try
        {
            QuickAutoReapplyCheck.IsChecked = state.Installed && state.Trusted && state.Enabled;
            QuickAutoReapplyCheck.IsEnabled = !checking && !queued &&
                (!state.Installed || state.Trusted);
            bool autoReportApproved = AutoCompatibilityReporting.IsEnabled(
                DirectReportingSettings.Load().GoogleAppsScriptUrl);
            QuickAutoReapplyStatus.Text = state.Message +
                (state.Installed && !state.Trusted && !state.Repairable
                    ? " Open Task Scheduler for manual review." : "") +
                (autoReportApproved
                    ? " Silent unified reports: consent ON."
                    : " Silent unified reports: OFF.");
            QuickRevokeAutoReportsButton.Visibility = autoReportApproved
                ? Visibility.Visible : Visibility.Collapsed;
            QuickRevokeAutoReportsButton.IsEnabled =
                autoReportApproved && SystemInfo.IsAdministrator() && !queued;
            QuickRepairTaskButton.Visibility = state.Repairable
                ? Visibility.Visible : Visibility.Collapsed;
            QuickRepairTaskButton.IsEnabled = state.Repairable && !checking && !queued &&
                SystemInfo.IsAdministrator() && !autoTaskChanging;
        }
        finally { autoTaskLoading = false; }
    }

    private async void RevokeAutoReports_Click(object sender, RoutedEventArgs e)
    {
        if (checking || queued || !SystemInfo.IsAdministrator()) return;
        if (ModernMessageDialog.Show(this,
                "Stop all future silent diagnostic and compatibility reports? " +
                "Auto Reapply stays enabled. No DLL or backups are changed.",
                "Disable automatic reports", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        try { await Task.Run(AutoCompatibilityReporting.Revoke); }
        catch (Exception ex)
        {
            QuickAutoReapplyStatus.Text = "Cannot revoke automatic reporting (" +
                ex.GetType().Name + ").";
        }
        await RefreshAutoReapplyAsync();
    }

    private async void RepairAutoReapply_Click(object sender, RoutedEventArgs e)
    {
        if (checking || queued || autoTaskChanging || !SystemInfo.IsAdministrator()) return;
        var task = AutoReapplyScheduler.ReadStatus();
        if (!task.Repairable || ModernMessageDialog.Show(this,
                "The existing task matches the program's SYSTEM action and schedule, " +
                "but Windows returned additional task permissions.\n\n" +
                "Restrict this task to SYSTEM and Administrators? " +
                "The DLL, backups and task triggers will not be changed.",
                "Repair Auto Reapply permissions", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        autoTaskChanging = true;
        QuickRepairTaskButton.IsEnabled = false;
        QuickAutoReapplyStatus.Text = "Verifying and repairing task permissions...";
        try
        {
            await Task.Run(AutoReapplyScheduler.RepairTaskPermissions);
            QuickAutoReapplyStatus.Text = "Scheduled task permissions verified.";
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Task ACL repair", ex);
            ModernMessageDialog.Show(this,
                "Could not verify protected task permissions (" + ex.GetType().Name +
                "). No task definition was replaced. Review Task Scheduler.",
                "Task permissions", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            autoTaskChanging = false;
            await RefreshAutoReapplyAsync();
        }
    }

    private async void AutoReapplyChanged(object sender, RoutedEventArgs e)
    {
        if (QuickAutoReapplyStatus is null || autoTaskLoading || autoTaskChanging) return;
        if (checking || queued) { await RefreshAutoReapplyAsync(); return; }
        bool enable = QuickAutoReapplyCheck.IsChecked == true;
        var status = AutoReapplyScheduler.ReadStatus();
        if (status.Installed && !status.Trusted ||
            !enable && !status.Installed)
        {
            await RefreshAutoReapplyAsync();
            return;
        }
        if (enable && ModernMessageDialog.Show(this,
                "Create a protected SYSTEM task to inspect termsrv.dll after Windows Update, " +
                "after restart and daily? It will apply ONLY a verified exact automatic profile " +
                "to a changed DLL, with full backup. You must have console recovery access. " +
                "No pattern will be guessed.",
                "Enable Auto Reapply", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            await RefreshAutoReapplyAsync();
            return;
        }
        if (!enable && ModernMessageDialog.Show(this,
                "Remove the persistent Auto Reapply task? Your DLL and backups remain unchanged.",
                "Disable Auto Reapply", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            await RefreshAutoReapplyAsync();
            return;
        }
        autoTaskChanging = true;
        QuickAutoReapplyCheck.IsEnabled = false;
        QuickAutoReapplyStatus.Text = enable ? "Creating protected task..." : "Removing task...";
        try
        {
            await Task.Run(() =>
            {
                if (enable) AutoReapplyScheduler.Enable();
                else AutoReapplyScheduler.Disable();
            });
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Auto Reapply", ex);
            ModernMessageDialog.Show(this, "Could not update the scheduled task: " + ex.Message,
                "Auto Reapply", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            autoTaskChanging = false;
            await RefreshAutoReapplyAsync();
        }
    }

    private async void Cleanup_Click(object sender, RoutedEventArgs e)
    {
        if (checking || queued)
        {
            ModernMessageDialog.Show(this, "Finish the current protected operation before Cleanup.");
            return;
        }
        new CleanupWindow { Owner = this }.ShowDialog();
        await RefreshAutoReapplyAsync();
        await CheckAsync();
    }

    private void ReadAutoUpdateSetting()
    {
        autoUpdateLoading = true;
        try
        {
            bool enabled = AutoUpdatePreferences.IsEnabled();
            QuickAutoUpdateCheck.IsChecked = enabled;
            QuickAutoUpdateCheck.IsEnabled = SystemInfo.IsAdministrator() && !autoUpdateChanging;
            QuickAutoUpdateStatus.Text = AutoUpdatePreferences.Label(enabled) +
                Environment.NewLine + AutoUpdatePreferences.ReadScheduledSummary() +
                (enabled && !AutoReapplyScheduler.ReadStatus().Enabled
                    ? Environment.NewLine +
                      "Scheduled checks run only when the protected Auto Reapply task is enabled." : "");
        }
        finally { autoUpdateLoading = false; }
    }

    private async void AutoUpdateChanged(object sender, RoutedEventArgs e)
    {
        if (QuickAutoUpdateStatus is null || autoUpdateLoading || autoUpdateChanging) return;
        bool enable = QuickAutoUpdateCheck.IsChecked == true;
        if (enable && ModernMessageDialog.Show(this,
                "Check Stable GitHub Releases at app launch and every four hours; " +
                "when enabled, the trusted Auto Reapply task checks for updates as well. " +
                "No automatic unsigned EXE installation occurs in a scheduled task. " +
                "The interactive Update Center must confirm each installation. Continue?",
                "Enable automatic update checks", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            ReadAutoUpdateSetting();
            return;
        }
        autoUpdateChanging = true;
        QuickAutoUpdateCheck.IsEnabled = false;
        try { await Task.Run(() => AutoUpdatePreferences.SetEnabled(enable)); }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Auto-update", ex);
            ModernMessageDialog.Show(this, "Automatic check preference was not changed: " + ex.Message,
                "Auto-update", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            autoUpdateChanging = false;
            ReadAutoUpdateSetting();
        }
        if (enable && AutoUpdatePreferences.IsEnabled())
            _ = autoUpdateCoordinator.CheckNowAsync();
    }

    private async Task StartupUpdatesAsync()
    {
        await BackgroundUpdateCheckAsync();
        await autoUpdateCoordinator.CheckNowAsync();
    }

    private async Task BackgroundUpdateCheckAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            foreach (var channel in new[] { UpdateChannel.Stable, UpdateChannel.Prerelease })
                await updates.Get(channel).CheckAsync(
                    forced: false, cancellationToken: timeout.Token);
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Updates", ex);
        }
    }

    private void RefreshUpdateIndicator() =>
        UpdateButtonIndicator.Apply(
            QuickUpdatesButton,
            updates.Get(UpdateChannel.Stable).Notice,
            updates.Get(UpdateChannel.Prerelease).Notice);

    private void Updates_Click(object sender, RoutedEventArgs e) =>
        new UpdateCenterWindow(updates) { Owner = this }.ShowDialog();

    private void Advanced_Click(object sender, RoutedEventArgs e)
    {
        // Change the application owner before closing the quick window:
        // OnMainWindowClose must not terminate the new Advanced window.
        var advanced = new MainWindow();
        advanced.SetBackupPreference(QuickNoBackupCheck.IsChecked != true);
        Application.Current.MainWindow = advanced;
        advanced.Show();
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();
}
