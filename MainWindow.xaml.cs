using Microsoft.Win32;
using UniversalUpdater;
using System.Windows.Media;
using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class MainWindow : Window
{
    private readonly TermsrvEngine engine;
    private PatchPlan? autoPlan;
    private InstalledDllStatus? currentDllClassification;
    private VerifiedSignatureSnapshot? signatureSnapshot;
    private PatchPlan? manualPlan;
    private ScanReport? lastScan;
    private OfflineDllPreview? offlinePreview;
    private string? importedFile;
    private IReadOnlyList<PatchProfile> imported = [];
    private CancellationTokenSource? fragmentLookup;
    private ManualFragmentSnapshot? fragmentSnapshot;
    private ImportedCatalogReport? importedReport;
    private bool busy;
    private bool autoTaskChanging;
    private bool autoTaskLoading;
    private int? observedRdpListenerPort;
    private int? previousRdpListenerPort;
    private bool portRestartNeedsReview;
    private RdpConfigurationReport? lastRdpPolicyReport;
    private RdpDoctorReport? latestRdpDoctorReport;
    private DllCompatibilityReport? latestDllCompatibilityReport;
    private bool openBlankAfterPolicyRefresh;
    private bool autoUpdateLoading;
    private bool autoUpdateChanging;
    private string? pendingIndependentApplyId;
    private string? lastOfferedIndependentApplyId;
    private bool independentReportDialogOpen;
    private bool independentReportRecoveryInProgress;
    private string? unverifiedIndependentReportJobId;
    private readonly DispatcherTimer independentReportTimer;
    private readonly UpdateIntegration updates = new();
    private readonly AutoUpdateGuiCoordinator autoUpdateCoordinator;

    public MainWindow(bool offlineStartup = false)
    {
        InitializeComponent();
        independentReportTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        independentReportTimer.Tick += (_, _) => RefreshIndependentReportOffer();
        autoUpdateCoordinator = new AutoUpdateGuiCoordinator(this, updates,
            () => IsActive && !busy && !autoTaskChanging && !autoUpdateChanging);
        Loaded += (_, _) => WindowLayout.FitToWorkArea(this);
        ManualHexColumnHeaders.ItemsSource = Enumerable.Range(0, 16)
            .Select(i => i.ToString("X2")).ToArray();
        if (offlineStartup) MainTabs.SelectedIndex = 3;
        engine = new TermsrvEngine(text => Dispatcher.BeginInvoke(() => FooterText.Text = text));
        WindowSettings.Restore(this);
        Closing += (_, _) =>
        {
            fragmentLookup?.Cancel();
            fragmentLookup?.Dispose();
            WindowSettings.Save(this);
            independentReportTimer.Stop();
            autoUpdateCoordinator.Dispose();
            updates.Dispose();
        };
        foreach (var channel in new[] { UpdateChannel.Stable, UpdateChannel.Prerelease })
            updates.Get(channel).NoticeChanged += (_, _) =>
                Dispatcher.BeginInvoke(RefreshUpdateIndicator);
        RefreshUpdateIndicator();
        Loaded += async (_, _) =>
        {
            independentReportTimer.Start();
            ReadAutoUpdateSetting();
            autoUpdateCoordinator.Start();
            if (offlineStartup)
            {
                FooterText.Text = "Offline DLL mode: select a file without elevated operations.";
                return;
            }
            try
            {
                SearchFile.Text = engine.EnvironmentInfo().DllPath;
                ReadRdp();
            }
            catch (Exception e) { FooterText.Text = "Settings read: " + e.Message; }
            await RefreshAutoReapplyAsync();
            await CheckAsync();
            var independent = IsolatedApplyExecutor.ReadLatestStatus();
            if (independent is not null)
                FooterText.Text = "Independent Apply: " + independent.State +
                                  " (job " + independent.Id[..8] + "). " +
                                  independent.Details;
            RefreshIndependentReportOffer();
            // Startup metadata discovery; opted-in auto-update can open a
            // per-release confirmation, but never replaces an EXE silently.
            _ = StartupUpdatesAsync();
        };
    }

    internal void SelectOfflineTab() => MainTabs.SelectedIndex = 3;

    private async Task RunBusy(Func<Task> job, string? historyOperation = null)
    {
        if (busy) return;
        busy = true;
        RefreshButton.IsEnabled = false;
        MainTabs.IsEnabled = false;
        RestoreButton.IsEnabled = false;
        ApplyAutoButton.IsEnabled = false;
        ApplyManualButton.IsEnabled = false;
        OfflineSaveButton.IsEnabled = false;
        try { await job(); }
        catch (Exception e)
        {
            DiagnosticsBridge.Remember("Application", e);
            if (historyOperation is not null)
                OperationHistory.TryRecord(historyOperation, "Failure", failureType: e.GetType().Name);
            FooterText.Text = "Error: " + e.Message;
            AuditLog.Append($"Operation failed: {e.GetType().Name}: {e.Message}");
            ModernMessageDialog.Show(this, e.Message, "TermsrvPatcher Unified", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            busy = false;
            RefreshButton.IsEnabled = true;
            MainTabs.IsEnabled = true;
            RestoreButton.IsEnabled = true;
            ApplyAutoButton.IsEnabled = autoPlan?.State == PatchState.Ready &&
                currentDllClassification?.CanOfferAutomaticApply == true &&
                NsudoDevilModeScope.IsBundled && SystemInfo.IsAdministrator() &&
                IsolatedApplyExecutor.ReadLatestStatus()?.State is not ("Queued" or "Running");
            ApplyManualButton.IsEnabled = manualPlan?.State == PatchState.Ready && NsudoDevilModeScope.IsBundled && SystemInfo.IsAdministrator();
            OfflineSaveButton.IsEnabled = offlinePreview?.Plan.State == PatchState.Ready;
        }
    }

    private async Task CheckAsync()
    {
        if (busy) return;
        // Never preserve an old Ready plan if the second read, scan, or hash
        // verification fails: RunBusy's finally must not re-enable stale Apply.
        autoPlan = null;
        currentDllClassification = null;
        AdvancedDllStateText.Text = "DLL STATUS: CHECKING...";
        AdvancedDllEvidenceText.Text = "Comparing exact signatures and SHA-256 of the installed DLL.";
        AdvancedDllStateText.Foreground = new SolidColorBrush(Color.FromRgb(11, 46, 90));
        signatureSnapshot = null;
        lastScan = null;
        AutoSignatureGrid.ItemsSource = null;
        AutoProfileGrid.ItemsSource = null;
        AutoPriorityGrid.ItemsSource = null;
        AutoPriorityGrid.SelectedItem = null;
        AutoSimpleStatus.Text = "Checking exact signatures...";
        AutoSimpleProfile.Text = "Detected pattern: checking...";
        AutoSimpleReason.Text = "No automatic Apply is available until the check finishes.";
        AutoPrioritySummary.Text = "Checking all priority candidates against the current DLL...";
        AutoSignatureGrid.SelectedItem = null;
        AutoSignatureSummary.Text = "Checking actual DLL bytes and verifying SHA-256 consistency...";
        AutoSignatureDetails.Clear();
        AutoSelectedPair.Text = "Select a signature group above to compare Find and Replace.";
        AutoInspectFindButton.IsEnabled = false;
        AutoInspectReplaceButton.IsEnabled = false;
        AutoEvidenceExportButton.IsEnabled = false;
        ApplyAutoButton.IsEnabled = false;

        await RunBusy(async () =>
        {
            var result = await Task.Run(() =>
            {
                var os = engine.EnvironmentInfo();
                var plan = engine.Inspect();
                // An independent read binds diagnostic evidence to exactly the
                // same SHA-256 as the engine's protected-write preview.
                var catalog = PatchCatalog.LoadAutomatic();
                var evidence = VerifiedSignatureSnapshot.Capture(
                    File.ReadAllBytes(os.DllPath), plan, catalog,
                    os.Is64Bit ? "x64" : "x86");
                // The priority list describes the existing engine decision.
                // It never reorders edits or creates a second Apply target.
                var priority = AutomaticPriorityPolicy.Build(os, plan, evidence, catalog);
                ScanReport? fallback = plan.State is PatchState.Unknown or PatchState.Ambiguous
                    ? engine.ScanDll(os.DllPath, null)
                    : null;
                if (fallback is not null &&
                    !fallback.Sha256.Equals(evidence.Sha256,
                        StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        "DLL changed before structural scanning; recheck the file.");
                AutomaticRevertPlan? recovery = null;
                bool recoveryInspectionFailed = false;
                try { recovery = AutomaticRevertSafety.Inspect(); }
                catch (Exception ex)
                {
                    recoveryInspectionFailed = true;
                    AuditLog.Append("Advanced Revert eligibility unavailable: " + ex.GetType().Name);
                }
                // Recovery is bound to the same current DLL snapshot.
                evidence.RequireCurrentFile(os.DllPath);
                return (Info: os, Preview: plan, Evidence: evidence,
                    Fallback: fallback, Priority: priority,
                    Recovery: recovery, RecoveryInspectionFailed: recoveryInspectionFailed);
            });
            var os = result.Info;
            autoPlan = result.Preview;
            signatureSnapshot = result.Evidence;
            lastScan = result.Fallback;
            SystemText.Text = os.Display + (os.Is64Bit ? " | x64" : " | x86");
            DllText.Text = $"termsrv.dll: {os.DllVersion}  |  {os.DllPath}";
            // The installed DLL byte result must be visible independently of
            // backup, Revert or an old Task Scheduler result.
            var installed = InstalledDllStatus.FromEvidence(
                autoPlan, result.Recovery, result.RecoveryInspectionFailed);
            currentDllClassification = installed;
            AdvancedDllStateText.Text = installed.Headline;
            AdvancedDllEvidenceText.Text = installed.Evidence;
            AdvancedDllStateText.Foreground = installed.Kind switch
            {
                InstalledDllKind.Patched => new SolidColorBrush(Color.FromRgb(11, 135, 76)),
                InstalledDllKind.NotPatched => new SolidColorBrush(Color.FromRgb(40, 88, 157)),
                _ => new SolidColorBrush(Color.FromRgb(160, 92, 14))
            };
            StatusText.Text = "Automatic signature result: " + autoPlan.State +
                " | " + autoPlan.Description;
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(100, 116, 139));
            AutoSimpleStatus.Text = installed.Headline;
            AutoSimpleStatus.Foreground = installed.Kind switch
            {
                InstalledDllKind.Patched => new SolidColorBrush(Color.FromRgb(11, 135, 76)),
                InstalledDllKind.NotPatched => new SolidColorBrush(Color.FromRgb(40, 88, 157)),
                _ => new SolidColorBrush(Color.FromRgb(160, 92, 14))
            };
            AutoSimpleProfile.Text = string.IsNullOrWhiteSpace(autoPlan.ProfileId)
                ? "Detected pattern: none"
                : "Detected pattern: " + autoPlan.ProfileId;
            AutoSimpleReason.Text = installed.Evidence + " " + installed.RevertHeadline +
                ". " + installed.RevertDetails;
            AutoSummary.Text = autoPlan.ProfileId.Length == 0 ? autoPlan.Description :
                $"Matched: {autoPlan.ProfileId}";
            AutoDetails.Text = PlanText(autoPlan);
            if (autoPlan.State == PatchState.Ambiguous)
                AutoDetails.Text += "\nAmbiguity classification (read-only): " +
                    signatureSnapshot.Inspection.AmbiguityReason +
                    "\nNo automatic profile chosen or Apply authorized.";
            AutoSignatureGrid.ItemsSource = signatureSnapshot.Inspection.Rows;
            AutoProfileGrid.ItemsSource = signatureSnapshot.Inspection.Profiles;
            AutoPriorityGrid.ItemsSource = result.Priority.Rows;
            AutoPrioritySummary.Text = result.Priority.Summary +
                " Selecting a row shows HEX only; it cannot change the Apply target.";
            ApplyAutoButton.ToolTip = installed.CanOfferAutomaticApply
                ? "Only " + autoPlan.ProfileId +
                  " will be applied. Row selection does not change the verified plan."
                : "No currently eligible automatic Apply plan.";
            AutoSignatureSummary.Text = signatureSnapshot.Inspection.Summary +
                (autoPlan.State == PatchState.Ready &&
                 autoPlan.Description.Contains("specific profile over", StringComparison.Ordinal)
                    ? " AUTO TARGET SELECTED: " + autoPlan.ProfileId +
                      ". Generic fallback matches are excluded from this Apply preview."
                    : "") +
                " Verified SHA-256: " + signatureSnapshot.Sha256;
            AutoSignatureDetails.Text = signatureSnapshot.Inspection.AsText();
            // Highlight the chosen profile first, when the engine resolves
            // a specific-vs-Generic match to a single inspected target.
            AutoSignatureGrid.SelectedItem = signatureSnapshot.Inspection.Rows.FirstOrDefault(x =>
                x.Profile == autoPlan.ProfileId) ??
                signatureSnapshot.Inspection.Rows.FirstOrDefault(x =>
                    x.FindHits != "0" || x.ReplaceHits != "0") ??
                signatureSnapshot.Inspection.Rows.FirstOrDefault();
            AutoPriorityGrid.SelectedItem = result.Priority.Rows.FirstOrDefault(x =>
                x.Decision is "Selected" or "Already patched") ??
                result.Priority.Rows.FirstOrDefault(x =>
                    x.Match.Contains("F:1", StringComparison.Ordinal) ||
                    x.Match.Contains("R:1", StringComparison.Ordinal)) ??
                result.Priority.Rows.FirstOrDefault();
            AutoEvidenceExportButton.IsEnabled = true;
            if (lastScan is not null)
            {
                ScanDetails.Text = lastScan.AsText();
                AutoDetails.Text += $"\nFallback scan: {lastScan.Similar.Count} near matches and " +
                    $"{lastScan.Hits.Count} structural markers. See Search DLL for details. " +
                    "No replacement bytes were generated.";
            }
            FooterText.Text = $"Check completed: {autoPlan.State}. Evidence SHA-256 verified.";
        });
        if (autoPlan is null)
        {
            AdvancedDllStateText.Text = "DLL STATUS: UNKNOWN";
            AdvancedDllEvidenceText.Text = "Signature or file SHA-256 inspection failed. Recheck the installed DLL.";
            AdvancedDllStateText.Foreground = new SolidColorBrush(Color.FromRgb(160, 92, 14));
            AutoSimpleStatus.Text = "Automatic check could not complete";
            AutoSimpleProfile.Text = "Detected pattern: unknown";
            AutoSimpleReason.Text = "No verified Apply is available. Review the error and run Check DLL again.";
        }
    }

    private void AutoPrioritySelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (AutoPriorityGrid?.SelectedItem is not AutomaticPriorityRow chosen ||
            signatureSnapshot is null || AutoSignatureGrid is null ||
            AutoSelectedPair is null)
            return;
        if (!chosen.ReferenceOnly)
        {
            var matching = signatureSnapshot.Inspection.Rows.FirstOrDefault(x =>
                x.Profile.Equals(chosen.Profile, StringComparison.Ordinal));
            if (matching is not null) AutoSignatureGrid.SelectedItem = matching;
            return;
        }
        // An external Hot Patch is an observation-only reference. Its row
        // cannot become a PatchPlan, even when its 12 bytes occur in a longer
        // selected 19-byte signature.
        AutoSignatureGrid.SelectedItem = null;
        var reference = new SignatureGroupFinding(chosen.Profile, 1,
            "External reference only", chosen.FindHex, chosen.ReplaceHex,
            "0", "0", "(none)", "(none)");
        AutoSelectedPair.Text = chosen.Profile + " — REFERENCE ONLY; NOT AN APPLY RULE" +
            Environment.NewLine + reference.AlignedPair +
            Environment.NewLine + chosen.Match + " at " + chosen.Offsets;
        AutoInspectFindButton.IsEnabled = false;
        AutoInspectReplaceButton.IsEnabled = false;
    }

    private void AutoSignatureSelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (AutoInspectFindButton is null || AutoInspectReplaceButton is null) return;
        var selected = AutoSignatureGrid?.SelectedItem as SignatureGroupFinding;
        if (AutoSelectedPair is not null)
            AutoSelectedPair.Text = selected is null
                ? "Select a signature group above to compare Find and Replace."
                : selected.Profile + " / group " + selected.Group + " — " + selected.State +
                  Environment.NewLine + selected.AlignedPair +
                  Environment.NewLine + "Find: " + selected.FindHits + " at " + selected.FindOffsets +
                  " | Replace: " + selected.ReplaceHits + " at " + selected.ReplaceOffsets;
        AutoInspectFindButton.IsEnabled = signatureSnapshot is not null && selected is not null &&
            selected.FindOffsets != "(none)";
        AutoInspectReplaceButton.IsEnabled = signatureSnapshot is not null && selected is not null &&
            selected.ReplaceOffsets != "(none)";
    }

    private void AutoInspectFind_Click(object sender, RoutedEventArgs e)
        => OpenAutomaticSignatureInManual(false);

    private void AutoInspectReplace_Click(object sender, RoutedEventArgs e)
        => OpenAutomaticSignatureInManual(true);

    private void OpenAutomaticSignatureInManual(bool useReplace)
    {
        if (busy || AutoSignatureGrid.SelectedItem is not SignatureGroupFinding selected ||
            signatureSnapshot is null || autoPlan is null) return;
        string offsets = useReplace ? selected.ReplaceOffsets : selected.FindOffsets;
        if (offsets == "(none)") return;
        try
        {
            signatureSnapshot.RequireCurrentFile(autoPlan.FilePath);
            string findMask = useReplace ? selected.ReplaceHex : selected.FindHex;
            // This is a Find-only inspection. Do not transfer any replacement
            // byte sequence into the Manual Replace field.
            ManualReplace.Clear();
            ManualFind.Text = findMask;
            MainTabs.SelectedIndex = 1;
            FooterText.Text = (useReplace ? "Replace-state bytes" : "Original Find mask") +
                " loaded for read-only HEX inspection. Check manual pattern is still required.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   InvalidOperationException or ArgumentException)
        {
            autoPlan = null;
            signatureSnapshot = null;
            AutoInspectFindButton.IsEnabled = false;
            AutoInspectReplaceButton.IsEnabled = false;
            AutoEvidenceExportButton.IsEnabled = false;
            ApplyAutoButton.IsEnabled = false;
            FooterText.Text = "DLL changed or became unreadable; Check DLL again. " +
                              ex.GetType().Name;
        }
    }

    private void AutoEvidenceExport_Click(object sender, RoutedEventArgs e)
    {
        if (busy || signatureSnapshot is null || autoPlan is null) return;
        try
        {
            signatureSnapshot.RequireCurrentFile(autoPlan.FilePath);
            var report = SignatureEvidenceExport.Build(engine.EnvironmentInfo(),
                autoPlan, signatureSnapshot, lastScan);
            var dialog = new SaveFileDialog
            {
                Title = "Save local read-only signature evidence",
                Filter = "Text reports (*.txt)|*.txt",
                FileName = "termsrv-signature-evidence.txt",
                AddExtension = true
            };
            if (dialog.ShowDialog(this) != true) return;
            signatureSnapshot.RequireCurrentFile(autoPlan.FilePath);
            SignatureEvidenceExport.SaveNew(report, dialog.FileName);
            FooterText.Text = "Local signature evidence exported. Review before sharing.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   InvalidOperationException or ArgumentException or
                                   InvalidDataException)
        {
            FooterText.Text = "Evidence export refused: " + ex.GetType().Name;
            ModernMessageDialog.Show(this, "The DLL changed, report was invalid, or the file could " +
                "not be saved. Run Check DLL again and choose a new .txt path.",
                "Signature evidence not exported", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static string PlanText(PatchPlan plan)
    {
        var b = new StringBuilder();
        b.AppendLine($"Status: {plan.State}");
        b.AppendLine($"DLL version: {plan.FileVersion}");
        b.AppendLine($"SHA-256: {plan.OriginalSha256}");
        b.AppendLine($"Catalog entry: {plan.ProfileId}");
        b.AppendLine($"Mode: {(plan.IsManual ? "manual" : "automatic")}");
        foreach (var edit in plan.Edits)
        {
            b.AppendLine($"Offset: 0x{edit.Offset:X8}  ({edit.Expected.Length} bytes)");
            b.AppendLine("Before: " + BitConverter.ToString(edit.Expected).Replace('-', ' '));
            b.AppendLine("After:  " + BitConverter.ToString(edit.Replacement).Replace('-', ' '));
        }
        b.AppendLine(plan.Description);
        return b.ToString();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await CheckAsync();

    private static bool Confirm(Window owner, string title, string message)
        => ModernMessageDialog.Confirm(owner, title, message,
            title.Contains("Group Policy", StringComparison.OrdinalIgnoreCase)
                ? "Refresh policy" : title.Contains("Restore", StringComparison.OrdinalIgnoreCase)
                ? "Restore" : title.Contains("Apply", StringComparison.OrdinalIgnoreCase)
                ? "Apply" : "Continue");

    private void About_Click(object sender, RoutedEventArgs e)
    {
        new AboutWindow { Owner = this }.ShowDialog();
    }

    private async Task ApplyAsync(PatchPlan? plan, bool manual)
    {
        if (plan?.State != PatchState.Ready || !NsudoDevilModeScope.IsBundled || !SystemInfo.IsAdministrator()) return;
        if (manual && InteractiveSessionDetector.RequiresIndependentExecutor())
        {
            ModernMessageDialog.Show(this,
                "Manual Apply is not yet supported by the isolated SYSTEM executor. " +
                "Use the local or VM console. Automatic Apply uses Task Scheduler over RDP.",
                "Manual Apply requires local console", MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }
        // Full backup is default ON, but the operator can opt out. Trusted
        // Automatic Apply ALWAYS saves an authenticated compact recovery
        // journal before any protected DLL writes, even when this is false.
        bool createBackup = CreateBackupCheck.IsChecked != false;
        bool isolatedAtConfirmation = !manual &&
            InteractiveSessionDetector.RequiresIndependentExecutor();
        string message = "This operation modifies the protected Windows termsrv.dll file and stops " +
            "Remote Desktop services temporarily. Active RDP connections may be disconnected. " +
            "Windows updates may revert the change. Proceed only on a system you administer and " +
            "where permitted by the applicable license.";
        if (manual)
            message += "\n\nMANUAL MODE: You supplied the replacement bytes. No automatic analysis " +
                "can guarantee that this patch is safe. Manual Apply is not yet independent " +
                "of the user session; use console access. Continue?";
        else
            message += isolatedAtConfirmation
                ? "\n\nRDP/UNCONFIRMED SESSION: The operation will be scheduled as a one-shot SYSTEM task " +
                  "with an authenticated recovery journal; disconnecting RDP will not terminate its process."
                : "\n\nLOCAL CONSOLE: The operation will use the normal elevated Apply " +
                  "with in-process verification and an authenticated recovery journal.";
        if (!createBackup)
            message += "\n\nFULL BACKUP IS OFF: No new System32 .bak or ProgramData DLL copy " +
                       "will be created. Automatic Apply still requires a small DPAPI-protected " +
                       "recovery journal. Manual Apply has only in-operation rollback. " +
                       "A VM snapshot remains strongly recommended.";
        if (!Confirm(this, manual ? "Apply manual patch?" : "Apply verified patch?", message)) return;
        if (!createBackup && !Confirm(this, "Confirm: no full backup",
                manual
                    ? "Manual Apply without a full backup cannot be recovered automatically. " +
                      "Continue ONLY with a VM snapshot or an independently verified original?"
                    : "No full DLL backup will be created. The small encrypted journal is " +
                      "required, but does not replace an offline VM snapshot. Continue?"))
            return;
        if (!manual)
        {
            // Check the session immediately before dispatch. A local console
            // keeps the original synchronous Apply/rollback flow. An RDP
            // session (or unverified session type) uses a Session 0 SYSTEM job.
            bool isolatedNow = InteractiveSessionDetector.RequiresIndependentExecutor();
            if (isolatedNow != isolatedAtConfirmation)
            {
                ModernMessageDialog.Show(this,
                    "The Windows session type changed after confirmation. No task or patch was started. " +
                    "Check DLL and approve Apply again.",
                    "Session type changed", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (isolatedNow)
            {
                await RunBusy(async () =>
                {
                    string jobId = await Task.Run(() => IsolatedApplyExecutor.Queue(plan, createBackup));
                    pendingIndependentApplyId = jobId;
                    FooterText.Text = "RDP/unknown session: SYSTEM Apply queued (" + jobId[..8] +
                                      "). Closing the GUI does not stop the job.";
                }, "Apply");
                return;
            }
            bool consoleSuccess = false;
            await RunBusy(async () =>
            {
                await Task.Run(() => engine.Apply(plan, createBackup: createBackup));
                consoleSuccess = true;
            }, "Apply");
            await CheckAsync();
            if (consoleSuccess)
            {
                FooterText.Text = "Local console Apply completed and verified.";
                OfferStructuredCompatibilityReport(plan);
            }
            return;
        }
        // Manual Apply still runs in the interactive context: do not imply
        // that it is independent of the user session.
        // A compatibility report is offered ONLY if the protected write, byte
        // verification and RDP-service recovery all returned successfully.
        bool applied = false;
        await RunBusy(async () =>
        {
            await Task.Run(() => engine.Apply(plan, createBackup));
            applied = true;
            FooterText.Text = "Patch applied and verified. Checking current DLL...";
        }, "Apply");
        await CheckAsync();
        if (applied)
            OfferStructuredCompatibilityReport(plan);
    }

    private void OfferStructuredCompatibilityReport(PatchPlan plan)
    {
        // This UI offer follows the completed protected Apply; it can never
        // authorize, affect or roll back the DLL operation.
        if (!IsLoaded) return;
        try
        {
            var versions = SuccessfulFixMetadata.FromSuccessfulApply(
                engine.EnvironmentInfo(), plan);
            new SuccessfulFixWindow(versions) { Owner = this }.ShowDialog();
            _ = RefreshAutoReapplyAsync(); // Update the consent badge immediately.
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Compatibility reporting", ex);
            AuditLog.Append("Optional compatibility dialog unavailable: " +
                ex.GetType().Name);
        }
    }

    /// <summary>
    /// Poll only the previously approved one-shot worker result. Windows Update
    /// Auto Reapply has separate state and NEVER triggers a GUI report prompt.
    /// </summary>
    private void RefreshIndependentReportOffer()
    {
        if (busy || independentReportDialogOpen || !IsLoaded) return;
        var status = IsolatedApplyExecutor.ReadLatestStatus();
        if (status?.State != "Succeeded" ||
            IsolatedApplyExecutor.WasReportDelivered(status.Id) ||
            string.Equals(unverifiedIndependentReportJobId, status.Id,
                StringComparison.OrdinalIgnoreCase) ||
            pendingIndependentApplyId is not null &&
                !string.Equals(status.Id, pendingIndependentApplyId,
                    StringComparison.OrdinalIgnoreCase))
        {
            AdvancedPendingReportButton.Visibility = Visibility.Collapsed;
            return;
        }
        AdvancedPendingReportButton.Visibility = Visibility.Visible;
        if (!string.Equals(lastOfferedIndependentApplyId, status.Id,
                StringComparison.OrdinalIgnoreCase))
        {
            lastOfferedIndependentApplyId = status.Id;
            _ = OfferIndependentApplyReportAsync(status.Id, userRequested: false);
        }
    }

    private async Task OfferIndependentApplyReportAsync(string jobId, bool userRequested)
    {
        if (!IsLoaded || independentReportDialogOpen ||
            independentReportRecoveryInProgress || busy) return;
        independentReportRecoveryInProgress = true;
        try
        {
            var status = IsolatedApplyExecutor.ReadLatestStatus();
            if (status?.State != "Succeeded" ||
                !string.Equals(status.Id, jobId, StringComparison.OrdinalIgnoreCase) ||
                IsolatedApplyExecutor.WasReportDelivered(status.Id))
                return;
            var result = await Task.Run(() =>
            {
                bool valid = IsolatedApplyExecutor.TryReadVerifiedReport(status,
                    out var metadata);
                return (valid, metadata);
            });
            if (!IsLoaded || independentReportDialogOpen) return;
            if (!result.valid || result.metadata is null)
            {
                unverifiedIndependentReportJobId = status.Id;
                AdvancedPendingReportButton.Visibility = Visibility.Collapsed;
                FooterText.Text =
                    "Protected Apply succeeded, but its report cannot be verified " +
                    "from the saved job and current DLL. No data was sent.";
                return;
            }
            if (!userRequested && !IsolatedApplyExecutor.TryClaimReportOffer(status.Id))
                return;
            independentReportDialogOpen = true;
            try
            {
                if (new SuccessfulFixWindow(result.metadata) { Owner = this }
                        .ShowDialog() == true)
                {
                    IsolatedApplyExecutor.TryMarkReportDelivered(status.Id);
                    AdvancedPendingReportButton.Visibility = Visibility.Collapsed;
                }
                await RefreshAutoReapplyAsync();
            }
            finally { independentReportDialogOpen = false; }
        }
        catch (Exception ex)
        {
            AuditLog.Append("Pending independent Apply report unavailable: " +
                            ex.GetType().Name);
            FooterText.Text = "Verified Apply report unavailable (" +
                ex.GetType().Name + "). No report was sent.";
        }
        finally { independentReportRecoveryInProgress = false; }
    }

    private void PendingApplyReport_Click(object sender, RoutedEventArgs e)
    {
        var status = IsolatedApplyExecutor.ReadLatestStatus();
        if (status?.State == "Succeeded" &&
            !IsolatedApplyExecutor.WasReportDelivered(status.Id))
            _ = OfferIndependentApplyReportAsync(status.Id, userRequested: true);
    }

    private async void ApplyAuto_Click(object sender, RoutedEventArgs e)
    {
        if (currentDllClassification?.CanOfferAutomaticApply != true) return;
        // Any attempt, including user cancellation, requires a fresh Check
        // before a second automatic Apply can be approved.
        currentDllClassification = null;
        AdvancedDllStateText.Text = "DLL STATUS: CHECK REQUIRED";
        AdvancedDllEvidenceText.Text = "Recheck installed DLL bytes after the Apply workflow.";
        AdvancedDllStateText.Foreground = new SolidColorBrush(Color.FromRgb(40, 88, 157));
        await ApplyAsync(autoPlan, false);
    }
    private async void ApplyManual_Click(object sender, RoutedEventArgs e) => await ApplyAsync(manualPlan, true);

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (InteractiveSessionDetector.RequiresIndependentExecutor())
        {
            ModernMessageDialog.Show(this,
                "Restore may stop Remote Desktop services. Use the local or VM console " +
                "until a separately verified SYSTEM Restore worker is available.",
                "Restore requires local console", MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }
        var verified = engine.BackupsForCurrentVersion();
        if (verified.Count == 0)
        {
            ModernMessageDialog.Show(this, "No trusted backup for the currently installed DLL.",
                "Restore unavailable", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dialog = new OpenFileDialog
        {
            Title = "Choose a verified DLL backup to restore",
            InitialDirectory = TermsrvEngine.BackupDirectory,
            Filter = "DLL backup (*.dll)|*.dll",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true) return;
        if (!Confirm(this, "Restore Windows DLL?", "Restoring will temporarily stop RDP and may disconnect you. " +
            "The backup DLL must match the currently installed file version. Continue?")) return;
        await RunBusy(async () => await Task.Run(() => engine.Restore(dialog.FileName)), "Restore");
        await CheckAsync();
    }

    private void OpenBackups_Click(object sender, RoutedEventArgs e)
    {
        if (!Directory.Exists(TermsrvEngine.BackupDirectory))
        {
            ModernMessageDialog.Show(this, "No backup directory has been created yet.",
                "Backups", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        Process.Start(new ProcessStartInfo(TermsrvEngine.BackupDirectory) { UseShellExecute = true });
    }

    private async void ManualEdited(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        manualPlan = null;
        if (ApplyManualButton is not null) ApplyManualButton.IsEnabled = false;
        if (ManualResult is not null)
            ManualResult.Text = "Pattern changed. Check again before applying.";
        if (ManualInputStatus is not null && ManualFind is not null && ManualReplace is not null)
        {
            var validation = ManualPatternValidator.Check(ManualFind.Text, ManualReplace.Text);
            ManualInputStatus.Text = validation.Message;
            ManualInputStatus.Foreground = validation.IsValid
                ? System.Windows.Media.Brushes.DarkGreen
                : System.Windows.Media.Brushes.DarkOrange;
        }

        // Replacing HEX must not restart an unchanged Find lookup.
        if (sender != ManualFind || ManualFragmentSummary is null ||
            ManualFragmentGrid is null || ManualFind is null) return;

        fragmentLookup?.Cancel();
        fragmentLookup?.Dispose();
        fragmentLookup = new CancellationTokenSource();
        CancellationToken cancellation = fragmentLookup.Token;
        string find = ManualFind.Text;
        fragmentSnapshot = null;
        ManualFragmentGrid.ItemsSource = null;
        ClearManualHexViewer();
        if (string.IsNullOrWhiteSpace(find))
        {
            ManualFragmentSummary.Text = "Enter at least two complete fixed HEX bytes (e.g. 44 8B).";
            return;
        }

        ManualFragmentSummary.Text = "Searching installed termsrv.dll (read-only)...";
        try
        {
            await Task.Delay(300, cancellation);
            string path = await Task.Run(() => engine.EnvironmentInfo().DllPath, cancellation);
            var snapshot = await Task.Run(
                () => ManualFragmentSearch.SearchFileSnapshot(path, find), cancellation);
            if (cancellation.IsCancellationRequested) return;
            fragmentSnapshot = snapshot;
            ManualFragmentSummary.Text = snapshot.Report.Summary;
            ManualFragmentGrid.ItemsSource = snapshot.Report.Hits;
            if (snapshot.Report.Hits.Count != 0)
                ManualFragmentGrid.SelectedIndex = 0;
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException or
                                   ArgumentException or InvalidOperationException)
        {
            if (cancellation.IsCancellationRequested) return;
            ManualFragmentSummary.Text = "HEX lookup unavailable (" + ex.GetType().Name +
                "). Manual patch verification remains disabled.";
        }
    }

    private void ClearManualHexViewer()
    {
        if (ManualHexRows is null) return;
        ManualHexRows.ItemsSource = null;
        if (ManualHexHeader is not null)
            ManualHexHeader.Text = "Select a match to inspect real DLL bytes at that offset.";
        if (ManualHexMask is not null)
            ManualHexMask.Text = "Find mask: (not selected)";
        if (ManualHexPrevious is not null) ManualHexPrevious.IsEnabled = false;
        if (ManualHexNext is not null) ManualHexNext.IsEnabled = false;
        if (ManualHexCopy is not null) ManualHexCopy.IsEnabled = false;
    }

    private void ManualFragmentSelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (ManualFragmentGrid?.SelectedItem is not ManualFragmentHit selected ||
            fragmentSnapshot is null)
        {
            ClearManualHexViewer();
            return;
        }

        var frame = HexViewport.Build(fragmentSnapshot.Bytes, selected.Offset,
            selected.Length, selected.WildcardPositions);
        ManualHexRows.ItemsSource = frame.Rows;
        int position = ManualFragmentGrid.SelectedIndex;
        int total = fragmentSnapshot.Report.Hits.Count;
        ManualHexHeader.Text = $"Match {position + 1}/{total}  |  Address: 0x{selected.Offset:X8}  |  " +
            $"Length: {selected.Length} byte(s)  |  File: {fragmentSnapshot.Bytes.Length:N0} bytes";
        ManualHexMask.Text = "Find mask: " + selected.MaskHex +
                             Environment.NewLine + "Actual:    " + selected.ActualHex;
        ManualHexPrevious.IsEnabled = position > 0;
        ManualHexNext.IsEnabled = position >= 0 && position < total - 1;
        ManualHexCopy.IsEnabled = true;
    }

    private void ManualHexPrevious_Click(object sender, RoutedEventArgs e)
    {
        if (ManualFragmentGrid?.SelectedIndex > 0)
            ManualFragmentGrid.SelectedIndex--;
    }

    private void ManualHexNext_Click(object sender, RoutedEventArgs e)
    {
        if (ManualFragmentGrid is not null && fragmentSnapshot is not null &&
            ManualFragmentGrid.SelectedIndex >= 0 &&
            ManualFragmentGrid.SelectedIndex < fragmentSnapshot.Report.Hits.Count - 1)
            ManualFragmentGrid.SelectedIndex++;
    }

    private void ManualHexCopy_Click(object sender, RoutedEventArgs e)
    {
        if (ManualFragmentGrid?.SelectedItem is not ManualFragmentHit selected) return;
        try
        {
            Clipboard.SetText(selected.ActualHex);
            FooterText.Text = "Actual matched HEX copied locally (no replacement generated).";
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            FooterText.Text = "Clipboard is currently unavailable.";
        }
    }

    private void ImportedSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        manualPlan = null;
        if (ApplyManualButton is not null) ApplyManualButton.IsEnabled = false;
    }

    private void ScanInputChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        lastScan = null;
    }

    private async void CheckManual_Click(object sender, RoutedEventArgs e)
    {
        var validation = ManualPatternValidator.Check(ManualFind.Text, ManualReplace.Text);
        if (!validation.IsValid)
        {
            manualPlan = null;
            ApplyManualButton.IsEnabled = false;
            ManualResult.Text = validation.Message;
            ManualInputStatus.Text = validation.Message;
            FooterText.Text = "Manual input is incomplete or invalid; nothing was attempted.";
            return; // User input is not a failed system operation or diagnostic event.
        }
        await RunBusy(async () =>
        {
            var find = ManualFind.Text;
            var replace = ManualReplace.Text;
            manualPlan = await Task.Run(() => engine.InspectManual(find, replace));
            ManualResult.Text = PlanText(manualPlan);
            ApplyManualButton.IsEnabled = manualPlan.State == PatchState.Ready && NsudoDevilModeScope.IsBundled && SystemInfo.IsAdministrator();
            FooterText.Text = "Manual check: " + manualPlan.State;
        });
    }

    private void SaveManual_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var profile = PatchCatalog.Manual(ManualFind.Text, ManualReplace.Text);
            var dialog = new SaveFileDialog
            {
                Title = "Save manual pattern for later inspection",
                Filter = "Pattern file (*.txt)|*.txt",
                FileName = "MyManualPatterns.txt"
            };
            if (dialog.ShowDialog(this) != true) return;
            var lines = new StringBuilder("# Manual user-provided pattern (not used automatically)\n");
            lines.Append("x64, ");
            lines.Append(string.Join(" | ", profile.Groups.Select(g =>
                string.Join(" ", g.Search.Select(b => b.HasValue ? b.Value.ToString("X2") : "*")))));
            lines.Append(", ");
            lines.Append(string.Join(" | ", profile.Groups.Select(g =>
                BitConverter.ToString(g.Replace).Replace('-', ' '))));
            lines.AppendLine();
            File.WriteAllText(dialog.FileName, lines.ToString());
            FooterText.Text = "Manual pattern saved (not activated automatically).";
        }
        catch (Exception ex)
        {
            ModernMessageDialog.Show(this, ex.Message, "Cannot save pattern", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Import_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Import manual patterns", Filter = "Text patterns (*.txt)|*.txt|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            imported = PatchCatalog.Parse(File.ReadAllText(dialog.FileName), "Imported user patterns");
            if (imported.Count > 256)
                throw new FormatException("Imported catalogs are limited to 256 profiles for responsive read-only analysis.");
            importedFile = dialog.FileName;
            importedReport = null;
            ImportedResultsGrid.ItemsSource = null;
            ImportedCheckDetails.Clear();
            ImportSelector.ItemsSource = imported;
            ImportSelector.SelectedIndex = -1;
            ImportedInfo.Text = $"Imported {imported.Count} patterns. Checking all entries against the installed DLL...";
            manualPlan = null;
            ApplyManualButton.IsEnabled = false;
            _ = CheckAllImportedAsync();
        }
        catch (Exception ex) { ModernMessageDialog.Show(this, ex.Message, "Invalid pattern file"); }
    }

    private async void CheckAllImported_Click(object sender, RoutedEventArgs e)
        => await CheckAllImportedAsync();

    private async Task CheckAllImportedAsync()
    {
        if (busy || imported.Count == 0) return;
        var patterns = imported.ToArray();
        var source = importedFile;
        await RunBusy(async () =>
        {
            var report = await Task.Run(() =>
            {
                var os = engine.EnvironmentInfo();
                var data = File.ReadAllBytes(os.DllPath);
                return ImportedCatalogInspector.Inspect(data, os.DllVersion, os, patterns);
            });
            // Discard stale results if a new import occurred while inspection ran.
            if (source != importedFile) return;
            importedReport = report;
            ImportedResultsGrid.ItemsSource = report.Results;
            ImportedCatalogSummary.Text = report.Summary;
            ImportedInfo.Text = report.ExactMatches + " exact byte match(es); " +
                report.VersionHintMatches + " compatible Windows/build hints. " +
                "A version label never authorizes a patch.";
            if (report.SuggestedIndex is int index)
            {
                ImportSelector.SelectedIndex = index;
                ImportedCheckDetails.Text = report.Results.First(x => x.Index == index).Description;
                FooterText.Text = "Unique imported candidate selected for review (NOT applied).";
            }
            else
            {
                ImportSelector.SelectedIndex = -1;
                ImportedCheckDetails.Text = report.AsText();
                FooterText.Text = "Imported catalog inspection complete; no automatic Apply enabled.";
            }
        });
    }

    private void ImportedResultSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (ImportedResultsGrid?.SelectedItem is not ImportedProfileCheck result) return;
        if (ImportSelector is not null) ImportSelector.SelectedIndex = result.Index;
        if (ImportedCheckDetails is not null) ImportedCheckDetails.Text = result.Description;
        manualPlan = null;
        if (ApplyManualButton is not null) ApplyManualButton.IsEnabled = false;
    }

    private async void CheckImported_Click(object sender, RoutedEventArgs e)
    {
        if (importedFile is null || ImportSelector.SelectedIndex < 0) return;
        int index = ImportSelector.SelectedIndex;
        if (index >= imported.Count) return;
        var profile = imported[index];
        ManualFind.Text = string.Join(" | ", profile.Groups.Select(g => string.Join(" ", g.Search.Select(b =>
            b.HasValue ? b.Value.ToString("X2") : "*"))));
        ManualReplace.Text = string.Join(" | ", profile.Groups.Select(g => BitConverter.ToString(g.Replace).Replace('-', ' ')));
        await RunBusy(async () =>
        {
            manualPlan = await Task.Run(() => engine.InspectImported(importedFile, index));
            ManualResult.Text = PlanText(manualPlan);
            ApplyManualButton.IsEnabled = manualPlan.State == PatchState.Ready && NsudoDevilModeScope.IsBundled && SystemInfo.IsAdministrator();
            FooterText.Text = $"Imported manual profile: {manualPlan.State}";
        });
    }

    private void ExportAutoDryRun_Click(object sender, RoutedEventArgs e) => ExportDryRun(autoPlan);
    private void ExportManualDryRun_Click(object sender, RoutedEventArgs e) => ExportDryRun(manualPlan);

    private void ExportDryRun(PatchPlan? plan)
    {
        if (plan is null)
        {
            ModernMessageDialog.Show(this, "Check the DLL first.", "DryRun", MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }
        try
        {
            var report = PatchDryRun.Build(plan, engine.EnvironmentInfo(),
                CreateBackupCheck.IsChecked != false);
            var dialog = new SaveFileDialog
            {
                Title = "Save read-only DryRun JSON",
                Filter = "JSON (*.json)|*.json",
                FileName = "termsrv-dryrun.json",
                AddExtension = true
            };
            if (dialog.ShowDialog(this) != true) return;
            report.SaveNew(dialog.FileName, plan.FilePath);
            FooterText.Text = "Read-only DryRun exported; no system changes.";
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("DryRun export", ex);
            ModernMessageDialog.Show(this, ex.Message, "DryRun export refused",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OfflineBrowse_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        var dlg = new OpenFileDialog
        {
            Title = "Choose a termsrv.dll file for offline patching",
            Filter = "Windows Terminal Services DLL (termsrv.dll)|termsrv.dll",
            FileName = "termsrv.dll",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dlg.ShowDialog(this) != true) return;
        OfflineSource.Text = dlg.FileName;
        await CheckOfflineAsync();
    }

    private void OfflineInputsChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        offlinePreview = null;
        if (OfflineSaveButton is not null) OfflineSaveButton.IsEnabled = false;
        if (OfflineDetails is not null)
            OfflineDetails.Text = "Pattern changed. Check the selected DLL again.";
    }

    private async Task CheckOfflineAsync()
    {
        if (string.IsNullOrWhiteSpace(OfflineSource.Text))
        {
            ModernMessageDialog.Show(this, "Choose termsrv.dll first.", "Offline DLL");
            return;
        }
        var path = OfflineSource.Text;
        var find = OfflineFind.Text;
        var replace = OfflineReplace.Text;
        offlinePreview = null;
        await RunBusy(async () =>
        {
            var result = await Task.Run(() => OfflineDllPatcher.Inspect(path, find, replace));
            offlinePreview = result;
            OfflineDetails.Text = result.Summary();
            FooterText.Text = $"Offline DLL: {result.Architecture} | {result.Plan.State} | CRC32 {result.OriginalCrc32}";
        });
    }

    private async void OfflineInspect_Click(object sender, RoutedEventArgs e) => await CheckOfflineAsync();

    private async void OfflineSave_Click(object sender, RoutedEventArgs e)
    {
        if (busy || offlinePreview?.Plan.State != PatchState.Ready) return;
        var source = offlinePreview;
        var save = new SaveFileDialog
        {
            Title = "Save patched DLL as a NEW file (original is never replaced)",
            Filter = "Patched DLL (*.dll)|*.dll",
            FileName = "termsrv.patched.dll",
            InitialDirectory = Path.GetDirectoryName(source.SourcePath),
            AddExtension = true,
            DefaultExt = ".dll",
            OverwritePrompt = false
        };
        if (save.ShowDialog(this) != true) return;
        if (!Confirm(this, "Save offline DLL copy?",
                $"Write a new {source.Architecture} DLL copy? The source will remain unchanged. " +
                "Do not install this DLL on a production Windows system without an independent recovery plan."))
            return;
        OfflineDllResult? saved = null;
        await RunBusy(async () =>
        {
            saved = await Task.Run(() => OfflineDllPatcher.SavePatched(source, save.FileName));
            offlinePreview = null;
            OfflineDetails.Text = source.Summary() +
                $"\nSaved: {Path.GetFileName(saved.OutputPath)}" +
                $"\nVerified CRC32: {saved.FinalCrc32}" +
                $"\nVerified SHA-256: {saved.FinalSha256}" +
                "\nOriginal DLL not modified.";
            FooterText.Text = "Offline patched copy saved and verified. Original preserved.";
            OperationHistory.TryRecord("OfflineCopy", "Success", source.FileVersion,
                source.OriginalSha256, saved.FinalSha256);
        }, "OfflineCopy");
        if (saved is null) return;
        try
        {
            var report = saved.PublicMetadata();
            new SuccessfulFixWindow(report) { Owner = this }.ShowDialog();
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Offline compatibility reporting", ex);
            FooterText.Text = "Offline file saved; GitHub report unavailable: " + ex.GetType().Name;
        }
    }

    private void OfflineCopy_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(OfflineDetails.Text))
            Clipboard.SetText(OfflineDetails.Text);
    }

    private void OfflineExport_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(OfflineDetails.Text)) return;
        var dlg = new SaveFileDialog
        {
            Title = "Export offline DLL metadata",
            Filter = "Text report (*.txt)|*.txt",
            FileName = "termsrv-offline-report.txt"
        };
        if (dlg.ShowDialog(this) != true) return;
        File.WriteAllText(dlg.FileName, OfflineDetails.Text, new UTF8Encoding(false));
        FooterText.Text = "Offline report saved locally; no data was uploaded.";
    }

    private void BrowseDll_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Open termsrv.dll for inspection", Filter = "DLL files (*.dll)|*.dll|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) == true) SearchFile.Text = dialog.FileName;
    }

    private async void Search_Click(object sender, RoutedEventArgs e)
    {
        await RunBusy(async () =>
        {
            var path = SearchFile.Text;
            var query = SearchPattern.Text;
            lastScan = await Task.Run(() => engine.ScanDll(path, query));
            ScanDetails.Text = lastScan.AsText();
            FooterText.Text = $"Scan completed: {lastScan.Hits.Count} informational markers.";
        });
    }

    private void ExportScan_Click(object sender, RoutedEventArgs e)
    {
        if (lastScan is null) { ModernMessageDialog.Show(this, "Run Search inside DLL first."); return; }
        var dialog = new SaveFileDialog { Title = "Save read-only inspection report", Filter = "Text report (*.txt)|*.txt",
            FileName = "termsrv-inspection.txt" };
        if (dialog.ShowDialog(this) != true) return;
        File.WriteAllText(dialog.FileName, lastScan.AsText());
        FooterText.Text = "Report exported. Review its file hash and offsets before sharing.";
    }

    private void CopyScan_Click(object sender, RoutedEventArgs e)
    {
        if (lastScan is null)
        {
            ModernMessageDialog.Show(this, "Run Search inside DLL first.");
            return;
        }
        Clipboard.SetText(lastScan.AsText());
        FooterText.Text = "Read-only scan report copied.";
    }

    private void DisplayDllHealth(DllHealthReport report)
    {
        DllHealthDetails.Text = report.AsText();
        DllHealthStatusText.Text = report.Status switch
        {
            DllDriftStatus.FirstSeenUnverified =>
                "First observation recorded locally — UNVERIFIED. Matches the first seen DLL, not a verified Microsoft original.",
            DllDriftStatus.Unchanged =>
                "Current DLL matches the operator-recorded baseline. Original Microsoft origin is NOT proven.",
            DllDriftStatus.FileVersionChanged =>
                "DLL version changed since the reference. Compare Windows Update and signed system files.",
            DllDriftStatus.BytesChanged =>
                "DLL SHA-256 changed since the reference. Investigate before any repair.",
            DllDriftStatus.InvalidBaseline =>
                "Saved baseline is invalid or unavailable — comparison could not be verified.",
            _ => "No baseline. First-seen observation could not be established."
        };
        if (!string.IsNullOrWhiteSpace(report.FirstSeenWarning) &&
            report.FirstSeen is null)
            DllHealthStatusText.Text += " " + report.FirstSeenWarning;
        DllHealthStatusText.Foreground = report.Status is
            DllDriftStatus.BytesChanged or DllDriftStatus.InvalidBaseline or
            DllDriftStatus.FileVersionChanged
            ? new SolidColorBrush(Color.FromRgb(160, 92, 14))
            : new SolidColorBrush(Color.FromRgb(52, 90, 126));
    }

    private async void CheckDllHealth_Click(object sender, RoutedEventArgs e)
    {
        await RunBusy(async () =>
        {
            var report = await Task.Run(DllHealthMonitor.CheckLocal);
            DisplayDllHealth(report);
            FooterText.Text = "DLL health: " + report.Status +
                ". An unverified first-seen snapshot is local reference metadata only.";
        });
    }

    private async void CheckDllCompatibility_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        latestDllCompatibilityReport = null;
        DllCompatibilityGrid.ItemsSource = null;
        DllCompatibilitySummary.Text = "Inspecting local DLL metadata and bundled evidence...";
        CopyCompatibilityButton.IsEnabled = false;
        await RunBusy(async () =>
        {
            var report = await Task.Run(() =>
            {
                var health = DllHealthMonitor.CheckLocal();
                return (Health: health, Evidence: DllCompatibilityIndex.ReadLocal(health));
            });
            DisplayDllHealth(report.Health);
            latestDllCompatibilityReport = report.Evidence;
            DllCompatibilityGrid.ItemsSource = report.Evidence.Rows;
            DllCompatibilitySummary.Text = report.Evidence.Summary;
            CopyCompatibilityButton.IsEnabled = true;
            FooterText.Text = "DLL compatibility evidence inspected locally. No report submitted or DLL changed.";
        });
    }

    private void CopyDllCompatibility_Click(object sender, RoutedEventArgs e)
    {
        if (latestDllCompatibilityReport is null) return;
        try
        {
            Clipboard.SetText(latestDllCompatibilityReport.AsText());
            FooterText.Text = "Local compatibility evidence copied (no hostnames or file paths).";
        }
        catch (Exception error) when (error is System.Runtime.InteropServices.ExternalException or
                                       System.Threading.ThreadStateException)
        {
            ModernMessageDialog.Show(this,
                "Windows clipboard is not available: " + error.GetType().Name,
                "DLL compatibility evidence", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private async void SaveDllBaseline_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm(this, "Record DLL health baseline?",
                "Save the current termsrv.dll SHA-256 and version in your local profile? " +
                "This replaces your previous user-local baseline. It never changes the DLL " +
                "or authorizes Apply/Restore.")) return;
        await RunBusy(async () =>
        {
            await Task.Run(DllHealthMonitor.RecordLocalBaseline);
            var report = await Task.Run(DllHealthMonitor.CheckLocal);
            DisplayDllHealth(report);
            FooterText.Text = "Local DLL reference saved. No RDP or system settings were changed.";
            OperationHistory.TryRecord("Baseline", "Success", report.Current.DllVersion,
                report.Current.Sha256, report.Current.Sha256);
        });
    }

    private async void RunRdpDoctor_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        // One entry point in Remote Desktop: summary + technical details are
        // collected by the SAME read-only RDP Doctor scan.
        RdpDoctorPanel.IsExpanded = true;
        RdpDoctorPanel.BringIntoView();
        latestRdpDoctorReport = null;
        DoctorFindingsGrid.ItemsSource = null;
        DoctorEventsGrid.ItemsSource = null;
        DoctorBlockersText.Text = DoctorAttentionText.Text = DoctorUnknownText.Text =
            DoctorLocalEvidenceText.Text = DoctorUnavailableText.Text =
            DoctorNotTestedText.Text = "--";
        DoctorVerdictText.Text = "Inspecting service, local policy, TCP listeners and Windows logs...";
        DoctorCheckedText.Text = "Local inspection in progress. No Windows configuration changes.";
        DoctorEventStatus.Text = "Checking recent RDP event channels...";
        RdpDoctorQuickStatus.Text = "Doctor: inspecting local RDP evidence...";
        RdpInspectionStatus.Text = "Collecting local security evidence in the same scan...";
        RdpFirewallInspection.Text = RdpRightsInspection.Text =
            RdpCertificateInspection.Text = RdpGraphicsInspection.Text =
            "Not yet inspected. Status UNKNOWN.";
        CopyRdpDoctorButton.IsEnabled = false;
        await RunBusy(async () =>
        {
            var report = await Task.Run(RdpDoctor.ReadLocal);
            latestRdpDoctorReport = report;
            DoctorFindingsGrid.ItemsSource = report.Findings;
            DoctorEventsGrid.ItemsSource = report.Events;
            DoctorBlockersText.Text = report.Blockers.ToString(System.Globalization.CultureInfo.InvariantCulture);
            DoctorAttentionText.Text = report.AttentionCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
            DoctorUnknownText.Text = report.UnknownCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
            DoctorLocalEvidenceText.Text = report.LocalEvidenceCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
            DoctorUnavailableText.Text = report.UnavailableCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
            DoctorNotTestedText.Text = report.NotTestedCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
            DoctorVerdictText.Text = report.Verdict;
            DoctorCheckedText.Text = "Checked " +
                report.CheckedUtc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") +
                " UTC. Read-only local evidence; no remote sign-in attempted.";
            DoctorEventStatus.Text = report.Events.Count + " event metadata record(s); " +
                report.EventWarnings.Count + " inaccessible/unavailable channel(s)." +
                (report.EventWarnings.Count == 0
                    ? ""
                    : Environment.NewLine + string.Join(Environment.NewLine, report.EventWarnings));

            // This raw security text may contain local identities or certificate
            // details. It is displayed ONLY in the collapsed local technical panel;
            // RdpDoctorReport.AsText() deliberately excludes it.
            if (report.LocalSecurityDetails is { } details)
            {
                RdpFirewallInspection.Text = details.Firewall;
                RdpRightsInspection.Text = details.LogonRights;
                RdpCertificateInspection.Text = details.Certificate;
                RdpGraphicsInspection.Text = details.Graphics;
                RdpInspectionStatus.Text = "Detailed local evidence collected " +
                    details.CheckedUtc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") +
                    " UTC. Incomplete sources are identified explicitly. Sensitive details remain local.";
            }
            else
            {
                RdpInspectionStatus.Text = "Security inspection unavailable (UNKNOWN). " +
                    "No valid technical detail was collected.";
            }
            RdpDoctorQuickStatus.Text = "Doctor: " + report.Blockers +
                " blocker(s), " + report.AttentionCount + " attention, " +
                report.LocalEvidenceCount + " local evidence, " +
                report.UnavailableCount + " unavailable, " +
                report.UnknownCount + " incomplete. Remote RDP NOT tested.";
            CopyRdpDoctorButton.IsEnabled = true;
            FooterText.Text = "RDP Doctor completed. " + report.Blockers +
                " local blocker(s), " + report.UnavailableCount +
                " unavailable source(s). Windows Firewall and system DLL unchanged.";
        });
        if (latestRdpDoctorReport is null)
        {
            DoctorVerdictText.Text = "RDP diagnostic unavailable. No results are treated as verified.";
            RdpDoctorQuickStatus.Text = "Doctor: inspection unavailable. No changes made.";
            DoctorCheckedText.Text = "No completed scan available. Check Diagnostics for error details.";
            RdpInspectionStatus.Text = "Technical evidence unavailable. No changes were made.";
        }
    }

    private void CopyRdpDoctor_Click(object sender, RoutedEventArgs e)
    {
        if (latestRdpDoctorReport is null) return;
        try
        {
            Clipboard.SetText(latestRdpDoctorReport.AsText());
            FooterText.Text = "RDP Doctor report copied locally (no usernames, event messages or IP addresses).";
        }
        catch (Exception error) when (error is System.Runtime.InteropServices.ExternalException or
                                       System.Threading.ThreadStateException)
        {
            ModernMessageDialog.Show(this, "Windows clipboard is not available: " +
                error.GetType().Name, "RDP Doctor", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private async void RefreshRdpSessions_Click(object sender, RoutedEventArgs e)
    {
        await RunBusy(async () =>
        {
            var sessions = await Task.Run(RdpSessionViewer.ReadLocal);
            RdpSessionsGrid.ItemsSource = sessions;
            RdpSessionSummary.Text =
                $"{sessions.Count} local Windows sessions. Read-only WTS inventory; " +
                "account names are displayed here only and never included in reports.";
            RdpSessionsCountText.Text = $"{sessions.Count} Windows session(s) found.";
            FooterText.Text = "Session inventory refreshed. No RDP sessions were changed.";
        });
    }

    private static RdpConfigurationReport AnnotateRdpPolicyRows(RdpConfigurationReport report)
    {
        bool admin = SystemInfo.IsAdministrator();
        bool console = InteractiveSessionDetector.Detect() == SessionKind.Console;
        var rows = new List<RdpPolicyEvidence>(report.Values.Count);
        foreach (var row in report.Values)
        {
            if (row.Setting == RdpPolicyDiagnostics.BlankPasswordSetting)
            {
                // LSA security policy has its own explicit, verified writer.
                // We cannot infer a winning security GPO from the RDP policy key.
                rows.Add(RdpRowEditStatus.Annotate(row, admin, console,
                    policyManaged: null, validValue: RdpBlankPasswordSecurity.Read().HasValue));
                continue;
            }
            var spec = RdpLocalAdvancedSettings.Find(row.Setting);
            if (spec is null)
            {
                rows.Add(RdpRowEditStatus.Annotate(row, admin, console,
                    policyManaged: null, validValue: false));
                continue;
            }
            try
            {
                bool managed = RdpLocalAdvancedSettings.IsPolicyManaged(spec);
                bool valid = RdpLocalAdvancedSettings.ReadLocal(spec).HasValue;
                rows.Add(RdpRowEditStatus.Annotate(row, admin, console,
                    policyManaged: managed, validValue: valid));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                       System.Security.SecurityException or ArgumentException or
                                       InvalidOperationException)
            {
                rows.Add(RdpRowEditStatus.Annotate(row, admin, console,
                    policyManaged: null, validValue: false));
            }
        }
        return report with { Values = rows };
    }

    private void OpenBlankPasswordSetting_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        RdpTechnicalAdvanced.IsExpanded = true;
        var row = lastRdpPolicyReport?.Values.FirstOrDefault(x =>
            x.Setting == RdpPolicyDiagnostics.BlankPasswordSetting);
        if (row is null)
        {
            openBlankAfterPolicyRefresh = true;
            CheckRdpPolicy_Click(sender, e);
            return;
        }
        RdpPolicyGrid.SelectedItem = row;
        RdpPolicyGrid.ScrollIntoView(row);
        BlankPasswordInlineEditor.Visibility = Visibility.Visible;
    }

    private async void RdpPolicySelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (RdpPolicySelectedOwner is null || BlankPasswordInlineEditor is null) return;
        BlankPasswordInlineEditor.Visibility = Visibility.Collapsed;
        if (RdpPolicyGrid.SelectedItem is not RdpPolicyEvidence selected)
        {
            RdpPolicySelectedOwner.Text = "Select a row to inspect its source and editing permissions.";
            return;
        }
        if (selected.Setting == RdpPolicyDiagnostics.BlankPasswordSetting)
        {
            ReadBlankPasswordPolicy();
            BlankPasswordInlineEditor.Visibility = Visibility.Visible;
            RdpPolicySelectedOwner.Text = selected.Explanation + Environment.NewLine +
                "Editing: " + selected.EditStatus +
                ". This Windows security option does not apply to domain accounts. " +
                "Changing it never proves an RDP session can authenticate.";
            return;
        }
        string? registryName = RdpPolicySourceResolver.ValueForSetting(selected.Setting);
        if (registryName is null)
        {
            RdpPolicySelectedOwner.Text = selected.Explanation + Environment.NewLine +
                "Editing: " + selected.EditStatus;
            return;
        }
        RdpPolicySelectedOwner.Text = "Checking computer GPO source for " + selected.Setting + "...";
        try
        {
            var info = await Task.Run(() =>
            {
                bool managed = RdpPolicySourceResolver.IsPolicyPresent(registryName);
                var source = managed ? RdpPolicySourceResolver.ReadWinning(registryName) : null;
                return (managed, source);
            });
            if (!ReferenceEquals(RdpPolicyGrid.SelectedItem, selected)) return;
            RdpPolicySelectedOwner.Text = info.managed
                ? "Computer GPO controls this value. " +
                  (info.source?.Details ?? "Winning GPO not verified.") +
                  Environment.NewLine + "Editing: " + selected.EditStatus
                : "No matching Terminal Services computer policy registry value was detected. " +
                  RdpPolicySourceResolver.TerminalPolicyPath + "\\" + registryName +
                  Environment.NewLine + selected.Explanation + Environment.NewLine +
                  "Editing: " + selected.EditStatus +
                  ". A missing registry policy does not prove all Windows policies are absent.";
        }
        catch (Exception ex)
        {
            if (!ReferenceEquals(RdpPolicyGrid.SelectedItem, selected)) return;
            RdpPolicySelectedOwner.Text =
                "Policy origin cannot be verified (" + ex.GetType().Name +
                "). Editing is blocked until the policy is rechecked. " +
                RdpPolicySourceResolver.TerminalPolicyPath + "\\" + registryName;
        }
    }

    private void RdpPolicyGrid_MouseDoubleClick(object sender,
        System.Windows.Input.MouseButtonEventArgs e)
    {
        if (busy || e.OriginalSource is not DependencyObject source) return;
        var row = System.Windows.Controls.ItemsControl.ContainerFromElement(RdpPolicyGrid, source)
            as System.Windows.Controls.DataGridRow;
        if (row?.Item is RdpPolicyEvidence selected)
            OpenRdpPolicyEditor(selected);
    }

    private void EditRdpPolicyRow_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button button &&
            button.Tag is RdpPolicyEvidence row)
            OpenRdpPolicyEditor(row);
    }

    private void OpenRdpPolicyEditor(RdpPolicyEvidence selected)
    {
        if (busy || !selected.CanEdit) return;
        if (selected.Setting == RdpPolicyDiagnostics.BlankPasswordSetting)
        {
            RdpTechnicalAdvanced.IsExpanded = true;
            RdpPolicyGrid.SelectedItem = selected;
            BlankPasswordInlineEditor.Visibility = Visibility.Visible;
            RdpPolicyGrid.ScrollIntoView(selected);
            return; // The user still must explicitly select and save a value.
        }
        var spec = RdpLocalAdvancedSettings.Find(selected.Setting);
        if (spec is null) return;
        new RdpLocalSettingEditWindow(spec) { Owner = this }.ShowDialog();
        CheckRdpPolicy_Click(this, new RoutedEventArgs());
    }

    private void CopySelectedPolicy_Click(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(RdpPolicySelectedOwner.Text); }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            FooterText.Text = "Clipboard unavailable; the policy information remains on screen.";
        }
    }

    private async void CheckRdpPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        var previouslySelected = (RdpPolicyGrid.SelectedItem as RdpPolicyEvidence)?.Setting;
        lastRdpPolicyReport = null; // Never present stale policy evidence as current.
        await RunBusy(async () =>
        {
            var report = await Task.Run(() =>
                AnnotateRdpPolicyRows(RdpPolicyDiagnostics.ReadLocal()));
            ShowRdpPolicyReport(report);
            RdpPolicyGrid.ItemsSource = report.Values;
            RdpPolicySummary.Text = report.Values.Count + " settings inspected, " +
                report.Warnings.Count + " notice(s). TermService: " + report.TermServiceStatus +
                ". No changes made.";
            RdpPolicyDetails.Text = report.AsText();
            FooterText.Text = "RDP configuration diagnostic completed (read-only).";
        });
        if (lastRdpPolicyReport is not null)
        {
            string? select = openBlankAfterPolicyRefresh
                ? RdpPolicyDiagnostics.BlankPasswordSetting : previouslySelected;
            openBlankAfterPolicyRefresh = false;
            var row = lastRdpPolicyReport.Values.FirstOrDefault(x => x.Setting == select);
            if (row is not null)
            {
                RdpPolicyGrid.SelectedItem = row;
                RdpPolicyGrid.ScrollIntoView(row);
                if (row.Setting == RdpPolicyDiagnostics.BlankPasswordSetting)
                    BlankPasswordInlineEditor.Visibility = Visibility.Visible;
            }
            ReadBlankPasswordPolicy();
        }
    }

    private void MainTabs_SelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, MainTabs) || !IsLoaded || busy)
            return;
        if (MainTabs.SelectedItem is System.Windows.Controls.TabItem tab &&
            tab.Header as string == "Remote Desktop" && lastRdpPolicyReport is null)
            CheckRdpPolicy_Click(sender, new RoutedEventArgs());
    }

    private async void RefreshOperationHistory_Click(object sender, RoutedEventArgs e)
    {
        await RunBusy(async () =>
        {
            var result = await Task.Run(() => OperationHistory.ReadRecent(100));
            OperationHistoryGrid.ItemsSource = result.Entries;
            OperationHistorySummary.Text = result.Entries.Count + " local operation(s), " +
                result.InvalidEntries + " invalid record(s) skipped. " +
                (result.Warning ?? "No network calls or service changes.");
            FooterText.Text = "Local operation history refreshed.";
        });
    }

    private static readonly Brush RdpGoodBrush =
        new SolidColorBrush(Color.FromRgb(22, 101, 52));
    private static readonly Brush RdpWarningBrush =
        new SolidColorBrush(Color.FromRgb(146, 64, 14));
    private static readonly Brush RdpUnknownBrush =
        new SolidColorBrush(Color.FromRgb(71, 85, 105));

    private static void RenderRdpTile(System.Windows.Controls.TextBlock tile,
        string value, string source, bool safe)
    {
        tile.Text = value + Environment.NewLine + source;
        tile.Foreground = source == "Unknown" ? RdpUnknownBrush
            : safe ? RdpGoodBrush : RdpWarningBrush;
        tile.ToolTip = "Configured values only. Current RDP connectivity is not independently verified.";
    }

    private static (string Source, string Value) RdpPolicyValue(
        RdpConfigurationReport report, string setting)
    {
        var row = report.Values.FirstOrDefault(x => x.Setting == setting);
        if (row is null || row.Assessment == "Invalid value")
            return ("Unknown", "");
        if (row.Assessment is "Policy differs" or "Policy configured")
            return ("GPO configured*", row.PolicyValue);
        if (row.Assessment == "Local setting")
            return ("Local", row.LocalValue);
        return ("Unknown", "");
    }

    private static string RdpSourceLabel(RdpConfigurationReport report, string setting)
    {
        var row = report.Values.FirstOrDefault(x => x.Setting == setting);
        return row?.Assessment switch
        {
            "Policy configured" => "GPO configured*",
            "Policy differs" => "GPO differs* - review",
            "Local setting" => "Local",
            "Invalid value" => "Invalid - review",
            _ => "Unknown"
        };
    }

    private void ShowRdpPolicyReport(RdpConfigurationReport report)
    {
        lastRdpPolicyReport = report;
        RdpServiceText.Text = "TermService: " + report.TermServiceStatus +
            " | " + report.Warnings.Count + " notice(s). Service running does not prove remote reachability.";
        var policyCount = report.Values.Count(v => v.Assessment is "Policy configured" or "Policy differs");
        RdpPolicyOverviewText.Text = policyCount == 0
            ? "Policy source: no applicable registry policy detected in inspected settings; GPO application not independently confirmed."
            : "Policy source: " + policyCount +
              " computer policy setting(s) detected; *GPO configured does not prove effective application. See Advanced for the winning RSoP GPO.";
        RdpEnabledSourceText.Text = RdpSourceLabel(report, "Remote Desktop");
        NlaSourceText.Text = RdpSourceLabel(report, "Network Level Authentication");
        SingleSourceText.Text = RdpSourceLabel(report, "One session per user");
        var remote = RdpPolicyValue(report, "Remote Desktop");
        var nla = RdpPolicyValue(report, "Network Level Authentication");
        var single = RdpPolicyValue(report, "One session per user");
        string remoteValue = remote.Value.StartsWith("Enabled (", StringComparison.Ordinal)
            ? "Enabled" : remote.Value.StartsWith("Disabled (", StringComparison.Ordinal)
            ? "Disabled" : "Unknown";
        string nlaValue = nla.Value.StartsWith("Required (", StringComparison.Ordinal)
            ? "Required" : nla.Value.StartsWith("Not required (", StringComparison.Ordinal)
            ? "Not required" : "Unknown";
        string singleValue = single.Value.StartsWith("On (", StringComparison.Ordinal)
            ? "On" : single.Value.StartsWith("Off (", StringComparison.Ordinal)
            ? "Off" : "Unknown";
        RenderRdpTile(RdpEffectiveEnabledText, remoteValue, remote.Source, remoteValue == "Enabled");
        RenderRdpTile(RdpEffectiveNlaText, nlaValue, nla.Source, nlaValue == "Required");
        RenderRdpTile(RdpEffectiveSingleText, singleValue, single.Source, singleValue == "On");

        var port = RdpPolicyValue(report, "RDP TCP port");
        RdpEffectivePortText.Text = port.Source == "Unknown" ? "Configured port: unknown"
            : "Configured port: " + port.Value + " (" + port.Source + ")";
        RdpOverviewText.Text = "RDP configuration: " + remoteValue +
            " | NLA: " + nlaValue + " | Service: " + report.TermServiceStatus;
    }

    private void ReadRdp()
    {
        var status = RdpConfiguration.Read();
        RdpEnabled.IsChecked = status.Enabled;
        NlaEnabled.IsChecked = status.NetworkLevelAuthentication;
        SingleSession.IsChecked = status.OneSessionPerUser;
        RdpOverviewText.Text = "Local RDP: " + (status.Enabled ? "Enabled" : "Disabled") +
            " | Local NLA: " + (status.NetworkLevelAuthentication ? "Required" : "Not required") +
            " | Effective remote access: not verified";
        RenderRdpTile(RdpEffectiveEnabledText, status.Enabled ? "Enabled" : "Disabled",
            "Local", status.Enabled);
        RenderRdpTile(RdpEffectiveNlaText, status.NetworkLevelAuthentication ? "Required" : "Not required",
            "Local", status.NetworkLevelAuthentication);
        RenderRdpTile(RdpEffectiveSingleText, status.OneSessionPerUser ? "On" : "Off",
            "Local", status.OneSessionPerUser);
        RdpEnabledSourceText.Text = NlaSourceText.Text = SingleSourceText.Text =
            "Local (GPO not yet checked)";
        RdpPolicyOverviewText.Text = "Policy: not checked. Local values can be overridden by domain policy.";
        RdpServiceText.Text = "TermService: not yet verified.";
        RdpEffectiveFirewallText.Text = "Firewall: not independently verified";
        RdpDetails.Text = "Local values loaded. Use Check configuration under Advanced to inspect policy evidence.";
        var port = RdpPostApply.ReadLocalPort();
        RdpEffectivePortText.Text = "Configured port (local): " +
            (port?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown");
        if (RdpPostApply.ListenerRestartRequired(observedRdpListenerPort, port))
        {
            previousRdpListenerPort = observedRdpListenerPort;
            portRestartNeedsReview = true;
            RdpApplyImpactText.Text =
                "Local RDP listener port changed from " + previousRdpListenerPort +
                " to " + port + ". A TermService restart or Windows reboot may be required. " +
                "Do not restart from an RDP-only connection.";
            RdpPostApplyActions.Text =
                "Restart review required. Verify Firewall rules for the new port and arrange independent console recovery.";
        }
        observedRdpListenerPort = port;
        RdpEffectiveRestartText.Text = portRestartNeedsReview
            ? "Restart: review required (port changed)" : "Restart: no port drift observed";
        ReviewRdpRestartButton.IsEnabled = portRestartNeedsReview && port.HasValue;
        ReadBlankPasswordPolicy();
        // Only reuse policy results in the same read cycle when a fresh report
        // was explicitly requested; a UI reload must not claim a stale GPO state.
        if (lastRdpPolicyReport is not null)
            ShowRdpPolicyReport(lastRdpPolicyReport);
    }

    private void ReadSettings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            lastRdpPolicyReport = null;
            ReadRdp();
            if (MainTabs.SelectedItem is System.Windows.Controls.TabItem tab &&
                tab.Header as string == "Remote Desktop")
                CheckRdpPolicy_Click(sender, e);
        }
        catch (Exception ex)
        {
            ModernMessageDialog.Show(this, ex.Message, "Read settings failed", MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void ReadBlankPasswordPolicy()
    {
        bool? restricted = RdpBlankPasswordSecurity.Read();
        BlankPasswordStatus.Text = restricted switch
        {
            true => "Current: restriction ON. Empty-password local accounts are blocked from ordinary remote logon (recommended).",
            false => "Current: restriction OFF. Windows does not block empty-password local accounts under this security option (HIGH RISK).",
            _ => "Current: unknown (missing, invalid or unreadable). Editing disabled."
        };
        BlankPasswordStatus.Text += Environment.NewLine +
            "LSA: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse" +
            Environment.NewLine + "Winning security GPO: not identified. RDP sign-in depends on other policies and NLA.";
        RenderRdpTile(RdpEffectiveBlankText, restricted switch
        {
            true => "Restriction ON",
            false => "Restriction OFF",
            _ => "Unknown"
        }, restricted.HasValue ? "Local security" : "Unknown", restricted == true);
        BlankPasswordStatus.Foreground = restricted == false
            ? new SolidColorBrush(Color.FromRgb(153, 49, 24))
            : new SolidColorBrush(Color.FromRgb(30, 84, 104));
        bool canEdit = restricted.HasValue && SystemInfo.IsAdministrator() && !busy;
        BlankPasswordChoice.IsEnabled = canEdit;
        SaveBlankPasswordButton.IsEnabled = canEdit;
        BlankPasswordChoice.SelectedIndex = restricted switch
        {
            true => 0,
            false => 1,
            _ => -1
        };
    }

    private async void SaveBlankPassword_Click(object sender, RoutedEventArgs e)
    {
        if (busy || !SystemInfo.IsAdministrator()) return;
        if (BlankPasswordChoice.SelectedIndex is not (0 or 1))
            return;
        bool restrict = BlankPasswordChoice.SelectedIndex == 0;
        bool? currentBlankRestriction = RdpBlankPasswordSecurity.Read();
        if (currentBlankRestriction is null)
        {
            ReadBlankPasswordPolicy();
            ModernMessageDialog.Show(this, "The local security policy cannot be inspected. No changes made.",
                "Security setting unavailable", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (currentBlankRestriction.Value == restrict)
        {
            FooterText.Text = "Blank-password local policy is already set. No change required.";
            return;
        }
        if (!restrict)
        {
            if (!Confirm(this, "Security risk: permit blank passwords?",
                    "This will DISABLE a recommended Windows security restriction. " +
                    "Local accounts with empty passwords may then become accessible remotely. " +
                    "The change is not limited to RDP, and domain policy may override it. " +
                    "Never use this on shared, exposed, or production computers. Continue?"))
                return;
            if (!Confirm(this, "Final confirmation: weaken logon security",
                    "Confirm that you accept remote logon with a BLANK local-account password. " +
                    "Any remote party knowing such an account name could attempt sign-in. " +
                    "Do not continue without a strong network boundary and console access."))
                return;
        }
        else if (!Confirm(this, "Restrict remote blank-password logon?",
                     "Re-enable the recommended local security restriction?")) return;

        bool succeeded = false;
        await RunBusy(async () =>
        {
            await Task.Run(() => RdpBlankPasswordSecurity.SetRestricted(restrict));
            succeeded = true;
            ReadBlankPasswordPolicy();
            FooterText.Text = restrict
                ? "Blank-password console-only restriction enabled and verified."
                : "Local restriction disabled by explicit confirmation. Review domain policy.";
            RdpApplyImpactText.Text =
                "Local account blank-password restriction was read back. " +
                "A reboot is not normally needed; test a NEW sign-in. " +
                "Domain GPO may overwrite the local security setting.";
            RdpPostApplyActions.Text =
                "Reconnect or sign in again to validate policy. gpupdate is only for pending computer GPO changes.";
        }, "RdpSettings");
        ReadBlankPasswordPolicy(); // Never leave speculative or disabled status behind.
        if (succeeded)
            CheckRdpPolicy_Click(sender, new RoutedEventArgs());
    }

    private async void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        // Capture all WPF input on the UI thread BEFORE Task.Run.
        bool enableRdp = RdpEnabled.IsChecked == true;
        bool enforceNla = NlaEnabled.IsChecked == true;
        bool oneSession = SingleSession.IsChecked == true;
        bool syncFirewall = FirewallEnabled.IsChecked == true;
        RdpStatus previous;
        try { previous = RdpConfiguration.Read(); }
        catch (Exception readError)
        {
            ModernMessageDialog.Show(this, "Could not read original RDP settings: " + readError.Message,
                "Save blocked", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (!Confirm(this, "Change RDP settings?",
            "This operation checks policy conflicts, then updates RDP settings " +
            "and optionally Windows Firewall rules. Partial failures trigger a verified rollback. " +
            "A rollback failure will require local-console recovery. " +
            "Network Level Authentication should remain enabled. Proceed?")) return;

        bool completed = false;
        await RunBusy(async () =>
        {
            await Task.Run(() =>
                RdpConfiguration.Save(enableRdp, enforceNla, oneSession, syncFirewall));
            completed = true;
            var current = RdpConfiguration.Read();
            var followUp = RdpPostApply.Build(previous, current, syncFirewall);
            lastRdpPolicyReport = null;
            ReadRdp(); // UI-thread readback, not a guess based on requested values.
            ShowRdpPolicyReport(await Task.Run(RdpPolicyDiagnostics.ReadLocal));
            RdpApplyImpactText.Text = followUp.Summary +
                (portRestartNeedsReview
                    ? " RDP listener port drift was detected and requires restart review." : "");
            RdpPostApplyActions.Text = string.Join(Environment.NewLine,
                followUp.Rows.Where(row => row.Status != "No local change" &&
                                          row.Status != "Not changed")
                    .Select(row => row.Setting + ": " + row.RequiredAction));
            FooterText.Text = "RDP settings verified. Check resultant Group Policy and firewall scope.";
        }, "RdpSettings");

        if (!completed)
        {
            // A failed save can be followed by a successful rollback. Never leave
            // the requested checkbox values looking as though they were applied.
            try
            {
                ReadRdp();
                RdpDetails.Text = "Settings change failed. Current local values reloaded; " +
                    "read the error and RDP policy diagnostics before retrying.";
            }
            catch (Exception error)
            {
                RdpDetails.Text = "Settings change failed; current registry values could not be read (" +
                    error.GetType().Name + "). Recover from the local console if necessary.";
            }
        }
    }

    private async void RefreshComputerPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (busy || !SystemInfo.IsAdministrator())
        {
            ModernMessageDialog.Show(this, "Computer policy refresh requires administrator privileges.",
                "Refresh Computer Policy", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!Confirm(this, "Refresh computer Group Policy?",
            "Run gpupdate /target:computer /force /wait:90? This refreshes ALL computer " +
            "policies, not only RDP, and can override local settings or affect remote " +
            "access. There will be NO automatic service restart, logoff or reboot. " +
            "Keep independent console recovery access."))
            return;
        await RunBusy(async () =>
        {
            var result = await Task.Run(RdpPostApply.RefreshComputerPolicy);
            if (!result.Success)
                throw new InvalidOperationException(
                    "Group Policy refresh returned exit code " + result.ExitCode +
                    ". Check gpresult and the Windows Group Policy event logs.");
            var report = await Task.Run(() =>
                AnnotateRdpPolicyRows(RdpPolicyDiagnostics.ReadLocal()));
            ShowRdpPolicyReport(report);
            RdpPolicyGrid.ItemsSource = report.Values;
            RdpPolicySummary.Text = report.Values.Count + " local/policy settings, " +
                report.Warnings.Count + " notice(s).";
            RdpPolicyDetails.Text = report.AsText();
            ReadRdp();
            RdpApplyImpactText.Text =
                "Computer Group Policy refresh completed (exit 0). " +
                "No automatic reboot, logoff or TermService restart was requested. " +
                "Some policies require a NEW session or a later restart.";
            RdpPostApplyActions.Text =
                "Review applied policy results and check the next connection. " +
                (portRestartNeedsReview
                    ? "Listener port drift detected: review TermService restart at local console."
                    : "No observed listener port change since this GUI opened.");
            FooterText.Text = "Computer Group Policy refreshed; new RDP connection verification remains necessary.";
        });
    }

    private void ReviewRdpRestart_Click(object sender, RoutedEventArgs e)
    {
        if (busy || !portRestartNeedsReview) return;
        ModernMessageDialog.Show(this,
            "The local RDP listener port was observed changing from " +
            (previousRdpListenerPort?.ToString() ?? "unknown") + " to " +
            (observedRdpListenerPort?.ToString() ?? "unknown") + ".\n\n" +
            "A restart of TermService (or of Windows) may be needed to activate the new " +
            "listener. Restarting TermService can disconnect every RDP session and " +
            "interrupt access to this computer.\n\n" +
            "No restart has been performed. Verify Firewall rules for the new port, " +
            "confirm console access, and arrange a separate protected or local-console restart. " +
            "Then reopen the application and verify a new connection.",
            "Review RDP restart — no changes made",
            MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void Log_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(AuditLog.Root);
        var file = Path.Combine(AuditLog.Root, "operations.log");
        if (!File.Exists(file)) File.WriteAllText(file, "No operations logged yet." + Environment.NewLine);
        Process.Start(new ProcessStartInfo(file) { UseShellExecute = true });
    }

    private void ReadAutoUpdateSetting()
    {
        autoUpdateLoading = true;
        try
        {
            bool enabled = AutoUpdatePreferences.IsEnabled();
            AdvancedAutoUpdateCheck.IsChecked = enabled;
            AdvancedAutoUpdateCheck.IsEnabled = SystemInfo.IsAdministrator() && !autoUpdateChanging;
            AdvancedAutoUpdateStatus.Text = AutoUpdatePreferences.Label(enabled) +
                Environment.NewLine + AutoUpdatePreferences.ReadScheduledSummary() +
                (enabled && !AutoReapplyScheduler.ReadStatus().Enabled
                    ? Environment.NewLine +
                      "Scheduled checks run only if the protected Auto Reapply task is enabled." : "");
        }
        finally { autoUpdateLoading = false; }
    }

    private async void AutoUpdateChanged(object sender, RoutedEventArgs e)
    {
        if (AdvancedAutoUpdateStatus is null || autoUpdateLoading || autoUpdateChanging) return;
        bool enable = AdvancedAutoUpdateCheck.IsChecked == true;
        if (enable && ModernMessageDialog.Show(this,
                "Auto-update will check Stable GitHub Releases at startup and every four hours. " +
                "An enabled, trusted Auto Reapply scheduled task also checks for new versions. " +
                "This is NOT unattended installation: the application is unsigned, so the " +
                "Update Center must approve every EXE replacement. Continue?",
                "Enable automatic update checks", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            ReadAutoUpdateSetting();
            return;
        }
        autoUpdateChanging = true;
        AdvancedAutoUpdateCheck.IsEnabled = false;
        try { await Task.Run(() => AutoUpdatePreferences.SetEnabled(enable)); }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Auto-update", ex);
            ModernMessageDialog.Show(this,
                "Automatic checks were not changed: " + ex.Message,
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
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            foreach (var channel in new[] { UpdateChannel.Stable, UpdateChannel.Prerelease })
                await updates.Get(channel).CheckAsync(
                    forced: false, cancellationToken: timeout.Token);
        }
        catch (Exception ex)
        {
            // An unavailable release endpoint never means the app is up to date.
            DiagnosticsBridge.Remember("Updates", ex);
        }
    }

    private void RefreshUpdateIndicator() =>
        UpdateButtonIndicator.Apply(
            UpdatesButton,
            updates.Get(UpdateChannel.Stable).Notice,
            updates.Get(UpdateChannel.Prerelease).Notice);

    internal void SetBackupPreference(bool createFullBackup)
        => CreateBackupCheck.IsChecked = createFullBackup;

    private void SimpleMode_Click(object sender, RoutedEventArgs e)
    {
        if (busy || autoTaskChanging)
        {
            ModernMessageDialog.Show(this, "Finish the current operation before switching views.",
                "Switch view", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // Switch the WPF MainWindow owner BEFORE closing Advanced. The simple
        // view performs a new read-only DLL and recovery-evidence inspection;
        // an old Ready plan must never be carried across this navigation.
        var simple = new QuickApplyWindow();
        simple.SetBackupPreference(CreateBackupCheck.IsChecked == true);
        Application.Current.MainWindow = simple;
        simple.Show();
        Close();
    }


    private async Task RefreshAutoReapplyAsync()
    {
        if (autoTaskChanging) return;
        var task = await Task.Run(AutoReapplyScheduler.ReadStatus);
        autoTaskLoading = true;
        try
        {
            AdvancedAutoReapplyCheck.IsChecked = task.Trusted && task.Enabled;
            AdvancedAutoReapplyCheck.IsEnabled = !busy &&
                (!task.Installed || task.Trusted);
            bool autoReportApproved = AutoCompatibilityReporting.IsEnabled(
                DirectReportingSettings.Load().GoogleAppsScriptUrl);
            AdvancedAutoReapplyStatus.Text = task.Message +
                (autoReportApproved
                    ? " Silent unified reports: consent ON."
                    : " Silent unified reports: OFF.");
            AdvancedRevokeAutoReportsButton.Visibility = autoReportApproved
                ? Visibility.Visible : Visibility.Collapsed;
            AdvancedRevokeAutoReportsButton.IsEnabled =
                autoReportApproved && SystemInfo.IsAdministrator() && !busy;
            AdvancedRepairTaskButton.Visibility = task.Repairable
                ? Visibility.Visible : Visibility.Collapsed;
            AdvancedRepairTaskButton.IsEnabled = task.Repairable && !busy &&
                SystemInfo.IsAdministrator() && !autoTaskChanging;
        }
        finally { autoTaskLoading = false; }
    }

    private async void RevokeAutoReports_Click(object sender, RoutedEventArgs e)
    {
        if (busy || autoTaskChanging || !SystemInfo.IsAdministrator()) return;
        if (ModernMessageDialog.Show(this,
                "Remove permission for future silent diagnostic and compatibility reports? " +
                "The Auto Reapply task, installed DLL and backups remain unchanged.",
                "Disable automatic reports", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        try { await Task.Run(AutoCompatibilityReporting.Revoke); }
        catch (Exception ex)
        {
            FooterText.Text = "Could not revoke reporting permission: " +
                              ex.GetType().Name;
        }
        await RefreshAutoReapplyAsync();
    }

    private async void RepairAutoReapply_Click(object sender, RoutedEventArgs e)
    {
        if (busy || autoTaskChanging || !SystemInfo.IsAdministrator()) return;
        var task = AutoReapplyScheduler.ReadStatus();
        if (!task.Repairable || ModernMessageDialog.Show(this,
                "The task runs the expected SYSTEM worker, but its permissions " +
                "do not match the protected profile.\n\n" +
                "Restrict editing to SYSTEM and Administrators? No DLL, backups " +
                "or trigger settings will be changed.",
                "Repair scheduled task security", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        autoTaskChanging = true;
        AdvancedRepairTaskButton.IsEnabled = false;
        AdvancedAutoReapplyStatus.Text = "Checking and repairing the task ACL...";
        try
        {
            await Task.Run(AutoReapplyScheduler.RepairTaskPermissions);
            AdvancedAutoReapplyStatus.Text = "Task permissions successfully verified.";
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Task ACL repair", ex);
            ModernMessageDialog.Show(this,
                "Cannot verify the restricted task permissions (" + ex.GetType().Name +
                "). The task definition was not overwritten. Check Task Scheduler.",
                "Task security", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            autoTaskChanging = false;
            await RefreshAutoReapplyAsync();
        }
    }

    private async void AutoReapplyChanged(object sender, RoutedEventArgs e)
    {
        if (AdvancedAutoReapplyStatus is null || autoTaskLoading || autoTaskChanging) return;
        if (busy) { await RefreshAutoReapplyAsync(); return; }
        bool enable = AdvancedAutoReapplyCheck.IsChecked == true;
        var current = AutoReapplyScheduler.ReadStatus();
        if (current.Installed && !current.Trusted ||
            !enable && !current.Installed)
        {
            await RefreshAutoReapplyAsync();
            return;
        }
        if (enable && ModernMessageDialog.Show(this,
                "Install a protected SYSTEM task to check changed termsrv.dll after Windows Update, " +
                "at startup and daily? Automatic Apply only uses a uniquely verified exact signature, " +
                "always with full backup. Maintain independent console recovery access.",
                "Enable Auto Reapply", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            await RefreshAutoReapplyAsync();
            return;
        }
        if (!enable && ModernMessageDialog.Show(this,
                "Remove the Auto Reapply task? This does not change the installed DLL.",
                "Disable Auto Reapply", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            await RefreshAutoReapplyAsync();
            return;
        }
        autoTaskChanging = true;
        AdvancedAutoReapplyCheck.IsEnabled = false;
        AdvancedAutoReapplyStatus.Text = enable ? "Installing scheduled task..." : "Removing scheduled task...";
        try
        {
            await Task.Run(() =>
            {
                if (enable) AutoReapplyScheduler.Enable();
                else AutoReapplyScheduler.Disable();
            });
        }
        catch (Exception error)
        {
            DiagnosticsBridge.Remember("Auto Reapply", error);
            ModernMessageDialog.Show(this, "The scheduled task was not changed successfully: " + error.Message,
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
        if (busy || autoTaskChanging) return;
        new CleanupWindow { Owner = this }.ShowDialog();
        await RefreshAutoReapplyAsync();
        await CheckAsync();
    }

    private void Updates_Click(object sender, RoutedEventArgs e)
        => new UpdateCenterWindow(updates) { Owner = this }.ShowDialog();

    private void Diagnostics_Click(object sender, RoutedEventArgs e)
        => new DiagnosticsWindow { Owner = this }.ShowDialog();
}
