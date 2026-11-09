using Microsoft.Win32;
using UniversalUpdater;
using System.Windows.Media;
using System.Diagnostics;
using System.Text;
using System.Windows;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class MainWindow : Window
{
    private readonly TermsrvEngine engine;
    private PatchPlan? autoPlan;
    private PatchPlan? manualPlan;
    private ScanReport? lastScan;
    private OfflineDllPreview? offlinePreview;
    private string? importedFile;
    private IReadOnlyList<PatchProfile> imported = [];
    private bool busy;
    private readonly UpdateIntegration updates = new();

    public MainWindow(bool offlineStartup = false)
    {
        InitializeComponent();
        if (offlineStartup) MainTabs.SelectedIndex = 3;
        engine = new TermsrvEngine(text => Dispatcher.BeginInvoke(() => FooterText.Text = text));
        WindowSettings.Restore(this);
        Closing += (_, _) => { WindowSettings.Save(this); updates.Dispose(); };
        updates.Get(UpdateChannel.Prerelease).NoticeChanged += (_, _) =>
            Dispatcher.BeginInvoke(RefreshUpdateIndicator);
        RefreshUpdateIndicator();
        Loaded += async (_, _) =>
        {
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
            await CheckAsync();
            // Background metadata-only update check: no download or installation.
            _ = BackgroundUpdateCheckAsync();
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
            MessageBox.Show(this, e.Message, "TermsrvPatcher Unified", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            busy = false;
            RefreshButton.IsEnabled = true;
            MainTabs.IsEnabled = true;
            RestoreButton.IsEnabled = true;
            ApplyAutoButton.IsEnabled = autoPlan?.State == PatchState.Ready && NsudoDevilModeScope.IsBundled && SystemInfo.IsAdministrator();
            ApplyManualButton.IsEnabled = manualPlan?.State == PatchState.Ready && NsudoDevilModeScope.IsBundled && SystemInfo.IsAdministrator();
            OfflineSaveButton.IsEnabled = offlinePreview?.Plan.State == PatchState.Ready;
        }
    }

    private async Task CheckAsync()
    {
        await RunBusy(async () =>
        {
            var result = await Task.Run(() => (Info: engine.EnvironmentInfo(), Preview: engine.Inspect()));
            var os = result.Info;
            autoPlan = result.Preview;
            SystemText.Text = os.Display + (os.Is64Bit ? " | x64" : " | x86");
            DllText.Text = $"termsrv.dll: {os.DllVersion}  |  {os.DllPath}";
            StatusText.Text = $"Automatic status: {autoPlan.State}  |  {autoPlan.Description}";
            AutoSummary.Text = autoPlan.ProfileId.Length == 0 ? autoPlan.Description :
                $"Matched: {autoPlan.ProfileId}";
            AutoDetails.Text = PlanText(autoPlan);
            ApplyAutoButton.IsEnabled = autoPlan.State == PatchState.Ready && NsudoDevilModeScope.IsBundled && SystemInfo.IsAdministrator();
            if (autoPlan.State is PatchState.Unknown or PatchState.Ambiguous)
            {
                lastScan = await Task.Run(() => engine.ScanDll(os.DllPath, null));
                ScanDetails.Text = lastScan.AsText();
                AutoDetails.Text += $"\nFallback scan: {lastScan.Similar.Count} near matches and " +
                    $"{lastScan.Hits.Count} structural markers. See Search DLL for details. " +
                    "No replacement bytes were generated.";
            }
            FooterText.Text = $"Check completed: {autoPlan.State}.";
        });
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
        => MessageBox.Show(owner, message, title, MessageBoxButton.YesNo,
            MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;

    private void About_Click(object sender, RoutedEventArgs e)
    {
        new AboutWindow { Owner = this }.ShowDialog();
    }

    private async Task ApplyAsync(PatchPlan? plan, bool manual)
    {
        if (plan?.State != PatchState.Ready || !NsudoDevilModeScope.IsBundled || !SystemInfo.IsAdministrator()) return;
        bool createBackup = CreateBackupCheck.IsChecked != false;
        string message = "This operation modifies the protected Windows termsrv.dll file and stops " +
            "Remote Desktop services temporarily. Active RDP connections may be disconnected. " +
            "Windows updates may revert the change. Proceed only on a system you administer and " +
            "where permitted by the applicable license.";
        if (manual)
            message += "\n\nMANUAL MODE: You supplied the replacement bytes. No automatic analysis " +
                "can guarantee that this patch is safe. Continue?";
        if (!createBackup)
            message += "\n\nCREATE BACKUP IS OFF: No persistent DLL backup will be saved. " +
                       "After the operation, Restore will not be available unless an earlier " +
                       "valid backup exists. A failed write still attempts in-memory rollback.";
        if (!Confirm(this, manual ? "Apply manual patch?" : "Apply verified patch?", message)) return;
        if (!createBackup && !Confirm(this, "Confirm: no backup",
                "Continue WITHOUT creating a backup? A later Restore is not guaranteed. " +
                "Use a VM snapshot or an independent trusted backup for recovery.")) return;
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
        {
            try
            {
                var versions = SuccessfulFixMetadata.FromSuccessfulApply(
                    engine.EnvironmentInfo(), plan);
                new SuccessfulFixWindow(versions) { Owner = this }.ShowDialog();
            }
            catch (Exception ex)
            {
                // Reporting never determines the outcome of the local operation.
                DiagnosticsBridge.Remember("Compatibility reporting", ex);
                AuditLog.Append("Optional compatibility dialog was unavailable: " +
                    ex.GetType().Name);
            }
        }
    }

    private async void ApplyAuto_Click(object sender, RoutedEventArgs e) => await ApplyAsync(autoPlan, false);
    private async void ApplyManual_Click(object sender, RoutedEventArgs e) => await ApplyAsync(manualPlan, true);

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        var verified = engine.BackupsForCurrentVersion();
        if (verified.Count == 0)
        {
            MessageBox.Show(this, "No trusted backup for the currently installed DLL.",
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
            MessageBox.Show(this, "No backup directory has been created yet.",
                "Backups", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        Process.Start(new ProcessStartInfo(TermsrvEngine.BackupDirectory) { UseShellExecute = true });
    }

    private void ManualEdited(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        manualPlan = null;
        if (ApplyManualButton is not null) ApplyManualButton.IsEnabled = false;
        if (ManualResult is not null) ManualResult.Text = "Pattern changed. Check again before applying.";
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
            MessageBox.Show(this, ex.Message, "Cannot save pattern", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Import_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Import manual patterns", Filter = "Text patterns (*.txt)|*.txt|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            imported = PatchCatalog.Parse(File.ReadAllText(dialog.FileName), "Imported user patterns");
            importedFile = dialog.FileName;
            ImportSelector.ItemsSource = imported;
            if (imported.Count > 0) ImportSelector.SelectedIndex = 0;
            ImportedInfo.Text = $"Imported {imported.Count} patterns. Select one then Check selected.";
            manualPlan = null;
            ApplyManualButton.IsEnabled = false;
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Invalid pattern file"); }
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
            MessageBox.Show(this, "Check the DLL first.", "DryRun", MessageBoxButton.OK,
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
            MessageBox.Show(this, ex.Message, "DryRun export refused",
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
            MessageBox.Show(this, "Choose termsrv.dll first.", "Offline DLL");
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
        if (lastScan is null) { MessageBox.Show(this, "Run Search inside DLL first."); return; }
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
            MessageBox.Show(this, "Run Search inside DLL first.");
            return;
        }
        Clipboard.SetText(lastScan.AsText());
        FooterText.Text = "Read-only scan report copied.";
    }

    private async void CheckDllHealth_Click(object sender, RoutedEventArgs e)
    {
        await RunBusy(async () =>
        {
            var report = await Task.Run(DllHealthMonitor.CheckLocal);
            DllHealthDetails.Text = report.AsText();
            FooterText.Text = "DLL health: " + report.Status + ". No system changes.";
        });
    }

    private async void SaveDllBaseline_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm(this, "Record DLL health baseline?",
                "Save the current termsrv.dll SHA-256 and version in your local profile? " +
                "This replaces your previous user-local baseline. It never changes the DLL " +
                "or authorizes Apply/Restore.")) return;
        await RunBusy(async () =>
        {
            var report = await Task.Run(DllHealthMonitor.RecordLocalBaseline);
            DllHealthDetails.Text = report.AsText();
            FooterText.Text = "Local DLL reference saved. No RDP or system settings were changed.";
            OperationHistory.TryRecord("Baseline", "Success", report.Current.DllVersion,
                report.Current.Sha256, report.Current.Sha256);
        });
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
            FooterText.Text = "Session inventory refreshed. No RDP sessions were changed.";
        });
    }

    private async void CheckRdpPolicy_Click(object sender, RoutedEventArgs e)
    {
        await RunBusy(async () =>
        {
            var report = await Task.Run(RdpPolicyDiagnostics.ReadLocal);
            RdpPolicyGrid.ItemsSource = report.Values;
            RdpPolicySummary.Text = report.Values.Count + " settings inspected, " +
                report.Warnings.Count + " notice(s). TermService: " + report.TermServiceStatus +
                ". No changes made.";
            RdpPolicyDetails.Text = report.AsText();
            FooterText.Text = "RDP configuration diagnostic completed (read-only).";
        });
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

    private void ReadRdp()
    {
        var status = RdpConfiguration.Read();
        RdpEnabled.IsChecked = status.Enabled;
        NlaEnabled.IsChecked = status.NetworkLevelAuthentication;
        SingleSession.IsChecked = status.OneSessionPerUser;
        RdpDetails.Text = "Windows RDP configuration loaded.";
    }

    private void ReadSettings_Click(object sender, RoutedEventArgs e)
    {
        try { ReadRdp(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Read settings failed"); }
    }

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm(this, "Change RDP settings?", "These changes affect remote access and can be overridden by Group Policy. " +
            "Network Level Authentication should remain enabled. Proceed?")) return;
        try
        {
            RdpConfiguration.Save(RdpEnabled.IsChecked == true, NlaEnabled.IsChecked == true,
                SingleSession.IsChecked == true, FirewallEnabled.IsChecked == true);
            ReadRdp();
            FooterText.Text = "RDP settings saved. Verify effective Group Policy and firewall scope.";
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("RDP Settings", ex);
            AuditLog.Append("RDP settings failure: " + ex.GetType().Name);
            OperationHistory.TryRecord("RdpSettings", "Failure", failureType: ex.GetType().Name);
            MessageBox.Show(this, ex.Message, "Settings error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Log_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(AuditLog.Root);
        var file = Path.Combine(AuditLog.Root, "operations.log");
        if (!File.Exists(file)) File.WriteAllText(file, "No operations logged yet." + Environment.NewLine);
        Process.Start(new ProcessStartInfo(file) { UseShellExecute = true });
    }

    private async Task BackgroundUpdateCheckAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            await updates.Get(UpdateChannel.Prerelease).CheckAsync(
                forced: false, cancellationToken: timeout.Token);
        }
        catch (Exception ex)
        {
            // An unavailable release endpoint never means the app is up to date.
            DiagnosticsBridge.Remember("Updates", ex);
        }
    }

    private void RefreshUpdateIndicator()
    {
        var notice = updates.Get(UpdateChannel.Prerelease).Notice;
        if (notice.ShowUpdateBadge)
        {
            UpdatesButton.Content = $"● Update {notice.AvailableVersion}";
            UpdatesButton.Background = new SolidColorBrush(Color.FromRgb(255, 228, 181));
            UpdatesButton.Foreground = Brushes.Black;
        }
        else
        {
            UpdatesButton.Content = "Updates";
            UpdatesButton.ClearValue(System.Windows.Controls.Control.BackgroundProperty);
            UpdatesButton.ClearValue(System.Windows.Controls.Control.ForegroundProperty);
        }
        UpdatesButton.ToolTip = notice.IsCached
            ? "Cached status. Open Updates and press Check for a live result."
            : notice.Status.ToString();
    }

    private void Updates_Click(object sender, RoutedEventArgs e)
        => new UpdateCenterWindow(updates) { Owner = this }.ShowDialog();

    private void Diagnostics_Click(object sender, RoutedEventArgs e)
        => new DiagnosticsWindow { Owner = this }.ShowDialog();
}
