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
    private string? importedFile;
    private IReadOnlyList<PatchProfile> imported = [];
    private bool busy;
    private readonly UpdateIntegration updates = new();

    public MainWindow()
    {
        InitializeComponent();
        engine = new TermsrvEngine(text => Dispatcher.BeginInvoke(() => FooterText.Text = text));
        WindowSettings.Restore(this);
        Closing += (_, _) => { WindowSettings.Save(this); updates.Dispose(); };
        updates.Get(UpdateChannel.Prerelease).NoticeChanged += (_, _) =>
            Dispatcher.BeginInvoke(RefreshUpdateIndicator);
        RefreshUpdateIndicator();
        Loaded += async (_, _) =>
        {
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

    private async Task RunBusy(Func<Task> job)
    {
        if (busy) return;
        busy = true;
        RefreshButton.IsEnabled = false;
        MainTabs.IsEnabled = false;
        RestoreButton.IsEnabled = false;
        ApplyAutoButton.IsEnabled = false;
        ApplyManualButton.IsEnabled = false;
        try { await job(); }
        catch (Exception e)
        {
            DiagnosticsBridge.Remember("Application", e);
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
        string message = "This operation modifies the protected Windows termsrv.dll file and stops " +
            "Remote Desktop services temporarily. Active RDP connections may be disconnected. " +
            "Windows updates may revert the change. Proceed only on a system you administer and " +
            "where permitted by the applicable license.";
        if (manual)
            message += "\n\nMANUAL MODE: You supplied the replacement bytes. No automatic analysis " +
                "can guarantee that this patch is safe. Continue?";
        if (!Confirm(this, manual ? "Apply manual patch?" : "Apply verified patch?", message)) return;
        // A compatibility report is offered ONLY if the protected write, byte
        // verification and RDP-service recovery all returned successfully.
        bool applied = false;
        await RunBusy(async () =>
        {
            await Task.Run(() => engine.Apply(plan));
            applied = true;
            FooterText.Text = "Patch applied and verified. Checking current DLL...";
        });
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
        Directory.CreateDirectory(TermsrvEngine.BackupDirectory);
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
        await RunBusy(async () => await Task.Run(() => engine.Restore(dialog.FileName)));
        await CheckAsync();
    }

    private void OpenBackups_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(TermsrvEngine.BackupDirectory);
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
            AuditLog.Append("RDP settings failure: " + ex.Message);
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
