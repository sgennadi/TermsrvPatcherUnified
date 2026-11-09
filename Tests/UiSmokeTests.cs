using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TermsrvPatcherUnified;
using TermsrvPatcherUnified.Core;

internal static class UiSmokeTests
{
    internal static int Run()
    {
        if (!OperatingSystem.IsWindows()) return 0;
        Exception? failure = null;
        int verified = 0;
        var worker = new Thread(() =>
        {
            try
            {
                // Windows CI is headless: create the WPF visual tree on STA,
                // do not show any window, access RDP, or launch networking.
                var app = new App();
                app.InitializeComponent();
                using var updater = new UpdateIntegration();
                var record = new SuccessfulFixMetadata(
                    "Windows 11", "24H2", 26100, 1234, "10.0.26100.1234",
                    UpdateIntegration.Version, "automatic",
                    new string('a', 64), new string('b', 64),
                    [new ChangedBytes(40, "11223344", "AABBCCDD")]);
                var main = new MainWindow();
                if (main.FindName("CreateBackupCheck") is not CheckBox backup ||
                    backup.IsChecked != true)
                    throw new Exception("Create backup must be checked by default.");
                var tabs = main.FindName("MainTabs") as TabControl;
                if (tabs is null || tabs.Items.OfType<TabItem>()
                        .Count(tab => (tab.Header as string) == "Offline DLL") != 1 ||
                    main.FindName("OfflineSource") is not TextBox ||
                    main.FindName("OfflineSaveButton") is not Button)
                    throw new Exception("Expected exactly one offline DLL patch tab and its controls.");
                if (main.FindName("RdpSessionsGrid") is not DataGrid grid ||
                    !grid.IsReadOnly || main.FindName("DllHealthDetails") is not TextBox)
                    throw new Exception("Read-only RDP Health controls are missing.");
                if (main.FindName("RdpPolicyGrid") is not DataGrid policyGrid ||
                    !policyGrid.IsReadOnly || main.FindName("RdpPolicyDetails") is not TextBox ||
                    main.FindName("OperationHistoryGrid") is not DataGrid historyGrid ||
                    !historyGrid.IsReadOnly)
                    throw new Exception("Read-only policy and history controls are missing.");
                if (main.FindName("AutoPriorityGrid") is not DataGrid priorityGrid ||
                    !priorityGrid.IsReadOnly || priorityGrid.CanUserSortColumns ||
                    priorityGrid.CanUserReorderColumns ||
                    main.FindName("AutoPrioritySummary") is not TextBlock)
                    throw new Exception("Automatic priority list must be read-only and order-locked.");
                if (main.FindName("AutoProfileGrid") is not DataGrid profileEvidence ||
                    !profileEvidence.IsReadOnly ||
                    main.FindName("AutoSignatureGrid") is not DataGrid automaticEvidence ||
                    !automaticEvidence.IsReadOnly ||
                    main.FindName("AutoSelectedPair") is not TextBox pair ||
                    !pair.IsReadOnly || pair.Text is null ||
                    main.FindName("AutoInspectFindButton") is not Button fromFind ||
                    fromFind.IsEnabled ||
                    main.FindName("AutoInspectReplaceButton") is not Button fromReplace ||
                    fromReplace.IsEnabled ||
                    main.FindName("AutoEvidenceExportButton") is not Button exportEvidence ||
                    exportEvidence.IsEnabled ||
                    main.FindName("ManualFragmentGrid") is not DataGrid fragmentGrid ||
                    !fragmentGrid.IsReadOnly ||
                    main.FindName("ManualInputStatus") is not TextBlock ||
                    main.FindName("ImportedResultsGrid") is not DataGrid importedGrid ||
                    !importedGrid.IsReadOnly ||
                    main.FindName("CheckAllImportedButton") is not Button)
                    throw new Exception("Signature evidence, partial HEX and Check all imported controls missing.");
                if (main.FindName("ManualHexColumnHeaders") is not ItemsControl columns ||
                    columns.Items.Count != 16 ||
                    main.FindName("ManualHexRows") is not ItemsControl ||
                    main.FindName("ManualHexMask") is not TextBlock ||
                    main.FindName("ManualHexHeader") is not TextBlock ||
                    main.FindName("ManualHexPrevious") is not Button back ||
                    back.IsEnabled ||
                    main.FindName("ManualHexNext") is not Button next ||
                    next.IsEnabled ||
                    main.FindName("ManualHexCopy") is not Button copy ||
                    copy.IsEnabled)
                    throw new Exception("Read-only 16-column HEX viewer and navigation controls are missing.");
                var updaterWindow = new UpdateCenterWindow(updater);
                if (updaterWindow.FindName("InstallHelp") is not TextBlock eligibilityHelp ||
                    eligibilityHelp.Text.Contains("signed update installer", StringComparison.OrdinalIgnoreCase) ||
                    updaterWindow.FindName("ReleasePageButton") is not Button ||
                    updaterWindow.FindName("InstallButton") is not Button installButton ||
                    installButton.IsEnabled)
                    throw new Exception("Update eligibility explanation or manual-release fallback is missing.");
                var diagnosticsWindow = new DiagnosticsWindow();
                if (diagnosticsWindow.FindName("AnonymousButton") is not Button anonymous ||
                    anonymous.IsEnabled ||
                    diagnosticsWindow.FindName("RelayState") is not TextBlock relayStatus ||
                    string.IsNullOrWhiteSpace(relayStatus.Text))
                    throw new Exception("Anonymous HTTPS reporting must be visible but disabled before local capture.");
                var quick = new QuickApplyWindow();
                if (quick.FindName("QuickApplyButton") is not Button quickApply ||
                    quickApply.IsEnabled ||
                    quick.FindName("QuickRevertButton") is not Button quickRevert ||
                    quickRevert.IsEnabled ||
                    quick.FindName("QuickNoBackupCheck") is not CheckBox noBackup ||
                    noBackup.IsChecked != false ||
                    quick.FindName("QuickBackupInfoText") is not TextBlock ||
                    quick.FindName("QuickCancelButton") is not Button ||
                    quick.FindName("QuickAdvancedButton") is not Button ||
                    quick.FindName("QuickCheckButton") is not Button ||
                    quick.FindName("QuickStatusText") is not TextBlock)
                    throw new Exception("Compact Apply / Revert / Check / Advanced / Cancel and safe backup default missing.");
                var windows = new Window[]
                {
                    quick,
                    main,
                    updaterWindow,
                    diagnosticsWindow,
                    new AboutWindow(),
                    new SuccessfulFixWindow(record)
                };
                foreach (var window in windows)
                {
                    if (!window.Title.Contains(UpdateIntegration.Version,
                            StringComparison.Ordinal))
                        throw new Exception("Window title lacks version: " +
                            window.GetType().Name);
                    if (window.Icon is null)
                        throw new Exception("Window lacks application icon: " +
                            window.GetType().Name);
                    if (window.MinWidth < 400 || window.MinHeight < 350)
                        throw new Exception("Window min geometry is unsafe: " +
                            window.GetType().Name);
                    if (window.Content is not FrameworkElement root)
                        throw new Exception("Window content is not a WPF layout root.");
                    // Synthetic viewports; these are NOT actual system-DPI
                    // screenshots or visual proof of text non-clipping.
                    foreach (var factor in new[] { 1.0, 1.25, 1.50, 2.0 })
                    {
                        var logicalWidth = Math.Max(420.0, window.Width / factor);
                        var logicalHeight = Math.Max(355.0, window.Height / factor);
                        root.LayoutTransform = new ScaleTransform(factor, factor);
                        root.Measure(new Size(logicalWidth, logicalHeight));
                        root.Arrange(new Rect(0, 0, logicalWidth, logicalHeight));
                        root.UpdateLayout();
                        if (!double.IsFinite(root.RenderSize.Width) ||
                            !double.IsFinite(root.RenderSize.Height) ||
                            root.RenderSize.Width <= 0 || root.RenderSize.Height <= 0)
                            throw new Exception("Synthetic layout became invalid.");
                        verified++;
                    }
                    window.Close();
                }
                app.Shutdown();
            }
            catch (Exception e)
            {
                failure = e;
            }
        }) { IsBackground = true, Name = "Offscreen WPF synthetic layout smoke" };
        worker.SetApartmentState(ApartmentState.STA);
        worker.Start();
        if (!worker.Join(TimeSpan.FromSeconds(45)))
            throw new TimeoutException("WPF smoke did not terminate within the safety timeout.");
        if (failure is not null)
            throw new InvalidOperationException("WPF offscreen layout smoke failed.", failure);
        Console.WriteLine($"PASS: {verified} offscreen WPF viewport layouts; titles and icons; no windows shown.");
        return verified;
    }
}
