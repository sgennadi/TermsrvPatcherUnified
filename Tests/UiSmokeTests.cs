using System.IO;
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
                if (tabs.Items.OfType<TabItem>().Count(tab =>
                        tab.Header as string == "Remote Desktop") != 1 ||
                    tabs.Items.OfType<TabItem>().Any(tab =>
                        (tab.Header as string) is "RDP Health" or "RDP Settings"))
                    throw new Exception("RDP settings and health must be merged into exactly one tab.");
                if (main.FindName("RdpSessionsGrid") is not DataGrid grid ||
                    !grid.IsReadOnly || main.FindName("DllHealthDetails") is not TextBox ||
                    main.FindName("RdpSessionsCountText") is not TextBlock ||
                    main.FindName("RdpOverviewText") is not TextBlock ||
                    main.FindName("BlankPasswordStatus") is not TextBlock ||
                    main.FindName("RdpSecurityAdvanced") is not Expander secExpanded ||
                    secExpanded.IsExpanded ||
                    main.FindName("BlankPasswordRestriction") is not CheckBox ||
                    main.FindName("SaveBlankPasswordButton") is not Button ||
                    main.FindName("SimpleModeButton") is not Button)
                    throw new Exception("Unified RDP dashboard, hidden security controls or back navigation missing.");
                if (main.FindName("RdpApplyImpactText") is not TextBlock ||
                    main.FindName("RdpPostApplyActions") is not TextBlock ||
                    main.FindName("RefreshComputerPolicyButton") is not Button policyRefresh ||
                    policyRefresh.Content is not string policyText ||
                    !policyText.Contains("Refresh Computer Policy", StringComparison.Ordinal) ||
                    main.FindName("ReviewRdpRestartButton") is not Button restartReview ||
                    restartReview.IsEnabled)
                    throw new Exception(
                        "RDP post-apply action guidance and fail-safe restart review controls are missing.");
                if (main.FindName("AdvancedAutoReapplyCheck") is not CheckBox advancedReapply ||
                    advancedReapply.IsChecked != false ||
                    main.FindName("AdvancedAutoReapplyStatus") is not TextBlock ||
                    main.FindName("CleanupButton") is not Button)
                    throw new Exception("Advanced Auto Reapply and Cleanup controls are missing.");
                if (main.FindName("RdpPolicyGrid") is not DataGrid policyGrid ||
                    !policyGrid.IsReadOnly || main.FindName("RdpPolicyDetails") is not TextBox ||
                    main.FindName("OperationHistoryGrid") is not DataGrid historyGrid ||
                    !historyGrid.IsReadOnly)
                    throw new Exception("Read-only policy and history controls are missing.");
                if (main.FindName("AutoTechnicalDetails") is not Expander autoDetails ||
                    autoDetails.IsExpanded ||
                    main.FindName("AutoSimpleStatus") is not TextBlock ||
                    main.FindName("AutoSimpleProfile") is not TextBlock ||
                    main.FindName("AutoSimpleReason") is not TextBlock)
                    throw new Exception("Automatic must default to concise status with collapsed technical evidence.");
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
                // Desktop/Downloads are legal portable update targets; no EXE
                // is executed and no system application is changed by this smoke test.
                var tempRoot = Path.Combine(Path.GetTempPath(),
                    "TermsrvPortableQA-" + Guid.NewGuid().ToString("N"));
                var pseudoDesktop = Path.Combine(tempRoot, "Desktop");
                Directory.CreateDirectory(pseudoDesktop);
                try
                {
                    var dummyExe = Path.Combine(pseudoDesktop, UpdateInstallBridge.ExecutableName);
                    File.WriteAllBytes(dummyExe, [0x4D, 0x5A]);
                    if (!UpdateInstallBridge.IsSafePortableInstallTarget(dummyExe, out _) ||
                        UpdateInstallBridge.IsSafePortableInstallTarget(
                            Path.Combine(pseudoDesktop, "not-our-program.exe"), out _) ||
                        UpdateInstallBridge.IsSafePortableInstallTarget(
                            @"\\server\share\TermsrvPatcherUnified.exe", out _))
                        throw new Exception("Portable update location rules rejected local desktop or accepted an invalid target.");
                }
                finally { Directory.Delete(tempRoot, recursive: true); }
                var updaterWindow = new UpdateCenterWindow(updater);
                if (updaterWindow.FindName("InstallHelp") is not TextBlock eligibilityHelp ||
                    eligibilityHelp.Text.Contains("signed update installer", StringComparison.OrdinalIgnoreCase) ||
                    updaterWindow.FindName("ReleasePageButton") is not Button ||
                    updaterWindow.FindName("InstallButton") is not Button installButton ||
                    installButton.IsEnabled)
                    throw new Exception("Update eligibility explanation or manual-release fallback is missing.");
                var diagnosticsWindow = new DiagnosticsWindow();
                if (diagnosticsWindow.FindName("IncludeWindowsEvidenceCheck") is not CheckBox metadataConsent ||
                    metadataConsent.IsChecked != false)
                    throw new Exception("Sharing DLL SHA-256 and Windows build must be explicitly selected.");
                if (diagnosticsWindow.FindName("AnonymousButton") is not Button anonymous ||
                    anonymous.IsEnabled ||
                    diagnosticsWindow.FindName("RelayState") is not TextBlock relayStatus ||
                    string.IsNullOrWhiteSpace(relayStatus.Text))
                    throw new Exception("Anonymous HTTPS reporting must be visible but disabled before local capture.");
                if (diagnosticsWindow.FindName("FormspreeButton") is not Button formspree ||
                    formspree.IsEnabled ||
                    diagnosticsWindow.FindName("FormspreeFormIdInput") is not null ||
                    diagnosticsWindow.FindName("GitHubClientIdInput") is not null ||
                    diagnosticsWindow.FindName("GitHubSignInButton") is not Button ||
                    diagnosticsWindow.FindName("GitHubCancelButton") is not Button ||
                    diagnosticsWindow.FindName("CopyGitHubCodeButton") is not Button ||
                    diagnosticsWindow.FindName("PublishButton") is not Button publish ||
                    publish.IsEnabled)
                    throw new Exception("Direct reporting controls must be visible and fail closed before local review.");
                var quick = new QuickApplyWindow();
                if (quick.FindName("QuickAutoReapplyCheck") is not CheckBox quickAuto ||
                    quickAuto.IsChecked != false ||
                    quick.FindName("QuickAutoReapplyStatus") is not TextBlock ||
                    quick.FindName("QuickCleanupButton") is not Button)
                    throw new Exception("Simple Auto Reapply checkbox and Cleanup controls missing.");
                if (quick.FindName("QuickApplyButton") is not Button quickApply ||
                    quickApply.IsEnabled ||
                    quick.FindName("QuickRevertButton") is not Button quickRevert ||
                    quickRevert.IsEnabled ||
                    quick.FindName("QuickNoBackupCheck") is not CheckBox noBackup ||
                    noBackup.IsChecked != false ||
                    quick.FindName("QuickBackupInfoText") is not TextBlock ||
                    quick.FindName("QuickLastJobText") is not TextBlock ||
                    quick.FindName("QuickCancelButton") is not Button ||
                    quick.FindName("QuickAdvancedButton") is not Button ||
                    quick.FindName("QuickCheckButton") is not Button ||
                    quick.FindName("QuickStatusText") is not TextBlock)
                    throw new Exception("Compact Apply / Revert / Check / Advanced / Cancel and safe backup default missing.");
                var cleanup = new CleanupWindow();
                if (cleanup.FindName("CleanupBackupsCheck") is not CheckBox ||
                    cleanup.FindName("CleanupReportsCheck") is not CheckBox ||
                    cleanup.FindName("CleanupTaskCheck") is not CheckBox taskOption ||
                    taskOption.IsChecked != false ||
                    cleanup.FindName("CleanupExecuteButton") is not Button cleanButton ||
                    cleanButton.IsEnabled)
                    throw new Exception("Cleanup categories and task deletion must require explicit opt-in.");
                var overview = CleanupService.Preview(new CleanupService.Options(
                    Backups: true, LocalReports: true, ScheduledTask: false));
                if (!overview.Contains("recovery journals", StringComparison.OrdinalIgnoreCase) ||
                    !overview.Contains("Windows Event Logs", StringComparison.OrdinalIgnoreCase))
                    throw new Exception("Cleanup preview must warn about recovery loss and excluded system logs.");

                var windows = new Window[]
                {
                    quick,
                    main,
                    updaterWindow,
                    diagnosticsWindow,
                    cleanup,
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
