using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TermsrvPatcherUnified;
using TermsrvPatcherUnified.Core;
using UniversalUpdater;

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
                if (main.FindName("UpdatesButton") is not Button advancedUpdates ||
                    advancedUpdates.Content is not string advancedCaption ||
                    advancedCaption != "Updates")
                    throw new Exception("Advanced Updates button must start neutral.");
                var noUpdate = new UpdateNotice(UpdateNoticeStatus.UpToDate,
                    UpdateIntegration.Version, null, false, "NO_NEWER_RELEASE", null);
                var newStable = new UpdateNotice(UpdateNoticeStatus.Available,
                    UpdateIntegration.Version, "1.1.0", false, "UPDATE_AVAILABLE", null);
                var newPreview = new UpdateNotice(UpdateNoticeStatus.Available,
                    UpdateIntegration.Version, "1.2.0-preview.1", true, "UPDATE_AVAILABLE", null);
                var description = UpdateButtonIndicator.Describe(newStable, newPreview);
                if (!description.HasUpdate || description.Channel != UpdateChannel.Stable ||
                    !description.Caption.Contains("NEW", StringComparison.Ordinal) ||
                    !description.Tooltip.Contains("1.1.0", StringComparison.Ordinal))
                    throw new Exception("Available Stable update must highlight button and show version.");
                var cached = UpdateButtonIndicator.Describe(noUpdate, newPreview);
                if (!cached.HasUpdate || cached.Channel != UpdateChannel.Prerelease ||
                    !cached.Tooltip.Contains("previously checked", StringComparison.Ordinal))
                    throw new Exception("Cached Preview updates must be labelled and require live verification.");
                if (UpdateButtonIndicator.Describe(noUpdate, noUpdate).HasUpdate ||
                    UpdateButtonIndicator.Describe(
                        new UpdateNotice(UpdateNoticeStatus.CheckFailed,
                            UpdateIntegration.Version, null, false, "CHECK_FAILED", null),
                        noUpdate).HasUpdate)
                    throw new Exception("No-update and failed checks must not show a false badge.");
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
                if (tabs.Items.OfType<TabItem>().Count(tab =>
                        tab.Header as string == "System Health") != 1)
                    throw new Exception("DLL monitoring must be in a separate System Health tab.");
                if (main.FindName("DllCompatibilityGrid") is not DataGrid compatibility ||
                    !compatibility.IsReadOnly || compatibility.Columns.Count != 4 ||
                    main.FindName("DllCompatibilitySummary") is not TextBlock ||
                    main.FindName("RefreshCompatibilityButton") is not Button ||
                    main.FindName("CopyCompatibilityButton") is not Button compatibilityCopy ||
                    compatibilityCopy.IsEnabled)
                    throw new Exception(
                        "Compatibility index must be read-only with explicit local scan and disabled copy until scanned.");
                if (tabs.Items.OfType<TabItem>().Any(tab =>
                        tab.Header as string == "RDP Doctor") ||
                    main.FindName("RdpDoctorPanel") is not Expander doctorPanel ||
                    doctorPanel.IsExpanded ||
                    main.FindName("RunRdpDoctorButton") is not Button doctorScan ||
                    doctorScan.Content is not string scanLabel ||
                    scanLabel != "Run RDP Doctor" ||
                    main.FindName("RdpDoctorQuickStatus") is not TextBlock ||
                    main.FindName("CopyRdpDoctorButton") is not Button copyDoctor ||
                    copyDoctor.IsEnabled ||
                    main.FindName("DoctorVerdictText") is not TextBlock ||
                    main.FindName("DoctorBlockersText") is not TextBlock ||
                    main.FindName("DoctorAttentionText") is not TextBlock ||
                    main.FindName("DoctorUnknownText") is not TextBlock ||
                    main.FindName("DoctorFindingsGrid") is not DataGrid doctorFindings ||
                    !doctorFindings.IsReadOnly || doctorFindings.Columns.Count != 4 ||
                    main.FindName("DoctorEventsGrid") is not DataGrid doctorEvents ||
                    !doctorEvents.IsReadOnly || doctorEvents.Columns.Count != 4 ||
                    main.FindName("DoctorEventStatus") is not TextBlock)
                    throw new Exception("RDP Doctor must be nested in Remote Desktop, read-only, with disabled export before the one scan.");

                if (main.FindName("RdpTechnicalAdvanced") is not Expander technicalRdp ||
                    technicalRdp.IsExpanded ||
                    main.FindName("RdpEffectiveEnabledText") is not TextBlock ||
                    main.FindName("RdpEffectiveNlaText") is not TextBlock ||
                    main.FindName("RdpEffectiveSingleText") is not TextBlock ||
                    main.FindName("RdpEffectiveBlankText") is not TextBlock ||
                    main.FindName("RdpEffectivePortText") is not TextBlock ||
                    main.FindName("RdpEffectiveFirewallText") is not TextBlock ||
                    main.FindName("RdpEffectiveRestartText") is not TextBlock ||
                    main.FindName("RdpPolicyOverviewText") is not TextBlock ||
                    main.FindName("RdpEnabledSourceText") is not TextBlock ||
                    main.FindName("NlaSourceText") is not TextBlock ||
                    main.FindName("SingleSourceText") is not TextBlock)
                    throw new Exception("Compact RDP status, policy source rows or collapsed details are missing.");
                if (main.FindName("RdpEffectiveFirewallText") is TextBlock firewall &&
                    !firewall.Text.Contains("not", StringComparison.OrdinalIgnoreCase))
                    throw new Exception("Firewall status must not claim success without verification.");
                if (main.FindName("RdpSessionsGrid") is not DataGrid grid ||
                    !grid.IsReadOnly || main.FindName("DllHealthDetails") is not TextBox ||
                    main.FindName("RdpSessionsCountText") is not TextBlock ||
                    main.FindName("RdpOverviewText") is not TextBlock ||
                    main.FindName("BlankPasswordStatus") is not TextBlock ||
                    main.FindName("BlankPasswordInlineEditor") is not Border blankEditor ||
                    blankEditor.Visibility != Visibility.Collapsed ||
                    main.FindName("BlankPasswordChoice") is not ComboBox choices ||
                    choices.Items.Count != 2 ||
                    main.FindName("OpenBlankPasswordSettingButton") is not Button ||
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
                if (main.FindName("RdpExtendedDiagnostics") is not Expander extended ||
                    extended.IsExpanded ||
                    (extended.Header as string)?.StartsWith("Technical evidence", StringComparison.Ordinal) != true ||
                    main.FindName("InspectRdpSecurityButton") is not null ||
                    main.FindName("RdpInspectionStatus") is not TextBlock ||
                    main.FindName("RdpFirewallInspection") is not TextBox firewallEvidence ||
                    !firewallEvidence.IsReadOnly ||
                    main.FindName("RdpRightsInspection") is not TextBox rightsEvidence ||
                    !rightsEvidence.IsReadOnly ||
                    main.FindName("RdpCertificateInspection") is not TextBox certEvidence ||
                    !certEvidence.IsReadOnly ||
                    main.FindName("RdpGraphicsInspection") is not TextBox graphicsEvidence ||
                    !graphicsEvidence.IsReadOnly)
                    throw new Exception("Four read-only RDP security evidence panels must be inside Doctor without a second scan button.");
                if (main.FindName("AdvancedAutoUpdateCheck") is not CheckBox autoCheck ||
                    autoCheck.IsChecked != false ||
                    main.FindName("AdvancedAutoUpdateStatus") is not TextBlock)
                    throw new Exception("Auto-update opt-in must be visible and initially unchecked.");

                if (main.FindName("RdpPolicyGrid") is not DataGrid policyGrid ||
                    !policyGrid.IsReadOnly || policyGrid.Columns.Count < 7 ||
                    policyGrid.Columns.OfType<DataGridTemplateColumn>().Count() != 1 ||
                    policyGrid.Columns.All(c => c.Header?.ToString() != "Details") ||
                    main.FindName("RdpPolicyDetails") is not TextBox ||
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
                if (updaterWindow.FindName("StableChannelButton") is not RadioButton stableChannel ||
                    updaterWindow.FindName("PreviewChannelButton") is not RadioButton previewChannel ||
                    previewChannel.IsChecked != UpdateIntegration.Version.Contains('-', StringComparison.Ordinal) ||
                    stableChannel.IsChecked == UpdateIntegration.Version.Contains('-', StringComparison.Ordinal) ||
                    updaterWindow.FindName("ChannelSelector") is not null ||
                    updaterWindow.FindName("ChannelHint") is not TextBlock)
                    throw new Exception("Stable/Preview must be a visible segmented selector with Preview selected for preview builds.");
                if (updaterWindow.FindName("InstallHelp") is not TextBlock eligibilityHelp ||
                    eligibilityHelp.Text.Contains("signed update installer", StringComparison.OrdinalIgnoreCase) ||
                    updaterWindow.FindName("ReleasePageButton") is not Button ||
                    updaterWindow.FindName("InstallButton") is not Button installButton ||
                    installButton.IsEnabled)
                    throw new Exception("Update eligibility explanation or manual-release fallback is missing.");
                var autoOffer = new UpdateCenterWindow(updater, offerStableAutomatically: true);
                if (autoOffer.FindName("StableChannelButton") is not RadioButton autoStable ||
                    autoStable.IsChecked != true ||
                    autoOffer.FindName("ChannelHint") is not TextBlock offerHint ||
                    !offerHint.Text.Contains("Auto-update found", StringComparison.Ordinal))
                    throw new Exception("Auto-update may offer only the Stable channel and must require review.");
                var diagnosticsWindow = new DiagnosticsWindow();
                if (diagnosticsWindow.FindName("IncludeWindowsEvidenceCheck") is not CheckBox metadataConsent ||
                    metadataConsent.IsChecked != true)
                    throw new Exception("Windows/DLL evidence must be checked by default and still removable by the user.");
                if (diagnosticsWindow.FindName("AnonymousButton") is not Button anonymous ||
                    anonymous.IsEnabled ||
                    diagnosticsWindow.FindName("RelayState") is not TextBlock relayStatus ||
                    string.IsNullOrWhiteSpace(relayStatus.Text))
                    throw new Exception("Anonymous HTTPS reporting must be visible but disabled before local capture.");
                if (diagnosticsWindow.FindName("GoogleButton") is not Button google ||
                    google.IsEnabled != DirectReportingSettings.Load().HasGoogleScript ||
                    diagnosticsWindow.FindName("PreviewDirectButton") is not Button preview ||
                    preview.IsEnabled != DirectReportingSettings.Load().HasGoogleScript ||
                    diagnosticsWindow.FindName("GoogleEndpointInput") is not null ||
                    diagnosticsWindow.FindName("OpenConfirmedIssueButton") is not Button issueLink ||
                    issueLink.Visibility != Visibility.Collapsed ||
                    diagnosticsWindow.FindName("GitHubClientIdInput") is not null ||
                    diagnosticsWindow.FindName("GitHubSignInButton") is not Button ||
                    diagnosticsWindow.FindName("GitHubCancelButton") is not Button ||
                    diagnosticsWindow.FindName("CopyGitHubCodeButton") is not Button ||
                    diagnosticsWindow.FindName("PublishButton") is not Button publish ||
                    publish.IsEnabled)
                    throw new Exception("Direct reporting must be immediately available when configured, while GitHub publishing requires review.");
                if (diagnosticsWindow.FindName("SaveButton") is not Button ||
                    diagnosticsWindow.FindName("ReportPreview") is not TextBox)
                    throw new Exception("Optional local copy and direct metadata preview controls are missing.");
                // No network calls or windows shown. Invalid receipt must never
                // dismiss Diagnostics; a valid repository Issue must close it.
                var completedReportDialog = new DiagnosticsWindow();
                if (completedReportDialog.CloseAfterConfirmedDelivery(null) ||
                    completedReportDialog.CloseAfterConfirmedDelivery(
                        new Uri("https://evil.example/issues/40")))
                    throw new Exception("Unconfirmed report closed Diagnostics.");
                if (!completedReportDialog.CloseAfterConfirmedDelivery(
                        new Uri("https://github.com/sgennadi/TermsrvPatcherUnified/issues/40")))
                    throw new Exception("Confirmed GitHub report did not close Diagnostics.");
                verified++;
                var quick = new QuickApplyWindow();
                if (quick.FindName("QuickAutoUpdateCheck") is not CheckBox autoUpdateOption ||
                    autoUpdateOption.IsChecked != false ||
                    quick.FindName("QuickAutoUpdateStatus") is not TextBlock)
                    throw new Exception("Simple mode must expose the same machine-wide Auto-update opt-in.");
                if (quick.FindName("QuickUpdatesButton") is not Button simpleUpdates ||
                    simpleUpdates.Content is not string simpleCaption ||
                    simpleCaption != "Updates")
                    throw new Exception("Simple Updates button must be named and start neutral.");
                if (quick.Content is not Grid quickRoot ||
                    quickRoot.RowDefinitions.Count != 2 ||
                    quickRoot.Children.OfType<ScrollViewer>()
                        .Any(scroll => Grid.GetRow(scroll) != 0) ||
                    !quickRoot.Children.OfType<Grid>()
                        .Any(panel => Grid.GetRow(panel) == 1))
                    throw new Exception("Simple view footer must stay outside the scrolling region.");
                if (quick.FindName("QuickAutoReapplyCheck") is not CheckBox quickAuto ||
                    quickAuto.IsChecked != false ||
                    quick.FindName("QuickAutoReapplyStatus") is not TextBlock ||
                    quick.FindName("QuickRepairTaskButton") is not Button repair ||
                    repair.Visibility != Visibility.Collapsed ||
                    quick.FindName("QuickShareReportButton") is not Button share ||
                    share.Visibility != Visibility.Collapsed ||
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

                var successReport = new SuccessfulFixWindow(record);
                if (successReport.FindName("SendButton") is not Button compatibilitySend ||
                    compatibilitySend.IsEnabled != DirectReportingSettings.Load().HasGoogleScript ||
                    successReport.FindName("Preview") is not TextBox publicPreview ||
                    !publicPreview.IsReadOnly ||
                    !publicPreview.Text.Contains("termsrv-compatibility/v1", StringComparison.Ordinal) ||
                    !publicPreview.Text.Contains("termsrv-success/v2", StringComparison.Ordinal) ||
                    !publicPreview.Text.Contains("universal-diagnostics/v1", StringComparison.Ordinal) ||
                    !publicPreview.Text.Contains("GENERAL DIAGNOSTICS", StringComparison.Ordinal) ||
                    successReport.FindName("AutoSendConsentCheck") is not CheckBox autoConsent ||
                    autoConsent.Visibility != Visibility.Visible ||
                    successReport.FindName("TokenInput") is not null ||
                    successReport.FindName("SkipButton") is not Button)
                    throw new Exception("Completed Apply must offer read-only, token-free Google compatibility review.");
                var offlineReport = new OfflineFixMetadata("x64", "10.0.26100.1234",
                    UpdateIntegration.Version, new string('a', 64), "1234ABCD",
                    new string('b', 64), "FFFFFFFF",
                    [new ChangedBytes(40, "11223344", "AABBCCDD")]);
                var offlineShare = new SuccessfulFixWindow(offlineReport);
                if (offlineShare.FindName("Preview") is not TextBox offlinePreview ||
                    !offlinePreview.Text.Contains("termsrv-offline/v1", StringComparison.Ordinal) ||
                    offlinePreview.IsReadOnly != true ||
                    offlineShare.FindName("AutoSendConsentCheck") is not CheckBox offlineConsent ||
                    offlineConsent.Visibility != Visibility.Collapsed ||
                    offlineShare.FindName("SendButton") is not Button)
                    throw new Exception("Offline DLL copy must have separate, clearly unverified token-free review.");
                if (main.FindName("AdvancedRevokeAutoReportsButton") is not Button ||
                    quick.FindName("QuickRevokeAutoReportsButton") is not Button)
                    throw new Exception("Both views must expose silent reporting revocation.");
                var confirm = new ModernConfirmDialog();
                if (confirm.FindName("DetailsText") is not TextBox reportDetails ||
                    !reportDetails.IsReadOnly ||
                    confirm.FindName("ConfirmButton") is not Button confirmButton ||
                    confirmButton.IsDefault ||
                    confirm.FindName("CancelButton") is not Button cancelButton ||
                    !cancelButton.IsCancel ||
                    confirm.FindName("CopyButton") is not Button)
                    throw new Exception("Modern report/update review must show exact details, require manual consent, and allow cancellation.");
                var modernMessage = new ModernMessageDialog();
                if (modernMessage.FindName("HeadingText") is not TextBlock ||
                    modernMessage.FindName("BodyText") is not TextBlock ||
                    modernMessage.FindName("AcceptButton") is not Button modernAccept ||
                    modernAccept.IsDefault ||
                    modernMessage.FindName("CancelButton") is not Button modernCancel ||
                    !modernCancel.IsCancel)
                    throw new Exception("Modern inline help/error/confirmation dialog is incomplete or auto-confirms.");
                var editable = new RdpPolicyEvidence("RDP TCP port", "3389", "(none)", "Local setting", "Local");
                var ready = RdpRowEditStatus.Annotate(editable, administrator: true,
                    console: true, policyManaged: false, validValue: true);
                if (!ready.CanEdit || ready.PolicyLocked ||
                    !ready.EditStatus.Contains("Editable", StringComparison.Ordinal))
                    throw new Exception("Editable local rows must have an enabled action and status.");
                var blocked = RdpRowEditStatus.Annotate(editable, administrator: true,
                    console: true, policyManaged: true, validValue: true);
                var needsConsole = RdpRowEditStatus.Annotate(editable, administrator: true,
                    console: false, policyManaged: false, validValue: true);
                if (blocked.CanEdit || !blocked.PolicyLocked ||
                    needsConsole.CanEdit || !needsConsole.EditStatus.Contains("console", StringComparison.OrdinalIgnoreCase))
                    throw new Exception("GPO and console-only rows must be clearly locked.");
                var blank = RdpPolicyDiagnostics.DescribeBlankPasswordPolicy(false);
                var blankView = RdpRowEditStatus.Annotate(blank, administrator: true,
                    console: false, policyManaged: null, validValue: true);
                if (!blankView.CanEdit || blankView.PolicyLocked ||
                    !blank.LocalValue.Equals("Restriction OFF", StringComparison.Ordinal) ||
                    !blank.Explanation.Contains("LimitBlankPasswordUse", StringComparison.Ordinal))
                    throw new Exception("Blank-password policy must explain DWORD 0 and allow guarded local editing.");
                var blankUnknown = RdpRowEditStatus.Annotate(
                    RdpPolicyDiagnostics.DescribeBlankPasswordPolicy(null), administrator: true,
                    console: true, policyManaged: null, validValue: false);
                if (blankUnknown.CanEdit || !blankUnknown.EditStatus.Contains("invalid", StringComparison.OrdinalIgnoreCase))
                    throw new Exception("Unknown LSA values must never enable editing.");

                var tinyDesktop = new Rect(0, 0, 800, 560);
                var fitted = WindowLayout.FitBounds(tinyDesktop, 1120, 795);
                if (fitted.Left < tinyDesktop.Left ||
                    fitted.Top < tinyDesktop.Top ||
                    fitted.Right > tinyDesktop.Right ||
                    fitted.Bottom > tinyDesktop.Bottom ||
                    fitted.Width < 400 || fitted.Height < 350)
                    throw new Exception("Window sizing fails to keep the startup window on screen.");
                var windows = new Window[]
                {
                    modernMessage,
                    confirm,
                    quick,
                    main,
                    updaterWindow,
                    autoOffer,
                    diagnosticsWindow,
                    cleanup,
                    new AboutWindow(),
                    successReport
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
