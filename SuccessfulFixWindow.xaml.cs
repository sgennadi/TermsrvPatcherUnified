using System.Net.Http;
using System.Text.Json;
using System.Windows;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class SuccessfulFixWindow : Window
{
    private readonly CompatibilityRelaySubmission submission;
    private readonly UnifiedApplyReport? unified;
    private readonly DirectReportingSettings settings;
    private readonly bool initialAutoConsent;
    private Uri? diagnosticsReceipt;
    private Uri? compatibilityReceipt;
    private bool sending;

    internal SuccessfulFixWindow(SuccessfulFixMetadata metadata)
    {
        InitializeComponent();
        unified = new UnifiedApplyReport(metadata);
        submission = unified.Compatibility;
        settings = DirectReportingSettings.Load();
        Title = "Unified Apply report - " + UpdateIntegration.Version;
        Preview.Text = unified.ReviewedText;
        ReportHeading.Text = "Apply completed - unified report";
        ReportExplanation.Text =
            "One review and one confirmation for Windows/DLL diagnostics and the " +
            "self-reported compatibility result. Google publishes a diagnostic Issue " +
            "and a separate Issue #1 compatibility comment. Both remain UNVERIFIED: " +
            "successful patching is not proof that an external RDP connection works.";
        AutoSendConsentCheck.Visibility = Visibility.Visible;
        initialAutoConsent = AutoCompatibilityReporting.IsEnabled(
            settings.GoogleAppsScriptUrl);
        AutoSendConsentCheck.IsChecked = initialAutoConsent;
        AutoSendConsentCheck.IsEnabled = settings.HasGoogleScript;
        AutoConsentNote.Visibility = Visibility.Visible;
        InitializeAvailability();
    }

    internal SuccessfulFixWindow(OfflineFixMetadata report)
    {
        InitializeComponent();
        submission = CompatibilityRelaySubmission.Create(report);
        settings = DirectReportingSettings.Load();
        Preview.Text = submission.Json;
        ReportHeading.Text = "Offline DLL copy saved";
        ReportHeading.Foreground = new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(11, 46, 90));
        ReportExplanation.Text =
            "This DLL was changed OFFLINE and was not installed or tested in Remote Desktop. " +
            "Only the offline compatibility observation is shared. It is UNVERIFIED. " +
            "There is no consent option for unattended reports from offline copies.";
        Title = "Offline DLL report - " + UpdateIntegration.Version;
        InitializeAvailability();
    }

    private void InitializeAvailability()
    {
        Loaded += (_, _) => WindowLayout.FitToWorkArea(this);
        SendButton.IsEnabled = settings.HasGoogleScript;
        Status.Text = settings.HasGoogleScript
            ? "Preview only. No report sent. One review and confirmation are required."
            : "The Google reporting receiver is not configured. Sending is disabled.";
    }

    private async void Send_Click(object sender, RoutedEventArgs e)
    {
        if (sending || !settings.HasGoogleScript) return;
        sending = true;
        SendButton.IsEnabled = false;
        SkipButton.IsEnabled = false;
        bool futureAutoReports = unified is not null &&
            AutoSendConsentCheck.IsChecked == true;
        bool revokeAutoReports = unified is not null &&
            initialAutoConsent && !futureAutoReports;
        try
        {
            string futureNotice = unified is null
                ? "Offline reports never enable unattended sending."
                : futureAutoReports
                    ? "You also grant machine-wide permission for future SUCCESSFUL " +
                      "post-Windows-Update Auto Reapply runs to send both typed " +
                      "report sections silently. No routine errors or raw logs are sent. " +
                      "You can revoke this later in Simple or Advanced."
                    : revokeAutoReports
                        ? "Existing permission for future unattended reports will be " +
                          "REVOKED after this manual report is confirmed."
                        : "Unattended reporting is NOT being enabled by this approval.";
            if (!ModernConfirmDialog.Ask(this,
                    unified is null ? "Share offline DLL observation?"
                                    : "Share combined Apply report?",
                    "The exact public metadata appears below. Reports are self-reported; " +
                    "no remote RDP connectivity was tested.",
                    "Google Apps Script -> public GitHub Issues\n" +
                    settings.GoogleAppsScriptUrl,
                    Preview.Text,
                    "Send report",
                    "A single confirmation sends " +
                    (unified is null ? "one compatibility comment." :
                        "two distinct public records (diagnostic Issue + compatibility comment). ") +
                    " Google may process your IP address. No DLL file, credentials, " +
                    "computer name or account identifiers are included. " + futureNotice,
                    diagnosticReport: true))
            {
                Status.Text = "Cancelled. No new report was sent.";
                return;
            }

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            using var client = new GoogleAppsScriptReportClient();
            if (unified is not null && diagnosticsReceipt is null)
            {
                diagnosticsReceipt = await client.SendAsync(
                    settings.GoogleAppsScriptUrl, unified.DiagnosticJson,
                    unified.Diagnostics, timeout.Token);
                Status.Text = "General diagnostics confirmed by GitHub. Sending DLL compatibility...";
            }
            if (compatibilityReceipt is null)
                compatibilityReceipt = await client.SendCompatibilityAsync(
                    settings.GoogleAppsScriptUrl, submission.Json, submission, timeout.Token);

            string consentStatus = "";
            if (futureAutoReports)
            {
                try
                {
                    AutoCompatibilityReporting.EnableAfterConfirmedReport(
                        settings.GoogleAppsScriptUrl);
                    consentStatus = "\nFuture verified Auto Reapply unified reports: ON (silent).";
                    AuditLog.Append("Administrator approved protected silent Auto Reapply compatibility reporting.");
                }
                catch (Exception ex)
                {
                    consentStatus = "\nFuture automatic reporting was NOT enabled (" +
                        ex.GetType().Name + ").";
                    AuditLog.Append("Auto compatibility consent could not be saved: " +
                                    ex.GetType().Name);
                }
            }
            if (revokeAutoReports)
            {
                try
                {
                    AutoCompatibilityReporting.Revoke();
                    consentStatus = "\nFuture automatic reports: OFF (permission revoked).";
                }
                catch (Exception ex)
                {
                    consentStatus = "\nAutomatic report permission could NOT be revoked (" +
                        ex.GetType().Name + "). Use Stop automatic reports.";
                    AuditLog.Append("Automatic reporting revocation failed: " +
                                    ex.GetType().Name);
                }
            }
            Status.Text = "Confirmed public report: " + compatibilityReceipt.AbsoluteUri +
                (diagnosticsReceipt is null ? "" :
                    "\nGeneral diagnostics: " + diagnosticsReceipt.AbsoluteUri) +
                consentStatus + "\nThis does not certify external RDP connectivity.";
            AuditLog.Append("Explicit unified/compatibility Google report confirmed by GitHub.");
            // No extra success popup: verified receipt(s) close this report dialog.
            DialogResult = true;
            Close();
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or
                                   InvalidOperationException or OperationCanceledException or
                                   JsonException or ArgumentException or IOException)
        {
            DiagnosticsBridge.Remember("Compatibility reporting", ex);
            Status.Text = "Delivery not fully confirmed (" + ex.GetType().Name + "). " +
                (diagnosticsReceipt is null ? "" :
                    "General diagnostics WERE delivered: " +
                    diagnosticsReceipt.AbsoluteUri + ". ") +
                "Check GitHub Issues before retrying. " +
                "The DLL operation is unchanged; no automatic consent was granted.";
        }
        finally
        {
            sending = false;
            if (IsLoaded)
            {
                SendButton.IsEnabled = settings.HasGoogleScript;
                SkipButton.IsEnabled = true;
            }
        }
    }

    private void Skip_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
