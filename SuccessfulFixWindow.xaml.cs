using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Windows;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class SuccessfulFixWindow : Window
{
    private readonly CompatibilityRelaySubmission submission;
    private readonly DirectReportingSettings settings;
    private bool sending;

    internal SuccessfulFixWindow(SuccessfulFixMetadata metadata)
    {
        InitializeComponent();
        submission = CompatibilityRelaySubmission.Create(metadata);
        settings = DirectReportingSettings.Load();
        Title = "Successful operation — " + UpdateIntegration.Version;
        Preview.Text = submission.Json;
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
            "This DLL was modified OFFLINE and was not installed or tested in Remote Desktop. " +
            "Its public report is an UNVERIFIED offline observation, not a successful RDP connection. " +
            "Review the exact JSON below. No GitHub login or token is required.";
        Title = "Offline DLL report — " + UpdateIntegration.Version;
        InitializeAvailability();
    }

    private void InitializeAvailability()
    {
        Loaded += (_, _) => WindowLayout.FitToWorkArea(this);
        SendButton.IsEnabled = settings.HasGoogleScript;
        Status.Text = settings.HasGoogleScript
            ? "Preview only. No report sent. Sending requires your explicit approval."
            : "The Google compatibility receiver is not configured. Sending is disabled.";
    }

    private async void Send_Click(object sender, RoutedEventArgs e)
    {
        if (sending || !settings.HasGoogleScript) return;
        sending = true;
        SendButton.IsEnabled = false;
        SkipButton.IsEnabled = false;
        try
        {
            // A distinct confirmation shows the precise immutable JSON and URL.
            // Declining never schedules a report, and does not affect the patch.
            if (!ModernConfirmDialog.Ask(this,
                    submission.Kind == "offline_file"
                        ? "Share offline DLL observation?"
                        : "Share completed Apply observation?",
                    "Review the exact public metadata and destination. The report is " +
                    "self-reported and does not prove that RDP connections work.",
                    "Google Apps Script -> public GitHub Issue #1\n" +
                    settings.GoogleAppsScriptUrl,
                    submission.Json,
                    "Send report",
                    "GitHub publishes the supplied byte changes and SHA-256. " +
                    "Google may process your IP address. No personal account, DLL file, " +
                    "username or password is included.",
                    diagnosticReport: true))
            {
                Status.Text = "Cancelled. No information was transmitted.";
                return;
            }

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var client = new GoogleAppsScriptReportClient();
            Uri receipt = await client.SendCompatibilityAsync(
                settings.GoogleAppsScriptUrl, submission.Json, submission, timeout.Token);
            Status.Text = "GitHub accepted the public report: " + receipt.AbsoluteUri +
                "\nCSV aggregation runs separately; this does not prove RDP works.";
            AuditLog.Append("Explicit compatibility submission confirmed by GitHub.");
            ModernMessageDialog.Show(this,
                "Compatibility report accepted by GitHub. The database will be updated " +
                "by a separate GitHub workflow after format validation.",
                "Report received", MessageBoxButton.OK, MessageBoxImage.Information);
            DialogResult = true;
            Close();
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or
                                   InvalidOperationException or OperationCanceledException or
                                   JsonException or ArgumentException or IOException)
        {
            DiagnosticsBridge.Remember("Compatibility reporting", ex);
            Status.Text = "Delivery not confirmed (" + ex.GetType().Name +
                "). Check GitHub Issue #1 before sending again. The local DLL operation is unchanged.";
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
