using System.Windows;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class SuccessfulFixWindow : Window
{
    private readonly SuccessfulFixMetadata? metadata;
    private readonly OfflineFixMetadata? offlineMetadata;
    private bool sending;

    internal SuccessfulFixWindow(SuccessfulFixMetadata metadata)
    {
        InitializeComponent();
        this.metadata = metadata;
        Preview.Text = metadata.AsComment();
        Closed += (_, _) => TokenInput.Clear();
    }

    internal SuccessfulFixWindow(OfflineFixMetadata report)
    {
        InitializeComponent();
        offlineMetadata = report;
        Preview.Text = report.AsComment();
        ReportHeading.Text = "Offline DLL copy saved";
        ReportHeading.Foreground = new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(11, 46, 90));
        SimpleReportBox.Visibility = Visibility.Collapsed; // Offline patch is not verified live success.
        ReportExplanation.Text = "The file was patched OFFLINE, not installed or tested for RDP functionality. " +
            "The metadata below includes CRC32, SHA-256, DLL version, architecture and edited bytes. " +
            "This report is PUBLIC if you choose Send; Skip sends nothing. No source DLL, paths, " +
            "hostnames, usernames or tokens are included.";
        Title = "Offline DLL report — " + UpdateIntegration.Version;
        Closed += (_, _) => TokenInput.Clear();
    }

    private void SimpleReport_Click(object sender, RoutedEventArgs e)
    {
        if (offlineMetadata is not null || sending) return;
        // This only opens a prefilled dialog. Google reporting still requires a
        // separate explicit confirmation with the exact outgoing JSON.
        try
        {
            new DiagnosticsWindow(new DiagnosticsBridge.DiagnosticDraft(
                "Manual Apply", "VerifiedSuccess", "SUCCESS",
                "The protected patch completed and was verified."))
            { Owner = this }.ShowDialog();
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Optional compatibility report", ex);
            Status.Text = "The reporting window could not open. The completed patch is unchanged.";
        }
    }

    private async void Send_Click(object sender, RoutedEventArgs e)
    {
        if (sending) return;
        var token = TokenInput.Password;
        TokenInput.Clear();
        if (string.IsNullOrWhiteSpace(token))
        {
            Status.Text = "Enter a temporary GitHub Issues write token or choose Skip.";
            return;
        }
        if (MessageBox.Show(this,
            offlineMetadata is null
                ? "Send the displayed Windows versions, SHA-256 and changed byte ranges to " +
                  "the PUBLIC GitHub compatibility issue? The token is used only for this request."
                : "Send the OFFLINE file's architecture, DLL version, original and patched " +
                  "CRC32/SHA-256 and changed bytes to PUBLIC GitHub? This does NOT confirm " +
                  "the file will work in Windows. The token is not stored.",
            "Confirm public version report", MessageBoxButton.YesNo,
            MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;

        sending = true;
        SendButton.IsEnabled = false;
        SkipButton.IsEnabled = false;
        Status.Text = "Sending reviewed compatibility data (hashes and changed bytes)...";
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var reporter = new SuccessfulFixPublisher();
            if (offlineMetadata is not null)
                await reporter.PublishAsync(offlineMetadata, token, cts.Token);
            else
                await reporter.PublishAsync(metadata!, token, cts.Token);
            AuditLog.Append(offlineMetadata is null
                ? "Successful fix compatibility metadata was submitted to GitHub Issues."
                : "Offline DLL compatibility metadata was submitted to GitHub Issues.");
            Status.Text = "GitHub accepted the report. Repository aggregation is separate.";
            MessageBox.Show(this, Status.Text, "Compatibility report", MessageBoxButton.OK,
                MessageBoxImage.Information);
            DialogResult = true;
            Close();
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Compatibility reporting", ex);
            Status.Text = "Report not confirmed (" + ex.GetType().Name +
                "). The successful local fix remains unchanged.";
        }
        finally
        {
            token = string.Empty;
            sending = false;
            if (IsLoaded)
            {
                SendButton.IsEnabled = true;
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
