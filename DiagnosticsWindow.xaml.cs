using System.Diagnostics;
using System.Text.Json;
using System.Windows;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class DiagnosticsWindow : Window
{
    private readonly DiagnosticsBridge.DiagnosticDraft draft;
    private string? savedReport;

    public DiagnosticsWindow()
    {
        InitializeComponent();
        draft = DiagnosticsBridge.Current();
        ErrorLabel.Text = $"Component: {draft.Component}  |  {draft.ErrorType} ({draft.Code})";
        DescriptionInput.Text = draft.Summary;
        ReportPreview.Text = "Reports are stored on this computer only after you explicitly confirm. " +
            "No raw application log is included. No GitHub credentials are required.";
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(DescriptionInput.Text))
        {
            MessageBox.Show(this, "Enter a short description before saving a report.");
            return;
        }
        var proposed = $"Project: {DiagnosticsBridge.Project}\nComponent: {draft.Component}\n" +
            $"Type: {draft.ErrorType}\nCode: {draft.Code}\n" +
            $"Version: {UpdateIntegration.Version}\n\n{DescriptionInput.Text}";
        if (MessageBox.Show(this,
                "Review this description. The diagnostics module will redact common identifiers " +
                "and save a local event. Nothing will be uploaded automatically.\n\n" + proposed,
                "Confirm local diagnostic capture", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        SaveButton.IsEnabled = false;
        try
        {
            var receipt = await Task.Run(() => DiagnosticsBridge.Capture(draft, DescriptionInput.Text));
            savedReport = DiagnosticsBridge.ReportMarkdown(await File.ReadAllTextAsync(receipt.Path));
            ReportPreview.Text = savedReport;
            Status.Text = $"Saved locally. Report ID: {receipt.Id}. Review before sharing.";
        }
        catch (Exception ex)
        {
            Status.Text = $"Unable to save report: {ex.GetType().Name}.";
        }
        finally { SaveButton.IsEnabled = true; }
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (savedReport is null)
        {
            MessageBox.Show(this, "Save and review the report first.");
            return;
        }
        Clipboard.SetText(savedReport);
        Status.Text = "Report copied. Check the clipboard contents before sharing.";
    }

    private void OpenIssue_Click(object sender, RoutedEventArgs e)
    {
        if (savedReport is null)
        {
            MessageBox.Show(this, "Save and review the report first.");
            return;
        }
        Process.Start(new ProcessStartInfo(
            "https://github.com/sgennadi/TermsrvPatcherUnified/issues/new")
        { UseShellExecute = true });
        Status.Text = "Issue page opened. Paste the reviewed report yourself to submit.";
    }
}
