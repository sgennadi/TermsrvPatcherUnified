using System.Diagnostics;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class DiagnosticsWindow : Window
{
    private readonly DiagnosticsBridge.DiagnosticDraft draft;
    private string? savedReport;
    private string? savedPath;
    private string? savedId;
    private Uri? submittedIssue;
    private bool publishing;

    public DiagnosticsWindow()
    {
        InitializeComponent();
        draft = DiagnosticsBridge.Current();
        ErrorLabel.Text = $"Component: {draft.Component}  |  {draft.ErrorType} ({draft.Code})";
        DescriptionInput.Text = draft.Summary;
        ReportPreview.Text = "Reports are stored locally only after explicit confirmation. " +
            "No raw logs or GitHub credentials are captured.";
        Closed += (_, _) => SessionToken.Clear();
    }

    private void DescriptionChanged(object sender, TextChangedEventArgs e)
    {
        if (PublishButton is null || ReportPreview is null) return;
        savedReport = null;
        savedPath = null;
        savedId = null;
        submittedIssue = null;
        PublishButton.IsEnabled = false;
        ReportPreview.Text = "Description changed. Review and save the updated report before publishing.";
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(DescriptionInput.Text))
        {
            MessageBox.Show(this, "Enter a short description before saving a report.");
            return;
        }
        var description = DescriptionInput.Text;
        var proposed = $"Project: {DiagnosticsBridge.Project}\nComponent: {draft.Component}\n" +
            $"Type: {draft.ErrorType}\nCode: {draft.Code}\n" +
            $"Version: {UpdateIntegration.Version}\n\n{description}";
        if (MessageBox.Show(this,
                "Review this description. The diagnostics module will redact common identifiers " +
                "and save a local event. Nothing will be uploaded automatically.\n\n" + proposed,
                "Confirm local diagnostic capture", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        SaveButton.IsEnabled = false;
        DescriptionInput.IsEnabled = false;
        PublishButton.IsEnabled = false;
        try
        {
            var receipt = await Task.Run(() => DiagnosticsBridge.Capture(draft, description));
            var markdown = DiagnosticsBridge.ReportMarkdown(await File.ReadAllTextAsync(receipt.Path));
            savedReport = markdown;
            savedPath = receipt.Path;
            savedId = receipt.Id;
            submittedIssue = null;
            ReportPreview.Text = markdown;
            PublishButton.IsEnabled = true;
            Status.Text = $"Saved locally. Report ID: {receipt.Id}. Review before sharing.";
        }
        catch (Exception ex)
        {
            Status.Text = $"Unable to save report: {ex.GetType().Name}.";
        }
        finally
        {
            SaveButton.IsEnabled = true;
            DescriptionInput.IsEnabled = true;
        }
    }

    private async void Publish_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || savedReport is null || savedId is null || savedPath is null ||
            submittedIssue is not null) return;
        if (MessageBox.Show(this,
                "Publish this saved report to the PUBLIC GitHub Issues page?\n\n" +
                "Only the text in Review is sent. Do not publish passwords, tokens, " +
                "identifiers or sensitive information.\n\nContinue?",
                "Publish reviewed diagnostics?", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;

        var token = SessionToken.Password;
        SessionToken.Clear(); // Token never persists in the report or application settings.
        publishing = true;
        PublishButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        DescriptionInput.IsEnabled = false;
        Uri? created = null;
        try
        {
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var publisher = new GitHubIssuePublisher();
            created = await publisher.PublishAsync(savedReport, savedId, token, cancellation.Token);
            submittedIssue = created;
            try
            {
                DiagnosticsBridge.MarkSubmitted(savedPath, savedId, created);
                Status.Text = "Published and acknowledged locally: " + created.AbsoluteUri;
            }
            catch
            {
                // Never retry automatically: the Issue already exists on GitHub.
                Status.Text = "Published, but local queue acknowledgement failed. Issue: " + created.AbsoluteUri;
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or
                                   InvalidDataException or ArgumentException or OperationCanceledException or JsonException)
        {
            Status.Text = "GitHub submission was not confirmed (" + ex.GetType().Name +
                "). Check the Issues page before retrying to avoid duplicates.";
        }
        finally
        {
            token = string.Empty;
            publishing = false;
            SaveButton.IsEnabled = true;
            DescriptionInput.IsEnabled = true;
            PublishButton.IsEnabled = savedReport is not null && submittedIssue is null;
        }
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
        Process.Start(new ProcessStartInfo(submittedIssue?.AbsoluteUri ??
            "https://github.com/sgennadi/TermsrvPatcherUnified/issues/new")
        { UseShellExecute = true });
        Status.Text = submittedIssue is null ?
            "Issue page opened. Paste the reviewed report yourself to submit." :
            "Published issue opened in browser.";
    }
}
