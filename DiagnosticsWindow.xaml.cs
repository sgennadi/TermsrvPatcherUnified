using UniversalDiagnostics.Transport;
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
    private AnonymousDiagnosticPayload? anonymousPayload;
    private Uri? relayEndpoint;
    private string? githubSessionToken;
    private CancellationTokenSource? githubLoginCancel;
    private bool formspreeConfirmed;
    private DirectReportingSettings reportingSettings = new("", "");

    public DiagnosticsWindow()
    {
        InitializeComponent();
        draft = DiagnosticsBridge.Current();
        ErrorLabel.Text = $"Component: {draft.Component}  |  {draft.ErrorType} ({draft.Code})";
        DescriptionInput.Text = draft.Summary;
        ReportPreview.Text = "Reports are stored locally only after explicit confirmation. " +
            "No raw logs or GitHub credentials are captured.";
        try
        {
            relayEndpoint = UniversalDiagnosticsRelayClient.ReadConfiguredEndpoint();
            RelayState.Text = relayEndpoint is null
                ? "Not configured — local reports only"
                : "Relay configured — anonymous reporting available";
        }
        catch (Exception)
        {
            RelayState.Text = "Invalid relay configuration — local reports only";
        }
        try
        {
            reportingSettings = DirectReportingSettings.Load();
            GitHubSignInButton.IsEnabled = reportingSettings.HasGitHubOAuth;
            GitHubDeviceStatus.Text = reportingSettings.HasGitHubOAuth
                ? "Ready: connect through GitHub browser sign-in when you wish to publish."
                : "GitHub OAuth is not configured in this EXE; optional temporary token remains available.";
            FormspreeStatus.Text = reportingSettings.HasFormspree
                ? "Step 1: Review and save locally. Step 2: Send report (no login needed)."
                : "Formspree is not configured in this EXE. Reporting stays local.";
        }
        catch (Exception ex) when (ex is InvalidDataException or UnauthorizedAccessException or IOException or JsonException)
        {
            GitHubSignInButton.IsEnabled = false;
            FormspreeButton.IsEnabled = false;
            GitHubDeviceStatus.Text = "Embedded GitHub reporting configuration is invalid. Disabled.";
            FormspreeStatus.Text = "Embedded Formspree reporting configuration is invalid. Disabled.";
        }
        Closed += (_, _) =>
        {
            githubLoginCancel?.Cancel();
            githubSessionToken = null;
            SessionToken.Clear();
        };
    }

    private void DescriptionChanged(object sender, TextChangedEventArgs e)
        => InvalidateSavedReview();

    private void EvidenceSelectionChanged(object sender, RoutedEventArgs e)
        => InvalidateSavedReview();

    private void InvalidateSavedReview()
    {
        if (PublishButton is null || ReportPreview is null) return;
        anonymousPayload = null;
        if (AnonymousButton is not null) AnonymousButton.IsEnabled = false;
        if (FormspreeButton is not null) FormspreeButton.IsEnabled = false;
        savedReport = null;
        savedPath = null;
        savedId = null;
        submittedIssue = null;
        formspreeConfirmed = false;
        PublishButton.IsEnabled = false;
        ReportPreview.Text = "Report options changed. Review and save the report again before publishing.";
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(DescriptionInput.Text))
        {
            MessageBox.Show(this, "Enter a short description before saving a report.");
            return;
        }
        var description = DescriptionInput.Text;
        // A digest may be expensive. Read it without blocking the WPF dispatcher.
        // Evidence is never captured or uploaded unless the user explicitly
        // reviews the resolved version/hash and confirms the report.
        bool includeWindowsEvidence = IncludeWindowsEvidenceCheck.IsChecked == true;
        DiagnosticEnvironment? environment = includeWindowsEvidence
            ? await Task.Run(DiagnosticEnvironment.TryRead) : null;
        var evidencePreview = !includeWindowsEvidence
            ? "Windows build / DLL SHA-256: excluded by operator."
            : environment is null
                ? "Windows build / DLL SHA-256: unavailable; report will omit these fields."
                : environment.AsPreview();
        var proposed = $"Project: {DiagnosticsBridge.Project}\nComponent: {draft.Component}\n" +
            $"Type: {draft.ErrorType}\nCode: {draft.Code}\n" +
            $"Version: {UpdateIntegration.Version}\n\n{evidencePreview}\n\n{description}";
        if (MessageBox.Show(this,
                "Review this description. The diagnostics module will redact common identifiers " +
                "and save a local event. Nothing will be uploaded automatically.\n\n" + proposed,
                "Confirm local diagnostic capture", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        SaveButton.IsEnabled = false;
        DescriptionInput.IsEnabled = false;
        IncludeWindowsEvidenceCheck.IsEnabled = false;
        PublishButton.IsEnabled = false;
        try
        {
            var receipt = await Task.Run(() =>
                DiagnosticsBridge.Capture(draft, description, environment));
            var markdown = DiagnosticsBridge.ReportMarkdown(await File.ReadAllTextAsync(receipt.Path));
            // Local capture must succeed even if a category cannot be sent anonymously.
            try
            {
                anonymousPayload = UniversalDiagnosticsRelayClient.Prepare(
                    await File.ReadAllTextAsync(receipt.Path));
            }
            catch (InvalidDataException)
            {
                anonymousPayload = null;
                RelayState.Text = "Report contains unsupported categories — local only";
            }
            savedReport = markdown;
            savedPath = receipt.Path;
            savedId = receipt.Id;
            submittedIssue = null;
            formspreeConfirmed = false;
            ReportPreview.Text = markdown;
            PublishButton.IsEnabled = true;
            FormspreeButton.IsEnabled = anonymousPayload is not null &&
                reportingSettings.HasFormspree;
            AnonymousButton.IsEnabled = relayEndpoint is not null && anonymousPayload is not null;
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
            IncludeWindowsEvidenceCheck.IsEnabled = true;
        }
    }

    private async void Publish_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || savedReport is null || savedId is null || savedPath is null ||
            submittedIssue is not null || formspreeConfirmed || githubLoginCancel is not null) return;
        if (string.IsNullOrWhiteSpace(SessionToken.Password) &&
            string.IsNullOrWhiteSpace(githubSessionToken))
        {
            Status.Text = "Connect GitHub using browser sign-in, or enter an optional temporary token.";
            return;
        }
        if (MessageBox.Show(this,
                "Publish this saved report to the PUBLIC GitHub Issues page?\n\n" +
                "Only the text in Review is sent. Do not publish passwords, tokens, " +
                "identifiers or sensitive information.\n\nContinue?",
                "Publish reviewed diagnostics?", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;

        var token = !string.IsNullOrWhiteSpace(SessionToken.Password)
            ? SessionToken.Password : githubSessionToken ?? "";
        SessionToken.Clear(); // Manual PAT is never persisted.
        publishing = true;
        PublishButton.IsEnabled = false;
        AnonymousButton.IsEnabled = false;
        FormspreeButton.IsEnabled = false;
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
            IncludeWindowsEvidenceCheck.IsEnabled = true;
            PublishButton.IsEnabled = savedReport is not null && submittedIssue is null;
            AnonymousButton.IsEnabled = relayEndpoint is not null && anonymousPayload is not null && submittedIssue is null;
            FormspreeButton.IsEnabled = savedReport is not null && anonymousPayload is not null &&
                submittedIssue is null && !formspreeConfirmed &&
                reportingSettings.HasFormspree;
        }
    }

    private async void Anonymous_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || relayEndpoint is null || anonymousPayload is null ||
            savedPath is null || savedId is null || submittedIssue is not null || formspreeConfirmed) return;
        var payload = anonymousPayload;
        // The operator sees the exact JSON that will be sent, not the local summary.
        if (MessageBox.Show(this,
                "Only the following typed fields will be sent over HTTPS to the configured " +
                "relay and may become a PUBLIC GitHub Issue. No description, logs, " +
                "passwords or paths are uploaded. Review all fields.\n\n" + payload.Json +
                "\n\nSend anonymously?",
                "Review anonymous diagnostic report", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        publishing = true;
        AnonymousButton.IsEnabled = false;
        PublishButton.IsEnabled = false;
        FormspreeButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        DescriptionInput.IsEnabled = false;
        IncludeWindowsEvidenceCheck.IsEnabled = false;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var relayClient = new UniversalDiagnosticsRelayClient();
            var issue = await relayClient.SendAsync(payload, relayEndpoint, deadline.Token);
            submittedIssue = issue;
            try
            {
                DiagnosticsBridge.MarkSubmitted(savedPath, savedId, issue);
                Status.Text = "Anonymous report delivered and acknowledged: " + issue.AbsoluteUri;
            }
            catch
            {
                Status.Text = "Issue confirmed, but local acknowledgement failed: " +
                    issue.AbsoluteUri;
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or
                                   InvalidDataException or ArgumentException or
                                   OperationCanceledException or JsonException)
        {
            Status.Text = "Anonymous delivery not confirmed (" + ex.GetType().Name +
                "). Report remains in local queue. Do not assume it was sent.";
        }
        finally
        {
            publishing = false;
            SaveButton.IsEnabled = true;
            DescriptionInput.IsEnabled = true;
            IncludeWindowsEvidenceCheck.IsEnabled = true;
            PublishButton.IsEnabled = savedReport is not null && submittedIssue is null;
            AnonymousButton.IsEnabled = relayEndpoint is not null &&
                anonymousPayload is not null && submittedIssue is null;
            FormspreeButton.IsEnabled = savedReport is not null && anonymousPayload is not null &&
                submittedIssue is null && !formspreeConfirmed &&
                reportingSettings.HasFormspree;
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
            "GitHub Issue form opened. Sign in to publish; anonymous GitHub Issues are not supported." :
            "Published issue opened in browser.";
    }
}
