using System.Diagnostics;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using TermsrvPatcherUnified.Core;
using UniversalDiagnostics.Transport;

namespace TermsrvPatcherUnified;

/// <summary>UI actions for independent, opt-in reporting without a relay.</summary>
public partial class DiagnosticsWindow
{
    private void CopyDeviceCode_Click(object sender, RoutedEventArgs e)
    {
        if (GitHubCodeInput.Text.Length == 9)
        {
            Clipboard.SetText(GitHubCodeInput.Text);
            GitHubDeviceStatus.Text = "Verification code copied. Enter it at github.com/login/device.";
        }
    }

    private void GitHubCancel_Click(object sender, RoutedEventArgs e)
    {
        githubLoginCancel?.Cancel();
        GitHubDeviceStatus.Text = "Cancelling browser sign-in. No report is sent.";
    }

    private async void GitHubConnect_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || githubLoginCancel is not null) return;
        string clientId = reportingSettings.GitHubOAuthClientId;
        if (!DirectReportingSettings.ValidClientId(clientId))
        {
            GitHubDeviceStatus.Text = "GitHub OAuth is not configured in this EXE.";
            return;
        }
        if (MessageBox.Show(this,
                "A GitHub account is required. This OAuth App requests public_repo scope, " +
                "which permits public repository code access in addition to Issues. " +
                "Authorize only an OAuth App you trust. No report is submitted during sign-in.\n\nContinue?",
                "Review GitHub OAuth permissions", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;

        var cancellation = new CancellationTokenSource();
        githubLoginCancel = cancellation;
        githubSessionToken = null;
        GitHubCodeInput.Text = "";
        CopyGitHubCodeButton.IsEnabled = false;
        GitHubSignInButton.IsEnabled = false;
        GitHubCancelButton.IsEnabled = true;
        try
        {
            using var auth = new GitHubDeviceAuthorization();
            var challenge = await auth.RequestCodeAsync(clientId, cancellation.Token);
            GitHubCodeInput.Text = challenge.UserCode;
            CopyGitHubCodeButton.IsEnabled = true;
            GitHubDeviceStatus.Text = "Enter " + challenge.UserCode +
                " at github.com/login/device. Waiting for authorization...";
            try
            {
                Process.Start(new ProcessStartInfo(challenge.VerificationUri.AbsoluteUri)
                { UseShellExecute = true });
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                GitHubDeviceStatus.Text = "Open " +
                    challenge.VerificationUri.AbsoluteUri + " manually and enter " + challenge.UserCode;
            }
            githubSessionToken = await auth.WaitForAuthorizationAsync(challenge,
                status => GitHubDeviceStatus.Text = status, cancellation.Token);
            GitHubDeviceStatus.Text = "GitHub connected for this dialog only. " +
                "Review and save a report, then choose Publish via GitHub.";
        }
        catch (OperationCanceledException)
        {
            GitHubDeviceStatus.Text = "GitHub authorization cancelled or expired. No report sent.";
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or
                                   InvalidOperationException or ArgumentException or JsonException)
        {
            GitHubDeviceStatus.Text = "GitHub authorization unavailable (" + ex.GetType().Name +
                "). Check OAuth client ID, Device Flow and network access.";
        }
        finally
        {
            githubLoginCancel = null;
            cancellation.Dispose();
            GitHubSignInButton.IsEnabled = reportingSettings.HasGitHubOAuth;
            GitHubCancelButton.IsEnabled = false;
        }
    }

    // Typed report is created only in memory. No call to Capture(), no
    // local file, and no free-text description is required for Google.
    private async Task<(AnonymousDiagnosticPayload Payload, string Json)> CreateDirectReportAsync()
    {
        DiagnosticEnvironment? environment = null;
        if (IncludeWindowsEvidenceCheck.IsChecked == true)
        {
            environment = await Task.Run(DiagnosticEnvironment.TryRead);
            if (environment is null)
                throw new InvalidOperationException(
                    "Windows/DLL details could not be verified. Choose Retry or uncheck the option.");
        }
        var payload = DiagnosticsBridge.PrepareDirect(draft, environment);
        return (payload, GoogleAppsScriptReportClient.BuildSubmission(payload));
    }

    private async void PreviewDirect_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || !reportingSettings.HasGoogleScript ||
            IncludeWindowsEvidenceCheck.IsChecked != true) return;
        try
        {
            PreviewDirectButton.IsEnabled = false;
            var outgoing = await CreateDirectReportAsync();
            ReportPreview.Text = outgoing.Json;
            Status.Text = "Preview only. Nothing has been sent or saved.";
        }
        catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException or
                                   IOException or JsonException)
        {
            Status.Text = "Could not prepare a report (" + ex.GetType().Name +
                "). Retry or adjust the Windows details option.";
        }
        finally { PreviewDirectButton.IsEnabled = reportingSettings.HasGoogleScript &&
                IncludeWindowsEvidenceCheck.IsChecked == true; }
    }

    private async void GoogleReport_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || googleConfirmed || submittedIssue is not null ||
            !reportingSettings.HasGoogleScript || IncludeWindowsEvidenceCheck.IsChecked != true)
            return;
        publishing = true;
        GoogleButton.IsEnabled = false;
        PreviewDirectButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        IncludeWindowsEvidenceCheck.IsEnabled = false;
        try
        {
            var (payload, outgoing) = await CreateDirectReportAsync();
            ReportPreview.Text = outgoing;
            if (MessageBox.Show(this,
                    "Share a short compatibility report to help improve this program?\n\n" +
                    "It includes Windows build, DLL version and SHA-256, but no user name, " +
                    "computer name, passwords, file contents or free-form notes.\n" +
                    "Google may observe your IP address; the submitted information " +
                    "will become a PUBLIC GitHub Issue.\n\n" +
                    "Destination: " + reportingSettings.GoogleAppsScriptUrl +
                    "\n\nExact report to share:\n" + outgoing +
                    "\n\nSend to GitHub now?",
                    "Review compatibility report", MessageBoxButton.YesNo,
                    MessageBoxImage.Information, MessageBoxResult.No) != MessageBoxResult.Yes)
            {
                Status.Text = "Nothing sent. You can choose to share later.";
                return;
            }
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var client = new GoogleAppsScriptReportClient();
            Uri issue = await client.SendAsync(reportingSettings.GoogleAppsScriptUrl,
                outgoing, payload, timeout.Token);
            googleConfirmed = true;
            submittedIssue = issue;
            OpenConfirmedIssueButton.Visibility = Visibility.Visible;
            GoogleStatus.Text = "Thank you — your report was received and added to GitHub.";
            Status.Text = "Confirmed public GitHub Issue: " + issue.AbsoluteUri;
            AuditLog.Append("User-approved Google diagnostics submission acknowledged by GitHub.");
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or
                                   InvalidOperationException or OperationCanceledException or
                                   JsonException or ArgumentException or IOException)
        {
            GoogleStatus.Text = "Delivery not confirmed (" + ex.GetType().Name +
                "). Check GitHub Issues before sending again.";
            Status.Text = "No automatic retry. The patch or restore was not affected.";
        }
        finally
        {
            publishing = false;
            SaveButton.IsEnabled = true;
            IncludeWindowsEvidenceCheck.IsEnabled = true;
            PreviewDirectButton.IsEnabled = reportingSettings.HasGoogleScript &&
                IncludeWindowsEvidenceCheck.IsChecked == true;
            GoogleButton.IsEnabled = reportingSettings.HasGoogleScript &&
                IncludeWindowsEvidenceCheck.IsChecked == true && !googleConfirmed &&
                submittedIssue is null;
            PublishButton.IsEnabled = savedReport is not null && submittedIssue is null &&
                !googleConfirmed;
            AnonymousButton.IsEnabled = relayEndpoint is not null && anonymousPayload is not null &&
                submittedIssue is null && !googleConfirmed;
        }
    }

    private void OpenConfirmedIssue_Click(object sender, RoutedEventArgs e)
    {
        if (!googleConfirmed || submittedIssue is null ||
            !GitHubIssuePublisher.IsApprovedIssueUri(submittedIssue)) return;
        try
        {
            Process.Start(new ProcessStartInfo(submittedIssue.AbsoluteUri)
            { UseShellExecute = true });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Status.Text = "Could not open the browser. Issue: " + submittedIssue.AbsoluteUri;
        }
    }
}
