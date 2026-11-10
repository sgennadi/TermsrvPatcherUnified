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
    // local file, and no free-text description is required for Formspree.
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
        return (payload, FormspreeReportClient.BuildSubmission(payload, DiagnosticsBridge.Project));
    }

    private async void PreviewDirect_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || !reportingSettings.HasFormspree) return;
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
        finally { PreviewDirectButton.IsEnabled = true; }
    }

    private async void Formspree_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || formspreeConfirmed || submittedIssue is not null ||
            !reportingSettings.HasFormspree) return;
        // Lock against double-clicks before the async environment hashing step.
        publishing = true;
        FormspreeButton.IsEnabled = false;
        PreviewDirectButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        IncludeWindowsEvidenceCheck.IsEnabled = false;
        try
        {
            var (payload, outgoing) = await CreateDirectReportAsync();
            ReportPreview.Text = outgoing;
            string details = IncludeWindowsEvidenceCheck.IsChecked == true
                ? "Includes Windows version, build and the SHA-256 of termsrv.dll."
                : "Includes app/version/error category only; Windows DLL details are excluded.";
            if (MessageBox.Show(this,
                    "Share this compatibility report to help improve the program?\n\n" +
                    details + "\nIt contains no username, password, computer name or file contents.\n" +
                    "The reporting provider may receive your network IP address.\n\n" +
                    "Destination: https://formspree.io/f/" + reportingSettings.FormspreeFormId +
                    "\n\nExact information to send:\n" + outgoing +
                    "\n\nSend report?",
                    "Send compatibility report", MessageBoxButton.YesNo,
                    MessageBoxImage.Information, MessageBoxResult.No) != MessageBoxResult.Yes)
            {
                Status.Text = "Nothing sent. You can share it later.";
                return;
            }
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var client = new FormspreeReportClient();
            await client.SendAsync(reportingSettings.FormspreeFormId, outgoing, payload,
                DiagnosticsBridge.Project, timeout.Token);
            formspreeConfirmed = true;
            FormspreeStatus.Text = "Thank you — your report was sent successfully.";
            Status.Text = "Delivery confirmed by Formspree. No local report was required.";
            AuditLog.Append("Optional typed compatibility report accepted by Formspree.");
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or
                                   InvalidOperationException or OperationCanceledException or
                                   JsonException or ArgumentException or IOException)
        {
            FormspreeStatus.Text = "Delivery could not be confirmed (" + ex.GetType().Name +
                "). Check the Formspree inbox before trying again.";
            Status.Text = "No automatic retry. Local patch or restore was not affected.";
        }
        finally
        {
            publishing = false;
            SaveButton.IsEnabled = true;
            IncludeWindowsEvidenceCheck.IsEnabled = true;
            PreviewDirectButton.IsEnabled = reportingSettings.HasFormspree;
            FormspreeButton.IsEnabled = reportingSettings.HasFormspree && !formspreeConfirmed &&
                submittedIssue is null;
            PublishButton.IsEnabled = savedReport is not null && submittedIssue is null &&
                !formspreeConfirmed;
            AnonymousButton.IsEnabled = relayEndpoint is not null && anonymousPayload is not null &&
                submittedIssue is null && !formspreeConfirmed;
        }
    }

}