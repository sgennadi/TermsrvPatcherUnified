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

    private async void Formspree_Click(object sender, RoutedEventArgs e)
    {
        if (publishing || formspreeConfirmed || submittedIssue is not null ||
            savedPath is null || savedId is null || anonymousPayload is null) return;
        string formId = reportingSettings.FormspreeFormId;
        if (!DirectReportingSettings.ValidFormId(formId))
        {
            FormspreeStatus.Text = "Formspree is not configured in this EXE.";
            return;
        }
        string outgoing;
        try { outgoing = FormspreeReportClient.BuildSubmission(anonymousPayload, DiagnosticsBridge.Project); }
        catch (Exception ex) when (ex is InvalidDataException or JsonException)
        {
            FormspreeStatus.Text = "The report must be saved and reviewed again: " + ex.GetType().Name;
            return;
        }
        if (MessageBox.Show(this,
                "Send the following exact JSON to Formspree?\n\n" +
                "Destination: https://formspree.io/f/" + formId + "\n" +
                "This third-party service may observe your IP address.\n" +
                "This DOES NOT create a GitHub Issue or update our compatibility CSV.\n\n" +
                outgoing + "\n\nSubmit to Formspree?",
                "Confirm third-party submission", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;

        publishing = true;
        FormspreeButton.IsEnabled = false;
        PublishButton.IsEnabled = false;
        AnonymousButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        DescriptionInput.IsEnabled = false;
        IncludeWindowsEvidenceCheck.IsEnabled = false;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var client = new FormspreeReportClient();
            await client.SendAsync(formId, outgoing, anonymousPayload, DiagnosticsBridge.Project, deadline.Token);
            formspreeConfirmed = true;
            try
            {
                DiagnosticsBridge.MarkFormspreeSubmitted(savedPath, savedId, formId);
                FormspreeStatus.Text = "Formspree confirmed receipt; local delivery recorded. GitHub CSV unchanged.";
            }
            catch
            {
                FormspreeStatus.Text = "Formspree confirmed receipt but local acknowledgement failed. " +
                    "Check Formspree before retrying.";
            }
            Status.Text = "Formspree accepted typed diagnostic metadata. No GitHub Issue was created.";
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or
                                   InvalidOperationException or OperationCanceledException or
                                   JsonException or ArgumentException)
        {
            FormspreeStatus.Text = "Formspree delivery NOT confirmed (" + ex.GetType().Name +
                "). Local report remains pending. Check its dashboard before retrying.";
        }
        finally
        {
            publishing = false;
            SaveButton.IsEnabled = true;
            DescriptionInput.IsEnabled = true;
            IncludeWindowsEvidenceCheck.IsEnabled = true;
            PublishButton.IsEnabled = savedReport is not null && submittedIssue is null && !formspreeConfirmed;
            FormspreeButton.IsEnabled = anonymousPayload is not null && savedReport is not null &&
                submittedIssue is null && !formspreeConfirmed &&
                reportingSettings.HasFormspree;
            AnonymousButton.IsEnabled = relayEndpoint is not null && anonymousPayload is not null &&
                submittedIssue is null && !formspreeConfirmed;
        }
    }
}