using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using TermsrvPatcherUnified.Core;
using UniversalUpdater;

namespace TermsrvPatcherUnified;

public partial class UpdateCenterWindow : Window
{
    private readonly UpdateIntegration updates;
    private bool checking;
    private bool installing;

    internal UpdateCenterWindow(UpdateIntegration updates)
    {
        InitializeComponent();
        this.updates = updates;
        InstalledText.Text = $"Installed: {UpdateIntegration.Version} | Windows x64";
        ChannelSelector.SelectedIndex = 1; // The installed app is currently a preview.
        RenderNotice();
    }

    private UpdateChannel Channel => ChannelSelector.SelectedIndex == 0 ?
        UpdateChannel.Stable : UpdateChannel.Prerelease;

    private void RenderNotice()
    {
        if (ChannelSelector is null || StatusText is null) return;
        var controller = updates.Get(Channel);
        var notice = controller.Notice;
        string cache = notice.IsCached ? " (cached, not install authorization)" : "";
        StatusText.Text = notice.Status switch
        {
            UpdateNoticeStatus.Available => $"New version available: {notice.AvailableVersion}{cache}",
            UpdateNoticeStatus.UpToDate => "No newer compatible release found.",
            UpdateNoticeStatus.CheckFailed => $"Update check failed ({notice.ResultCode}).",
            UpdateNoticeStatus.Checking => "Checking GitHub Releases...",
            UpdateNoticeStatus.InstallationHeld => "Installation is held after a prior failure.",
            _ => "No recent check for this release channel."
        };
        SourceText.Text = $"Source: {UpdateIntegration.Repository}  •  {Channel}  •  win-x64";
        var live = controller.LiveRelease;
        NotesText.Text = live is null
            ? "Press Check to retrieve release notes. A cached update cannot be installed."
            : $"Version {live.Version}\nPublished: {live.PublishedAt?.ToString("u") ?? "Unknown"}\n\n{live.ReleaseNotes}";
        // Explain why Install is disabled. A discovered update is not
        // sufficient proof that an in-place EXE replacement is safe.
        bool canInstall = UpdateInstallBridge.CanInstall(out string reason);
        bool freshRelease = notice.Status == UpdateNoticeStatus.Available &&
            !notice.IsCached && live is not null;
        bool available = !checking && !installing && freshRelease && canInstall;
        InstallButton.IsEnabled = available;
        InstallHelp.Text = available
            ? "Ready: administrator-owned Program Files EXE. The unsigned preview is verified; the current EXE is backed up and rollback is attempted if health verification fails."
            : checking ? "Checking release metadata. Installation is unavailable until the live check completes."
            : installing ? "Installation in progress."
            : notice.Status == UpdateNoticeStatus.InstallationHeld
                ? "Install blocked: a previous failed update needs administrator review."
            : notice.IsCached ? "Install blocked: cached release information is not enough. Press Check for a LIVE result."
            : notice.Status == UpdateNoticeStatus.CheckFailed
                ? "Install blocked: the GitHub release check failed. Press Check again or open the release page."
            : notice.Status == UpdateNoticeStatus.Available && live is null
                ? "Install blocked: no verified LIVE release details. Press Check."
            : freshRelease && !canInstall
                ? "Install blocked: " + reason + " Download the full ZIP from GitHub for a manual, administrator-approved installation."
            : "Install is unavailable: no newer LIVE release is selected. Choose Preview and press Check.";
        InstallButton.ToolTip = available ? "Install the verified update" : InstallHelp.Text;

    }

    private void ChannelChanged(object sender, SelectionChangedEventArgs e) => RenderNotice();

    private async void Check_Click(object sender, RoutedEventArgs e)
    {
        if (checking) return;
        checking = true;
        CheckButton.IsEnabled = false;
        StatusText.Text = "Checking GitHub Releases...";
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await updates.Get(Channel).CheckAsync(forced: true, cancellationToken: timeout.Token);
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Check timed out. Update status is unknown.";
            return;
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Updates", ex);
            StatusText.Text = "Update check failed. The release state is unknown.";
            return;
        }
        finally
        {
            checking = false;
            CheckButton.IsEnabled = true;
        }
        RenderNotice();
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        if (installing || checking) return;
        var channel = Channel;
        var controller = updates.Get(channel);
        var release = controller.LiveRelease;
        var canInstall = UpdateInstallBridge.CanInstall(out var reason);
        if (release is null || controller.Notice.Status != UpdateNoticeStatus.Available ||
            controller.Notice.IsCached || !canInstall)
        {
            MessageBox.Show(this, "Check the selected channel again before installing. " +
                (reason ?? ""), "Install unavailable", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var warning = "INSTALL UNSIGNED PREVIEW " + release.Version + "?\n\n" +
            "The release originates from this project's GitHub repository. The updater " +
            "checks the SHA-256 digest published by GitHub, ZIP structure and x64 PE format. " +
            "This is NOT a digital publisher signature.\n\n" +
            "The existing EXE will be backed up; the app will close, replace the EXE and " +
            "run a health probe. If the probe fails, a rollback is attempted. " +
            "Install only on a computer you administer, from a trusted location.\n\nProceed?";
        if (MessageBox.Show(this, warning, "Confirm manual EXE replacement",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        installing = true;
        CheckButton.IsEnabled = false;
        InstallButton.IsEnabled = false;
        ChannelSelector.IsEnabled = false;
        var progress = new Progress<UpdateProgress>(value =>
        {
            if (value.TotalBytes is > 0)
                StatusText.Text = $"Downloading and verifying: {100.0 * value.ReceivedBytes / value.TotalBytes:F0}%";
            else
                StatusText.Text = "Downloading and verifying the release...";
        });
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
            await UpdateInstallBridge.PrepareAndLaunchAsync(channel, release, progress, timeout.Token);
            StatusText.Text = "Verified updater started. Closing application for EXE replacement...";
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("Updates Install", ex);
            StatusText.Text = "Installation was not started: " + ex.GetType().Name;
            MessageBox.Show(this, "The original application has not been replaced. " +
                ex.Message, "Update installation failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            installing = false;
            CheckButton.IsEnabled = true;
            ChannelSelector.IsEnabled = true;
            RenderNotice();
        }
    }

    private void OpenRelease_Click(object sender, RoutedEventArgs e)
    {
        // Fixed official link: opening it sends no diagnostics or credentials.
        try
        {
            Process.Start(new ProcessStartInfo(
                "https://github.com/sgennadi/TermsrvPatcherUnified/releases")
            { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            StatusText.Text = "Could not open the browser; open the project's GitHub Releases page manually.";
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
