using System.Windows;
using System.Windows.Controls;
using TermsrvPatcherUnified.Core;
using UniversalUpdater;

namespace TermsrvPatcherUnified;

public partial class UpdateCenterWindow : Window
{
    private readonly UpdateIntegration updates;
    private bool checking;

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
        // The shared core never performs installation on its own. Our host does not yet
        // provide a signed elevated installer with verified publisher and rollback.
        InstallButton.IsEnabled = false;
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

    private void Install_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(this,
            "This preview does not include a trusted installer. Download/install is disabled " +
            "until the signed-release, publisher verification and rollback steps are implemented.",
            "Install unavailable", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
