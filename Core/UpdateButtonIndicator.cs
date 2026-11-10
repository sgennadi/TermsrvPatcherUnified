using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using UniversalUpdater;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// A purely informational badge on the existing Updates button.
/// It never starts an update, authorizes installation, or trusts cached
/// release metadata as an executable. Stable is preferred when both channels
/// offer an upgrade, but Preview is still shown when it is the only upgrade.
/// </summary>
internal sealed record UpdateButtonDisplay(
    string Caption, string Tooltip, bool HasUpdate, UpdateChannel? Channel);

internal static class UpdateButtonIndicator
{
    internal static UpdateButtonDisplay Describe(UpdateNotice stable, UpdateNotice preview)
    {
        UpdateNotice? available = stable.ShowUpdateBadge ? stable :
            preview.ShowUpdateBadge ? preview : null;
        if (available is not null)
        {
            string channel = ReferenceEquals(available, stable) ? "Stable" : "Preview";
            bool cached = available.IsCached;
            return new UpdateButtonDisplay(
                "Updates  • NEW",
                $"{channel} update available: {available.AvailableVersion}. " +
                (cached
                    ? "This is a previously checked result. Open Updates and press Check to verify it live before installing."
                    : "Open Updates to review the release and choose whether to install."),
                true, ReferenceEquals(available, stable)
                    ? UpdateChannel.Stable : UpdateChannel.Prerelease);
        }

        string tooltip = stable.Status == UpdateNoticeStatus.Checking ||
                         preview.Status == UpdateNoticeStatus.Checking
            ? "Checking Stable and Preview releases..."
            : stable.Status == UpdateNoticeStatus.CheckFailed ||
              preview.Status == UpdateNoticeStatus.CheckFailed
                ? "One or more update checks failed. Open Updates and press Check to retry."
                : "Open Updates to check Stable or Preview releases.";
        return new UpdateButtonDisplay("Updates", tooltip, false, null);
    }

    internal static void Apply(Button button, UpdateNotice stable, UpdateNotice preview)
    {
        var display = Describe(stable, preview);
        button.Content = display.Caption;
        button.ToolTip = display.Tooltip;
        if (display.HasUpdate)
        {
            // Accessible navy-on-amber highlight in both compact and advanced layouts.
            button.Background = new SolidColorBrush(Color.FromRgb(255, 235, 188));
            button.Foreground = new SolidColorBrush(Color.FromRgb(11, 46, 90));
            button.BorderBrush = new SolidColorBrush(Color.FromRgb(230, 158, 33));
        }
        else
        {
            // Restore theme defaults when the update is installed or disproved.
            button.ClearValue(Control.BackgroundProperty);
            button.ClearValue(Control.ForegroundProperty);
            button.ClearValue(Control.BorderBrushProperty);
        }
    }
}
