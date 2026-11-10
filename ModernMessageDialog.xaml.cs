using System.Windows;
using System.Windows.Media;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

/// <summary>
/// Compact, review-first replacement for legacy MessageBox UI.
/// Escape and the window close button never approve a protected change.
/// </summary>
public partial class ModernMessageDialog : Window
{
    private MessageBoxResult outcome = MessageBoxResult.None;
    private MessageBoxResult accepted = MessageBoxResult.OK;

    public ModernMessageDialog()
    {
        InitializeComponent();
        Title = "Message — " + UpdateIntegration.Version;
        Loaded += (_, _) => WindowLayout.FitToWorkArea(this);
    }

    internal static MessageBoxResult Show(Window? owner, string message,
        string caption = "TermsrvPatcherUnified",
        MessageBoxButton buttons = MessageBoxButton.OK,
        MessageBoxImage image = MessageBoxImage.None,
        MessageBoxResult defaultResult = MessageBoxResult.None)
    {
        var dialog = new ModernMessageDialog
        {
            Title = caption + " — " + UpdateIntegration.Version
        };
        if (owner is not null && owner.IsVisible)
            dialog.Owner = owner;
        else
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;

        dialog.HeadingText.Text = caption;
        dialog.BodyText.Text = message;
        dialog.SubtitleText.Text = image switch
        {
            MessageBoxImage.Error => "Operation could not be completed.",
            MessageBoxImage.Warning => "Review the impact before proceeding.",
            MessageBoxImage.Question => "Your explicit approval is required.",
            _ => "Review the information below."
        };

        if (image is MessageBoxImage.Error or MessageBoxImage.Warning)
        {
            dialog.MessageIcon.Text = "!";
            dialog.MessageIcon.Foreground = new SolidColorBrush(
                Color.FromRgb(146, 64, 14));
            dialog.MessageIconBorder.Background = new SolidColorBrush(
                Color.FromRgb(255, 247, 237));
        }
        else if (image == MessageBoxImage.Question)
        {
            dialog.MessageIcon.Text = "?";
        }

        dialog.accepted = buttons is MessageBoxButton.YesNo or MessageBoxButton.YesNoCancel
            ? MessageBoxResult.Yes : MessageBoxResult.OK;
        dialog.AcceptButton.Content = buttons is MessageBoxButton.YesNo or MessageBoxButton.YesNoCancel
            ? GetApprovalCaption(caption) : "Close";

        dialog.CancelButton.Visibility = buttons is MessageBoxButton.OKCancel or MessageBoxButton.YesNoCancel
            ? Visibility.Visible : Visibility.Collapsed;
        dialog.NoButton.Visibility = buttons is MessageBoxButton.YesNo or MessageBoxButton.YesNoCancel
            ? Visibility.Visible : Visibility.Collapsed;
        dialog.HintText.Text = buttons == MessageBoxButton.OK
            ? "Information only. No changes are made by this window."
            : "Esc / Close does not approve any changes.";
        // Never honor a positive default result: an explicit click is required.
        _ = defaultResult;
        dialog.ShowDialog();
        return dialog.outcome;
    }

    internal static MessageBoxResult Show(string message,
        string caption = "TermsrvPatcherUnified",
        MessageBoxButton buttons = MessageBoxButton.OK,
        MessageBoxImage image = MessageBoxImage.None,
        MessageBoxResult defaultResult = MessageBoxResult.None)
        => Show(Application.Current?.MainWindow, message, caption, buttons, image, defaultResult);

    internal static bool Confirm(Window owner, string heading, string message,
        string approvalCaption = "Continue")
    {
        var dialog = new ModernMessageDialog
        {
            Owner = owner,
            Title = heading + " — " + UpdateIntegration.Version
        };
        dialog.HeadingText.Text = heading;
        dialog.BodyText.Text = message;
        dialog.SubtitleText.Text = "Review carefully. This action requires confirmation.";
        dialog.MessageIcon.Text = "!";
        dialog.MessageIcon.Foreground = new SolidColorBrush(Color.FromRgb(146, 64, 14));
        dialog.MessageIconBorder.Background = new SolidColorBrush(Color.FromRgb(255, 247, 237));
        dialog.accepted = MessageBoxResult.Yes;
        dialog.AcceptButton.Content = approvalCaption;
        dialog.NoButton.Visibility = Visibility.Visible;
        dialog.NoButton.Content = "Cancel";
        dialog.HintText.Text = "Esc / Close cancels without applying changes.";
        dialog.ShowDialog();
        return dialog.outcome == MessageBoxResult.Yes;
    }

    private static string GetApprovalCaption(string caption)
    {
        if (caption.Contains("Group Policy", StringComparison.OrdinalIgnoreCase))
            return "Refresh policy";
        if (caption.Contains("Cleanup", StringComparison.OrdinalIgnoreCase))
            return "Clean up";
        if (caption.Contains("Restore", StringComparison.OrdinalIgnoreCase) ||
            caption.Contains("Revert", StringComparison.OrdinalIgnoreCase))
            return "Restore";
        if (caption.Contains("Apply", StringComparison.OrdinalIgnoreCase))
            return "Apply";
        if (caption.Contains("backup", StringComparison.OrdinalIgnoreCase))
            return "Continue";
        return "Confirm";
    }

    private void Accept_Click(object sender, RoutedEventArgs e)
    {
        outcome = accepted;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        outcome = MessageBoxResult.Cancel;
        DialogResult = false;
    }

    private void No_Click(object sender, RoutedEventArgs e)
    {
        outcome = MessageBoxResult.No;
        DialogResult = false;
    }
}
