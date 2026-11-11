using System.Windows;
using System.Windows.Media;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

/// <summary>
/// Review-first confirmation shared by diagnostics and the manual updater.
/// An affirmative click is always required; no Enter-key default action.
/// Report bytes are never sent, persisted or modified by this dialog.
/// </summary>
public partial class ModernConfirmDialog : Window
{
    public ModernConfirmDialog()
    {
        InitializeComponent();
        Title = "Review and confirm — " + UpdateIntegration.Version;
        Loaded += (_, _) => WindowLayout.FitToWorkArea(this);
    }

    internal static bool Ask(Window owner, string heading, string description,
        string destination, string details, string confirmLabel,
        string note, bool diagnosticReport)
    {
        var dialog = new ModernConfirmDialog
        {
            Owner = owner,
            Title = heading + " — " + UpdateIntegration.Version
        };
        dialog.HeadingText.Text = heading;
        dialog.DescriptionText.Text = description;
        dialog.DestinationTitle.Text = diagnosticReport
            ? "Where the report goes" : "Update source";
        dialog.DestinationText.Text = destination;
        dialog.DetailsHeading.Text = diagnosticReport
            ? "Exact report to be published" : "What will happen";
        dialog.DetailsText.Text = details;
        dialog.DetailsText.FontFamily = new FontFamily(
            diagnosticReport ? "Consolas" : "Segoe UI");
        dialog.ConfirmButton.Content = confirmLabel;
        dialog.PrivacyText.Text = note;
        return dialog.ShowDialog() == true;
    }

    private void Confirm_Click(object sender, RoutedEventArgs e) =>
        DialogResult = true;

    private void Cancel_Click(object sender, RoutedEventArgs e) =>
        DialogResult = false;

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(DetailsText.Text);
            PrivacyText.Text = "Details copied to clipboard.";
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            PrivacyText.Text = "Clipboard unavailable. Details remain visible above.";
        }
    }
}
