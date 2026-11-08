using System.Windows;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        AppVersionText.Text = UpdateIntegration.Version + " | Windows x64 | .NET 10";
        NSudoStatusText.Text = NsudoDevilModeScope.ComponentStatus;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
