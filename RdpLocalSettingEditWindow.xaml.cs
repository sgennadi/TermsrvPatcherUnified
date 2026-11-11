using System.Windows;
using System.Windows.Media;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class RdpLocalSettingEditWindow : Window
{
    private readonly RdpLocalSettingSpec spec;
    private int? loadedValue;
    private bool blocked = true;
    private bool saving;

    internal RdpLocalSettingEditWindow(RdpLocalSettingSpec selected)
    {
        spec = selected ?? throw new ArgumentNullException(nameof(selected));
        if (RdpLocalAdvancedSettings.Find(selected.Setting) != selected)
            throw new InvalidDataException("Unsupported local RDP setting.");
        InitializeComponent();
        Title = "Local RDP setting — " + UpdateIntegration.Version;
        SettingTitle.Text = spec.Setting;
        GuidanceText.Text = spec.Guidance;
        ImpactText.Text = (spec.ConsoleOnly
            ? "This option requires the local or hypervisor console. "
            : "") +
            "No automatic gpupdate, TermService restart or reboot is performed. " +
            "Changes are verified, with rollback on failure.";
        if (spec.HasChoices)
        {
            ValueChoices.Visibility = Visibility.Visible;
            ValueChoices.ItemsSource = spec.Choices;
        }
        else
        {
            NumericValue.Visibility = Visibility.Visible;
            NumberHint.Text = $"Allowed: {spec.Minimum}–{spec.Maximum}. " +
                (spec.RegistryValue == "PortNumber"
                    ? "TCP port. Ensure firewall rules and independent console access."
                    : "Unit: milliseconds (0 means unlimited).");
        }
        Loaded += async (_, _) =>
        {
            WindowLayout.FitToWorkArea(this);
            await ReloadAsync();
        };
    }

    private async Task ReloadAsync()
    {
        ApplyButton.IsEnabled = false;
        StatusText.Text = "Reading actual local value and controlling policy...";
        loadedValue = null;
        blocked = true;
        try
        {
            var state = await Task.Run(() =>
            {
                int? value = RdpLocalAdvancedSettings.ReadLocal(spec);
                bool controlled = RdpLocalAdvancedSettings.IsPolicyManaged(spec);
                RdpPolicySource? source = controlled
                    ? RdpPolicySourceResolver.ReadWinning(spec.RegistryValue) : null;
                return (value, controlled, source);
            });
            loadedValue = state.value;
            blocked = state.controlled;
            CurrentValueText.Text = state.value?.ToString() ?? "Unknown / missing (editing disabled)";
            if (spec.HasChoices)
                ValueChoices.SelectedItem = spec.Choices.FirstOrDefault(x => x.Value == state.value);
            else
                NumericValue.Text = state.value?.ToString() ?? "";

            if (blocked)
            {
                PolicyHeading.Text = "Managed by Group Policy — local edit blocked";
                PolicySummaryText.Text = state.source?.Resolved == true
                    ? "Winning GPO: " + state.source.Label
                    : "This setting is managed by Group Policy; its winning GPO name could not be verified.";
                PolicyDetailsText.Text = state.source?.Details ??
                    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\" +
                    spec.RegistryValue + "\nSource unavailable; check gpresult.";
                StatusText.Text = "Blocked by GPO. No local override will be attempted.";
                StatusText.Foreground = new SolidColorBrush(Color.FromRgb(160, 92, 14));
            }
            else
            {
                PolicyHeading.Text = "No local policy override detected";
                PolicySummaryText.Text = "The corresponding Group Policy registry value is not configured.";
                PolicyDetailsText.Text = RdpPolicySourceResolver.TerminalPolicyPath + "\\" +
                    spec.RegistryValue + "\nLocal value is editable, subject to administrator rights.";
                StatusText.Text = !SystemInfo.IsAdministrator()
                    ? "Administrator rights required; viewing only."
                    : spec.ConsoleOnly && InteractiveSessionDetector.Detect() != SessionKind.Console
                        ? "This setting requires local/VM console access; editing blocked in remote sessions."
                        : "Ready to review the requested local change.";
                StatusText.Foreground = new SolidColorBrush(Color.FromRgb(52, 90, 126));
            }
            bool console = !spec.ConsoleOnly ||
                InteractiveSessionDetector.Detect() == SessionKind.Console;
            ApplyButton.IsEnabled = !blocked && state.value.HasValue &&
                SystemInfo.IsAdministrator() && console && !saving;
        }
        catch (Exception ex)
        {
            PolicyHeading.Text = "Policy status cannot be verified";
            PolicySummaryText.Text = "No local change is allowed until Windows policy can be inspected.";
            PolicyDetailsText.Text = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\" +
                "Terminal Services\\" + spec.RegistryValue + "\n" + ex.GetType().Name;
            StatusText.Text = "Inspection failed. Local editing blocked.";
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(185, 28, 28));
        }
    }

    private async void Reload_Click(object sender, RoutedEventArgs e) => await ReloadAsync();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void CopyPolicy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(PolicySummaryText.Text + Environment.NewLine +
                              PolicyDetailsText.Text);
            StatusText.Text = "Policy source copied.";
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            StatusText.Text = "Clipboard is temporarily unavailable.";
        }
    }

    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (saving || blocked || loadedValue is null || !SystemInfo.IsAdministrator()) return;
        int requested;
        try
        {
            string value = spec.HasChoices
                ? (ValueChoices.SelectedItem as RdpLocalSettingChoice)?.Value.ToString() ?? ""
                : NumericValue.Text.Trim();
            requested = RdpLocalAdvancedSettings.ParseValue(spec, value);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or
                                   ArgumentException or FormatException)
        {
            StatusText.Text = "Invalid value. Select one of the supported options.";
            return;
        }
        if (requested == loadedValue.Value)
        {
            StatusText.Text = "Already configured. Nothing changed.";
            return;
        }
        if (spec.ConsoleOnly && InteractiveSessionDetector.Detect() != SessionKind.Console)
        {
            StatusText.Text = "Changing this value requires direct console access.";
            return;
        }

        if (!ModernConfirmDialog.Ask(this,
                "Apply this local RDP setting?",
                "The change is limited to one approved local registry value. " +
                "Group Policy is checked again before any write.",
                RdpPolicySourceResolver.TerminalPolicyPath + "\\" + spec.RegistryValue,
                $"Setting: {spec.Setting}\nCurrent: {loadedValue}\nRequested: {requested}\n\n" +
                spec.Guidance,
                "Apply change",
                "Back up your access route. No gpupdate, remote session disconnect, " +
                "TermService restart or Windows reboot will be triggered automatically.",
                diagnosticReport: false))
            return;

        saving = true;
        ApplyButton.IsEnabled = false;
        try
        {
            await Task.Run(() => RdpLocalAdvancedSettings.SaveLocal(
                spec, loadedValue.Value, requested));
            StatusText.Text = "Local value saved and verified. Check GPO and new RDP sessions.";
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(11, 135, 76));
            await ReloadAsync();
        }
        catch (Exception ex)
        {
            DiagnosticsBridge.Remember("RdpSettings", ex);
            PolicySummaryText.Text = "Change blocked or failed. The actual policy source is shown below.";
            if (ex.Message.Contains("Winning GPO:", StringComparison.Ordinal))
                PolicyDetailsText.Text = ex.Message;
            StatusText.Text = "No verified change: " + ex.GetType().Name +
                ". Reload to check the current value.";
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(185, 28, 28));
        }
        finally { saving = false; }
    }
}
