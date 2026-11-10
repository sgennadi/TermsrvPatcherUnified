using System.Windows;
using System.Windows.Threading;
using UniversalUpdater;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Per-window 4-hour Stable release discovery. Installing an UNSIGNED EXE is
/// never unattended, even after the machine-wide automatic-check opt-in.
/// Uses exactly the same updater confirmation and rollback path as manual UI.
/// </summary>
internal sealed class AutoUpdateGuiCoordinator : IDisposable
{
    private readonly Window owner;
    private readonly UpdateIntegration updates;
    private readonly Func<bool> safeToPrompt;
    private readonly DispatcherTimer timer;
    private bool checking;
    private bool disposed;
    private string? offeredVersion;

    internal AutoUpdateGuiCoordinator(Window owner, UpdateIntegration updates,
        Func<bool> safeToPrompt)
    {
        this.owner = owner;
        this.updates = updates;
        this.safeToPrompt = safeToPrompt;
        timer = new DispatcherTimer(DispatcherPriority.Background, owner.Dispatcher)
        {
            Interval = AutoUpdatePreferences.GuiInterval
        };
        timer.Tick += async (_, _) => await CheckNowAsync();
    }

    internal void Start() => timer.Start();

    internal async Task CheckNowAsync()
    {
        if (disposed || checking || !AutoUpdatePreferences.IsEnabled()) return;
        checking = true;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var controller = updates.Get(UpdateChannel.Stable);
            await controller.CheckAsync(forced: true, cancellationToken: timeout.Token);
            if (disposed || !owner.IsVisible) return;
            var live = controller.LiveRelease;
            if (!AutoUpdatePreferences.ShouldOffer(controller.Notice, live,
                    offeredVersion, AutoUpdatePreferences.IsEnabled(), !safeToPrompt()))
                return;
            if (!UpdateInstallBridge.CanInstall(out _))
                return; // Interactive updater will show the reason on manual open.
            offeredVersion = live!.Version.ToString();
            // This dialog NEVER installs by itself. The existing updater
            // asks per-release consent before any download or EXE replacement.
            new UpdateCenterWindow(updates, offerStableAutomatically: true)
            {
                Owner = owner
            }.ShowDialog();
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or
                                   InvalidOperationException or OperationCanceledException or
                                   UnauthorizedAccessException or ArgumentException or
                                   System.Security.SecurityException)
        {
            DiagnosticsBridge.Remember("Updates", ex);
        }
        finally { checking = false; }
    }

    public void Dispose()
    {
        disposed = true;
        timer.Stop();
    }
}
