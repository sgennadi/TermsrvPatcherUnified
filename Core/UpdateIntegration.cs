using UniversalUpdater;

namespace TermsrvPatcherUnified.Core;

// The updater core is vendored unchanged from sgennadi/UniversalUpdater (RC3).
// No build-time checkout, GitHub credential or external updater executable is necessary.
internal sealed class UpdateIntegration : IDisposable
{
    public const string Repository = "sgennadi/TermsrvPatcherUnified";
    public const string Version = "0.1.0-preview.19";
    private readonly Dictionary<UpdateChannel, UpdateNotificationController> controllers = new();

    public UpdateIntegration()
    {
        controllers[UpdateChannel.Stable] = new UpdateNotificationController(Options(UpdateChannel.Stable));
        controllers[UpdateChannel.Prerelease] = new UpdateNotificationController(Options(UpdateChannel.Prerelease));
    }

    public UpdateNotificationController Get(UpdateChannel channel) => controllers[channel];

    internal static UpdateOptions Options(UpdateChannel channel) => new()
    {
        ProductId = "TermsrvPatcherUnified",
        Repository = Repository,
        InstalledVersion = Version,
        Architecture = "win-x64",
        Channel = channel,
        StateDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "TermsrvPatcherUnified", "Updates", channel.ToString()),
        Assets = [new UpdateAssetRule("win-x64", "TermsrvPatcherUnified-update-win-x64.zip",
            PackageKind.SingleExeZip, "TermsrvPatcherUnified.exe")]
    };

    public void Dispose()
    {
        foreach (var controller in controllers.Values) controller.Dispose();
    }
}
