using UniversalUpdater;

namespace TermsrvPatcherUnified.Core;

// The updater core is vendored unchanged from sgennadi/UniversalUpdater (RC3).
// No build-time checkout, GitHub credential or external updater executable is necessary.
internal sealed class UpdateIntegration : IDisposable
{
    public const string Repository = "sgennadi/TermsrvPatcherUnified";
    // Read the actual compiled assembly version. A disposable 1.0.6 fixture must
    // identify itself as 1.0.6 even when built from current 1.0.7 sources.
    // This also prevents updater/UI version drift after future releases.
    public static readonly string Version = GetAssemblyVersion();

    private static string GetAssemblyVersion()
    {
        var version = typeof(UpdateIntegration).Assembly.GetName().Version
            ?? throw new InvalidOperationException("Application assembly version is missing.");
        if (version.Major < 0 || version.Minor < 0 || version.Build < 0)
            throw new InvalidOperationException("Application assembly version is incomplete.");
        return $"{version.Major}.{version.Minor}.{version.Build}";
    }
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
