using UniversalUpdater;
using System.Reflection;

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
    // AssemblyVersion has only numeric components. Preserve the release channel
    // and prerelease sequence from the SDK-generated informational version for
    // updater ordering and the installed EXE health probe.
    public static readonly string InstalledReleaseVersion = GetInstalledReleaseVersion();

    private static string GetAssemblyVersion()
    {
        var version = typeof(UpdateIntegration).Assembly.GetName().Version
            ?? throw new InvalidOperationException("Application assembly version is missing.");
        if (version.Major < 0 || version.Minor < 0 || version.Build < 0)
            throw new InvalidOperationException("Application assembly version is incomplete.");
        return $"{version.Major}.{version.Minor}.{version.Build}";
    }

    private static string GetInstalledReleaseVersion()
    {
        var informational = typeof(UpdateIntegration).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrWhiteSpace(informational))
            throw new InvalidOperationException("Application release identity is missing.");
        // SDK builds may append +SourceRevisionId; build metadata does not
        // affect SemVer ordering and is not part of GitHub's release tag.
        var releaseText = informational.Split('+', 2)[0];
        if (!SemanticVersion.TryParse(releaseText, out var release))
            throw new InvalidOperationException("Application release identity is invalid.");
        var numeric = $"{release.Major}.{release.Minor}.{release.Patch}";
        if (!string.Equals(numeric, Version, StringComparison.Ordinal))
            throw new InvalidOperationException("Release identity and executable assembly version disagree.");
        return release.ToString();
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
        InstalledVersion = InstalledReleaseVersion,
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
