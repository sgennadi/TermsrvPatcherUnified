using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace UniversalUpdater;

public enum UpdateChannel { Stable, Prerelease }
public enum PackageKind { SingleExeZip, PluginZip, GenericZip, Apk, DirectExe }
public enum UpdatePhase { Idle, Checking, Available, Downloading, Verified, AwaitingInstall, Installing, Healthy, RolledBack, Failed, Held }

public sealed record UpdateAssetRule(
    string Architecture,
    string AssetName,
    PackageKind Kind,
    string? SingleExecutableName = null,
    IReadOnlyList<string>? AllowedZipEntries = null);

public sealed class UpdateOptions
{
    public required string ProductId { get; init; }
    public required string Repository { get; init; }
    public required string InstalledVersion { get; init; }
    public required string Architecture { get; init; }
    public required IReadOnlyList<UpdateAssetRule> Assets { get; init; }
    public UpdateChannel Channel { get; init; } = UpdateChannel.Stable;
    public long MaxArchiveBytes { get; init; } = 512L * 1024 * 1024;
    public long MaxExpandedBytes { get; init; } = 768L * 1024 * 1024;
    public string? StateDirectory { get; init; }

    public static string CurrentWindowsArchitecture() => RuntimeInformation.ProcessArchitecture switch
    {
        System.Runtime.InteropServices.Architecture.X86 => "win-x86",
        System.Runtime.InteropServices.Architecture.X64 => "win-x64",
        System.Runtime.InteropServices.Architecture.Arm64 => "win-arm64",
        _ => throw new PlatformNotSupportedException("Unsupported Windows architecture.")
    };

    public void Validate()
    {
        if (!Regex.IsMatch(ProductId, @"^[A-Za-z][A-Za-z0-9._-]{1,63}$", RegexOptions.CultureInvariant))
            throw new ArgumentException("Invalid product ID.");
        if (!Regex.IsMatch(Repository, @"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant))
            throw new ArgumentException("Repository must be an explicit owner/repository pair.");
        _ = SemanticVersion.Parse(InstalledVersion);
        if (!Regex.IsMatch(Architecture, @"^[a-z0-9-]{3,24}$", RegexOptions.CultureInvariant))
            throw new ArgumentException("Invalid architecture.");
        if (MaxArchiveBytes is < 1 or > 2_147_483_648L || MaxExpandedBytes is < 1 or > 4_294_967_296L)
            throw new ArgumentException("Invalid release limits.");
        if (Assets is null || Assets.Count is < 1 or > 16)
            throw new ArgumentException("Define one or more exact release asset rules.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in Assets)
        {
            if (string.IsNullOrWhiteSpace(rule.Architecture) ||
                !IsSafeFileName(rule.AssetName) ||
                !names.Add(rule.Architecture + "/" + rule.AssetName))
                throw new ArgumentException("Invalid or duplicate release asset rule.");
            if (rule.Kind is PackageKind.SingleExeZip or PackageKind.PluginZip or PackageKind.GenericZip &&
                !rule.AssetName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("ZIP release rules must name a .zip asset.");
            if (rule.Kind == PackageKind.DirectExe &&
                (!rule.AssetName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                 (rule.SingleExecutableName is not null && rule.SingleExecutableName != rule.AssetName)))
                throw new ArgumentException("Direct EXE must be an exact .exe asset, without renaming.");
            if (rule.Kind == PackageKind.SingleExeZip &&
                (rule.SingleExecutableName is null || !IsSafeFileName(rule.SingleExecutableName) ||
                 !rule.SingleExecutableName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException("Single EXE ZIP requires an exact executable filename.");
            if (rule.Kind == PackageKind.PluginZip || rule.Kind == PackageKind.GenericZip)
            {
                if (rule.AllowedZipEntries is null || rule.AllowedZipEntries.Count == 0 ||
                    rule.AllowedZipEntries.Count > 2048 ||
                    rule.AllowedZipEntries.Any(x => !ZipSafety.IsSafeRelativeEntry(x) || x.EndsWith('/')) ||
                    rule.AllowedZipEntries.Distinct(StringComparer.OrdinalIgnoreCase).Count() != rule.AllowedZipEntries.Count)
                    throw new ArgumentException("Multi-file ZIP requires an explicit safe entry allowlist.");
            }
            if (rule.Kind == PackageKind.Apk && !rule.AssetName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("APK rule must name an APK file.");
        }
        if (!Assets.Any(x => x.Architecture == Architecture))
            throw new ArgumentException("No asset rule for the current architecture.");
    }

    internal static bool IsSafeFileName(string name) =>
        name.Length is > 0 and <= 128 && !name.Contains('/') &&
        ZipSafety.IsSafeRelativeEntry(name);
}

public sealed record UpdateRelease(
    string Repository, SemanticVersion Version, string Tag, string ReleaseUrl,
    string ReleaseNotes, DateTimeOffset? PublishedAt, UpdateAssetRule Rule,
    Uri AssetUrl, long SizeBytes, string Sha256, long? AssetId = null);

public sealed record StagedPackage(UpdateRelease Release, string ArchivePath, string ArchiveSha256,
    string? ExtractedExecutablePath = null, string? ExtractedExecutableSha256 = null);

public sealed record UpdateProgress(UpdatePhase Phase, long ReceivedBytes, long? TotalBytes);

public sealed record UpdateInstallResult(bool Success, bool RolledBack, string Summary);

public interface IUpdateInstaller
{
    // The host owns UI, elevation, signatures, file replacement and final self-test.
    Task<UpdateInstallResult> InstallAsync(StagedPackage package, CancellationToken cancellationToken);
}

public interface IUpdaterDiagnosticSink
{
    // Only sanitized structured categories. Never include tokens, paths or raw exception text.
    void Record(string productId, string category, string code);
}
