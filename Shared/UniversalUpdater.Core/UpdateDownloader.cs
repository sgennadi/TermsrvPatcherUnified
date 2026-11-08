using System.Buffers;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace UniversalUpdater;

/// <summary>Download to an isolated staging directory and validate before exposing a package.</summary>
public sealed class UpdateDownloader : IDisposable
{
    private readonly HttpClient client;
    private readonly bool ownClient;

    public UpdateDownloader(HttpClient? httpClient = null)
    {
        client = httpClient ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        ownClient = httpClient is null;
    }

    public async Task<StagedPackage> StageAsync(
        UpdateOptions options, UpdateRelease release,
        IProgress<UpdateProgress>? progress = null, CancellationToken cancellationToken = default,
        string? sessionToken = null)
    {
        options.Validate();
        sessionToken = GitHubCredentialScope.ValidateSessionToken(sessionToken);
        if (sessionToken is not null && release.AssetId is not > 0)
            throw new InvalidDataException("Private GitHub downloads require a verified numeric asset ID.");
        if (!string.Equals(options.Repository, release.Repository, StringComparison.Ordinal) ||
            !string.Equals(release.Rule.Architecture, options.Architecture, StringComparison.Ordinal) ||
            !options.Assets.Any(a => a == release.Rule) ||
            !release.Version.Equals(SemanticVersion.Parse(release.Tag)))
            throw new InvalidDataException("Staged release does not match configured product/architecture.");
        if (release.Version <= SemanticVersion.Parse(options.InstalledVersion))
            throw new InvalidDataException("Automatic downgrade or reinstall is not permitted.");
        if (options.Channel == UpdateChannel.Stable && release.Version.IsPrerelease)
            throw new InvalidDataException("Prerelease is forbidden by stable channel policy.");
        if (release.SizeBytes < 1 || release.SizeBytes > options.MaxArchiveBytes ||
            !IsValidSha(release.Sha256) || !IsOriginalDownload(release.AssetUrl, options.Repository, release.Tag, release.Rule.AssetName))
            throw new InvalidDataException("Invalid release digest, size or origin.");

        var stagingRoot = UpdateStateStore.GetStagingRoot(options);
        var working = Path.Combine(stagingRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(working);
        var archivePath = Path.Combine(working, release.Rule.AssetName);
        try
        {
            progress?.Report(new UpdateProgress(UpdatePhase.Downloading, 0, release.SizeBytes));
            await DownloadFileAsync(release, archivePath, options.MaxArchiveBytes, progress, cancellationToken, sessionToken);
            var actual = await HashFileAsync(archivePath, cancellationToken);
            if (!string.Equals(actual, release.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Release archive failed SHA-256 verification.");

            string? exePath = null;
            string? exeDigest = null;
            if (release.Rule.Kind is PackageKind.SingleExeZip or PackageKind.PluginZip or PackageKind.GenericZip)
            {
                ZipSafety.Validate(archivePath, release.Rule, options.MaxExpandedBytes);
                if (release.Rule.Kind == PackageKind.SingleExeZip)
                {
                    exePath = Path.Combine(working, release.Rule.SingleExecutableName!);
                    using var zip = ZipFile.OpenRead(archivePath);
                    var entry = zip.Entries.Single(x => x.FullName == release.Rule.SingleExecutableName);
                    await using (var source = entry.Open())
                    await using (var destination = new FileStream(exePath, FileMode.CreateNew, FileAccess.Write,
                                     FileShare.None, 81920, FileOptions.Asynchronous))
                    {
                        await source.CopyToAsync(destination, cancellationToken);
                        await destination.FlushAsync(cancellationToken);
                    }
                    if (new FileInfo(exePath).Length != entry.Length)
                        throw new InvalidDataException("Staged executable has incorrect extracted length.");
                    PeSafety.ValidateArchitecture(exePath, options.Architecture);
                    exeDigest = await HashFileAsync(exePath, cancellationToken);
                }
            }
            if (release.Rule.Kind == PackageKind.DirectExe)
            {
                PeSafety.ValidateArchitecture(archivePath, options.Architecture);
                exePath = archivePath;
                exeDigest = actual;
            }
            // APK is only downloaded. Android must verify APK signatures and install it itself.
            progress?.Report(new UpdateProgress(UpdatePhase.Verified, release.SizeBytes, release.SizeBytes));
            return new StagedPackage(release, archivePath, actual, exePath, exeDigest);
        }
        catch
        {
            try { Directory.Delete(working, recursive: true); } catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            throw;
        }
    }

    private async Task DownloadFileAsync(
        UpdateRelease release, string destination, long maximum,
        IProgress<UpdateProgress>? progress, CancellationToken ct, string? sessionToken)
    {
        // Authentication is scoped to the exact GitHub API asset ID.
        // The signed GitHub CDN redirect never receives Authorization.
        Uri next = sessionToken is null ? release.AssetUrl :
            GitHubCredentialScope.AssetApiUri(release.Repository, release.AssetId!.Value);
        bool apiRequest = sessionToken is not null;
        for (int redirectCount = 0; redirectCount <= 5; redirectCount++)
        {
            bool allowed = apiRequest
                ? GitHubCredentialScope.IsAssetEndpoint(next, release.Repository, release.AssetId!.Value)
                : IsAllowedDownloadHost(next);
            if (!allowed)
                throw new InvalidDataException("Untrusted release redirect host or insecure URL.");
            using var request = new HttpRequestMessage(HttpMethod.Get, next);
            GitHubCredentialScope.AttachIfAllowed(request, apiRequest ? sessionToken : null, allowed && apiRequest);
            if (apiRequest)
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("UniversalUpdater", "0.1"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.RequestMessage?.RequestUri is not { } effectiveUrl || effectiveUrl != next)
                throw new InvalidDataException("The HTTP client unexpectedly redirected the download.");
            if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect or
                HttpStatusCode.RedirectMethod or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
            {
                var location = response.Headers.Location ??
                    throw new InvalidDataException("GitHub release redirect did not specify a destination.");
                next = location.IsAbsoluteUri ? location : new Uri(next, location);
                if (!IsAllowedDownloadHost(next))
                    throw new InvalidDataException("Asset redirect destination is not a pinned GitHub CDN.");
                // Never send a bearer token to GitHub download URLs or CDN hosts.
                apiRequest = false;
                continue;
            }
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is { } expected &&
                (expected < 1 || expected > maximum || expected != release.SizeBytes))
                throw new InvalidDataException("Release size differs from verified metadata.");
            await using var input = await response.Content.ReadAsStreamAsync(ct);
            await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
            long received = 0;
            try
            {
                int n;
                while ((n = await input.ReadAsync(buffer.AsMemory(), ct)) > 0)
                {
                    if (n > maximum - received || n > release.SizeBytes - received)
                        throw new InvalidDataException("Release download exceeds its declared size.");
                    await output.WriteAsync(buffer.AsMemory(0, n), ct);
                    received += n;
                    progress?.Report(new UpdateProgress(UpdatePhase.Downloading, received, release.SizeBytes));
                }
                await output.FlushAsync(ct);
            }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
            if (received != release.SizeBytes)
                throw new InvalidDataException("Release download is incomplete.");
            return;
        }
        throw new InvalidDataException("Release download has too many redirects.");
    }

    private static bool IsAllowedDownloadHost(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
        (uri.Host is "github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com");

    private static bool IsOriginalDownload(Uri uri, string repo, string tag, string filename) =>
        IsAllowedDownloadHost(uri) && uri.Host == "github.com" && uri.Query.Length == 0 &&
        uri.Fragment.Length == 0 &&
        Uri.UnescapeDataString(uri.AbsolutePath) == $"/{repo}/releases/download/{tag}/{filename}";

    private static bool IsValidSha(string? digest) =>
        digest is { Length: 64 } && digest.All(Uri.IsHexDigit);

    internal static async Task<string> HashFileAsync(string filePath, CancellationToken ct)
    {
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var bytes = await SHA256.HashDataAsync(stream, ct);
        return Convert.ToHexStringLower(bytes);
    }
    public void Dispose() { if (ownClient) client.Dispose(); }
}
