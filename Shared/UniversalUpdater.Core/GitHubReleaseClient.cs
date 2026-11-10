using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace UniversalUpdater;

/// <summary>Read-only GitHub Releases metadata client. Never accepts arbitrary repositories from a release.</summary>
public sealed class GitHubReleaseClient : IDisposable
{
    private readonly HttpClient client;
    private readonly bool ownClient;
    private const int MaxResponseBytes = 4 * 1024 * 1024;

    public GitHubReleaseClient(HttpClient? httpClient = null)
    {
        client = httpClient ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        ownClient = httpClient is null;
    }

    /// <summary>
    /// Check the configured GitHub Releases list. A 404 is an inaccessible source, NOT
    /// evidence that the installed version is current. Prereleases are ranked by SemVer.
    /// For private sources provide a temporary Contents:Read token in memory only.
    /// </summary>
    public async Task<UpdateRelease?> CheckAsync(UpdateOptions options,
        CancellationToken cancellationToken = default, string? sessionToken = null)
    {
        options.Validate();
        sessionToken = GitHubCredentialScope.ValidateSessionToken(sessionToken);
        var current = SemanticVersion.Parse(options.InstalledVersion);
        var url = GitHubCredentialScope.MetadataApiUri(options.Repository);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        GitHubCredentialScope.AttachIfAllowed(request, sessionToken,
            GitHubCredentialScope.IsMetadataEndpoint(url, options.Repository));
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("UniversalUpdater", "0.1"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new InvalidOperationException("GitHub Releases not accessible (HTTP 404). " +
                "Check repository visibility or read-only token permissions; status is unknown.");
        // A caller-injected HttpClient must also disable automatic redirects.
        // This check is defense in depth; the owned HttpClient always disables them.
        if (response.RequestMessage?.RequestUri != url)
            throw new InvalidDataException("Unexpected GitHub API origin or redirect.");
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
            throw new InvalidDataException("GitHub release metadata exceeds the size limit.");
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var limited = new MemoryStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = await stream.ReadAsync(buf, cancellationToken)) != 0)
        {
            if (limited.Length + n > MaxResponseBytes)
                throw new InvalidDataException("GitHub release metadata exceeds the size limit.");
            limited.Write(buf, 0, n);
        }
        limited.Position = 0;
        using var doc = await JsonDocument.ParseAsync(limited,
            new JsonDocumentOptions { MaxDepth = 32 }, cancellationToken);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Unexpected GitHub release list metadata.");
        UpdateRelease? best = null;
        foreach (var candidate in doc.RootElement.EnumerateArray())
        {
            var parsed = ParseRelease(candidate, options);
            if (parsed is not null && parsed.Version > current &&
                (best is null || parsed.Version > best.Version)) best = parsed;
        }
        return best;
    }

    private static UpdateRelease? ParseRelease(JsonElement item, UpdateOptions options)
    {
        if (item.ValueKind != JsonValueKind.Object || ReadBool(item, "draft")) return null;
        var tag = ReadString(item, "tag_name");
        if (!SemanticVersion.TryParse(tag, out var version)) return null;
        // GitHub's releases array mixes Stable and Preview entries. Both the
        // release's declared kind AND SemVer must match the selected channel.
        // Otherwise a newer Stable build could be incorrectly offered as Preview.
        if (!MatchesChannel(options.Channel, ReadBool(item, "prerelease"), version))
            return null;
        var releaseUrl = ReadString(item, "html_url");
        if (!IsExactGitHubUrl(releaseUrl, $"/{options.Repository}/releases/tag/{tag}"))
            throw new InvalidDataException("Release page does not match the configured repository/tag.");
        if (!item.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
            return null;
        UpdateAssetRule? chosenRule = null;
        JsonElement chosenAsset = default;
        var candidates = options.Assets.Where(x => x.Architecture == options.Architecture).ToArray();
        foreach (var asset in assets.EnumerateArray())
        {
            string name = ReadString(asset, "name");
            foreach (var rule in candidates)
            {
                if (!string.Equals(name, rule.AssetName, StringComparison.Ordinal)) continue;
                if (chosenRule is not null) throw new InvalidDataException("Ambiguous release assets.");
                chosenRule = rule;
                chosenAsset = asset;
            }
        }
        if (chosenRule is null) return null;
        string download = ReadString(chosenAsset, "browser_download_url");
        if (!IsExactGitHubUrl(download, $"/{options.Repository}/releases/download/{tag}/{chosenRule.AssetName}"))
            throw new InvalidDataException("Release asset URL is not the configured GitHub download.");
        if (!chosenAsset.TryGetProperty("size", out var sizeJson) || !sizeJson.TryGetInt64(out long size) ||
            size < 1 || size > options.MaxArchiveBytes)
            throw new InvalidDataException("Release asset has invalid size.");
        var rawDigest = ReadString(chosenAsset, "digest");
        if (!rawDigest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ||
            !IsSha256(rawDigest[7..]))
            throw new InvalidDataException("GitHub release asset has no valid SHA-256 digest.");
        DateTimeOffset? published = null;
        if (item.TryGetProperty("published_at", out var p) && p.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(p.GetString(), out var time)) published = time;
        var notes = ReadString(item, "body");
        if (notes.Length > 32_000) notes = notes[..32_000];
        long? assetId = null;
        if (chosenAsset.TryGetProperty("id", out var idJson) &&
            idJson.TryGetInt64(out var parsedId) && parsedId > 0)
            assetId = parsedId;
        return new UpdateRelease(options.Repository, version, tag, releaseUrl, notes, published,
            chosenRule, new Uri(download), size, rawDigest[7..].ToLowerInvariant(), assetId);
    }

    public static bool MatchesChannel(UpdateChannel channel, bool markedPrerelease,
        SemanticVersion version) => channel switch
    {
        UpdateChannel.Stable => !markedPrerelease && !version.IsPrerelease,
        UpdateChannel.Prerelease => markedPrerelease && version.IsPrerelease,
        _ => false
    };

    private static bool IsExactGitHubUrl(string text, string expectedPath)
    {
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)) return false;
        return uri.Scheme == Uri.UriSchemeHttps && uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) &&
               uri.IsDefaultPort && uri.UserInfo.Length == 0 && uri.Query.Length == 0 &&
               uri.Fragment.Length == 0 &&
               string.Equals(Uri.UnescapeDataString(uri.AbsolutePath), expectedPath, StringComparison.Ordinal);
    }
    private static bool IsSha256(string s) => s.Length == 64 && s.All(Uri.IsHexDigit);
    private static string ReadString(JsonElement value, string key) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var property) &&
        property.ValueKind == JsonValueKind.String ? property.GetString() ?? string.Empty : string.Empty;
    private static bool ReadBool(JsonElement value, string key) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var property) &&
        property.ValueKind == JsonValueKind.True;
    public void Dispose() { if (ownClient) client.Dispose(); }
}
