using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace UniversalUpdater;

/// <summary>
/// Restricts a temporary read-only GitHub token to the configured repository's API endpoints.
/// No token persistence and no authorization header on GitHub download/CDN redirects.
/// Never embed an administrator's write-capable GitHub token in a released application.
/// </summary>
public static class GitHubCredentialScope
{
    private static readonly Regex SessionSyntax = new(
        @"\A[A-Za-z0-9_-]{12,512}\z", RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    public static string? ValidateSessionToken(string? token)
    {
        if (token is null or "") return null;
        // Do not trim a secret and silently change what the operator supplied.
        if (!SessionSyntax.IsMatch(token))
            throw new ArgumentException("Invalid temporary GitHub token syntax.");
        return token;
    }

    public static Uri MetadataApiUri(string repository)
    {
        ValidateRepository(repository);
        return new Uri($"https://api.github.com/repos/{repository}/releases?per_page=100");
    }

    public static Uri AssetApiUri(string repository, long assetId)
    {
        ValidateRepository(repository);
        if (assetId < 1) throw new InvalidDataException("Invalid GitHub release asset ID.");
        return new Uri($"https://api.github.com/repos/{repository}/releases/assets/{assetId}");
    }

    public static bool IsMetadataEndpoint(Uri uri, string repository) =>
        IsPinnedApiHost(uri) && uri.AbsolutePath == $"/repos/{repository}/releases" &&
        uri.Query == "?per_page=100";

    public static bool IsAssetEndpoint(Uri uri, string repository, long assetId) =>
        IsPinnedApiHost(uri) && assetId > 0 &&
        uri.AbsolutePath == $"/repos/{repository}/releases/assets/{assetId}" &&
        uri.Query.Length == 0;

    internal static void AttachIfAllowed(HttpRequestMessage request, string? token, bool allowed)
    {
        if (token is null) return;
        if (!allowed)
            throw new InvalidDataException("Refusing to forward a GitHub token outside its pinned endpoint.");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    private static bool IsPinnedApiHost(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttps && uri.Host == "api.github.com" &&
        uri.IsDefaultPort && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0;

    private static void ValidateRepository(string repository)
    {
        if (string.IsNullOrWhiteSpace(repository) || !Regex.IsMatch(repository,
                @"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z", RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(250)))
            throw new InvalidDataException("Invalid configured GitHub repository.");
    }
}
