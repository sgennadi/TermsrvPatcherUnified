using System.Net;
using System.Text.Json;

namespace UniversalUpdater;

public enum UpdateCheckDisposition { UpdateAvailable, NoNewerRelease, SkippedBySchedule }

/// <summary>Represents a completed check, not an install authorization.</summary>
public sealed record UpdateCheckResult(UpdateCheckDisposition Disposition,
    UpdateRelease? Release, DateTimeOffset? CheckedAtUtc);

/// <summary>
/// Combines the GPOSettingsExplorer check intervals with BitKeyBridge's safe,
/// local-only status lifecycle. A network failure never becomes "up to date".
/// No installation, authorization or telemetry is performed.
/// </summary>
public sealed class UpdateCheckCoordinator : IDisposable
{
    private readonly GitHubReleaseClient releases;
    private readonly bool ownClient;

    public UpdateCheckCoordinator(GitHubReleaseClient? client = null)
    {
        releases = client ?? new GitHubReleaseClient();
        ownClient = client is null;
    }

    public async Task<UpdateCheckResult> CheckAsync(UpdateOptions options,
        bool forced = false, CancellationToken cancellationToken = default,
        string? sessionToken = null)
    {
        options.Validate();
        var store = new UpdateStateStore(options);
        var state = store.Read();
        var now = DateTimeOffset.UtcNow;
        // A cached result or cooldown from a different source/version is never reusable.
        var sameTarget = state.LastCheckedRepository == options.Repository &&
            state.LastCheckedArchitecture == options.Architecture &&
            state.LastCheckedChannel == options.Channel &&
            state.LastCheckedInstalledVersion == options.InstalledVersion;
        if (!forced && sameTarget && !UpdatePolicy.ShouldCheck(now,
                state.LastSuccessfulCheckUtc, state.LastAttemptUtc))
            return new UpdateCheckResult(UpdateCheckDisposition.SkippedBySchedule, null, null);

        cancellationToken.ThrowIfCancellationRequested();
        state.LastAttemptUtc = now;
        state.Phase = state.FailureHold ? UpdatePhase.Held : UpdatePhase.Checking;
        state.LastResultCode = "CHECK_STARTED";
        store.Write(state);
        try
        {
            var release = await releases.CheckAsync(options, cancellationToken, sessionToken);
            var updated = store.Read();
            updated.LastAttemptUtc = now;
            updated.LastSuccessfulCheckUtc = DateTimeOffset.UtcNow;
            updated.LastResultCode = release is null ? "NO_NEWER_RELEASE" : "UPDATE_AVAILABLE";
            updated.LastSeenVersion = release?.Version.ToString() ?? string.Empty;
            updated.LastCheckedRepository = options.Repository;
            updated.LastCheckedArchitecture = options.Architecture;
            updated.LastCheckedChannel = options.Channel;
            updated.LastCheckedInstalledVersion = options.InstalledVersion;
            updated.Phase = updated.FailureHold ? UpdatePhase.Held :
                release is null ? UpdatePhase.Idle : UpdatePhase.Available;
            store.Write(updated);
            return new UpdateCheckResult(release is null ? UpdateCheckDisposition.NoNewerRelease :
                UpdateCheckDisposition.UpdateAvailable, release, updated.LastSuccessfulCheckUtc);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or
                                   InvalidOperationException or JsonException or ArgumentException or
                                   OperationCanceledException)
        {
            var updated = store.Read();
            updated.LastAttemptUtc = now;
            updated.LastResultCode = FailureCode(ex);
            updated.Phase = updated.FailureHold ? UpdatePhase.Held : UpdatePhase.Failed;
            store.Write(updated);
            throw;
        }
    }

    internal static string FailureCode(Exception ex) => ex switch
    {
        OperationCanceledException => "CHECK_CANCELLED",
        HttpRequestException { StatusCode: HttpStatusCode.Unauthorized } => "ACCESS_DENIED",
        HttpRequestException { StatusCode: HttpStatusCode.Forbidden } => "ACCESS_DENIED_OR_RATE_LIMIT",
        HttpRequestException { StatusCode: HttpStatusCode.TooManyRequests } => "RATE_LIMITED",
        HttpRequestException => "NETWORK_FAILURE",
        InvalidOperationException ioe when ioe.Message.Contains("HTTP 404", StringComparison.Ordinal) =>
            "RELEASES_NOT_ACCESSIBLE",
        JsonException or InvalidDataException => "INVALID_RELEASE_METADATA",
        ArgumentException => "INVALID_CONFIGURATION",
        _ => "CHECK_FAILED"
    };

    public void Dispose() { if (ownClient) releases.Dispose(); }
}
