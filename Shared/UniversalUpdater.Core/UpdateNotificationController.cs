using System.Net;
using System.Text.Json;

namespace UniversalUpdater;

/// <summary>Pure presentation status. An indicator is never an install authorization.</summary>
public enum UpdateNoticeStatus { NotChecked, Checking, Available, UpToDate, CheckFailed, InstallationHeld }

public sealed record UpdateNotice(
    UpdateNoticeStatus Status,
    string InstalledVersion,
    string? AvailableVersion,
    bool IsCached,
    string ResultCode,
    DateTimeOffset? CheckedAtUtc)
{
    public bool ShowUpdateBadge => Status == UpdateNoticeStatus.Available &&
        !string.IsNullOrEmpty(AvailableVersion);
}

/// <summary>
/// Standalone, UI-independent update notification source. Uses the existing
/// coordinator, never downloads or installs anything. A cached notice must
/// match the exact pinned repository, architecture and channel and is labelled
/// as cached; an installation needs a separate live release and host approval.
/// </summary>
public sealed class UpdateNotificationController : IDisposable
{
    private readonly UpdateOptions options;
    private readonly UpdateCheckCoordinator coordinator;
    private readonly bool ownsCoordinator;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly CancellationTokenSource lifetime = new();
    private UpdateNotice notice;
    private UpdateRelease? liveRelease;
    private bool disposed;

    public UpdateNotificationController(UpdateOptions options,
        UpdateCheckCoordinator? coordinator = null)
    {
        options.Validate();
        this.options = options;
        this.coordinator = coordinator ?? new UpdateCheckCoordinator();
        ownsCoordinator = coordinator is null;
        notice = ReadCache(options);
    }

    public UpdateOptions Options => options;
    public UpdateNotice Notice => notice;

    /// <summary>Only a release checked successfully in this process may be installed.</summary>
    public UpdateRelease? LiveRelease => liveRelease;

    public event EventHandler<UpdateNotice>? NoticeChanged;

    public async Task<UpdateNotice> CheckAsync(bool forced = false,
        CancellationToken cancellationToken = default, string? sessionToken = null)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token);
        if (!await gate.WaitAsync(0, linked.Token)) return notice;
        try
        {
            Set(new UpdateNotice(UpdateNoticeStatus.Checking, options.InstalledVersion,
                null, false, "CHECK_STARTED", null));
            UpdateCheckResult result = await coordinator.CheckAsync(options, forced,
                linked.Token, sessionToken);
            if (result.Disposition == UpdateCheckDisposition.SkippedBySchedule)
            {
                liveRelease = null;
                Set(ReadCache(options));
            }
            else if (result.Release is { } release &&
                     result.Disposition == UpdateCheckDisposition.UpdateAvailable)
            {
                liveRelease = release;
                Set(new UpdateNotice(UpdateNoticeStatus.Available, options.InstalledVersion,
                    release.Version.ToString(), false, "UPDATE_AVAILABLE", result.CheckedAtUtc));
            }
            else
            {
                liveRelease = null;
                Set(new UpdateNotice(UpdateNoticeStatus.UpToDate, options.InstalledVersion,
                    null, false, "NO_NEWER_RELEASE", result.CheckedAtUtc));
            }
            return notice;
        }
        catch (Exception)
        {
            liveRelease = null;
            // The persisted coordinator result is a fixed diagnostic category.
            var state = new UpdateStateStore(options).Read();
            Set(new UpdateNotice(state.FailureHold ? UpdateNoticeStatus.InstallationHeld :
                UpdateNoticeStatus.CheckFailed, options.InstalledVersion,
                null, false, state.LastResultCode ?? "CHECK_FAILED", null));
            throw;
        }
        finally { gate.Release(); }
    }

    /// <summary>Refresh the visual cache only. Does not query the network.</summary>
    public void RefreshCachedNotice()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        liveRelease = null;
        Set(ReadCache(options));
    }

    private static UpdateNotice ReadCache(UpdateOptions options)
    {
        var state = new UpdateStateStore(options).Read();
        UpdateNotice Make(UpdateNoticeStatus status, string? version = null) =>
            new(status, options.InstalledVersion, version, true,
                state.LastResultCode ?? "NOT_CHECKED", state.LastSuccessfulCheckUtc);

        if (state.FailureHold) return Make(UpdateNoticeStatus.InstallationHeld);
        if (state.Phase == UpdatePhase.Failed) return Make(UpdateNoticeStatus.CheckFailed);

        // Older state files have no source binding: do not show a potentially
        // misleading update badge after repository, channel or RID changes.
        bool matchingSource =
            string.Equals(state.LastCheckedRepository, options.Repository, StringComparison.Ordinal) &&
            string.Equals(state.LastCheckedArchitecture, options.Architecture, StringComparison.Ordinal) &&
            state.LastCheckedChannel == options.Channel &&
            string.Equals(state.LastCheckedInstalledVersion, options.InstalledVersion, StringComparison.Ordinal);
        if (!matchingSource) return Make(UpdateNoticeStatus.NotChecked);

        if (state.LastResultCode == "UPDATE_AVAILABLE" &&
            SemanticVersion.TryParse(state.LastSeenVersion, out var remote) &&
            remote > SemanticVersion.Parse(options.InstalledVersion))
            return Make(UpdateNoticeStatus.Available, remote.ToString());
        if (state.LastResultCode == "NO_NEWER_RELEASE")
            return Make(UpdateNoticeStatus.UpToDate);
        return Make(UpdateNoticeStatus.NotChecked);
    }

    private void Set(UpdateNotice value)
    {
        notice = value;
        NoticeChanged?.Invoke(this, value);
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        lifetime.Cancel();
        if (ownsCoordinator) coordinator.Dispose();
        lifetime.Dispose();
        // A concurrent in-flight check may still be unwinding its finally block.
        // SemaphoreSlim does not allocate an OS handle unless AvailableWaitHandle
        // is accessed, so intentionally keep it alive instead of disposing it
        // from another thread during Release().
    }
}
