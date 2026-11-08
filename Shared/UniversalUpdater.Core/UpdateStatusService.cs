namespace UniversalUpdater;

/// <summary>
/// Explicitly cached read-only status; not evidence of current online release availability.
/// Only fixed result codes and product version are returned; no secrets or local paths.
/// </summary>
public sealed record UpdateStatusSnapshot(
    string ProductId, string InstalledVersion, UpdateChannel Channel,
    UpdatePhase Phase, bool IsLive, bool FailureHold, string? LastResultCode,
    DateTimeOffset? LastAttemptUtc, DateTimeOffset? LastSuccessfulCheckUtc,
    string LastSeenNewerVersion, DateTimeOffset? LastInstalledUtc,
    UpdateHistoryRecord? LastOperation, UpdateHistoryRecord? LastSuccessfulInstall,
    UpdateHistoryRecord? LastFailedOperation);

public static class UpdateStatusService
{
    public static UpdateStatusSnapshot Capture(UpdateOptions options)
    {
        options.Validate();
        var state = new UpdateStateStore(options).Read();
        var history = new UpdateHistoryStore(options).Read().ToList();
        history.Reverse();
        return new UpdateStatusSnapshot(
            options.ProductId, options.InstalledVersion, options.Channel,
            state.Phase, false, state.FailureHold, state.LastResultCode,
            state.LastAttemptUtc, state.LastSuccessfulCheckUtc,
            state.LastSeenVersion, state.LastInstalledUtc,
            history.FirstOrDefault(x => x.Operation is "INSTALL" or "ROLLBACK"),
            history.FirstOrDefault(x => x.Operation == "INSTALL" && x.ResultCode == "INSTALL_OK"),
            history.FirstOrDefault(x => (x.Operation is "INSTALL" or "ROLLBACK") &&
                x.ResultCode is not ("INSTALL_OK" or "MANUAL_ROLLBACK")));
    }
}
