using System.Text.Json;
using System.Text.Json.Serialization;

namespace UniversalUpdater;

public sealed class UpdateRuntimeState
{
    public DateTimeOffset? LastAttemptUtc { get; set; }
    public DateTimeOffset? LastSuccessfulCheckUtc { get; set; }
    public string LastSeenVersion { get; set; } = string.Empty;
    // Bind cached notifications and check throttling to the exact target.
    public string LastCheckedRepository { get; set; } = string.Empty;
    public string LastCheckedArchitecture { get; set; } = string.Empty;
    public UpdateChannel LastCheckedChannel { get; set; } = UpdateChannel.Stable;
    public string LastCheckedInstalledVersion { get; set; } = string.Empty;
    public UpdatePhase Phase { get; set; } = UpdatePhase.Idle;
    public string? LastResultCode { get; set; }
    public bool FailureHold { get; set; }
    public DateTimeOffset? LastInstalledUtc { get; set; }
}

/// <summary>Local non-sensitive state; no raw URLs, paths, user identifiers, secrets or logs.</summary>
public sealed class UpdateStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    private readonly string statePath;
    private readonly string directory;
    public UpdateStateStore(UpdateOptions options)
    {
        options.Validate();
        directory = GetStateRoot(options);
        statePath = Path.Combine(directory, "state.json");
    }

    public UpdateRuntimeState Read()
    {
        if (!File.Exists(statePath)) return new UpdateRuntimeState();
        try
        {
            var json = File.ReadAllText(statePath);
            return JsonSerializer.Deserialize<UpdateRuntimeState>(json, JsonOptions) ?? HeldOnCorruption();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return HeldOnCorruption(); // Fail closed: damaged state cannot enable automatic installation.
        }
    }

    private static UpdateRuntimeState HeldOnCorruption() =>
        new() { FailureHold = true, Phase = UpdatePhase.Held, LastResultCode = "STATE_INVALID" };

    public void Write(UpdateRuntimeState state)
    {
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(state, JsonOptions));
            File.Move(temporary, statePath, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public void Hold(string errorCategory)
    {
        var s = Read();
        s.FailureHold = true;
        s.Phase = UpdatePhase.Held;
        s.LastResultCode = errorCategory;
        Write(s);
    }

    /// <summary>Only call after an administrator has inspected the failed update.</summary>
    public void ClearHoldWithAdministratorApproval(bool approved)
    {
        if (!approved) throw new UnauthorizedAccessException("Administrator approval is required.");
        var state = Read();
        state.FailureHold = false;
        state.Phase = UpdatePhase.Idle;
        state.LastResultCode = "HOLD_CLEARED_BY_ADMIN";
        Write(state);
    }

    internal static string GetStateRoot(UpdateOptions options) =>
        Path.Combine(options.StateDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UniversalUpdater"), options.ProductId);
    internal static string GetStagingRoot(UpdateOptions options) =>
        Path.Combine(GetStateRoot(options), "staging");
}
