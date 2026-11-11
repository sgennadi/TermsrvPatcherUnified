using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Machine-wide, explicit consent for future silent, verified Auto Reapply
/// compatibility reports. This is NOT consent for ordinary diagnostics,
/// offline files, failed jobs or a queued one-shot RDP Apply.
/// Consent lives in the existing SYSTEM/Administrators-only Task Scheduler
/// directory, not in an interactive user's profile.
/// </summary>
internal static class AutoCompatibilityReporting
{
    private const string Schema = "termsrv-auto-compatibility-consent/v1";
    private const string FileName = "compatibility-consent.json";
    private static string ConsentPath => Path.Combine(AutoReapplyScheduler.Root, FileName);

    private sealed record Consent(string SchemaId, string ReceiverSha256, bool Enabled);

    internal static string ReceiverFingerprint(string endpoint) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(endpoint)));

    // Pure, fail-closed policy used both by the SYSTEM worker and synthetic QA.
    internal static bool HasConsent(string? json, string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(json) || json.Length > 1024 ||
            !GoogleAppsScriptReportClient.IsApprovedEndpoint(endpoint))
            return false;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Count() != 3 ||
                !root.TryGetProperty("SchemaId", out var schema) ||
                schema.ValueKind != JsonValueKind.String ||
                schema.GetString() != Schema ||
                !root.TryGetProperty("ReceiverSha256", out var hash) ||
                hash.ValueKind != JsonValueKind.String ||
                !string.Equals(hash.GetString(), ReceiverFingerprint(endpoint!), StringComparison.Ordinal) ||
                !root.TryGetProperty("Enabled", out var enabled) ||
                enabled.ValueKind != JsonValueKind.True)
                return false;
            return root.EnumerateObject().All(x =>
                x.Name is "SchemaId" or "ReceiverSha256" or "Enabled");
        }
        catch (JsonException) { return false; }
    }

    internal static bool IsEnabled(string? endpoint)
    {
        if (!OperatingSystem.IsWindows() ||
            !GoogleAppsScriptReportClient.IsApprovedEndpoint(endpoint) ||
            !Directory.Exists(AutoReapplyScheduler.Root))
            return false;
        try
        {
            EnsureProtectedRoot();
            if (!File.Exists(ConsentPath) ||
                (File.GetAttributes(ConsentPath) & FileAttributes.ReparsePoint) != 0 ||
                new FileInfo(ConsentPath).Length > 1024)
                return false;
            return HasConsent(File.ReadAllText(ConsentPath), endpoint);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   SecurityException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Called ONLY from the GUI, after GitHub has confirmed receipt of the
    /// explicitly reviewed first compatibility report.
    /// </summary>
    internal static void EnableAfterConfirmedReport(string endpoint)
    {
        if (!SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Administrator approval is required for machine-wide reporting.");
        if (!GoogleAppsScriptReportClient.IsApprovedEndpoint(endpoint))
            throw new InvalidDataException("Unapproved reporting destination.");
        EnsureProtectedRoot();
        if (File.Exists(ConsentPath) &&
            (File.GetAttributes(ConsentPath) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Reporting consent file is linked.");
        string stage = Path.Combine(AutoReapplyScheduler.Root,
            Guid.NewGuid().ToString("N") + ".consent.tmp");
        try
        {
            File.WriteAllText(stage, JsonSerializer.Serialize(new Consent(
                Schema, ReceiverFingerprint(endpoint), Enabled: true)));
            File.Move(stage, ConsentPath, overwrite: true);
            if (!IsEnabled(endpoint))
                throw new IOException("Protected reporting consent could not be verified.");
        }
        finally { if (File.Exists(stage)) File.Delete(stage); }
    }

    /// <summary>Immediately revoke future unattended reporting; does not remove Auto Reapply.</summary>
    internal static void Revoke()
    {
        if (!SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Administrator rights required to revoke machine-wide consent.");
        if (!Directory.Exists(AutoReapplyScheduler.Root)) return;
        EnsureProtectedRoot();
        if (File.Exists(ConsentPath))
        {
            if ((File.GetAttributes(ConsentPath) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Reporting consent file is linked.");
            File.Delete(ConsentPath);
        }
    }

    private static void EnsureProtectedRoot()
    {
        NsudoDevilModeScope.EnsurePrivateDirectory(
            Path.GetDirectoryName(AutoReapplyScheduler.Root)!);
        NsudoDevilModeScope.EnsurePrivateDirectory(AutoReapplyScheduler.Root);
    }

    internal static bool CanAutoSend(bool authorized, bool inSystemSessionZero,
        PatchState planState, bool isManual, bool checksumVerified)
        => authorized && inSystemSessionZero && planState == PatchState.Ready &&
           !isManual && checksumVerified;

    /// <summary>
    /// Best-effort network step AFTER the protected Apply, SHA verification
    /// and durable state save have completed. No prompts, retry queue, or UI.
    /// Delivery failure never changes the Apply outcome.
    /// </summary>
    internal static void TrySendAfterVerifiedAutoReapply(
        WindowsDetails os, PatchPlan plan, string verifiedSha)
    {
        try
        {
            var settings = DirectReportingSettings.Load();
            bool consent = settings.HasGoogleScript && IsEnabled(settings.GoogleAppsScriptUrl);
            bool validHash = plan.PatchedBytes is not null &&
                SystemInfo.Sha256(plan.PatchedBytes).Equals(verifiedSha,
                    StringComparison.OrdinalIgnoreCase);
            if (!CanAutoSend(consent, IsolatedApplyExecutor.IsSystemSessionZero(),
                    plan.State, plan.IsManual, validHash))
                return;

            var payload = CompatibilityRelaySubmission.Create(
                SuccessfulFixMetadata.FromSuccessfulApply(os, plan));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            using var client = new GoogleAppsScriptReportClient();
            _ = client.SendCompatibilityAsync(
                settings.GoogleAppsScriptUrl, payload.Json, payload, timeout.Token)
                .GetAwaiter().GetResult();
            AuditLog.Append("Silent Auto Reapply compatibility report confirmed by GitHub.");
        }
        catch (Exception ex)
        {
            // No exception from optional telemetry may convert a completed
            // Apply into failure or trigger another protected DLL operation.
            AuditLog.Append("Silent Auto Reapply report not confirmed: " + ex.GetType().Name);
        }
    }
}
