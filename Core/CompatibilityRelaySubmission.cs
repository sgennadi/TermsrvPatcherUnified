using System.Globalization;
using System.Text.Json;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// A consent-only public compatibility report. Structured, bounded metadata:
/// no local paths, hosts, accounts, IPs, DLL files, logs or credentials.
/// The Google gateway and GitHub aggregator must treat it as UNVERIFIED.
/// </summary>
internal sealed class CompatibilityRelaySubmission
{
    private const string Project = "sgennadi/TermsrvPatcherUnified";
    internal string Kind { get; }
    internal string Body { get; }
    internal string EventId { get; }
    internal string TimestampUtc { get; }
    internal string Json { get; }

    private CompatibilityRelaySubmission(string kind, string body)
    {
        Kind = kind;
        Body = body;
        EventId = Guid.NewGuid().ToString("D");
        TimestampUtc = DateTimeOffset.UtcNow.ToString(
            "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        Json = Serialize();
        Validate();
    }

    internal static CompatibilityRelaySubmission Create(SuccessfulFixMetadata report)
    {
        ArgumentNullException.ThrowIfNull(report);
        report.Validate();
        return new("successful_apply", report.AsComment());
    }

    internal static CompatibilityRelaySubmission Create(OfflineFixMetadata report)
    {
        ArgumentNullException.ThrowIfNull(report);
        report.Validate();
        return new("offline_file", report.AsComment());
    }

    private string Serialize() => JsonSerializer.Serialize(new
    {
        @event = new
        {
            schema = "termsrv-compatibility/v1",
            id = EventId,
            timestamp_utc = TimestampUtc,
            project = Project,
            kind = Kind,
            body = Body
        }
    });

    internal void Validate()
    {
        if (Kind is not ("successful_apply" or "offline_file") ||
            Body.Length is < 80 or > 6144 ||
            Body.Contains('\r') || Body.Contains('\0') ||
            !(Kind == "successful_apply"
                ? Body.StartsWith("termsrv-success/v2\n", StringComparison.Ordinal)
                : Body.StartsWith("termsrv-offline/v1\n", StringComparison.Ordinal)) ||
            !Guid.TryParseExact(EventId, "D", out _) ||
            Serialize() != Json)
            throw new InvalidDataException("Compatibility report changed after review.");
    }
}
