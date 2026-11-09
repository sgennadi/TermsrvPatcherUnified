using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>Local informational history; never an authorization or Restore index.</summary>
internal sealed record OperationHistoryEntry(
    string Schema, DateTimeOffset AtUtc, string Operation, string Result,
    string AppVersion, string? DllVersion, string? BeforeSha256,
    string? AfterSha256, string? FailureType)
{
    internal const string SchemaId = "termsrv-operation-history/v1";

    internal bool IsValid()
        => Schema == SchemaId &&
           AtUtc.Offset == TimeSpan.Zero &&
           AtUtc >= new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero) &&
           AtUtc <= DateTimeOffset.UtcNow.AddMinutes(5) &&
           OperationHistory.AllowedOperations.Contains(Operation) &&
           (Result == "Success" || Result == "Failure") &&
           AppVersion is not null && AppVersion.Length is > 0 and <= 48 &&
           Regex.IsMatch(AppVersion, @"\A[0-9a-zA-Z.-]+\z") &&
           (DllVersion is null || OperationHistory.IsDllVersion(DllVersion)) &&
           (BeforeSha256 is null || OperationHistory.IsSha( BeforeSha256 )) &&
           (AfterSha256 is null || OperationHistory.IsSha( AfterSha256 )) &&
           (FailureType is null ||
            FailureType.Length is > 0 and <= 48 &&
            Regex.IsMatch(FailureType, @"\A[A-Za-z][A-Za-z0-9]+\z"));
}

internal sealed record OperationHistoryResult(
    IReadOnlyList<OperationHistoryEntry> Entries, int InvalidEntries, string? Warning);

internal static class OperationHistory
{
    internal static readonly HashSet<string> AllowedOperations =
        new(StringComparer.Ordinal) { "Apply", "Restore", "RdpSettings", "OfflineCopy", "Baseline" };

    internal static string LocalFile => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TermsrvPatcherUnified", "History", "operations.jsonl");

    internal static bool IsSha(string value)
        => value.Length == 64 &&
           value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static bool IsDllVersion(string value)
        => value.Length is >= 3 and <= 48 &&
           Regex.IsMatch(value, @"\A[0-9]+(?:\.[0-9]+){1,3}\z");

    internal static bool TryRecord(string operation, string result,
        string? dllVersion = null, string? beforeSha256 = null,
        string? afterSha256 = null, string? failureType = null,
        string? file = null)
    {
        if (!AllowedOperations.Contains(operation) ||
            result is not ("Success" or "Failure"))
            return false;
        // Only narrowly validated metadata is persisted, never paths,
        // usernames, exception messages, tokens or session identities.
        var item = new OperationHistoryEntry(OperationHistoryEntry.SchemaId,
            DateTimeOffset.UtcNow, operation, result, UpdateIntegration.Version,
            dllVersion is not null && IsDllVersion(dllVersion) ? dllVersion : null,
            beforeSha256 is not null && IsSha(beforeSha256) ? beforeSha256 : null,
            afterSha256 is not null && IsSha(afterSha256) ? afterSha256 : null,
            failureType is not null && Regex.IsMatch(failureType, @"\A[A-Za-z][A-Za-z0-9]{0,47}\z")
                ? failureType : null);
        if (!item.IsValid()) return false;

        string path;
        try { path = Path.GetFullPath(file ?? LocalFile); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or
                                   PathTooLongException) { return false; }
        if (!Path.GetExtension(path).Equals(".jsonl", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            string directory = Path.GetDirectoryName(path)!;
            Directory.CreateDirectory(directory);
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                return false;
            if (File.Exists(path) &&
                ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
                 new FileInfo(path).Length > 2_000_000))
                return false;
            using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            writer.WriteLine(JsonSerializer.Serialize(item));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException or ArgumentException)
        {
            // History must not interrupt a successful service recovery.
            return false;
        }
    }

    internal static OperationHistoryResult ReadRecent(int limit = 75, string? file = null)
    {
        if (limit is < 1 or > 200) throw new ArgumentOutOfRangeException(nameof(limit));
        string path = Path.GetFullPath(file ?? LocalFile);
        if (!File.Exists(path)) return new([], 0, null);
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                return new([], 0, "History is a reparse point; refusing to follow it.");
            if (new FileInfo(path).Length > 2_100_000)
                return new([], 0, "History exceeds the local read limit (2 MB). No entries loaded.");
            var recent = new Queue<OperationHistoryEntry>();
            int rejected = 0;
            foreach (var line in File.ReadLines(path, Encoding.UTF8))
            {
                if (line.Length is < 2 or > 1024) { rejected++; continue; }
                try
                {
                    var item = JsonSerializer.Deserialize<OperationHistoryEntry>(line);
                    if (item is null || !item.IsValid()) { rejected++; continue; }
                    recent.Enqueue(item);
                    if (recent.Count > limit) recent.Dequeue();
                }
                catch (JsonException) { rejected++; }
            }
            return new(recent.Reverse().ToArray(), rejected, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException or ArgumentException)
        {
            return new([], 0, "History cannot be read (" + ex.GetType().Name + ").");
        }
    }
}
