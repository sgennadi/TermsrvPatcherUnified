using System.Text.Json;

namespace UniversalUpdater;

/// <summary>
/// Local-only, bounded, privacy-preserving recovery diagnostics.
/// Never persists exception messages, stack traces, usernames, or file paths.
/// </summary>
internal static class RollbackFailureDiagnostics
{
    private sealed record Entry(DateTimeOffset Utc, string Operation, string ErrorType, int HResult);

    internal static void Record(UpdateOptions options, string operation, Exception error)
    {
        try
        {
            string root = UpdateStateStore.GetStateRoot(options);
            Directory.CreateDirectory(root);
            string file = Path.Combine(root, "rollback-diagnostics.jsonl");
            // Avoid unlimited growth and never overwrite a possibly corrupted oversized log.
            if (File.Exists(file) && new FileInfo(file).Length > 128 * 1024)
            {
                string rotated = file + ".previous";
                File.Move(file, rotated, overwrite: true);
            }
            string kind = error switch
            {
                UnauthorizedAccessException => "ACCESS_DENIED",
                IOException => "IO_ERROR",
                InvalidDataException => "INVALID_DATA",
                InvalidOperationException => "INVALID_STATE",
                OperationCanceledException => "CANCELED",
                _ => "OTHER"
            };
            string line = JsonSerializer.Serialize(new Entry(DateTimeOffset.UtcNow, operation, kind, error.HResult));
            using var stream = new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(stream);
            writer.WriteLine(line);
        }
        catch (Exception diagnosticError) when (diagnosticError is IOException or UnauthorizedAccessException or
                                                ArgumentException or NotSupportedException)
        {
            // Diagnostic logging is best-effort: never override the original recovery failure.
        }
    }

    internal static void TryDelete(UpdateOptions options, string operation, string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException error) { Record(options, operation, error); }
        catch (UnauthorizedAccessException error) { Record(options, operation, error); }
    }
}
