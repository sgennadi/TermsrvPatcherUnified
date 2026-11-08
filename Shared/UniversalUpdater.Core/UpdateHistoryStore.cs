using System.Text.Json;
using System.Text.RegularExpressions;

namespace UniversalUpdater;

public sealed record UpdateHistoryRecord(
    DateTimeOffset Utc, string ProductId, string Operation,
    string FromVersion, string ToVersion, string ResultCode);

/// <summary>Bounded, sanitized on-device history; never sends records to a server.</summary>
public sealed class UpdateHistoryStore
{
    private static readonly Regex CategoryPattern = new(@"^[A-Z][A-Z0-9_]{0,47}$",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(500));
    private const int MaxEntries = 200;
    private readonly string root;
    private readonly string file;
    private readonly string trustedProductId;
    public UpdateHistoryStore(UpdateOptions options)
    {
        options.Validate();
        root = UpdateStateStore.GetStateRoot(options);
        trustedProductId = options.ProductId;
        file = Path.Combine(root, "history.json");
    }

    public IReadOnlyList<UpdateHistoryRecord> Read()
    {
        if (!File.Exists(file)) return [];
        try
        {
            if (new FileInfo(file).Length > 256 * 1024)
                return []; // Refuse unexpected oversized or corrupted history.
            var data = JsonSerializer.Deserialize<List<UpdateHistoryRecord>>(File.ReadAllText(file));
            return data is { Count: <= MaxEntries } ? data : [];
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public void Append(string productId, string operation, string from, string to, string result)
    {
        if (!string.Equals(productId, trustedProductId, StringComparison.Ordinal) ||
            !CategoryPattern.IsMatch(operation) || !CategoryPattern.IsMatch(result))
            throw new ArgumentException("History requires a sanitized operation and result code.");
        if (!string.IsNullOrEmpty(from)) _ = SemanticVersion.Parse(from);
        if (!string.IsNullOrEmpty(to)) _ = SemanticVersion.Parse(to);
        Directory.CreateDirectory(root);
        using var gate = new FileStream(Path.Combine(root, "history.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var current = Read().ToList();
        current.Add(new UpdateHistoryRecord(DateTimeOffset.UtcNow, productId, operation, from, to, result));
        if (current.Count > MaxEntries) current.RemoveRange(0, current.Count - MaxEntries);
        string temporary = Path.Combine(root, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(current));
            File.Move(temporary, file, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
