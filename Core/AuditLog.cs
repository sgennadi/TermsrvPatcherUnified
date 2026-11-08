namespace TermsrvPatcherUnified.Core;

public static class AuditLog
{
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TermsrvPatcherUnified");

    public static void Append(string line)
    {
        try
        {
            Directory.CreateDirectory(Root);
            File.AppendAllText(Path.Combine(Root, "operations.log"),
                $"{DateTimeOffset.UtcNow:O}  {line.Replace('\r', ' ').Replace('\n', ' ')}{Environment.NewLine}");
        }
        catch { /* Diagnostics should not interrupt service recovery. */ }
    }
}
