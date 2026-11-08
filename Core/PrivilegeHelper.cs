namespace TermsrvPatcherUnified.Core;

internal static class PrivilegeHelper
{
    /// <summary>
    /// Write only during an explicit, elevated transaction. NSudo DM hooks are
    /// active exclusively for this small file-write scope. Never take ownership,
    /// modify ACLs, or disable Windows protections as an implicit fallback.
    /// </summary>
    public static void WriteProtected(string path, byte[] bytes)
    {
        if (bytes is null || bytes.Length == 0)
            throw new ArgumentException("Replacement bytes must not be empty.", nameof(bytes));
        using var devilMode = NsudoDevilModeScope.Enter();
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Write,
            FileShare.None, 65536, FileOptions.WriteThrough);
        if (stream.Length != bytes.Length)
            throw new IOException("Protected write refused: replacement length differs from original.");
        stream.Position = 0;
        stream.Write(bytes);
        stream.Flush(true);
    }
}
