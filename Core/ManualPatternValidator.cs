namespace TermsrvPatcherUnified.Core;

/// <summary>Nonthrowing, read-only validation for the Manual Find/Replace editor.</summary>
public sealed record ManualPatternValidation(bool IsValid, string Message, int GroupCount);

public static class ManualPatternValidator
{
    public static ManualPatternValidation Check(string? find, string? replace)
    {
        if (string.IsNullOrWhiteSpace(find))
            return new(false, "Enter Find HEX bytes first. Use two digits per byte, separated by spaces.", 0);
        if (string.IsNullOrWhiteSpace(replace))
            return new(false, "Enter Replace HEX bytes for verification (or continue read-only Find inspection).", 0);

        string[] originals = find.Split('|');
        string[] replacements = replace.Split('|');
        if (originals.Length != replacements.Length)
            return new(false, "Find contains " + originals.Length +
                " group(s) but Replace contains " + replacements.Length +
                ". Separate related groups using | on both sides.", 0);
        if (originals.Length > 8)
            return new(false, "Use at most eight related Find/Replace groups.", 0);

        int fixedBytes = 0;
        int total = 0;
        for (int i = 0; i < originals.Length; i++)
        {
            int number = i + 1;
            byte?[] before;
            byte[] after;
            try { before = BytePattern.ParseFind(originals[i]); }
            catch (FormatException)
            {
                return new(false, "Group " + number +
                    ": Find must use two-digit HEX bytes separated by spaces; * or ?? means one changing byte.", 0);
            }
            try { after = BytePattern.ParseReplace(replacements[i]); }
            catch (FormatException)
            {
                return new(false, "Group " + number +
                    ": Replace must contain complete two-digit HEX bytes (no * or ??).", 0);
            }
            if (before.Length < 4)
                return new(false, "Group " + number + ": Find has " + before.Length +
                    " byte(s); at least four are required.", 0);
            if (before.Length != after.Length)
                return new(false, "Group " + number + ": Find has " + before.Length +
                    " byte(s), Replace has " + after.Length +
                    ". Both must have the SAME number of bytes. No operation was attempted.", 0);
            if (before.All(x => !x.HasValue))
                return new(false, "Group " + number +
                    ": at least one Find byte must be fixed; all-wildcard masks are not valid.", 0);
            fixedBytes += before.Count(x => x.HasValue);
            total += before.Length;
        }
        return new(true, "Ready to CHECK only: " + originals.Length +
            " group(s), " + total + " Find/Replace byte pairs, " + fixedBytes +
            " fixed Find bytes. No DLL changes have been made.", originals.Length);
    }
}
