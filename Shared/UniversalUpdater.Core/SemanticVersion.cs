using System.Globalization;
using System.Text.RegularExpressions;

namespace UniversalUpdater;

/// <summary>SemVer 2.0 precedence; optional v prefix and a zero .revision for Windows product versions.</summary>
public readonly record struct SemanticVersion(int Major, int Minor, int Patch, string Prerelease)
    : IComparable<SemanticVersion>
{
    private static readonly Regex Pattern = new(
        @"^v?(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:\.0)?(?:-(?<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    public bool IsPrerelease => !string.IsNullOrEmpty(Prerelease);

    public static bool TryParse(string? text, out SemanticVersion result)
    {
        result = default;
        text = text?.Trim();
        if (string.IsNullOrEmpty(text) || text.Length > 160) return false;
        var match = Pattern.Match(text);
        if (!match.Success ||
            !int.TryParse(match.Groups["major"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int major) ||
            !int.TryParse(match.Groups["minor"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int minor) ||
            !int.TryParse(match.Groups["patch"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int patch))
            return false;
        var pre = match.Groups["pre"].Value;
        foreach (var part in pre.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            bool allDigits = part.All(c => c is >= '0' and <= '9');
            if (allDigits && part.Length > 1 && part[0] == '0') return false;
        }
        result = new SemanticVersion(major, minor, patch, pre);
        return true;
    }

    public static SemanticVersion Parse(string text) => TryParse(text, out var parsed)
        ? parsed : throw new FormatException("Unsupported semantic version.");

    public int CompareTo(SemanticVersion other)
    {
        int cmp = Major.CompareTo(other.Major);
        if (cmp == 0) cmp = Minor.CompareTo(other.Minor);
        if (cmp == 0) cmp = Patch.CompareTo(other.Patch);
        if (cmp != 0) return cmp;
        if (!IsPrerelease) return other.IsPrerelease ? 1 : 0;
        if (!other.IsPrerelease) return -1;
        var a = Prerelease.Split('.');
        var b = other.Prerelease.Split('.');
        for (int i = 0; i < Math.Min(a.Length, b.Length); i++)
        {
            bool ad = a[i].All(char.IsAsciiDigit);
            bool bd = b[i].All(char.IsAsciiDigit);
            if (ad && bd)
            {
                cmp = a[i].Length.CompareTo(b[i].Length);
                if (cmp == 0) cmp = string.CompareOrdinal(a[i], b[i]);
            }
            else if (ad != bd) cmp = ad ? -1 : 1;
            else cmp = string.CompareOrdinal(a[i], b[i]);
            if (cmp != 0) return cmp;
        }
        return a.Length.CompareTo(b.Length);
    }

    public static bool operator >(SemanticVersion a, SemanticVersion b) => a.CompareTo(b) > 0;
    public static bool operator <(SemanticVersion a, SemanticVersion b) => a.CompareTo(b) < 0;
    public static bool operator >=(SemanticVersion a, SemanticVersion b) => a.CompareTo(b) >= 0;
    public static bool operator <=(SemanticVersion a, SemanticVersion b) => a.CompareTo(b) <= 0;
    public override string ToString() => $"{Major}.{Minor}.{Patch}" + (IsPrerelease ? "-" + Prerelease : string.Empty);
}
