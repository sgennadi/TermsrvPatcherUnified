using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Optional, operator-reviewed Windows + installed termsrv.dll metadata.
/// No machine name, username, domain, IP, path, stack trace or DLL bytes.
/// </summary>
internal sealed record DiagnosticEnvironment(
    string WindowsRelease, int WindowsBuild, int WindowsUbr,
    string DllVersion, string DllSha256)
{
    private static readonly Regex ReleasePattern = new(
        @"\A[A-Za-z0-9._-]{1,20}\z", RegexOptions.CultureInvariant);
    private static readonly Regex VersionPattern = new(
        @"\A[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}\z", RegexOptions.CultureInvariant);
    private static readonly Regex HashPattern = new(
        @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);

    internal bool Valid =>
        ReleasePattern.IsMatch(WindowsRelease ?? "") &&
        WindowsBuild is >= 19041 and <= 99999 &&
        WindowsUbr is >= 0 and <= 999999 &&
        VersionPattern.IsMatch(DllVersion ?? "") &&
        HashPattern.IsMatch(DllSha256 ?? "");

    internal static DiagnosticEnvironment? TryRead()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var os = SystemInfo.Read();
            if (os.InstallationType != "Client" || os.DllVersion is "Unknown" or "Missing")
                return null;
            // Open the installed DLL ONLY for a read-only digest. A source file
            // may change during servicing: require stable length and mtime.
            var infoBefore = new FileInfo(os.DllPath);
            if (!infoBefore.Exists || infoBefore.Length is < 1024 or > 128_000_000)
                return null;
            string hash;
            using (var stream = new FileStream(os.DllPath, FileMode.Open, FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete))
                hash = Convert.ToHexStringLower(SHA256.HashData(stream));
            var infoAfter = new FileInfo(os.DllPath);
            infoAfter.Refresh();
            if (!infoAfter.Exists || infoBefore.Length != infoAfter.Length ||
                infoBefore.LastWriteTimeUtc != infoAfter.LastWriteTimeUtc)
                return null;
            var stamp = FileVersionInfo.GetVersionInfo(os.DllPath);
            if (!string.Equals(stamp.FileVersion, os.DllVersion,
                    StringComparison.Ordinal)) return null;
            // FileVersionInfo.FileVersion can contain a Windows build label,
            // e.g. '(WinBuild.160101.0800)'. Use numeric PE version parts.
            if (stamp.FileMajorPart < 0 || stamp.FileMinorPart < 0 ||
                stamp.FileBuildPart < 0 || stamp.FilePrivatePart < 0)
                return null;
            string numericVersion = string.Join(".", stamp.FileMajorPart, stamp.FileMinorPart,
                stamp.FileBuildPart, stamp.FilePrivatePart);
            var data = new DiagnosticEnvironment(os.DisplayVersion, os.Build, os.Ubr,
                numericVersion, hash);
            return data.Valid ? data : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   ArgumentException or System.Security.SecurityException or
                                   System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null; // Reporting errors must never prevent the original diagnostics.
        }
    }

    internal string AsPreview() =>
        $"Windows: {WindowsRelease} (build {WindowsBuild}.{WindowsUbr})\n" +
        $"termsrv.dll: {DllVersion}\nSHA-256: {DllSha256}";
}
