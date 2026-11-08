using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;

namespace TermsrvPatcherUnified.Core;

public sealed record WindowsDetails(string Name, string DisplayVersion, int Build, int Ubr,
    string InstallationType, bool Is64Bit, string DllPath, string DllVersion)
{
    // Desktop Windows only. Servers already have licensed RDS facilities.
    public bool Supported => InstallationType.Equals("Client", StringComparison.OrdinalIgnoreCase)
        && Is64Bit && Build >= 19041 && Environment.OSVersion.Platform == PlatformID.Win32NT;

    public string Display => $"{Name} {DisplayVersion} (build {Build}.{Ubr})";
}

public static class SystemInfo
{
    public static WindowsDetails Read()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            ?? throw new InvalidOperationException("Cannot inspect Windows version registry.");
        int.TryParse(Convert.ToString(key.GetValue("CurrentBuildNumber")), out int build);
        int.TryParse(Convert.ToString(key.GetValue("UBR")), out int ubr);
        string display = Convert.ToString(key.GetValue("DisplayVersion")) ?? "Unknown";
        string type = Convert.ToString(key.GetValue("InstallationType")) ?? "Unknown";
        string name = type == "Client" ? (build >= 22000 ? "Windows 11" : "Windows 10") : "Windows Server";
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "termsrv.dll");
        string version = File.Exists(path) ? FileVersionInfo.GetVersionInfo(path).FileVersion ?? "Unknown" : "Missing";
        return new WindowsDetails(name, display, build, ubr, type,
            Environment.Is64BitOperatingSystem, path, version);
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static string Sha256(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
