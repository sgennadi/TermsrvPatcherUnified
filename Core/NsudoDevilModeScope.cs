using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Opt-in native component: the official NSudo Devil Mode 8.2 x64 binary is
/// bundled in published EXEs. It is never loaded for inspection or updates.
/// LoadLibrary activates process-wide NT file/registry hooks; always keep the
/// scope short and do not use it for unrelated application operations.
/// </summary>
internal sealed class NsudoDevilModeScope : IDisposable
{
    private const string DllResource = "TermsrvPatcherUnified.NSudo.x64.NSudoDM.dll";
    private const string ShaResource = "TermsrvPatcherUnified.NSudo.x64.NSudoDM.sha256";
    private static readonly object Gate = new();
    private IntPtr module;
    private bool locked;

    private NsudoDevilModeScope() { }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string path);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr moduleHandle);

    public static bool IsBundled => typeof(NsudoDevilModeScope).Assembly.GetManifestResourceInfo(DllResource) is not null &&
        typeof(NsudoDevilModeScope).Assembly.GetManifestResourceInfo(ShaResource) is not null;

    public static string ComponentStatus => IsBundled
        ? "NSudo Devil Mode 8.2 (x64, embedded; loaded only for protected writes)"
        : "NSudo Devil Mode not bundled; protected writes disabled";

    // Verify and stage native code before interrupting Remote Desktop services.
    public static void Preflight()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess ||
            !SystemInfo.IsAdministrator() || !IsBundled)
            throw new InvalidOperationException("Protected write requires the bundled NSudo x64 DLL and elevation.");
        _ = ExtractVerifiedLibrary();
    }

    public static NsudoDevilModeScope Enter()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess ||
            RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("NSudo Devil Mode is configured only for Windows x64.");
        if (!SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("NSudo Devil Mode requires an elevated administrator.");
        if (!IsBundled)
            throw new InvalidOperationException("NSudo native library is unavailable in this build. " +
                "Use the verified Windows CI preview or run read-only inspection.");

        var scope = new NsudoDevilModeScope();
        Monitor.Enter(Gate);
        scope.locked = true;
        try
        {
            var dll = ExtractVerifiedLibrary();
            scope.module = LoadLibraryW(dll);
            if (scope.module == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to load embedded NSudoDM.dll.");
            return scope;
        }
        catch
        {
            scope.Dispose();
            throw;
        }
    }

    private static string ExtractVerifiedLibrary()
    {
        var assembly = typeof(NsudoDevilModeScope).Assembly;
        using var hashReader = new StreamReader(assembly.GetManifestResourceStream(ShaResource)
            ?? throw new InvalidDataException("Embedded NSudo SHA-256 manifest is missing."), Encoding.ASCII);
        var expected = hashReader.ReadToEnd().Trim().ToLowerInvariant();
        if (expected.Length != 64 || !expected.All(Uri.IsHexDigit))
            throw new InvalidDataException("Embedded NSudo SHA-256 is invalid.");
        using var resource = assembly.GetManifestResourceStream(DllResource)
            ?? throw new InvalidDataException("Embedded NSudo native DLL is missing.");
        using var data = new MemoryStream();
        resource.CopyTo(data);
        var bytes = data.ToArray();
        if (bytes.Length is < 8_192 or > 512_000 ||
            !Convert.ToHexStringLower(SHA256.HashData(bytes)).Equals(expected, StringComparison.Ordinal))
            throw new InvalidDataException("Embedded NSudo DLL integrity verification failed.");
        EnsureAmd64Dll(bytes);

        // Do not place executable native code below AuditLog.Root: the
        // audit directory may already exist with inherited user-writable ACLs.
        var basePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "TermsrvPatcherUnified.NativeProtected");
        var directory = Path.Combine(basePath, "NSudo-8.2-x64-" + expected[..16]);
        EnsurePrivateDirectory(basePath);
        EnsurePrivateDirectory(directory);

        var dll = Path.Combine(directory, "NSudoDM.dll");
        if (!File.Exists(dll))
        {
            // CreateNew prevents overwriting a file planted during a race.
            using var stream = new FileStream(dll, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 65536, FileOptions.WriteThrough);
            stream.Write(bytes);
            stream.Flush(true);
        }
        var attributes = File.GetAttributes(dll);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("NSudo destination must not be a reparse point.");
        if (!Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(dll)))
            .Equals(expected, StringComparison.Ordinal))
            throw new IOException("Extracted NSudo DLL differs from embedded approved binary.");
        return dll;
    }

    internal static void EnsureAmd64Dll(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 256 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z')
            throw new InvalidDataException("Native library is not a PE file.");
        int pe = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(0x3c, 4));
        if (pe < 0 || pe > bytes.Length - 24 ||
            !bytes.Slice(pe, 4).SequenceEqual(new byte[] { (byte)'P', (byte)'E', 0, 0 }))
            throw new InvalidDataException("Invalid native library PE signature.");
        if (BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(pe + 4, 2)) != 0x8664 ||
            (BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(pe + 22, 2)) & 0x2000) == 0)
            throw new InvalidDataException("Native library must be an AMD64 DLL.");
    }

    private static void EnsurePrivateDirectory(string path)
    {
        if (File.Exists(path) && !Directory.Exists(path))
            throw new IOException("Native runtime folder is occupied by a file.");
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(administrators);
        foreach (var account in new[] { administrators, system })
            acl.AddAccessRule(new FileSystemAccessRule(account, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        if (!Directory.Exists(path))
            FileSystemAclExtensions.CreateDirectory(acl, path);
        var actual = new DirectoryInfo(path);
        if ((actual.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Native runtime directory must not be a reparse point.");
        var security = actual.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!security.AreAccessRulesProtected || owner is null ||
            (!owner.Equals(administrators) && !owner.Equals(system)))
            throw new UnauthorizedAccessException("Native runtime directory does not have protected administrator ownership.");
        foreach (FileSystemAccessRule entry in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (entry.AccessControlType != AccessControlType.Allow) continue;
            if (entry.IdentityReference is not SecurityIdentifier sid ||
                (!sid.Equals(administrators) && !sid.Equals(system)))
                throw new UnauthorizedAccessException("Native runtime directory grants unexpected file rights.");
        }
    }

    public void Dispose()
    {
        try
        {
            var handle = module;
            module = IntPtr.Zero;
            if (handle != IntPtr.Zero && !FreeLibrary(handle))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not unload NSudo Devil Mode.");
        }
        finally
        {
            if (locked) { locked = false; Monitor.Exit(Gate); }
        }
    }
}
