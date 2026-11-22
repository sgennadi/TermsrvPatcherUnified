using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Windows Authenticode trust AND an independently provisioned signer public-key pin.
/// Never use a digest, certificate or key downloaded with the candidate release
/// as the trust anchor. A missing pin always fails closed.
/// </summary>
internal static class ReleaseSignatureVerifier
{
    // Pinned to the independently generated release-signing certificate.
    // SHA-256 of the signer SubjectPublicKeyInfo (RSA or ECDSA), hex encoded.
    internal const string PinnedSignerSpkiSha256 = "a185f90644de1c2c5ea2ae2e923eb08f93ebde4b06cc8273679a168dfa5535b9";

    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    internal static bool Verify(string executable, out string reason)
    {
        reason = "Release signature verification failed.";
        if (!OperatingSystem.IsWindows())
        {
            reason = "Windows Authenticode verification requires Windows.";
            return false;
        }
        if (PinnedSignerSpkiSha256.Length != 64 ||
            !PinnedSignerSpkiSha256.All(Uri.IsHexDigit))
        {
            reason = "No independently trusted release signing key is provisioned.";
            return false;
        }
        if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable))
        {
            reason = "Release executable is missing.";
            return false;
        }

        // WinVerifyTrust checks the PE's Authenticode digest, signer chain and
        // Windows trust policy. A certificate's presence alone proves nothing.
        IntPtr fileInfo = IntPtr.Zero;
        IntPtr fileName = IntPtr.Zero;
        try
        {
            fileName = Marshal.StringToCoTaskMemUni(Path.GetFullPath(executable));
            var file = new WinTrustFileInfo
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = fileName
            };
            fileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(file, fileInfo, false);
            var trust = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2, // WTD_UI_NONE
                RevocationChecks = 1, // WTD_REVOKE_WHOLECHAIN
                UnionChoice = 1, // WTD_CHOICE_FILE
                FileInfo = fileInfo,
                StateAction = 0, // WTD_STATEACTION_IGNORE
                ProviderFlags = 0x00000040 // WTD_REVOCATION_CHECK_CHAIN
            };
            var action = GenericVerifyV2;
            if (WinVerifyTrust(IntPtr.Zero, ref action, ref trust) != 0)
            {
                reason = "Windows rejected the executable's Authenticode signature.";
                return false;
            }

            using var certificate = X509CertificateLoader.LoadCertificate(
                X509Certificate.CreateFromSignedFile(executable).Export(X509ContentType.Cert));
            byte[] spki = certificate.GetRSAPublicKey() is { } rsa
                ? ExportRsa(rsa)
                : certificate.GetECDsaPublicKey() is { } ecdsa
                    ? ExportEcdsa(ecdsa)
                    : Array.Empty<byte>();
            if (spki.Length == 0)
            {
                reason = "Unsupported release signing public key.";
                return false;
            }
            var expected = Convert.FromHexString(PinnedSignerSpkiSha256);
            var actual = SHA256.HashData(spki);
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            {
                reason = "Authenticode signer does not match the pinned release key.";
                return false;
            }
            reason = "";
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
                                      CryptographicException or ArgumentException or
                                      NotSupportedException or System.Security.SecurityException)
        {
            reason = "Release signature check failed: " + error.GetType().Name;
            return false;
        }
        finally
        {
            if (fileInfo != IntPtr.Zero) Marshal.FreeHGlobal(fileInfo);
            if (fileName != IntPtr.Zero) Marshal.FreeCoTaskMem(fileName);
        }
    }

    private static byte[] ExportRsa(RSA key)
    {
        using (key) return key.ExportSubjectPublicKeyInfo();
    }

    private static byte[] ExportEcdsa(ECDsa key)
    {
        using (key) return key.ExportSubjectPublicKeyInfo();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(
        IntPtr window, ref Guid action, ref WinTrustData data);
}
