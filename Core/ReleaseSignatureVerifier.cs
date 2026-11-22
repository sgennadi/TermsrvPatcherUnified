using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Formats.Asn1;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Authenticode PE digest and CMS signature verification with an independently pinned signer key.
/// Never use a digest, certificate or key downloaded with the candidate release
/// as the trust anchor. A missing pin always fails closed.
/// </summary>
internal static class ReleaseSignatureVerifier
{
    // Pinned to the independently generated release-signing certificate.
    // SHA-256 of the signer SubjectPublicKeyInfo (RSA or ECDSA), hex encoded.
    internal const string PinnedSignerSpkiSha256 = "a185f90644de1c2c5ea2ae2e923eb08f93ebde4b06cc8273679a168dfa5535b9";

    internal static bool Verify(string executable, out string reason)
    {
        return VerifyWithPin(executable, PinnedSignerSpkiSha256, out reason);
    }

    // Test-only entry point: production always uses the compiled-in pin.
    internal static bool VerifyWithPin(string executable, string signerSpkiSha256, out string reason)
    {
        reason = "Release signature verification failed.";
        if (!OperatingSystem.IsWindows())
        {
            reason = "Windows Authenticode verification requires Windows.";
            return false;
        }
        if (signerSpkiSha256.Length != 64 ||
            !signerSpkiSha256.All(Uri.IsHexDigit))
        {
            reason = "No independently trusted release signing key is provisioned.";
            return false;
        }
        if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable))
        {
            reason = "Release executable is missing.";
            return false;
        }

        string verificationStage = "opening PE";
        try
        {
            // Verify the actual PE image digest, not merely a PKCS#7 blob or
            // the certificate attached to it. Windows ImageHlp implements the
            // Authenticode PE hashing exclusions (checksum and certificate table).
            using var stream = new FileStream(executable, FileMode.Open, FileAccess.Read,
                FileShare.Read);
            byte[] signature = ReadEmbeddedSignature(stream);
            verificationStage = "decoding PKCS#7";
            var cms = new SignedCms();
            cms.Decode(signature);
            if (cms.SignerInfos.Count != 1)
                throw new CryptographicException("Exactly one primary signer is required.");
            verificationStage = "verifying CMS signature";
            cms.CheckSignature(verifySignatureOnly: true);
            var signer = cms.SignerInfos[0];
            using var certificate = signer.Certificate ??
                throw new CryptographicException("Signer certificate missing.");
            verificationStage = "parsing Authenticode indirect data";
            byte[] expectedDigest = ReadAuthenticodeDigest(cms.ContentInfo.Content,
                out var algorithm);
            verificationStage = "hashing PE image";
            byte[] computedDigest = ComputeAuthenticodePeDigest(stream, algorithm);
            if (!CryptographicOperations.FixedTimeEquals(computedDigest, expectedDigest))
                throw new CryptographicException("Authenticode PE digest mismatch (expected " +
                    Convert.ToHexString(expectedDigest) + ", computed " +
                    Convert.ToHexString(computedDigest) + ").");
            verificationStage = "checking signer certificate and pin";
            // A pinned key alone does not authorize arbitrary certificate purposes.
            // Require a currently valid code-signing certificate, not a TLS or CA cert.
            var now = DateTime.UtcNow;
            if (now < certificate.NotBefore.ToUniversalTime() ||
                now > certificate.NotAfter.ToUniversalTime())
            {
                reason = "Release signing certificate is expired or not yet valid.";
                return false;
            }
            var ekuExtensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
            if (ekuExtensions.Length != 1 ||
                !ekuExtensions[0].EnhancedKeyUsages.Cast<Oid>()
                    .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.3"))
            {
                reason = "Release certificate does not permit code signing.";
                return false;
            }
            var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
            if (keyUsage.Length > 1 ||
                (keyUsage.Length == 1 &&
                 (keyUsage[0].KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0))
            {
                reason = "Release certificate is not authorized for digital signatures.";
                return false;
            }
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
            var expected = Convert.FromHexString(signerSpkiSha256);
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
            reason = "Release signature check failed at " + verificationStage + ": " + error.GetType().Name +
                (error is CryptographicException ? " (" + error.Message + ")" : "");
            return false;
        }
    }

    // Authenticode PE hashing follows the PE/COFF specification: checksum and
    // certificate directory entry are skipped; sections are hashed by file offset,
    // followed by remaining non-certificate overlay bytes.
    private static byte[] ComputeAuthenticodePeDigest(FileStream stream, string algorithm)
    {
        using HashAlgorithm hash = algorithm switch
        {
            "2.16.840.1.101.3.4.2.1" => SHA256.Create(),
            "2.16.840.1.101.3.4.2.2" => SHA384.Create(),
            "2.16.840.1.101.3.4.2.3" => SHA512.Create(),
            _ => throw new CryptographicException("Unsupported PE digest algorithm.")
        };
        using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        stream.Position = 0x3C;
        long pe = reader.ReadUInt32();
        stream.Position = pe + 6;
        int sectionCount = reader.ReadUInt16();
        stream.Position = pe + 20;
        int optionalSize = reader.ReadUInt16();
        long optional = pe + 24;
        stream.Position = optional;
        ushort magic = reader.ReadUInt16();
        int directoryStart = magic switch
        {
            0x10B => 96, 0x20B => 112,
            _ => throw new CryptographicException("Unsupported PE optional header.")
        };
        if (optionalSize < directoryStart + 40 || sectionCount > 96)
            throw new CryptographicException("Invalid PE header layout.");
        stream.Position = optional + 60;
        uint headersSize = reader.ReadUInt32();
        long checksumOffset = optional + 64;
        long securityDirectoryOffset = optional + directoryStart + 32;
        stream.Position = securityDirectoryOffset;
        long certOffset = reader.ReadUInt32();
        long certSize = reader.ReadUInt32();
        if (headersSize > stream.Length || securityDirectoryOffset + 8 > headersSize ||
            certOffset < headersSize || certSize < 8 || certOffset > stream.Length - certSize)
            throw new CryptographicException("Invalid Authenticode PE layout.");
        void Append(long start, long length)
        {
            if (start < 0 || length < 0 || start > stream.Length - length)
                throw new CryptographicException("PE hash range outside file.");
            stream.Position = start;
            byte[] buffer = new byte[65536];
            while (length > 0)
            {
                int count = stream.Read(buffer, 0, (int)Math.Min(length, buffer.Length));
                if (count <= 0) throw new EndOfStreamException();
                hash.TransformBlock(buffer, 0, count, buffer, 0);
                length -= count;
            }
        }
        Append(0, checksumOffset);
        Append(checksumOffset + 4, securityDirectoryOffset - checksumOffset - 4);
        Append(securityDirectoryOffset + 8, headersSize - securityDirectoryOffset - 8);
        long sectionTable = optional + optionalSize;
        var sections = new List<(long Start, long Length)>();
        for (int i = 0; i < sectionCount; i++)
        {
            stream.Position = sectionTable + i * 40L + 16;
            long size = reader.ReadUInt32();
            long offset = reader.ReadUInt32();
            if (size != 0) sections.Add((offset, size));
        }
        long lastSectionEnd = headersSize;
        foreach (var section in sections.OrderBy(x => x.Start))
        {
            if (section.Start < lastSectionEnd || section.Start > stream.Length - section.Length ||
                section.Start + section.Length > certOffset)
                throw new CryptographicException("Overlapping or invalid PE sections.");
            Append(section.Start, section.Length);
            lastSectionEnd = section.Start + section.Length;
        }
        // The certificate table is not included in the digest. Hash only overlay
        // bytes outside that table, including any bytes following it.
        if (certOffset > lastSectionEnd)
            Append(lastSectionEnd, certOffset - lastSectionEnd);
        if (certOffset + certSize < stream.Length)
            Append(certOffset + certSize, stream.Length - certOffset - certSize);
        hash.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return hash.Hash!;
    }

    private static byte[] ReadEmbeddedSignature(FileStream stream)
    {
        using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        if (reader.ReadUInt16() != 0x5A4D)
            throw new CryptographicException("Not a DOS/PE executable.");
        stream.Position = 0x3C;
        long pe = reader.ReadUInt32();
        if (pe < 0x40 || pe > stream.Length - 256)
            throw new CryptographicException("Invalid PE header.");
        stream.Position = pe;
        if (reader.ReadUInt32() != 0x00004550)
            throw new CryptographicException("Invalid PE signature.");
        stream.Position = pe + 20;
        int optionalSize = reader.ReadUInt16();
        long optionalStart = pe + 24;
        if (optionalStart + optionalSize > stream.Length)
            throw new CryptographicException("Truncated PE optional header.");
        stream.Position = optionalStart;
        int magic = reader.ReadUInt16();
        int dataDirectoryOffset = magic switch { 0x10B => 96, 0x20B => 112,
            _ => throw new CryptographicException("Unknown PE optional header.") };
        if (optionalSize < dataDirectoryOffset + 8 * 5)
            throw new CryptographicException("PE certificate directory missing.");
        stream.Position = optionalStart + dataDirectoryOffset + 8 * 4;
        long certificateOffset = reader.ReadUInt32();
        long certificateSize = reader.ReadUInt32();
        if (certificateOffset <= 0 || certificateSize < 8 ||
            certificateOffset > stream.Length - certificateSize ||
            certificateSize > 16 * 1024 * 1024)
            throw new CryptographicException("Invalid PE certificate table.");
        stream.Position = certificateOffset;
        long entrySize = reader.ReadUInt32();
        ushort revision = reader.ReadUInt16();
        ushort type = reader.ReadUInt16();
        if (revision != 0x0200 || type != 0x0002 ||
            entrySize < 8 || entrySize > certificateSize ||
            ((entrySize + 7) & ~7L) != certificateSize)
            throw new CryptographicException("Unsupported or ambiguous PE signature table.");
        byte[] result = reader.ReadBytes(checked((int)entrySize - 8));
        if (result.Length != entrySize - 8)
            throw new CryptographicException("Truncated Authenticode signature.");
        return result;
    }

    private static byte[] ReadAuthenticodeDigest(byte[] indirectData, out string algorithm)
    {
        var asn = new AsnReader(indirectData, AsnEncodingRules.BER);
        var outer = asn.ReadSequence();
        var data = outer.ReadSequence();
        string type = data.ReadObjectIdentifier();
        if (type != "1.3.6.1.4.1.311.2.1.15")
            throw new CryptographicException("Unexpected Authenticode content type.");
        // The optional SPC value is not used to establish trust.
        while (data.HasData) data.ReadEncodedValue();
        var digestInfo = outer.ReadSequence();
        var digestAlgorithm = digestInfo.ReadSequence();
        algorithm = digestAlgorithm.ReadObjectIdentifier();
        while (digestAlgorithm.HasData) digestAlgorithm.ReadEncodedValue();
        byte[] digest = digestInfo.ReadOctetString();
        digestInfo.ThrowIfNotEmpty();
        outer.ThrowIfNotEmpty();
        asn.ThrowIfNotEmpty();
        return digest;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool DigestCallback(IntPtr context, IntPtr data, uint length);

    [DllImport("imagehlp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImageGetDigestStream(
        SafeFileHandle file, uint digestLevel, DigestCallback callback, IntPtr context);

    private static byte[] ExportRsa(RSA key)
    {
        using (key) return key.ExportSubjectPublicKeyInfo();
    }

    private static byte[] ExportEcdsa(ECDsa key)
    {
        using (key) return key.ExportSubjectPublicKeyInfo();
    }

}
