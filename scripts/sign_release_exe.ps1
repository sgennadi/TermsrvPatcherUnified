# Sign only an audited, published EXE; fail closed on absent or wrong signer.
# This step is restricted to the release-signing GitHub environment.
param([string] $PublishDir = 'publish')
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:TPU_PFX_BASE64) -or
    [string]::IsNullOrWhiteSpace($env:TPU_PFX_PASSWORD) -or
    $env:TPU_PIN -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Missing code-signing credentials or signer SPKI pin.'
}
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exe = Join-Path (Join-Path $root $PublishDir) 'TermsrvPatcherUnified.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Published EXE is missing.' }
$pfx = Join-Path $env:RUNNER_TEMP ('tpu-sign-' + [Guid]::NewGuid().ToString('N') + '.pfx')
$tampered = Join-Path $env:RUNNER_TEMP ('tpu-tampered-' + [Guid]::NewGuid().ToString('N') + '.exe')
try {
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:TPU_PFX_BASE64))
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    $cert = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12FromFile(
        $pfx, $env:TPU_PFX_PASSWORD, $flags)
    try {
        if (-not $cert.HasPrivateKey) { throw 'Signing private key missing.' }
        $now = [DateTime]::UtcNow
        if ($now -lt $cert.NotBefore.ToUniversalTime() -or $now -gt $cert.NotAfter.ToUniversalTime()) {
            throw 'Code-signing certificate outside its validity period.'
        }
        $eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
        if ($eku.Count -ne 1) { throw 'Code-signing EKU missing or ambiguous.' }
        $decoded = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku[0], $eku[0].Critical)
        if (-not @($decoded.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }).Count) {
            throw 'Certificate is not authorized for code signing.'
        }
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
        if ($null -eq $rsa) { throw 'Expected RSA code-signing certificate.' }
        try {
            $actual = [Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData($rsa.ExportSubjectPublicKeyInfo()))
        } finally { $rsa.Dispose() }
        if ($actual -ne ($env:TPU_PIN).ToUpperInvariant()) {
            throw 'PFX public key does not match pinned SPKI SHA-256.'
        }

        $sdkRoot = Join-Path ([Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFilesX86)) 'Windows Kits\10\bin'
        $sdk = Get-ChildItem -LiteralPath $sdkRoot -Filter signtool.exe -Recurse -ErrorAction Stop |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if (-not $sdk) { throw 'Windows SDK x64 signtool.exe is missing.' }
        & $sdk.FullName sign /fd SHA256 /f $pfx /p $env:TPU_PFX_PASSWORD $exe
        if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed.' }
        $signature = Get-AuthenticodeSignature -LiteralPath $exe
        if ($null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint -or
            $signature.Status -in @([System.Management.Automation.SignatureStatus]::NotSigned,
                                    [System.Management.Automation.SignatureStatus]::HashMismatch)) {
            throw 'Signed EXE has the wrong signer or damaged signature.'
        }

        Copy-Item -LiteralPath $exe -Destination $tampered
        $stream = [IO.File]::Open($tampered, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
        try {
            $stream.Position = 0x40
            $byte = $stream.ReadByte()
            if ($byte -lt 0) { throw 'EXE too small for tamper test.' }
            $stream.Position = 0x40
            $stream.WriteByte([byte]($byte -bxor 1))
        } finally { $stream.Dispose() }
        $damaged = Get-AuthenticodeSignature -LiteralPath $tampered
        if ($damaged.Status -ne [System.Management.Automation.SignatureStatus]::HashMismatch) {
            throw 'Tampered Authenticode executable was not rejected as HashMismatch.'
        }
        dotnet run --project Tests/TermsrvPatcher.Tests.csproj -c Release --no-build -- --authenticode-qa $exe $tampered $env:TPU_PIN
        if ($LASTEXITCODE -ne 0) { throw 'Pinned Authenticode or tamper regression failed.' }
        Write-Host 'PASS: signed EXE, pinned public key and tamper rejection validated.'
    } finally { $cert.Dispose() }
} finally {
    Remove-Item -LiteralPath $tampered, $pfx -Force -ErrorAction SilentlyContinue
    Remove-Item Env:TPU_PFX_BASE64, Env:TPU_PFX_PASSWORD -ErrorAction SilentlyContinue
}
