# Verify the exact signed EXE bytes in both release archives before publishing.
param([string] $PublishDir = 'publish')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $root (Join-Path $PublishDir 'TermsrvPatcherUnified.exe')
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Published EXE missing.' }
$pin = $env:TPU_SIGNER_SPKI_SHA256
if ($pin -notmatch '^[a-fA-F0-9]{64}$') { throw 'Pinned signer SPKI is missing.' }
$expected = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$temporary = Join-Path $env:RUNNER_TEMP ('tpu-archive-verify-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $temporary -ItemType Directory | Out-Null
try {
    foreach ($archive in @('TermsrvPatcherUnified-win-x64.zip', 'TermsrvPatcherUnified-update-win-x64.zip')) {
        $zip = Join-Path $root $archive
        if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { throw "Missing release archive: $archive" }
        $folder = Join-Path $temporary ([IO.Path]::GetFileNameWithoutExtension($archive))
        Expand-Archive -LiteralPath $zip -DestinationPath $folder
        $exe = Join-Path $folder 'TermsrvPatcherUnified.exe'
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Archive has no executable: $archive" }
        if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $expected) {
            throw "Archive payload differs from signed release EXE: $archive"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $exe
        if ($null -eq $signature.SignerCertificate -or
            $signature.Status -in @([System.Management.Automation.SignatureStatus]::NotSigned,
                                    [System.Management.Automation.SignatureStatus]::HashMismatch)) {
            throw "Missing or damaged Authenticode signature in $archive"
        }
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($signature.SignerCertificate)
        if ($null -eq $rsa) { throw "Non-RSA signing key in $archive" }
        try { $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rsa.ExportSubjectPublicKeyInfo())) }
        finally { $rsa.Dispose() }
        if ($actual -ne $pin) { throw "Untrusted signing key in $archive" }
        Write-Host "PASS: $archive contains the exact signed, pinned EXE."
    }
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
