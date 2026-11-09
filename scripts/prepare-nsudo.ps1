#Requires -Version 7.0
param([string]$OutDir = "ThirdParty/NSudo/x64")
$ErrorActionPreference = 'Stop'

# Official NSudo 8.2 stable release (archived by M2-Team).
$source = 'https://github.com/M2TeamArchived/NSudo/releases/download/8.2/NSudo_8.2_All_Components.zip'
# SHA256 of the complete official 8.2 archive, recorded by an independent 2024 archive scan.
$archiveSha256 = '346e38030cc9eeef48223804ba27631db96691d68bfc5d1728140d468f555204'
# Secondary binary identity check (not used alone as a cryptographic guarantee).
$expectedX64Md5 = '5ed8991f370151275e73f53a9a3474e3'
$temp = Join-Path ([IO.Path]::GetTempPath()) ('nsudo-8.2-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $archive = Join-Path $temp 'NSudo_8.2_All_Components.zip'
    # Prefer the official pinned archive; if its archived CDN is unavailable,
    # recover the IDENTICAL, SHA-256-pinned library from our previously
    # verified preview.6 CI artifact. Never accept unverified native code.
    $downloaded = $false
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            if (Test-Path -LiteralPath $archive) {
                Remove-Item -LiteralPath $archive -Force
            }
            Invoke-WebRequest -Uri $source -OutFile $archive -MaximumRedirection 5 -TimeoutSec 45 -ErrorAction Stop
            $downloaded = $true
            break
        }
        catch {
            Write-Warning "Official NSudo 8.2 download unavailable (attempt $attempt of 2)."
            if ($attempt -lt 2) { Start-Sleep -Seconds 3 }
        }
    }
    if (-not $downloaded) {
        if ($env:GITHUB_REPOSITORY -ne 'sgennadi/TermsrvPatcherUnified' -or
            [string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
            throw "Official NSudo archive unavailable and authenticated CI artifact recovery is not available."
        }
        $artifactFolder = Join-Path $temp 'previous-preview'
        New-Item -ItemType Directory -Force -Path $artifactFolder | Out-Null
        gh run download 42562651909 --repo 'sgennadi/TermsrvPatcherUnified' --name 'TermsrvPatcherUnified-preview-win-x64' --dir $artifactFolder
        if ($LASTEXITCODE -ne 0) { throw 'Pinned prior preview GitHub Actions artifact cannot be downloaded.' }
        $trustedPriorZip = Join-Path $artifactFolder 'TermsrvPatcherUnified-win-x64.zip'
        python scripts/recover-nsudo-from-preview.py $trustedPriorZip $OutDir
        if ($LASTEXITCODE -ne 0) { throw 'Pinned prior preview failed NSudo recovery checks.' }
        return
    }
    $sha256 = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha256 -ne $archiveSha256) {
        throw "NSudo 8.2 release ZIP checksum differs from pinned expected value. No DLL will be staged."
    }
    $extracted = Join-Path $temp 'release'
    Expand-Archive -LiteralPath $archive -DestinationPath $extracted -Force
    $matches = @(Get-ChildItem -LiteralPath $extracted -Recurse -File -Filter 'NSudoDM.dll' |
        Where-Object { (Get-FileHash $_.FullName -Algorithm MD5).Hash.ToLowerInvariant() -eq $expectedX64Md5 })
    if ($matches.Count -ne 1) { throw "Expected unique NSudo 8.2 x64 DLL was not found." }
    $dll = $matches[0].FullName
    $data = [System.IO.File]::ReadAllBytes($dll)
    if ($data.Length -lt 8192 -or $data[0] -ne 0x4D -or $data[1] -ne 0x5A) {
        throw 'NSudo binary is not a valid MZ file.'
    }
    $pe = [BitConverter]::ToInt32($data, 0x3C)
    if ($pe -lt 0 -or $pe -gt $data.Length - 24 -or
        $data[$pe] -ne 0x50 -or $data[$pe+1] -ne 0x45 -or
        [BitConverter]::ToUInt16($data, $pe+4) -ne 0x8664 -or
        ([BitConverter]::ToUInt16($data, $pe+22) -band 0x2000) -eq 0) {
        throw 'NSudo binary is not an AMD64 DLL.'
    }
    $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dll).FileVersion
    if (-not $version.StartsWith('8.2')) { throw "Unexpected NSudo version: $version" }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    Copy-Item -LiteralPath $dll -Destination (Join-Path $OutDir 'NSudoDM.dll') -Force
    $dllSha = (Get-FileHash (Join-Path $OutDir 'NSudoDM.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText((Join-Path $OutDir 'NSudoDM.sha256'), $dllSha)
    Write-Output "NSudo 8.2 x64 prepared and verified (SHA256: $dllSha)"
}
finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
