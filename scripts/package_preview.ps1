# Sole packager used by Windows CI and release; no external runtime sidecars.
param([string] $PublishDir = 'publish')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $root
try {
    $exe = Join-Path $PublishDir 'TermsrvPatcherUnified.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Missing published EXE: $exe" }
    $stage = Join-Path $root 'preview-package'
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    New-Item -Path $stage -ItemType Directory | Out-Null
    Copy-Item -LiteralPath $exe -Destination (Join-Path $stage 'TermsrvPatcherUnified.exe') -Force

    # Retain complete legal text within Example.txt to honor exactly two files.
    $body = [System.Text.StringBuilder]::new()
    [void] $body.AppendLine([System.IO.File]::ReadAllText((Join-Path $root 'Example.txt')).TrimEnd())
    $sections = @(
        @{ Title = 'PROJECT NOTICES'; Path = 'NOTICE.md' },
        @{ Title = 'GPLv3 LICENSE'; Path = 'LICENSE' },
        @{ Title = 'NSUDO MIT LICENSE'; Path = 'licenses/NSudo-MIT.txt' },
        @{ Title = 'FABIANOSRC MIT LICENSE'; Path = 'licenses/fabianosrc-MIT.txt' }
    )
    foreach ($section in $sections) {
        $source = Join-Path $root $section.Path
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing license: $($section.Path)" }
        [void] $body.AppendLine()
        [void] $body.AppendLine("========== BEGIN $($section.Title) ==========")
        [void] $body.AppendLine([System.IO.File]::ReadAllText($source).TrimEnd())
        [void] $body.AppendLine("========== END $($section.Title) ==========")
    }
    [System.IO.File]::WriteAllText((Join-Path $stage 'Example.txt'),
        $body.ToString(), [System.Text.UTF8Encoding]::new($false))
    $fullZip = 'TermsrvPatcherUnified-win-x64.zip'
    $updateZip = 'TermsrvPatcherUnified-update-win-x64.zip'
    foreach ($zipName in @($fullZip, $updateZip)) {
        if (Test-Path -LiteralPath $zipName) { Remove-Item -LiteralPath $zipName -Force }
    }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $fullZip -CompressionLevel Optimal
    Compress-Archive -LiteralPath $exe -DestinationPath $updateZip -CompressionLevel Optimal
    python scripts/verify_update_package.py --full $fullZip
    if ($LASTEXITCODE -ne 0) { throw 'Invalid portable ZIP' }
    python scripts/verify_update_package.py $updateZip
    if ($LASTEXITCODE -ne 0) { throw 'Invalid updater ZIP' }
    $sums = foreach ($name in @($fullZip, $updateZip)) {
        '{0}  {1}' -f (Get-FileHash $name -Algorithm SHA256).Hash.ToLowerInvariant(), $name
    }
    Set-Content SHA256SUMS.txt -Value $sums -Encoding ascii
    Write-Host 'PASS: portable EXE + Example.txt; updater EXE only.'
}
finally { Pop-Location }
