# Build-time public reporting configuration. End users never run this script.
# The EXE contains only a public Google Apps Script URL and (optionally)
# a public GitHub OAuth client ID. GitHub PATs stay SERVER-SIDE in Apps Script.
[CmdletBinding()]
param(
    [AllowEmptyString()][string] $GoogleAppsScriptUrl,
    [AllowEmptyString()][string] $GitHubOAuthClientId,
    [switch] $FromEnvironment,
    [switch] $LocalOnly,
    [string] $Repository = 'sgennadi/TermsrvPatcherUnified'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Repository -cne 'sgennadi/TermsrvPatcherUnified') {
    throw 'Reporting configuration is pinned to sgennadi/TermsrvPatcherUnified.'
}
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$defaultFile = Join-Path $root 'config/reporting-defaults.json'
if (-not (Test-Path -LiteralPath $defaultFile -PathType Leaf) -or
    (Get-Item -LiteralPath $defaultFile).Length -gt 4096) {
    throw 'Public Google reporting defaults are missing or too large.'
}
$defaults = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($defaultFile)) -AsHashtable
if ($null -eq $defaults -or $defaults -isnot [System.Collections.IDictionary]) {
    throw 'Public reporting defaults must be a JSON object.'
}
foreach ($name in @($defaults.Keys)) {
    if ($name -cnotin @('google_apps_script_url', 'github_oauth_client_id') -or
        $defaults[$name] -isnot [string]) {
        throw 'Unexpected public reporting configuration field.'
    }
}
if ($FromEnvironment) {
    $GoogleAppsScriptUrl = if ([string]::IsNullOrWhiteSpace($env:TPU_GOOGLE_APPS_SCRIPT_URL)) {
        [string]$defaults['google_apps_script_url']
    } else { [string]$env:TPU_GOOGLE_APPS_SCRIPT_URL }
    $GitHubOAuthClientId = if ([string]::IsNullOrWhiteSpace($env:TPU_GITHUB_OAUTH_CLIENT_ID)) {
        [string]$defaults['github_oauth_client_id']
    } else { [string]$env:TPU_GITHUB_OAUTH_CLIENT_ID }
} else {
    if (-not $PSBoundParameters.ContainsKey('GoogleAppsScriptUrl')) {
        $value = Read-Host 'Google Apps Script /exec URL (Enter keeps repository default)'
        $GoogleAppsScriptUrl = if ([string]::IsNullOrWhiteSpace($value)) {
            [string]$defaults['google_apps_script_url']
        } else { [string]$value }
    }
    if (-not $PSBoundParameters.ContainsKey('GitHubOAuthClientId')) {
        $value = Read-Host 'Optional GitHub OAuth App Client ID (Enter skips)'
        $GitHubOAuthClientId = if ([string]::IsNullOrWhiteSpace($value)) {
            [string]$defaults['github_oauth_client_id']
        } else { [string]$value }
    }
}
$GoogleAppsScriptUrl = ([string]$GoogleAppsScriptUrl).Trim()
$GitHubOAuthClientId = ([string]$GitHubOAuthClientId).Trim()
$approved = $false
if ($GoogleAppsScriptUrl.Length -ge 60 -and $GoogleAppsScriptUrl.Length -le 256) {
    $parsed = $null
    if ([System.Uri]::TryCreate($GoogleAppsScriptUrl,
            [System.UriKind]::Absolute, [ref]$parsed)) {
        $approved = $parsed.Scheme -ceq 'https' -and
            $parsed.Host -ceq 'script.google.com' -and
            $parsed.IsDefaultPort -and $parsed.UserInfo.Length -eq 0 -and
            $parsed.Query.Length -eq 0 -and $parsed.Fragment.Length -eq 0 -and
            $parsed.AbsolutePath -cmatch '^/macros/s/[A-Za-z0-9_-]{25,180}/exec$' -and
            $parsed.AbsoluteUri -ceq $GoogleAppsScriptUrl
    }
}
if (-not $approved) {
    throw 'Google Apps Script must be an approved, public HTTPS /exec deployment URL.'
}
if ($GitHubOAuthClientId.Length -gt 0 -and
    $GitHubOAuthClientId -cnotmatch '^[A-Za-z0-9._-]{8,100}$') {
    throw 'Invalid GitHub OAuth client ID. Never supply the OAuth secret.'
}
$publishVariables = (-not $FromEnvironment) -and (-not $LocalOnly)
if ($publishVariables) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'GitHub CLI (gh) is required to update repository variables; use -LocalOnly to skip.'
    }
    & gh auth status 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Run gh auth login using the repository owner account.' }
    $existing = @(& gh variable list --repo $Repository --json name | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to list repository Actions Variables.' }
    foreach ($item in @(
        @{ Name = 'TPU_GOOGLE_APPS_SCRIPT_URL'; Value = $GoogleAppsScriptUrl },
        @{ Name = 'TPU_GITHUB_OAUTH_CLIENT_ID'; Value = $GitHubOAuthClientId }
    )) {
        if ($item.Value.Length -gt 0) {
            & gh variable set $item.Name --repo $Repository --body $item.Value
            if ($LASTEXITCODE -ne 0) { throw ("Could not set {0}" -f $item.Name) }
        } elseif (@($existing | Where-Object { $_.name -eq $item.Name }).Count -gt 0) {
            & gh variable delete $item.Name --repo $Repository
            if ($LASTEXITCODE -ne 0) { throw ("Could not clear {0}" -f $item.Name) }
        }
    }
}
$dir = Join-Path $root '.build'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$file = Join-Path $dir 'reporting.json'
$payload = ConvertTo-Json -InputObject ([ordered]@{
    google_apps_script_url = $GoogleAppsScriptUrl
    github_oauth_client_id = $GitHubOAuthClientId
}) -Depth 2
$temp = Join-Path $dir ('reporting-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    [System.IO.File]::WriteAllText($temp, $payload, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temp -Destination $file -Force
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
}
Write-Host 'PASS: Google reporting endpoint verified and embedded into EXE build resource.'
Write-Host 'Google reports require explicit review/approval and are published as public GitHub Issues.'
if ($publishVariables) { Write-Host 'PASS: public GitHub Actions Variables saved for future builds.' }
else { Write-Host 'No repository settings changed. Only the build resource was generated.' }
