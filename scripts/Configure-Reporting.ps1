# One-time ADMIN / BUILD configuration. End users NEVER run this script.
# The output is an EmbeddedResource inside TermsrvPatcherUnified.exe.
# No GitHub PATs, OAuth client secrets, Formspree API keys or credentials are stored.
[CmdletBinding()]
param(
    [AllowEmptyString()][string] $FormspreeFormId,
    [AllowEmptyString()][string] $GitHubOAuthClientId,
    [switch] $FromEnvironment,
    [switch] $LocalOnly,
    [string] $Repository = 'sgennadi/TermsrvPatcherUnified'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedRepo = 'sgennadi/TermsrvPatcherUnified'
if ($Repository -cne $expectedRepo) {
    throw "Reporting setup is pinned to $expectedRepo; refusing another repository."
}
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$generatedDir = Join-Path $root '.build'
$generatedFile = Join-Path $generatedDir 'reporting.json'
$publishVariables = (-not $FromEnvironment) -and (-not $LocalOnly)

if ($publishVariables) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "GitHub CLI (gh) is required for one-time repository variables setup. Install gh and run 'gh auth login', or use -LocalOnly."
    }
    & gh auth status 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub CLI is not signed in. Run 'gh auth login' on the administrator's PC (only once)."
    }
}
if ($FromEnvironment) {
    # No prompts, network requests or gh authentication in CI.
    # Unset variables produce disabled, never fake, reporting providers.
    $FormspreeFormId = [string] $env:TPU_FORMSPREE_FORM_ID
    $GitHubOAuthClientId = [string] $env:TPU_GITHUB_OAUTH_CLIENT_ID
} else {
    if (-not $PSBoundParameters.ContainsKey('FormspreeFormId')) {
        $FormspreeFormId = Read-Host 'Formspree Form ID (blank disables this provider)'
    }
    if (-not $PSBoundParameters.ContainsKey('GitHubOAuthClientId')) {
        $GitHubOAuthClientId = Read-Host 'GitHub OAuth App Client ID (blank disables this provider)'
    }
}
$FormspreeFormId = ([string] $FormspreeFormId).Trim()
$GitHubOAuthClientId = ([string] $GitHubOAuthClientId).Trim()
if ($FormspreeFormId.Length -gt 0 -and $FormspreeFormId -cnotmatch '^[A-Za-z0-9]{6,40}$') {
    throw 'Invalid Formspree Form ID: expected 6-40 ASCII letters or digits (not a full URL).'
}
if ($GitHubOAuthClientId.Length -gt 0 -and $GitHubOAuthClientId -cnotmatch '^[A-Za-z0-9._-]{8,100}$') {
    throw 'Invalid GitHub OAuth App Client ID (not a secret or URL).'
}
if ($publishVariables -and $FormspreeFormId.Length -eq 0 -and $GitHubOAuthClientId.Length -eq 0) {
    throw 'No provider IDs were supplied. Nothing was changed in GitHub.'
}
# Public IDs may be stored as repository VARIABLES (not Secrets). They are
# embedded into subsequent Actions-built EXEs, including normal updates.
# No Formspree/GitHub tokens or private credentials ever enter the EXE.
if ($publishVariables) {
    $existing = @(& gh variable list --repo $Repository --json name | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to read existing GitHub repository variables.'
    }
    foreach ($item in @(
        @{ Name = 'TPU_FORMSPREE_FORM_ID'; Value = $FormspreeFormId },
        @{ Name = 'TPU_GITHUB_OAUTH_CLIENT_ID'; Value = $GitHubOAuthClientId }
    )) {
        if ($item.Value.Length -gt 0) {
            & gh variable set $item.Name --repo $Repository --body $item.Value
            if ($LASTEXITCODE -ne 0) {
                throw ("Could not update GitHub Actions variable {0}." -f $item.Name)
            }
        } elseif (@($existing | Where-Object { $_.name -eq $item.Name }).Count -gt 0) {
            # Explicitly clearing a provider must not leave an old ID in CI.
            & gh variable delete $item.Name --repo $Repository
            if ($LASTEXITCODE -ne 0) {
                throw ("Could not clear obsolete GitHub Actions variable {0}." -f $item.Name)
            }
        }
    }
}
New-Item -ItemType Directory -Path $generatedDir -Force | Out-Null
$values = [ordered]@{
    formspree_form_id = $FormspreeFormId
    github_oauth_client_id = $GitHubOAuthClientId
}
$json = ConvertTo-Json -InputObject $values -Depth 2
# Atomic overwrite; never use the local machine ProgramData directory.
$tmp = Join-Path $generatedDir ('reporting-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $generatedFile -Force
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
}
$formStatus = if ($FormspreeFormId.Length -gt 0) { 'configured' } else { 'disabled' }
$githubStatus = if ($GitHubOAuthClientId.Length -gt 0) { 'configured' } else { 'disabled' }
Write-Host ('Formspree: {0}; GitHub OAuth: {1}' -f $formStatus, $githubStatus)
Write-Host 'PASS: generated private build-time reporting.json for embedding in TermsrvPatcherUnified.exe.'
if ($publishVariables) {
    Write-Host 'PASS: repository variables saved. Future GitHub Actions builds will embed these public IDs automatically.'
} else {
    Write-Host 'No GitHub variables were changed. Local build uses the generated resource only.'
}
Write-Host 'Note: users do not configure provider IDs; actual report sending still requires their explicit approval.'
