<#
.SYNOPSIS
    Publish FightRE to GitHub: create the repository, push, set metadata, tag and release.

.DESCRIPTION
    Token resolution order:
      1. $env:GH_TOKEN or $env:GITHUB_TOKEN
      2. github.txt: two whitespace-separated fields -> "owner-or-email  token"

    The token must be a fine-grained PAT with, for the target repository:
      - Administration: Read and write (create the repo)
      - Contents: Read and write (push)
      - Metadata: Read (implicit)

    A GitHub account password is NOT a token and cannot be used here; GitHub
    removed password authentication for the API and for git.

.EXAMPLE
    # put "my-login  github_pat_xxx" in github.txt, then:
    .\tools\publish_github.ps1
#>
[CmdletBinding()]
param(
    [string]$Repo = "fightre",
    [string]$Description = "Five-layer anti-reverse-engineering defense for the age of AI agents: PoW attestation, honey-schemas, canaries, native audit.",
    [string]$Tag = "v0.2.0",
    [switch]$Private
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $token = $env:GH_TOKEN
    if (-not $token) { $token = $env:GITHUB_TOKEN }
    if (-not $token) {
        $credFile = Join-Path $root "github.txt"
        if (Test-Path $credFile) {
            $parts = ((Get-Content -Raw $credFile).Trim() -split '\s+')
            if ($parts.Count -ge 2) { $token = $parts[1] }
            elseif ($parts.Count -eq 1) { $token = $parts[0] }
        }
    }
    if (-not $token) { throw "No token found. Set GH_TOKEN or put '<login> <token>' in github.txt." }
    if ($token -notmatch '^(gh[pousr]_|github_pat_)') {
        Write-Warning "The value does not look like a GitHub token (expected ghp_/github_pat_)."
    }

    $headers = @{
        Authorization          = "Bearer $token"
        Accept                 = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent"           = "fightre-publish"
    }

    Write-Host "Authenticating..."
    $me = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $headers
    $owner = $me.login
    Write-Host "Authenticated as $owner"

    $repoUri = "https://api.github.com/repos/$owner/$Repo"
    $exists = $false
    try {
        Invoke-RestMethod -Uri $repoUri -Headers $headers | Out-Null
        $exists = $true
        Write-Host "Repository $owner/$Repo already exists."
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
    }

    if (-not $exists) {
        Write-Host "Creating repository $owner/$Repo..."
        $payload = @{
            name        = $Repo
            description = $Description
            private     = [bool]$Private
            has_issues  = $true
            has_wiki    = $false
            has_projects = $false
        } | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri "https://api.github.com/user/repos" -Headers $headers `
            -Body $payload -ContentType "application/json" | Out-Null
    }

    Write-Host "Setting description and topics..."
    $topics = @(
        "anti-reverse-engineering", "bot-detection", "ja3", "tls-fingerprint",
        "proof-of-work", "deception", "canary-tokens", "security", "python",
        "asgi", "wsgi", "mcp", "ai-agents", "reverse-engineering"
    )
    Invoke-RestMethod -Method Put -Uri "$repoUri/topics" -Headers $headers `
        -Body (@{ names = $topics } | ConvertTo-Json) -ContentType "application/json" | Out-Null

    if (-not (git tag --list $Tag)) {
        git tag -a $Tag -m "FightRE $Tag"
    }

    Write-Host "Pushing main and $Tag..."
    $pushUrl = "https://x-access-token:$token@github.com/$owner/$Repo.git"
    & git push --quiet $pushUrl main
    if ($LASTEXITCODE -ne 0) { throw "git push main failed" }
    & git push --quiet $pushUrl $Tag
    if ($LASTEXITCODE -ne 0) { throw "git push tag failed" }

    # Leave a clean remote behind: never keep the token in .git/config.
    & git remote remove origin 2>$null
    & git remote add origin "https://github.com/$owner/$Repo.git"

    Write-Host "Creating release $Tag..."
    $body = @"
FightRE $Tag — five-layer anti-reverse-engineering defense for web services.

- L1 rate/path diversity · L2 header + JA3/HTTP2 fingerprints · L3 PoW attestation
- L4 request signing, honeypots, fabricated OpenAPI (honey-schema) · L5 canaries and watermarks
- Native: ELF/PE/Mach-O audit, runtime self-check, signed build manifests
- Shared state: zero-dependency RESP2 client, Redis nonce/rate/canary stores
- Android/iOS reference guards with Play Integrity / App Attest interfaces

Tests: 145 unit tests, end-to-end demo, CI on Python 3.9/3.11/3.13.
"@
    $releasePayload = @{
        tag_name   = $Tag
        name       = "FightRE $Tag"
        body       = $body
        draft      = $false
        prerelease = $false
    } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri "https://api.github.com/repos/$owner/$Repo/releases/tags/$Tag" -Headers $headers | Out-Null
        Write-Host "Release already exists."
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 404) {
            Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$owner/$Repo/releases" `
                -Headers $headers -Body $releasePayload -ContentType "application/json" | Out-Null
        } else { throw }
    }

    Write-Host ""
    Write-Host "Published: https://github.com/$owner/$Repo"
    Write-Host "Release:   https://github.com/$owner/$Repo/releases/tag/$Tag"
} finally {
    Pop-Location
}
