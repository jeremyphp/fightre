<#
.SYNOPSIS
    Point every repository URL in the docs at the account that will own the repo.

.DESCRIPTION
    Replaces both "your-org/fightre" (placeholder in shipped docs) and
    "<owner>/fightre" (placeholder in launch material) with the real owner.

    Reads and writes UTF-8 **without BOM**, through .NET, because the default
    Get-Content/Set-Content round-trip mangles non-ASCII content on Windows
    PowerShell 5.1 (README.zh-CN.md is Chinese and would be corrupted).

.EXAMPLE
    .\tools\set_repo_owner.ps1 -Owner your-github-username

    # then verify nothing was missed, commit and publish:
    python tools/check_publish_ready.py
    git commit -am "docs: point URLs at the real repository"
    .\tools\publish_github.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Owner,
    [string]$Repo = "fightre"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$tokens = @("your-org/$Repo", "<owner>/$Repo")
$new = "$Owner/$Repo"
$utf8 = New-Object System.Text.UTF8Encoding($false)
$changed = 0

Get-ChildItem -Path $root -Recurse -File -Include *.md, *.toml, *.yml, *.yaml, *.ps1, *.py |
    Where-Object {
        $_.FullName -notmatch '\\\.git\\' -and
        $_.FullName -notmatch '\\__pycache__\\' -and
        $_.Name -ne 'set_repo_owner.ps1' -and
        $_.Name -ne 'check_publish_ready.py'
    } |
    ForEach-Object {
        $text = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $original = $text
        foreach ($token in $tokens) {
            $text = $text.Replace($token, $new)
        }
        if ($text -ne $original) {
            [System.IO.File]::WriteAllText($_.FullName, $text, $utf8)
            Write-Host "updated $($_.FullName)"
            $changed++
        }
    }

Write-Host ""
Write-Host "$changed file(s) now point at https://github.com/$new"
Write-Host "next: python tools/check_publish_ready.py"
