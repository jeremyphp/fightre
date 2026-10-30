<#
.SYNOPSIS
    Point every repository URL in the docs at the account that will own the repo.

.EXAMPLE
    .\tools\set_repo_owner.ps1 -Owner 780420143

    # then commit and publish:
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
$old = "your-org/fightre"
$new = "$Owner/$Repo"
$changed = 0

Get-ChildItem -Path $root -Recurse -File -Include *.md, *.toml, *.yml, *.ps1 |
    Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -ne 'set_repo_owner.ps1' } |
    ForEach-Object {
        $text = Get-Content -Raw $_.FullName
        if ($text -like "*$old*") {
            $text = $text.Replace($old, $new)
            Set-Content -Path $_.FullName -Value $text -NoNewline -Encoding utf8
            Write-Host "updated $($_.FullName)"
            $changed++
        }
    }

Write-Host "$changed file(s) now point at https://github.com/$new"
