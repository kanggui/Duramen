# Install Duramen Copilot CLI hooks into a target repository.
# Usage: .\install.ps1 -RepoPath C:\path\to\repo

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$RepoPath
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path $RepoPath -PathType Container)) {
    Write-Error "Error: '$RepoPath' is not a directory"
    exit 1
}

if (-not (Test-Path (Join-Path $RepoPath ".git"))) {
    $reply = Read-Host "Warning: '$RepoPath' does not appear to be a git repository. Continue? [y/N]"
    if ($reply -notmatch '^[Yy]') {
        exit 1
    }
}

$HooksDir = Join-Path $RepoPath ".github\hooks"
New-Item -ItemType Directory -Force -Path $HooksDir | Out-Null

Copy-Item (Join-Path $ScriptDir "duramen.json") -Destination $HooksDir -Force
Copy-Item (Join-Path $ScriptDir "duramen-hook.sh") -Destination $HooksDir -Force
Copy-Item (Join-Path $ScriptDir "duramen-hook.ps1") -Destination $HooksDir -Force

Write-Output "Duramen hooks installed to $HooksDir\"
Write-Output "  - duramen.json"
Write-Output "  - duramen-hook.sh"
Write-Output "  - duramen-hook.ps1"
Write-Output ""

if (Get-Command duramen -ErrorAction SilentlyContinue) {
    Write-Output "[OK] duramen binary found in PATH"
} else {
    Write-Warning "duramen binary not found in PATH"
    Write-Output "  Build with: cargo build --release"
    Write-Output "  Then add target\release\ to your PATH"
}
