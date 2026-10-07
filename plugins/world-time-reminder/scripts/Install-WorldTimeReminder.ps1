[CmdletBinding()]
param(
    [string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA "Programs\WorldTimeReminder"),
    [switch]$RunNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sourceRoot = Split-Path -Parent $PSScriptRoot
$installDirectory = [System.IO.Path]::GetFullPath($InstallDirectory)
New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null

foreach ($directory in @("src", "scripts")) {
    $source = Join-Path $sourceRoot $directory
    $destination = Join-Path $installDirectory $directory
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Get-ChildItem -LiteralPath $source -Force |
        Copy-Item -Destination $destination -Recurse -Force
}

$buildScript = Join-Path $installDirectory "scripts\Build-WorldTimeReminder.ps1"
$executablePath = Join-Path $installDirectory "world-time-taskbar.exe"
& $buildScript -OutputPath $executablePath

$registerScript = Join-Path $installDirectory "scripts\Register-WorldTimeReminderTask.ps1"
& $registerScript -ExecutablePath $executablePath -RunNow:$RunNow

Write-Output "Installed merged world-time reminder to: $installDirectory"
