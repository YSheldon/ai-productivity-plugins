[CmdletBinding()]
param(
    [switch]$RemoveState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$taskTool = Join-Path $env:WINDIR "System32\schtasks.exe"
& $taskTool /Delete /TN "\WorldTimeReminder" /F 2>$null | Out-Null

Get-Process -Name "world-time-taskbar" -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

if ($RemoveState) {
    $stateDirectory = Join-Path $env:LOCALAPPDATA "WorldTimeReminder"
    if (Test-Path -LiteralPath $stateDirectory) {
        Remove-Item -LiteralPath $stateDirectory -Recurse -Force
    }
}

Write-Output "Removed unified world-time reminder task."
