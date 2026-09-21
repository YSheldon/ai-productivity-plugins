[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [string]$TaskName = "WorldTimeReminder",
    [switch]$RunNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$executablePath = [System.IO.Path]::GetFullPath($ExecutablePath)
if (-not (Test-Path -LiteralPath $executablePath)) {
    throw "Missing world-time reminder executable: $executablePath"
}

function Invoke-TaskTool {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $taskTool = Join-Path $env:WINDIR "System32\schtasks.exe"
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $taskTool
    $processInfo.Arguments = ($Arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + $_.Replace('"', '\"') + '"' } else { $_ } }) -join " "
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    [void]$process.Start()
    $standardOutput = $process.StandardOutput.ReadToEnd()
    $standardError = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = ($standardOutput + $standardError).Trim() }
}

function Remove-TaskIfPresent {
    param([Parameter(Mandatory = $true)][string]$Name)

    $query = Invoke-TaskTool -Arguments @("/Query", "/TN", "\$Name")
    if ($query.ExitCode -eq 0) {
        $delete = Invoke-TaskTool -Arguments @("/Delete", "/TN", "\$Name", "/F")
        if ($delete.ExitCode -ne 0) {
            throw "Failed to remove task '$Name': $($delete.Output)"
        }
    }
}

$nextMinute = (Get-Date).AddMinutes(1)
$nextMinute = Get-Date -Date $nextMinute -Second 0 -Millisecond 0
if ($nextMinute -le (Get-Date)) {
    $nextMinute = $nextMinute.AddMinutes(1)
}

$generator = Join-Path $PSScriptRoot "New-WorldTimeReminderTaskXml.ps1"
$taskXml = & $generator -ExecutablePath $executablePath -UserName ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -StartBoundary $nextMinute.ToString("yyyy-MM-ddTHH:mm:ss", [Globalization.CultureInfo]::InvariantCulture)
$xmlPath = Join-Path ([System.IO.Path]::GetTempPath()) ("{0}-{1}.xml" -f $TaskName, $PID)

try {
    [System.IO.File]::WriteAllText($xmlPath, ($taskXml -join [Environment]::NewLine), [System.Text.Encoding]::Unicode)
    $create = Invoke-TaskTool -Arguments @("/Create", "/TN", "\$TaskName", "/XML", $xmlPath, "/F")
    if ($create.ExitCode -ne 0) {
        throw "Failed to register task '$TaskName': $($create.Output)"
    }
} finally {
    if (Test-Path -LiteralPath $xmlPath) {
        Remove-Item -LiteralPath $xmlPath -Force
    }
}

Remove-TaskIfPresent -Name "FirstDutyRestReminder"

$startupDirectory = [Environment]::GetFolderPath("Startup")
foreach ($legacyStartupItem in @("FirstDutyRestReminder.cmd", "Beijing Taskbar Time.lnk")) {
    $legacyPath = Join-Path $startupDirectory $legacyStartupItem
    if (Test-Path -LiteralPath $legacyPath) {
        Remove-Item -LiteralPath $legacyPath -Force
    }
}

Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
    Where-Object { $_.CommandLine -like "*FirstDutyRestReminder.ps1*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

if ($RunNow) {
    Get-Process -Name "world-time-taskbar" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    $run = Invoke-TaskTool -Arguments @("/Run", "/TN", "\$TaskName")
    if ($run.ExitCode -ne 0) {
        throw "Failed to run task '$TaskName': $($run.Output)"
    }
}

Write-Output "Registered unified world-time reminder task: $TaskName"
