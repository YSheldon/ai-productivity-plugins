[CmdletBinding()]
param(
    [string]$PluginRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($PluginRoot)) {
    $PluginRoot = Split-Path -Parent $PSScriptRoot
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected', got '$Actual'."
    }
}

function Invoke-ScheduleCheck {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)][string]$UtcTime
    )

    $process = Start-Process -FilePath $ExecutablePath -ArgumentList @("--check-utc", $UtcTime) -PassThru -Wait
    return [string]$process.ExitCode
}

$buildScript = Join-Path $PluginRoot "scripts\Build-WorldTimeReminder.ps1"
if (-not (Test-Path -LiteralPath $buildScript)) {
    throw "Missing world-time reminder build script: $buildScript"
}

$taskXmlScript = Join-Path $PluginRoot "scripts\New-WorldTimeReminderTaskXml.ps1"
if (-not (Test-Path -LiteralPath $taskXmlScript)) {
    throw "Missing world-time reminder task XML generator: $taskXmlScript"
}

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("world-time-reminder-test-{0}" -f $PID)
New-Item -ItemType Directory -Path $temporaryDirectory -Force | Out-Null

try {
    $executablePath = Join-Path $temporaryDirectory "world-time-taskbar.exe"
    & $buildScript -OutputPath $executablePath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $executablePath)) {
        throw "Build did not produce the world-time reminder executable."
    }

    $dueExitCode = Invoke-ScheduleCheck -ExecutablePath $executablePath -UtcTime "2026-08-24T08:00:00Z"
    Assert-Equal -Actual $dueExitCode -Expected "10" -Message "Beijing 16:00 must trigger a reminder."

    $lateExitCode = Invoke-ScheduleCheck -ExecutablePath $executablePath -UtcTime "2026-08-24T08:00:06Z"
    Assert-Equal -Actual $lateExitCode -Expected "0" -Message "A reminder must not appear late within an hour."

    $xmlText = & $taskXmlScript -ExecutablePath $executablePath -UserName "CONTOSO\User" -StartBoundary "2026-08-24T15:45:00"
    [xml]$taskXml = $xmlText -join [Environment]::NewLine
    $namespace = New-Object System.Xml.XmlNamespaceManager($taskXml.NameTable)
    $namespace.AddNamespace("task", "http://schemas.microsoft.com/windows/2004/02/mit/task")

    if ($null -eq $taskXml.SelectSingleNode("/task:Task/task:Triggers/task:LogonTrigger", $namespace)) {
        throw "The unified task is missing its logon recovery trigger."
    }
    Assert-Equal -Actual $taskXml.SelectSingleNode("/task:Task/task:Triggers/task:CalendarTrigger/task:Repetition/task:Interval", $namespace).InnerText -Expected "PT1M" -Message "The unified task must check recovery every minute."
    Assert-Equal -Actual $taskXml.SelectSingleNode("/task:Task/task:Actions/task:Exec/task:Command", $namespace).InnerText -Expected $executablePath -Message "The unified task must launch the merged executable."

    "PASS: exact Beijing scheduling and unified task configuration are verified."
} finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
