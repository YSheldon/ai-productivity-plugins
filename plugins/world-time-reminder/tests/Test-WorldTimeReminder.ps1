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

    $process = Start-Process -FilePath $ExecutablePath -ArgumentList @("--check-utc", $UtcTime) -WindowStyle Hidden -PassThru -Wait
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

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("world-time-reminder-test-{0}" -f [Guid]::NewGuid().ToString("N"))
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

    $unscheduledExitCode = Invoke-ScheduleCheck -ExecutablePath $executablePath -UtcTime "2026-08-24T04:00:00Z"
    Assert-Equal -Actual $unscheduledExitCode -Expected "0" -Message "Beijing 12:00 is not a reminder hour."

    $invalidExitCode = Invoke-ScheduleCheck -ExecutablePath $executablePath -UtcTime "invalid"
    Assert-Equal -Actual $invalidExitCode -Expected "2" -Message "Invalid UTC input must be rejected."

    $xmlText = & $taskXmlScript -ExecutablePath $executablePath -UserName "CONTOSO\User" -StartBoundary "2026-08-24T15:45:00"
    [xml]$taskXml = $xmlText -join [Environment]::NewLine
    $namespace = New-Object System.Xml.XmlNamespaceManager($taskXml.NameTable)
    $namespace.AddNamespace("task", "http://schemas.microsoft.com/windows/2004/02/mit/task")

    if ($null -eq $taskXml.SelectSingleNode("/task:Task/task:Triggers/task:LogonTrigger", $namespace)) {
        throw "The unified task is missing its logon recovery trigger."
    }
    Assert-Equal -Actual $taskXml.SelectSingleNode("/task:Task/task:Triggers/task:CalendarTrigger/task:Repetition/task:Interval", $namespace).InnerText -Expected "PT1M" -Message "The unified task must check recovery every minute."
    Assert-Equal -Actual $taskXml.SelectSingleNode("/task:Task/task:Actions/task:Exec/task:Command", $namespace).InnerText -Expected $executablePath -Message "The unified task must launch the merged executable."

    # Run the real installer against fixture build/registration scripts without
    # touching Task Scheduler or starting the desktop application.
    $fixtureRoot = Join-Path $temporaryDirectory "fixture-plugin"
    $fixtureSource = Join-Path $fixtureRoot "src"
    $fixtureScripts = Join-Path $fixtureRoot "scripts"
    New-Item -ItemType Directory -Force $fixtureSource, $fixtureScripts | Out-Null
    $fixtureInstaller = Join-Path $fixtureScripts "Install-WorldTimeReminder.ps1"
    Copy-Item -LiteralPath (Join-Path $PluginRoot "scripts\Install-WorldTimeReminder.ps1") -Destination $fixtureInstaller
    $fixtureBuild = @'
param([string]$OutputPath)
[IO.File]::WriteAllText($OutputPath, 'fixture executable')
$global:LASTEXITCODE = 0
'@
    $fixtureRegistration = @'
param([string]$ExecutablePath, [switch]$RunNow)
[IO.File]::WriteAllText((Join-Path (Split-Path -Parent $PSScriptRoot) 'registration.txt'), 'VERSION')
'@
    [IO.File]::WriteAllText((Join-Path $fixtureScripts "Build-WorldTimeReminder.ps1"), $fixtureBuild)
    $fixtureRegistrationPath = Join-Path $fixtureScripts "Register-WorldTimeReminderTask.ps1"
    $fixtureSourcePath = Join-Path $fixtureSource "ReminderSchedule.cs"
    [IO.File]::WriteAllText($fixtureRegistrationPath, $fixtureRegistration.Replace("VERSION", "v1"))
    [IO.File]::WriteAllText($fixtureSourcePath, "source-v1")
    $fixtureInstall = Join-Path $temporaryDirectory "fixture-install"
    & $fixtureInstaller -InstallDirectory $fixtureInstall | Out-Null
    Assert-Equal -Actual ([IO.File]::ReadAllText((Join-Path $fixtureInstall "src\ReminderSchedule.cs"))) -Expected "source-v1" -Message "First install must copy the source."
    Assert-Equal -Actual ([IO.File]::ReadAllText((Join-Path $fixtureInstall "registration.txt"))) -Expected "v1" -Message "First install must use the current registration script."

    [IO.File]::WriteAllText($fixtureSourcePath, "source-v2")
    [IO.File]::WriteAllText($fixtureRegistrationPath, $fixtureRegistration.Replace("VERSION", "v2"))
    & $fixtureInstaller -InstallDirectory $fixtureInstall | Out-Null
    Assert-Equal -Actual ([IO.File]::ReadAllText((Join-Path $fixtureInstall "src\ReminderSchedule.cs"))) -Expected "source-v2" -Message "Reinstall must replace the installed source."
    Assert-Equal -Actual ([IO.File]::ReadAllText((Join-Path $fixtureInstall "registration.txt"))) -Expected "v2" -Message "Reinstall must run the updated registration script."
    if ((Test-Path -LiteralPath (Join-Path $fixtureInstall "src\src")) -or (Test-Path -LiteralPath (Join-Path $fixtureInstall "scripts\scripts"))) {
        throw "Reinstall must not create nested source or script directories."
    }

    "PASS: Beijing scheduling, task XML, and isolated reinstall/upgrade are verified."
} finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
