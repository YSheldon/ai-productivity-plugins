@echo off
setlocal
set "ROOT=%~dp0"
set "SCRIPT=%ROOT%bootstrap_windows_project_runner.ps1"
set "PWSH=C:\Program Files\PowerShell\7\pwsh.exe"
set "EXPECTED_SHA256=0cb81ec7fdb703459b5e0f86dcdd69917e1ba51bb87df46915ad33ff4e0e1dc4"

if not exist "%PWSH%" (
  echo PowerShell 7 is required.
  pause
  exit /b 2
)
if not exist "%SCRIPT%" (
  echo Verified bootstrap script is missing.
  pause
  exit /b 2
)

set "PMG_BOOTSTRAP_SCRIPT=%SCRIPT%"
set "PMG_BOOTSTRAP_EXPECTED_SHA256=%EXPECTED_SHA256%"
"%PWSH%" -NoProfile -Command "$path=$env:PMG_BOOTSTRAP_SCRIPT;$expected=$env:PMG_BOOTSTRAP_EXPECTED_SHA256;$actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($actual -ne $expected){Write-Error 'Bootstrap SHA256 mismatch';exit 3};$args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('""{0}""' -f $path));$p=Start-Process -FilePath '%PWSH%' -ArgumentList $args -Verb RunAs -Wait -PassThru;exit $p.ExitCode"
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" echo Provisioning completed.
if not "%RC%"=="0" echo Provisioning failed closed with exit code %RC%.
pause
exit /b %RC%
