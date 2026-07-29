@echo off
setlocal
set "ROOT=%~dp0"
set "SCRIPT=%ROOT%bootstrap_windows_project_runner.ps1"
set "WRAPPER=%ROOT%run_windows_project_runner_bootstrap_elevated.ps1"
set "DIAGNOSTIC=%ROOT%artifacts\runner-provisioning-diagnostic.json"
set "PWSH=C:\Program Files\PowerShell\7\pwsh.exe"
set "EXPECTED_SHA256=0cb81ec7fdb703459b5e0f86dcdd69917e1ba51bb87df46915ad33ff4e0e1dc4"
set "EXPECTED_WRAPPER_SHA256=40e69f5bc9b8a71005b0fb184f079fdcfe814e70eeb2bda114f7734037c26f9e"

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
if not exist "%WRAPPER%" (
  echo Verified elevated bootstrap wrapper is missing.
  pause
  exit /b 2
)

set "PMG_BOOTSTRAP_SCRIPT=%SCRIPT%"
set "PMG_BOOTSTRAP_WRAPPER=%WRAPPER%"
set "PMG_BOOTSTRAP_DIAGNOSTIC=%DIAGNOSTIC%"
set "PMG_BOOTSTRAP_EXPECTED_SHA256=%EXPECTED_SHA256%"
set "PMG_BOOTSTRAP_EXPECTED_WRAPPER_SHA256=%EXPECTED_WRAPPER_SHA256%"
if exist "%DIAGNOSTIC%" del /f /q "%DIAGNOSTIC%" >nul 2>nul
"%PWSH%" -NoProfile -Command "$path=$env:PMG_BOOTSTRAP_SCRIPT;$wrapper=$env:PMG_BOOTSTRAP_WRAPPER;$diagnostic=$env:PMG_BOOTSTRAP_DIAGNOSTIC;$expected=$env:PMG_BOOTSTRAP_EXPECTED_SHA256;$expectedWrapper=$env:PMG_BOOTSTRAP_EXPECTED_WRAPPER_SHA256;$actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($actual -ne $expected){Write-Error 'Bootstrap SHA256 mismatch';exit 3};$actualWrapper=(Get-FileHash -LiteralPath $wrapper -Algorithm SHA256).Hash.ToLowerInvariant();if($actualWrapper -ne $expectedWrapper){Write-Error 'Elevated wrapper SHA256 mismatch';exit 4};$args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('""{0}""' -f $wrapper),'-BootstrapPath',('""{0}""' -f $path),'-ExpectedBootstrapSha256',$expected,'-DiagnosticPath',('""{0}""' -f $diagnostic));$p=Start-Process -FilePath '%PWSH%' -ArgumentList $args -Verb RunAs -Wait -PassThru;exit $p.ExitCode"
set "RC=%ERRORLEVEL%"
set "DIAGCODE="
for /f "usebackq delims=" %%A in (`"%PWSH%" -NoProfile -Command "$p=$env:PMG_BOOTSTRAP_DIAGNOSTIC;if(Test-Path -LiteralPath $p){try{$d=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json;if($d.schema -eq 'PmgRunnerProvisioningDiagnostic/v1' -and $d.status -eq 'failed' -and ([string]$d.code -match '^E_[A-Z0-9_]+$')){[Console]::Write($d.code)}}catch{}}" `) do set "DIAGCODE=%%A"
echo.
if "%RC%"=="0" echo Provisioning completed.
if not "%RC%"=="0" if not "%DIAGCODE%"=="" echo Provisioning failed closed with code %DIAGCODE%.
if not "%RC%"=="0" if "%DIAGCODE%"=="" echo Provisioning failed closed with exit code %RC%.
pause
exit /b %RC%
