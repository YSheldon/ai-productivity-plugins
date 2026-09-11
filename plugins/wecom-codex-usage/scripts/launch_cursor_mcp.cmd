@echo off
setlocal EnableExtensions
set "ROOT=%~dp0.."
for %%I in ("%ROOT%") do set "ROOT=%%~fI"
cd /d "%ROOT%" || (
  echo Failed to enter plugin root 1>&2
  exit /b 1
)
set "PATH=%SystemRoot%\System32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0;%ProgramFiles%\nodejs;%ProgramFiles(x86)%\nodejs;%LocalAppData%\Programs\nodejs;%LocalAppData%\Programs\Python\Launcher;%PATH%"
py -3 "%ROOT%\src\wecom_codex_usage_mcp.py"
