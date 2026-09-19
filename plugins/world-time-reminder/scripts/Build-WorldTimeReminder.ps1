[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\build\world-time-taskbar.exe")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sourceDirectory = Join-Path $PSScriptRoot "..\src"
$sources = @(Get-ChildItem -LiteralPath $sourceDirectory -Filter "*.cs" -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
if ($sources.Count -lt 1) {
    throw "No C# source files were found in $sourceDirectory"
}

$compilerCandidates = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
)
$compiler = $compilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($null -eq $compiler) {
    throw "A .NET Framework C# compiler was not found."
}

$outputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

& $compiler /nologo /target:winexe ("/out:{0}" -f $outputPath) /r:System.Windows.Forms.dll /r:System.Drawing.dll $sources
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputPath)) {
    throw "Failed to build world-time reminder."
}

Write-Output $outputPath
