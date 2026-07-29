#Requires -Version 7.0
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BootstrapPath,
    [Parameter(Mandatory)][string]$ExpectedBootstrapSha256,
    [Parameter(Mandatory)][string]$DiagnosticPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$LiteralPath)
    (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-DiagnosticCode {
    param([Parameter(Mandatory)][System.Exception]$Exception)

    $message = [string]$Exception.Message
    if ($message -match 'Pinned download|Windows curl') { return 'E_PINNED_DOWNLOAD' }
    if ($message -match 'Python installer|Python runtime') { return 'E_PYTHON_RUNTIME' }
    if ($message -match 'GitLab plugin|Plugin') { return 'E_PLUGIN_INSTALL' }
    if ($message -match 'manager token|credential') { return 'E_MANAGER_CREDENTIAL' }
    if ($message -match 'admin CLI|Runner') { return 'E_RUNNER_PROVISION' }
    if ($message -match 'identity receipt|service') { return 'E_RUNNER_ATTESTATION' }
    return 'E_BOOTSTRAP_FAILED'
}

function Assert-DiagnosticPath {
    $stageRoot = Split-Path -Parent $BootstrapPath
    $expectedPath = Join-Path (Join-Path $stageRoot 'artifacts') 'runner-provisioning-diagnostic.json'
    $actualPath = [IO.Path]::GetFullPath($DiagnosticPath)
    if (-not [string]::Equals($actualPath, [IO.Path]::GetFullPath($expectedPath), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Diagnostic path does not match the fixed bootstrap artifact location'
    }
}

try {
    if (-not (Test-Path -LiteralPath $BootstrapPath -PathType Leaf)) {
        throw 'Verified bootstrap script is missing'
    }
    if ((Get-Sha256 -LiteralPath $BootstrapPath) -ne $ExpectedBootstrapSha256.ToLowerInvariant()) {
        throw 'Verified bootstrap script SHA256 mismatch'
    }
    Assert-DiagnosticPath

    & $BootstrapPath
    if ($LASTEXITCODE -ne 0) {
        throw 'Verified bootstrap script returned a nonzero exit code'
    }
}
catch {
    $code = Get-DiagnosticCode -Exception $_.Exception
    $receiptRoot = Split-Path -Parent $DiagnosticPath
    New-Item -ItemType Directory -Path $receiptRoot -Force | Out-Null
    $diagnostic = [ordered]@{
        schema = 'PmgRunnerProvisioningDiagnostic/v1'
        status = 'failed'
        code = $code
        bootstrap_sha256 = $ExpectedBootstrapSha256.ToLowerInvariant()
        completed_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    [IO.File]::WriteAllText(
        $DiagnosticPath,
        (($diagnostic | ConvertTo-Json -Depth 5) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )
    exit 1
}
