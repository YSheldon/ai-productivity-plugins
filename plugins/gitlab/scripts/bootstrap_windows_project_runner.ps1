#Requires -Version 7.0
#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PolicyName = 'product-material-gate-runner1'
$PluginCommit = '9d0a8bf75f810a4f2dee0a86467a7c4487ab9baf'
$PythonUrl = 'https://www.python.org/ftp/python/3.13.14/python-3.13.14-amd64.exe'
$PythonInstallerSha256 = 'c54d9b9bbb8a36e6489363ddd01139707fd781d72f1f9e90c7ec65d0061368e0'
$PythonSignerThumbprint = '9BA3C2E210C7E8296C5056515BFC0B0BBA78AC48'
$PythonSignerSubject = 'CN=Python Software Foundation, O=Python Software Foundation, L=Beaverton, S=Oregon, C=US'
$PythonFileVersion = '3.13.14150.0'
$PluginFiles = [ordered]@{
    'scripts\runner_admin_cli.py' = '3a6a718a28cba0cc481d788b905b139d62c450e56869505b0ae3ddc1050f19a2'
    'scripts\invoke_schannel.ps1' = '45281b9dfaa660f986206f036f52cf40f362b484b9a5ba416b6874bac6b57dd1'
    'src\gitlab_mcp.py' = 'cafa86ab5862a19cee0f916de6f414a20f9cb4b66d94774adf5267064a5fd556'
    'src\runner_manager_credentials.py' = '55fdbb5fb30f581257034e6fb58f684796aa9b2ab552514110ae22a9e8378215'
}

$StageRoot = $PSScriptRoot
$PythonInstaller = Join-Path $StageRoot 'python-runtime.exe'
$PluginStageRoot = Join-Path $StageRoot 'gitlab-admin'
$ProgramFilesRoot = [Environment]::GetFolderPath('ProgramFiles')
$ProductRoot = Join-Path $ProgramFilesRoot 'ProductMaterialGate'
$PythonRoot = Join-Path $ProductRoot 'RunnerAdminPython'
$PluginRoot = Join-Path $ProductRoot 'RunnerAdminGitLab'
$PythonExe = Join-Path $PythonRoot 'python.exe'
$AdminCli = Join-Path $PluginRoot 'scripts\runner_admin_cli.py'
$RuntimeRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) (
    'CodexGitLab\runners\' + $PolicyName
)
$JournalPath = Join-Path $RuntimeRoot 'provisioning-state.json'
$IdentityPath = Join-Path $RuntimeRoot 'runner-identity.json'
$ReceiptRoot = Join-Path $StageRoot 'artifacts'
$ReceiptPath = Join-Path $ReceiptRoot 'runner-provisioning-result.json'
$CurlExe = Join-Path $env:WINDIR 'System32\curl.exe'

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$LiteralPath)
    (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularFile {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "$Label is missing"
    }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point"
    }
}

function Invoke-PinnedDownload {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )
    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $currentMatches = (
        (Test-Path -LiteralPath $Destination -PathType Leaf) -and
        (Get-Sha256 -LiteralPath $Destination) -eq $ExpectedSha256
    )
    if (-not $currentMatches) {
        Assert-RegularFile -LiteralPath $CurlExe -Label 'Windows curl'
        & $CurlExe --fail --silent --show-error --proto '=https' --tlsv1.2 --output $Destination $Url
        if ($LASTEXITCODE -ne 0) {
            throw "Pinned download failed: $Url"
        }
    }
    Assert-RegularFile -LiteralPath $Destination -Label 'Pinned downloaded file'
    if ((Get-Sha256 -LiteralPath $Destination) -ne $ExpectedSha256) {
        throw "Pinned download SHA256 does not match: $Url"
    }
}

function New-ProtectedDirectoryAcl {
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($system, $administrators)) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    $acl
}

function New-ProtectedFileAcl {
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($system, $administrators)) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    $acl
}

function Set-ProtectedTreeAcl {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $root = Get-Item -LiteralPath $LiteralPath -Force
    if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Protected root must not be a reparse point: $LiteralPath"
    }
    Set-Acl -LiteralPath $LiteralPath -AclObject (New-ProtectedDirectoryAcl)
    foreach ($item in Get-ChildItem -LiteralPath $LiteralPath -Force -Recurse) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Protected tree contains a reparse point: $($item.FullName)"
        }
        if ($item.PSIsContainer) {
            Set-Acl -LiteralPath $item.FullName -AclObject (New-ProtectedDirectoryAcl)
        }
        else {
            Set-Acl -LiteralPath $item.FullName -AclObject (New-ProtectedFileAcl)
        }
    }
}

function Invoke-AdminCli {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('provision', 'resume', 'token-status')]
        [string]$Action
    )
    $output = @(& $PythonExe -I -S -B $AdminCli $Action --policy-name $PolicyName 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "GitLab Runner admin CLI failed closed during $Action (exit $exitCode): $($output -join ' ')"
    }
    if ($output.Count -ne 1) {
        throw "GitLab Runner admin CLI returned an unexpected response during $Action"
    }
    $payload = $output[0] | ConvertFrom-Json -Depth 30
    if ($null -eq $payload) {
        throw "GitLab Runner admin CLI returned invalid JSON during $Action"
    }
    $payload
}

Invoke-PinnedDownload -Url $PythonUrl -Destination $PythonInstaller -ExpectedSha256 $PythonInstallerSha256
$installerSignature = Get-AuthenticodeSignature -LiteralPath $PythonInstaller
if (
    $installerSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $null -eq $installerSignature.SignerCertificate -or
    $installerSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $PythonSignerThumbprint -or
    $installerSignature.SignerCertificate.Subject -ne $PythonSignerSubject -or
    (Get-Item -LiteralPath $PythonInstaller).VersionInfo.FileVersion -ne $PythonFileVersion
) {
    throw 'Pinned Python installer Authenticode identity or version does not match'
}

foreach ($relativePath in $PluginFiles.Keys) {
    $url = 'https://raw.githubusercontent.com/YSheldon/ai-productivity-plugins/{0}/plugins/gitlab/{1}' -f (
        $PluginCommit,
        $relativePath.Replace('\', '/')
    )
    Invoke-PinnedDownload -Url $url -Destination (Join-Path $PluginStageRoot $relativePath) -ExpectedSha256 (
        $PluginFiles[$relativePath]
    )
}

if (-not (Test-Path -LiteralPath $ProductRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $ProductRoot | Out-Null
}
if ((Get-Item -LiteralPath $ProductRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'ProductMaterialGate Program Files root must not be a reparse point'
}

$pythonReady = $false
if (Test-Path -LiteralPath $PythonExe -PathType Leaf) {
    $pythonSignature = Get-AuthenticodeSignature -LiteralPath $PythonExe
    $pythonReady = (
        $pythonSignature.Status -eq [Management.Automation.SignatureStatus]::Valid -and
        $null -ne $pythonSignature.SignerCertificate -and
        $pythonSignature.SignerCertificate.Subject -eq $PythonSignerSubject -and
        (Get-Item -LiteralPath $PythonExe).VersionInfo.FileVersion -eq $PythonFileVersion
    )
}
if (-not $pythonReady) {
    $arguments = @(
        '/quiet',
        'InstallAllUsers=1',
        ('TargetDir="{0}"' -f $PythonRoot),
        'Include_launcher=0',
        'Include_pip=0',
        'Include_test=0',
        'Include_doc=0',
        'Include_tcltk=0',
        'Include_dev=0',
        'Include_symbols=0',
        'Include_debug=0',
        'PrependPath=0',
        'Shortcuts=0'
    )
    $process = Start-Process -FilePath $PythonInstaller -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "Pinned Python installer failed with exit code $($process.ExitCode)"
    }
}

Assert-RegularFile -LiteralPath $PythonExe -Label 'Installed Python runtime'
$pythonSignature = Get-AuthenticodeSignature -LiteralPath $PythonExe
if (
    $pythonSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $null -eq $pythonSignature.SignerCertificate -or
    $pythonSignature.SignerCertificate.Subject -ne $PythonSignerSubject -or
    (Get-Item -LiteralPath $PythonExe).VersionInfo.FileVersion -ne $PythonFileVersion
) {
    throw 'Installed Python runtime Authenticode identity or version does not match'
}
Set-ProtectedTreeAcl -LiteralPath $PythonRoot

foreach ($directory in @(
    $PluginRoot,
    (Join-Path $PluginRoot 'scripts'),
    (Join-Path $PluginRoot 'src')
)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Protected GitLab plugin directory must not be a reparse point: $directory"
    }
}
foreach ($relativePath in $PluginFiles.Keys) {
    $source = Join-Path $PluginStageRoot $relativePath
    $destination = Join-Path $PluginRoot $relativePath
    if (Test-Path -LiteralPath $destination) {
        Assert-RegularFile -LiteralPath $destination -Label "Installed GitLab plugin file $relativePath"
    }
    [IO.File]::Copy($source, $destination, $true)
}
Set-ProtectedTreeAcl -LiteralPath $PluginRoot
foreach ($relativePath in $PluginFiles.Keys) {
    $destination = Join-Path $PluginRoot $relativePath
    if ((Get-Sha256 -LiteralPath $destination) -ne $PluginFiles[$relativePath]) {
        throw "Installed GitLab plugin file SHA256 does not match: $relativePath"
    }
}

$tokenStatus = Invoke-AdminCli -Action 'token-status'
if ($tokenStatus.token_present -ne $true) {
    Write-Host ''
    Write-Host 'Enter a short-lived, least-privilege GitLab Runner manager token.' -ForegroundColor Yellow
    Write-Host 'Input is hidden and the credential is deleted automatically after ready state.' -ForegroundColor Yellow
    & $PythonExe -I -S -B $AdminCli token-set --policy-name $PolicyName
    if ($LASTEXITCODE -ne 0) {
        throw 'GitLab Runner manager token setup failed closed'
    }
}

$action = if (Test-Path -LiteralPath $JournalPath -PathType Leaf) { 'resume' } else { 'provision' }
$lifecycle = Invoke-AdminCli -Action $action
if (
    $lifecycle.ready -ne $true -or
    (
        $lifecycle.PSObject.Properties.Name -contains 'security_ready' -and
        $lifecycle.security_ready -ne $true
    )
) {
    throw 'GitLab Runner did not reach security-ready state'
}

$tokenStatusAfter = Invoke-AdminCli -Action 'token-status'
if ($tokenStatusAfter.token_present -ne $false) {
    throw 'Temporary GitLab Runner manager credential was not removed after ready state'
}

Assert-RegularFile -LiteralPath $IdentityPath -Label 'GitLab Runner identity receipt'
$identity = Get-Content -LiteralPath $IdentityPath -Raw | ConvertFrom-Json -Depth 20
$expectedIdentityKeys = @(
    'schema',
    'policy_name',
    'project_id',
    'runner_id',
    'runner_name',
    'tags',
    'binary_sha256',
    'config_sha256',
    'service_name',
    'service_account',
    'machine_identity_sha256',
    'stage'
)
$actualIdentityKeys = @($identity.PSObject.Properties.Name)
if (
    @(Compare-Object -ReferenceObject $expectedIdentityKeys -DifferenceObject $actualIdentityKeys).Count -ne 0 -or
    $identity.schema -ne 'ProductMaterialGateRunnerIdentity/v1' -or
    $identity.policy_name -ne $PolicyName -or
    $identity.stage -ne 'ready' -or
    $identity.service_account -ne 'NetworkService'
) {
    throw 'GitLab Runner identity receipt failed the production contract'
}

$service = Get-CimInstance -ClassName Win32_Service -Filter (
    "Name='" + ([string]$identity.service_name).Replace("'", "''") + "'"
)
if (
    $null -eq $service -or
    $service.State -ne 'Running' -or
    $service.StartMode -ne 'Auto' -or
    $service.StartName -ne 'NT AUTHORITY\NetworkService'
) {
    throw 'Dedicated GitLab Runner service failed final service attestation'
}

New-Item -ItemType Directory -Path $ReceiptRoot -Force | Out-Null
$receipt = [ordered]@{
    schema = 'PmgRunnerProvisioningBootstrap/v1'
    ready = $true
    security_ready = $true
    policy_name = $PolicyName
    lifecycle_action = $action
    python_installer_sha256 = $PythonInstallerSha256
    python_installer_signer_thumbprint = $PythonSignerThumbprint
    python_runtime_version = (Get-Item -LiteralPath $PythonExe).VersionInfo.FileVersion
    plugin_commit = $PluginCommit
    plugin_hashes = $PluginFiles
    runner_identity_sha256 = Get-Sha256 -LiteralPath $IdentityPath
    runner_identity = $identity
    service = [ordered]@{
        name = $service.Name
        state = $service.State
        start_mode = $service.StartMode
        start_name = $service.StartName
    }
    manager_credential_present_after_ready = $false
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
}
[IO.File]::WriteAllText(
    $ReceiptPath,
    (($receipt | ConvertTo-Json -Depth 30) + [Environment]::NewLine),
    [Text.UTF8Encoding]::new($false)
)
$receiptHash = Get-Sha256 -LiteralPath $ReceiptPath

Write-Host ''
Write-Host 'Dedicated production Runner is registered and locally attested.' -ForegroundColor Green
Write-Host "Receipt: $ReceiptPath"
Write-Host "Receipt SHA256: $receiptHash"
