$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
& ([IO.Path]::Combine($PSScriptRoot,'..','scripts','web_approval.ps1')) -DescribeProtocol
exit $LASTEXITCODE
