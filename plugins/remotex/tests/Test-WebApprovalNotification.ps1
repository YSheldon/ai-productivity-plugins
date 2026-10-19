param([Parameter(Mandatory=$true)][string]$Scenario)
$ErrorActionPreference = 'Stop'
foreach ($name in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {
    Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name + '.psd1'))) -ErrorAction Stop
}
. (Join-Path $PSScriptRoot '..\scripts\web_approval_notification.ps1')
function Assert($Condition) { if (-not $Condition) { throw 'Notification boundary failed' } }
$script:remaining = 173
$script:pending = $true
$script:receipts = [Collections.Generic.List[string]]::new()
$form = [pscustomobject]@{ IsDisposed=$false; Visible=$true; WindowState='Normal'; Focuses=0 }
$form | Add-Member ScriptMethod Activate { $this.Focuses++ }
$form | Add-Member ScriptMethod BringToFront { }
$notice = [pscustomobject]@{ Text=''; BalloonTipTitle=''; BalloonTipText=''; Icon=$null; Visible=$false; Shows=0; Disposals=0; Click=$null; Shown=$null; Fail=$false }
$notice | Add-Member ScriptMethod add_BalloonTipClicked { param($Handler) $this.Click=$Handler }
$notice | Add-Member ScriptMethod add_BalloonTipShown { param($Handler) $this.Shown=$Handler }
$notice | Add-Member ScriptMethod ShowBalloonTip { param($Milliseconds) $this.Shows++; if ($this.Fail) { throw 'private-canary' } }
$notice | Add-Member ScriptMethod Dispose { $this.Disposals++ }
$factory = if ($Scenario -eq 'creation-failure') { { throw 'private-constructor-canary' } } else { { $notice }.GetNewClosure() }
$state = New-ApprovalNotification -Form $form -Digest ('a'*64) -RemainingSeconds { $script:remaining } -Pending { $script:pending } -Receipt { param($Reason) $script:receipts.Add($Reason) } -Factory $factory
Assert ($notice.Shows -eq 0)
if ($Scenario -eq 'failure') { $notice.Fail=$true }
Show-ApprovalNotification $state
Show-ApprovalNotification $state
if ($Scenario -eq 'creation-failure') {
    Assert ($notice.Shows -eq 0 -and $script:receipts -join ',' -ceq 'unavailable' -and $script:pending)
} elseif ($Scenario -eq 'failure') {
    Assert ($notice.Shows -eq 1)
    Assert ($script:receipts -join ',' -ceq 'requested,unavailable')
    Assert ($form.Focuses -eq 0 -and $notice.Disposals -eq 1 -and $script:pending)
} else {
    Assert ($notice.Shows -eq 1)
    Assert ($notice.BalloonTipTitle -ceq 'RemoteX')
    Assert ($notice.BalloonTipText -ceq 'aaaaaaaa - 173 seconds remaining')
    Assert ($notice.Text -ceq 'RemoteX')
    Assert ($script:receipts -join ',' -ceq 'requested')
    & $notice.Shown
    & $notice.Shown
    Assert ($script:receipts -join ',' -ceq 'requested,shown')
    if ($Scenario -eq 'pending-click') {
        $form.WindowState='Minimized'; & $notice.Click
        Assert ($form.Focuses -eq 1 -and $form.WindowState -eq 'Normal' -and $script:remaining -eq 173)
        $script:pending=$false; & $notice.Click
        Assert ($form.Focuses -eq 1)
    } elseif ($Scenario -eq 'expiry-click') {
        $script:remaining=0; & $notice.Click
        Assert ($form.Focuses -eq 0 -and $script:remaining -eq 0)
    } elseif ($Scenario -eq 'closed-click') {
        $form.IsDisposed=$true; & $notice.Click
        Assert ($form.Focuses -eq 0)
    } elseif ($Scenario -ne 'privacy-one-shot') { throw 'Unknown scenario' }
    Close-ApprovalNotification $state
    Close-ApprovalNotification $state
    & $notice.Click
    Assert ($notice.Disposals -eq 1 -and -not $notice.Visible -and $script:receipts[-1] -ceq 'removed')
}
[Console]::WriteLine('{"passed":true}')
