param([switch]$DescribeProtocol)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
foreach ($name in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {
    Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1')))
}
if ($DescribeProtocol) { [Console]::WriteLine('{"legacy_recovery":2,"review_seconds":180}'); exit 0 }
$script:manifest = $null
$script:sent = $false
$script:complete = $false
$script:reason = 'window-closed'
$script:notification = $null
function Send-RecoveryReceipt([string]$eventName,[string]$reason) {
    if (-not $script:manifest) { return }
    [Console]::Error.WriteLine((@{event=$eventName;reason=$reason;request_id=$manifest.request_id;nonce=$manifest.nonce;request_digest=$manifest.request_digest} | ConvertTo-Json -Compress))
    [Console]::Error.Flush()
}
function Send-RecoveryFrame([string]$eventName) {
    $frame=[ordered]@{event=$eventName;request_id=$manifest.request_id;nonce=$manifest.nonce;request_digest=$manifest.request_digest}
    if ($eventName -ceq 'decision') { $frame.owner_reviewed=$true }
    [Console]::WriteLine(($frame | ConvertTo-Json -Compress)); [Console]::Out.Flush()
}
try {
    if (-not [Environment]::UserInteractive) { exit 1 }
    [Console]::InputEncoding=New-Object Text.UTF8Encoding($false,$true)
    [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false,$true)
    $line=[Console]::ReadLine()
    if (-not $line -or [Text.Encoding]::UTF8.GetByteCount($line) -gt 32768) { throw 'Invalid review' }
    $manifest=$line | ConvertFrom-Json
    if ($manifest.ui_mode -cne 'recovery' -or $manifest.mode -cnotin @('initialize','finalize') -or
        $manifest.request_id -cnotmatch '^[a-f0-9]{32}$' -or $manifest.nonce -cnotmatch '^[a-f0-9]{64}$' -or
        $manifest.request_digest -cnotmatch '^[a-f0-9]{64}$' -or $manifest.wait_seconds -lt 1 -or $manifest.wait_seconds -gt 180 -or
        $manifest.target -isnot [string] -or $manifest.target.Length -gt 4096 -or
        $manifest.summary.scopeCount -lt 1 -or $manifest.summary.scopeCount -gt 256 -or
        $manifest.summary.historyPolicy -cnotin @('strict-v1','reconcile-v2') -or
        $manifest.summary.reviewText -isnot [string] -or $manifest.summary.reviewText.Length -gt 8192) { throw 'Invalid review' }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    . (Join-Path $PSScriptRoot 'web_approval_notification.ps1')
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Collections.Concurrent;
namespace RemoteX {
    public sealed class RecoveryReplies {
        public readonly ConcurrentQueue<string> Lines = new ConcurrentQueue<string>();
        public volatile bool Failed;
        public RecoveryReplies(TextReader reader) {
            var thread = new Thread(() => {
                try {
                    var text = new System.Text.StringBuilder();
                    while (true) {
                        int ch = reader.Read();
                        if (ch < 0) break;
                        if (ch == 10) {
                            if (Lines.Count >= 2) throw new IOException();
                            Lines.Enqueue(text.ToString()); text.Clear();
                        } else { if (text.Length >= 2048) throw new IOException(); text.Append((char)ch); }
                    }
                } catch { } finally { Failed = true; }
            });
            thread.IsBackground = true; thread.Start();
        }
    }
}
'@
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=New-Object Windows.Forms.Form
    $form.Text='RemoteX - Legacy Recovery'; $form.StartPosition='CenterScreen'
    $form.ClientSize=New-Object Drawing.Size(680,540); $form.MinimumSize=$form.Size
    $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false; $form.ShowInTaskbar=$true
    $title=New-Object Windows.Forms.Label; $title.Text='Review legacy recovery uncertainty'
    $title.Font=New-Object Drawing.Font('Segoe UI',14); $title.SetBounds(20,18,640,32)
    $details=New-Object Windows.Forms.TextBox
    $details.Multiline=$true; $details.ReadOnly=$true; $details.ScrollBars='Vertical'
    $details.Font=New-Object Drawing.Font('Segoe UI',10); $details.SetBounds(20,60,640,310)
    $body='Target: '+$manifest.target+"`r`nMode: "+$manifest.mode+"`r`nConfigured scopes (not historical attribution):"
    foreach ($scope in $manifest.summary.scopes) {
        $body += "`r`n"+[string]$scope.profile+' | '+[string]$scope.origin+' | '+[string]$scope.account
    }
    $body += "`r`n`r`n"+[string]$manifest.summary.reviewText
    $body += "`r`n`r`n"+[string]$manifest.summary.uncertainty
    $body += "`r`n`r`nPreserve the original key, save a private backup and record owner-reviewed recovery. No site permission, login, queue change or business operation is granted."
    $details.Text=$body
    $owner=New-Object Windows.Forms.CheckBox; $owner.Checked=$false
    $owner.Text='I have reconciled all prior effects, including completed actions with unknown historical scope, and accept this one-time recovery uncertainty.'
    $owner.SetBounds(20,382,640,45)
    $status=New-Object Windows.Forms.Label; $status.SetBounds(20,433,640,30)
    $recover=New-Object Windows.Forms.Button; $recover.Text='Recover Legacy State'; $recover.Enabled=$false
    $recover.SetBounds(330,485,205,34)
    $cancel=New-Object Windows.Forms.Button; $cancel.Text='Cancel'; $cancel.SetBounds(545,485,115,34)
    $form.Controls.AddRange(@($title,$details,$owner,$status,$recover,$cancel))
    $started=[Diagnostics.Stopwatch]::StartNew()
    $remaining={ [Math]::Max(0,[int][Math]::Floor([double]$manifest.wait_seconds-$started.Elapsed.TotalSeconds)) }
    $replies=New-Object RemoteX.RecoveryReplies([Console]::In)
    $notification=New-ApprovalNotification -Form $form -Digest $manifest.request_digest -RemainingSeconds $remaining -Pending { -not $script:sent } -Receipt { param($r) Send-RecoveryReceipt 'notification' $r }
    $owner.Add_CheckedChanged({ $recover.Enabled=$owner.Checked -and -not $script:sent })
    $recover.Add_Click({
        if (-not $owner.Checked -or $script:sent -or (& $remaining) -le 0) { return }
        $script:sent=$true; $recover.Enabled=$false; $owner.Enabled=$false
        $status.Text='Recording recovery. Closing now cancels any uncommitted transition.'
        Close-ApprovalNotification $notification
        Send-RecoveryFrame 'decision'
    })
    $cancel.Add_Click({ $script:reason='operator-rejected'; $form.Close() })
    $timer=New-Object Windows.Forms.Timer; $timer.Interval=200
    $timer.Add_Tick({
        $raw=''
        if ($replies.Lines.TryDequeue([ref]$raw)) {
            try {
                $reply=$raw | ConvertFrom-Json
                if ($reply.event -cne 'recovery-result' -or $reply.request_id -cne $manifest.request_id -or
                    $reply.nonce -cne $manifest.nonce -or $reply.request_digest -cne $manifest.request_digest -or
                    $reply.state -cnotin @('ready','committed-unverified') -or -not $script:sent -or $script:complete) { throw 'Invalid acknowledgment' }
                $script:complete=$true
                $script:reason=if ($reply.state -ceq 'ready') {'recovery-complete'} else {'window-closed'}
                $form.Close(); return
            } catch { Send-RecoveryReceipt 'error' 'helper-ui-failed'; $form.Close(); return }
        }
        if ($replies.Failed) { $form.Close(); return }
        $seconds=& $remaining
        if ($seconds -le 0) { $script:reason='review-expired'; $form.Close() }
        elseif (-not $script:sent) { $status.Text='Review time remaining: '+$seconds+' seconds' }
    })
    $form.Add_Shown({ Send-RecoveryReceipt 'shown' 'shown'; Show-ApprovalNotification $notification; $timer.Start() })
    $form.Add_FormClosing({
        Close-ApprovalNotification $notification
        if ($script:sent -and -not $script:complete) { Send-RecoveryFrame 'revoke' }
        Send-RecoveryReceipt 'closed' $script:reason
    })
    [void]$form.ShowDialog()
} catch { Send-RecoveryReceipt 'error' 'helper-ui-failed'; exit 1 }
finally {
    if ($timer) { $timer.Stop(); $timer.Dispose() }
    Close-ApprovalNotification $notification
    if ($form) { $form.Dispose() }
}
