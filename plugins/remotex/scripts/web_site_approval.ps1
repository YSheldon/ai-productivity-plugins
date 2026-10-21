param([switch]$DescribeProtocol)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
foreach ($name in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {
    Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$name,($name+'.psd1')))
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot 'web_approval_notification.ps1')
if ($DescribeProtocol) { [Console]::WriteLine('{"site_authorization":1,"review_seconds":180}'); exit 0 }
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Collections.Concurrent;
namespace RemoteX {
    public sealed class SiteReplies {
        public readonly ConcurrentQueue<string> Lines = new ConcurrentQueue<string>();
        public volatile bool Failed;
        public SiteReplies(TextReader reader) {
            var thread = new Thread(() => {
                try {
                    var text = new System.Text.StringBuilder();
                    while (true) {
                        int ch = reader.Read();
                        if (ch < 0) break;
                        if (ch == 10) {
                            if (Lines.Count >= 4) throw new IOException();
                            Lines.Enqueue(text.ToString()); text.Clear();
                        } else { if (text.Length >= 32768) throw new IOException(); text.Append((char)ch); }
                    }
                } catch { } finally { Failed = true; }
            });
            thread.IsBackground = true; thread.Start();
        }
    }
}
'@
$script:manifest = $null
$script:decided = $false
$script:sent = $false
$script:active = $false
$script:reason = 'window-closed'
$script:notification = $null
function Send-SiteReceipt([string]$eventName,[string]$reason) {
    if (-not $script:manifest) { return }
    [Console]::Error.WriteLine((@{event=$eventName;reason=$reason;request_id=$manifest.request_id;nonce=$manifest.nonce;request_digest=$manifest.request_digest} | ConvertTo-Json -Compress))
    [Console]::Error.Flush()
}
function Send-SiteFrame([string]$eventName) {
    $frame=[ordered]@{event=$eventName;request_id=$manifest.request_id;nonce=$manifest.nonce;request_digest=$manifest.request_digest}
    if ($eventName -eq 'decision') {
        $frame.choices=@(@{item_id='site';max_uses=1;targets=@()})
        $frame.ttl_seconds=[int]$manifest.ttl_seconds
    }
    [Console]::WriteLine(($frame | ConvertTo-Json -Depth 8 -Compress)); [Console]::Out.Flush()
}
try {
    if (-not [Environment]::UserInteractive) { exit 1 }
    [Console]::InputEncoding=New-Object Text.UTF8Encoding($false,$true)
    [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false,$true)
    $line=[Console]::ReadLine()
    if (-not $line -or [Text.Encoding]::UTF8.GetByteCount($line) -gt 32768) { throw 'Invalid review' }
    $manifest=$line | ConvertFrom-Json
    if ($manifest.ui_mode -cne 'site' -or $manifest.scope -cnotin @('site','action') -or
        $manifest.request_id -cnotmatch '^[a-f0-9]{32}$' -or $manifest.nonce -cnotmatch '^[a-f0-9]{64}$' -or
        $manifest.request_digest -cnotmatch '^[a-f0-9]{64}$' -or $manifest.wait_seconds -lt 1 -or $manifest.wait_seconds -gt 180 -or
        $manifest.ttl_seconds -lt 1 -or $manifest.ttl_seconds -gt 43200) { throw 'Invalid review' }
    $origin=[Uri]$manifest.binding.origin
    if ($origin.Scheme -cne 'https' -or $origin.UserInfo -or $origin.GetLeftPart([UriPartial]::Authority) -cne $manifest.binding.origin -or
        $manifest.binding.account -isnot [string] -or $manifest.binding.account.Length -gt 128 -or $manifest.binding.account -match '[\x00-\x1f]') { throw 'Invalid site' }
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=New-Object Windows.Forms.Form
    $form.Text='RemoteX - Site Automation'; $form.StartPosition='CenterScreen'
    $form.ClientSize=New-Object Drawing.Size(600,330); $form.MinimumSize=$form.Size
    $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false; $form.ShowInTaskbar=$true
    $title=New-Object Windows.Forms.Label
    $title.Text=if ($manifest.scope -ceq 'action') {'Confirm sensitive operation'} else {'Allow AI to operate this website?'}
    $title.Font=New-Object Drawing.Font('Segoe UI',14); $title.SetBounds(20,20,560,35)
    $details=New-Object Windows.Forms.TextBox
    $details.Multiline=$true; $details.ReadOnly=$true; $details.ScrollBars='Vertical'; $details.BorderStyle='None'
    $details.Font=New-Object Drawing.Font('Segoe UI',10); $details.SetBounds(20,65,560,165)
    $body=$manifest.binding.origin + "`r`nAccount: " + $manifest.binding.account
    if ($manifest.scope -ceq 'action') {
        $body += "`r`n`r`n" + [string]$manifest.preview.action + ': ' + [string]$manifest.preview.control
        $body += "`r`nTarget: " + [string]$manifest.preview.target
        if ($null -ne $manifest.preview.after) { $body += "`r`nNew value: " + [string]$manifest.preview.after }
    } else {
        $hours=[Math]::Round($manifest.ttl_seconds/3600,2)
        $body += "`r`nExpires in: " + $hours + " hours`r`n`r`nAutomatic login, reading, navigation, forms and ordinary business changes. Sensitive operations need separate confirmation."
    }
    $details.Text=$body
    $status=New-Object Windows.Forms.Label; $status.SetBounds(20,235,560,25)
    $allow=New-Object Windows.Forms.Button; $allow.SetBounds(300,280,165,32)
    $allow.Text=if ($manifest.scope -ceq 'action') {'Confirm Action'} else {'Allow Automation'}
    $cancel=New-Object Windows.Forms.Button; $cancel.Text='Cancel'; $cancel.SetBounds(475,280,105,32)
    $form.Controls.AddRange(@($title,$details,$status,$allow,$cancel))
    $started=[Diagnostics.Stopwatch]::StartNew()
    $remaining={ [Math]::Max(0,[int][Math]::Floor([double]$manifest.wait_seconds-$started.Elapsed.TotalSeconds)) }
    $replies=New-Object RemoteX.SiteReplies([Console]::In)
    $notification=New-ApprovalNotification -Form $form -Digest $manifest.request_digest -RemainingSeconds $remaining -Pending { -not $script:sent } -Receipt { param($r) Send-SiteReceipt 'notification' $r }
    $allow.Add_Click({
        if ($script:sent -or (& $remaining) -le 0) { return }
        $script:sent=$true; $allow.Enabled=$false; $status.Text='Recording your decision...'
        Close-ApprovalNotification $notification
        Send-SiteFrame 'decision'
    })
    $cancel.Add_Click({
        $script:reason=if ($script:active) {'operator-revoked'} else {'operator-rejected'}
        $form.Close()
    })
    $timer=New-Object Windows.Forms.Timer; $timer.Interval=200
    $timer.Add_Tick({
        if ($replies.Failed) { $form.Close(); return }
        $raw=''
        if ($replies.Lines.TryDequeue([ref]$raw)) {
            try {
                $reply=$raw | ConvertFrom-Json
                if ($reply.event -cne 'decision-result' -or $reply.request_id -cne $manifest.request_id -or
                    $reply.nonce -cne $manifest.nonce -or $reply.request_digest -cne $manifest.request_digest -or
                    $reply.state -cne 'active' -or $reply.expires_in_seconds -le 0 -or -not $script:sent -or $script:active) { throw 'Invalid acknowledgment' }
                $script:active=$true; $script:decided=$true
                $title.Text='Authorization Active'; $status.Text='Close this window or select Revoke to stop this authorization.'
                $cancel.Text='Revoke'; $allow.Visible=$false
            } catch { Send-SiteReceipt 'error' 'helper-ui-failed'; $form.Close(); return }
        }
        if (-not $script:active) {
            $seconds=& $remaining
            if ($seconds -le 0) { $script:reason='review-expired'; $form.Close() }
            elseif (-not $script:sent) { $status.Text='Review time remaining: '+$seconds+' seconds' }
        }
    })
    $form.Add_Shown({ Send-SiteReceipt 'shown' 'shown'; Show-ApprovalNotification $notification; $timer.Start() })
    $form.Add_FormClosing({
        Close-ApprovalNotification $notification
        if ($script:sent) { Send-SiteFrame 'revoke' }
        Send-SiteReceipt 'closed' $script:reason
    })
    [void]$form.ShowDialog()
} catch { Send-SiteReceipt 'error' 'helper-ui-failed'; exit 1 }
finally {
    if ($timer) { $timer.Stop(); $timer.Dispose() }
    Close-ApprovalNotification $notification
    if ($form) { $form.Dispose() }
}
