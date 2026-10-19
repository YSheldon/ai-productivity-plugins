function New-ApprovalNotification {
    param($Form, [string]$Digest, [scriptblock]$RemainingSeconds, [scriptblock]$Pending,
        [scriptblock]$Receipt, [scriptblock]$Factory = {
            $icon = New-Object Windows.Forms.NotifyIcon
            $icon.Icon = [Drawing.SystemIcons]::Information
            return $icon
        })
    if ($Digest -cnotmatch '^[a-f0-9]{64}$') { throw 'Notification context unavailable' }
    return [pscustomobject]@{ Form=$Form; ShortDigest=$Digest.Substring(0,8); Remaining=$RemainingSeconds;
        Pending=$Pending; Receipt=$Receipt; Factory=$Factory; Notifier=$null; Attempted=$false; Closed=$false; Shown=$false }
}

function Close-ApprovalNotification($State) {
    if (-not $State -or $State.Closed) { return }
    $State.Closed=$true
    if ($State.Notifier) {
        try { $State.Notifier.Visible=$false } catch { }
        try { $State.Notifier.Dispose() } catch { }
        $State.Notifier=$null
        try { & $State.Receipt 'removed' } catch { }
    }
}

function Show-ApprovalNotification($State) {
    if (-not $State -or $State.Attempted -or $State.Closed) { return }
    $State.Attempted=$true
    try {
        $remaining=[int](& $State.Remaining)
        if ($remaining -le 0 -or -not (& $State.Pending) -or $State.Form.IsDisposed -or -not $State.Form.Visible) { return }
        $icon=& $State.Factory
        $State.Notifier=$icon
        $icon.Text='RemoteX'; $icon.BalloonTipTitle='RemoteX'
        $icon.BalloonTipText=$State.ShortDigest + ' - ' + $remaining + ' seconds remaining'
        $icon.add_BalloonTipShown({
            if (-not $State.Closed -and -not $State.Shown) {
                $State.Shown=$true
                try { & $State.Receipt 'shown' } catch { }
            }
        }.GetNewClosure())
        $icon.add_BalloonTipClicked({
            try {
                if ($State.Closed -or $State.Form.IsDisposed -or -not $State.Form.Visible -or
                    -not (& $State.Pending) -or [int](& $State.Remaining) -le 0) { return }
                if ($State.Form.WindowState -eq 'Minimized') { $State.Form.WindowState='Normal' }
                $State.Form.BringToFront(); $State.Form.Activate()
            } catch { }
        }.GetNewClosure())
        $icon.Visible=$true
        & $State.Receipt 'requested'
        $icon.ShowBalloonTip(10000)
    } catch {
        try { & $State.Receipt 'unavailable' } catch { }
        # Failure is advisory; the original form and review clock remain authoritative.
        if ($State.Notifier) {
            try { $State.Notifier.Visible=$false; $State.Notifier.Dispose() } catch { }
            $State.Notifier=$null
        }
        $State.Closed=$true
    }
}
