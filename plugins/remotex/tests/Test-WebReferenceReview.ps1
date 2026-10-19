param([Parameter(Mandatory=$true)][string]$Scenario)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\scripts\web_reference_review.ps1')
function Assert-True([bool]$Value,[string]$Message) { if (-not $Value) { throw $Message } }
$state = New-V3ReferenceState -RequestId ('a' * 32) -ItemId 'setup.network.1' -Nonce ('b' * 64) -RequestDigest ('c' * 64) -UnitCount 5
$state.check_id = 'd' * 32; $state.pending = $true
$frame = [pscustomobject]@{event='reference-result';request_id=('a'*32);nonce=('b'*64);request_digest=('c'*64);check_id=('d'*32);item_id='setup.network.1';edit_revision=1;review_ref=('e'*32);unit_count=5;code='ready'}
switch ($Scenario) {
    'reference-json' {
        $value = ConvertFrom-UniqueReferenceJson '{"profile_id":"json-utf8-v1","public_headers":[{"name":"a","value":"b"},{"name":"c","value":"d"}]}'
        Assert-True (@($value.public_headers).Count -eq 2) 'Array records were treated as duplicate object keys'
        foreach ($text in @('{"profile_id":"first","profile_id":"second"}',
            '{"public_headers":[{"name":"a","n\u0061me":"b"}]}', '{"body_text":"a","body_text":"b"}')) {
            $rejected=$false
            try { $null = ConvertFrom-UniqueReferenceJson $text } catch { $rejected=$true }
            Assert-True $rejected 'Ambiguous independent reference JSON was collapsed before supervisor review'
        }
    }
    'state' {
        Assert-True (-not (Test-V3ReferenceDecisionReady $state)) 'An unreviewed state became ready'
        Assert-True (Apply-V3ReferenceResult -State $state -Frame $frame) 'A current result was rejected'
        Assert-True (Test-V3ReferenceDecisionReady $state) 'A matched native proof was not retained'
        Invalidate-V3ReferenceState -State $state
        Assert-True (-not (Test-V3ReferenceDecisionReady $state)) 'An edit retained native proof'
        Assert-True ($state.edit_revision -eq 2) 'An edit did not advance its revision'
        Assert-True (-not (Apply-V3ReferenceResult -State $state -Frame $frame)) 'An old reply survived the edit'
    }
    'foreign' {
        $frame.nonce = 'f' * 64
        Assert-True (-not (Apply-V3ReferenceResult -State $state -Frame $frame)) 'A foreign nonce was accepted'
        Assert-True (-not (Test-V3ReferenceDecisionReady $state)) 'A foreign frame created native proof'
    }
    'typed' {
        $frame.edit_revision = '1'
        Assert-True (-not (Apply-V3ReferenceResult -State $state -Frame $frame)) 'An untyped revision was accepted'
        Assert-True (-not (Test-V3ReferenceDecisionReady $state)) 'A string revision created native proof'
    }
    'unit-boundaries' {
        $state = New-V3ReferenceState -RequestId ('a'*32) -ItemId 'setup.network.1' -Nonce ('b'*64) -RequestDigest ('c'*64) -UnitCount 32
        $state.check_id = 'd'*32; $state.pending = $true; $frame.unit_count = 32
        Assert-True (Apply-V3ReferenceResult -State $state -Frame $frame) 'The approved 32-unit limit was rejected'
        Assert-True (Test-V3ReferenceDecisionReady $state) 'A complete 32-unit proof could not be staged'
        Invalidate-V3ReferenceState $state
        $state.check_id = 'd'*32; $state.pending = $true; $frame.edit_revision = $state.edit_revision; $frame.unit_count = 33
        Assert-True (-not (Apply-V3ReferenceResult -State $state -Frame $frame)) 'The 33rd unit bypassed the limit'
        Assert-True (-not (Test-V3ReferenceDecisionReady $state)) 'An oversized proof became ready'
    }
    'controls' {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $sent = New-Object Collections.ArrayList
        $state = New-V3ReferenceState -RequestId ('a' * 32) -ItemId 'setup.network.1' -Nonce ('b' * 64) -RequestDigest ('c' * 64) -UnitCount 5
        $meta = [pscustomobject]@{item_id='setup.network.1';profile_id='json-utf8-v1';cookie_context_ref=$null;
            locations=@(1..5 | ForEach-Object { [pscustomobject]@{ref=('{0:x32}' -f $_);position=$_;type='string';sensitive=$false} });
            response_checks=@([pscustomobject]@{pointer='/ready';test='equals-boolean';expected=$true})}
        $panel = New-V3PublicReferencePanel -State $state -ReferenceItem $meta -SendFrame {param($value) $null = $sent.Add($value); return $true}.GetNewClosure() -RemainingSeconds { return 100 }
        $panel.Form.Text = 'RemoteX Synthetic Reference Controls - No Authorization'
        try {
            $panel.Form.Show(); [Windows.Forms.Application]::DoEvents()
            Assert-True (-not $panel.Compare.Enabled) 'Incomplete controls enabled comparison'
            $panel.PublicReference.Text = '{"profile_id":"json-utf8-v1","target_text":"/bootstrap?mode=public","content_type":"application/json","body_text":"{\"mode\":\"public\"}","public_headers":[]}'
            $panel.Profile.SelectedItem = 'json-utf8-v1'
            $panel.DataStatus.SelectedItem = 'Public invariant'; $panel.Role.SelectedItem = 'Non-auth'
            $panel.Effect.SelectedItem = 'Initialization Read'; $panel.EvidenceKind.SelectedItem = 'verified-record'
            $panel.Source.Text = 'independent-fixture-source'; $panel.Revision.Text = 'fixture-v1'
            $panel.Deployment.Text = 'owned-loopback-fixture'; $panel.Basis.Text = 'Reviewed independent handler and public response checks'
            $panel.Reviewed.Checked = $true
            [Windows.Forms.Application]::DoEvents()
            Assert-True $panel.Compare.Enabled 'Complete independent review could not compare'
            $panel.Compare.PerformClick(); [Windows.Forms.Application]::DoEvents()
            Assert-True ($sent.Count -eq 1) 'The comparison did not emit exactly one private frame'
            Assert-True ($sent[0].event -ceq 'reference-check') 'Reference controls emitted a final decision'
            Assert-True ($sent[0].native_input.attestation.role -ceq 'non-auth') 'The independent role was not bound'
            Assert-True (-not (Test-V3ReferenceDecisionReady $state)) 'Comparison alone created authority'
            $frame.check_id = $state.check_id; $frame.edit_revision = $state.edit_revision
            Assert-True (Apply-V3ReferenceResult -State $state -Frame $frame) 'The current native proof was rejected'
            $panel.PublicReference.Text += ' '
            Assert-True (-not (Test-V3ReferenceDecisionReady $state)) 'Editing controls retained a proof'
        } finally { $panel.Form.Close(); $panel.Form.Dispose() }
    }
    'queue' {
        $bytes = [Text.Encoding]::ASCII.GetBytes("{}`n")
        $stream = New-Object IO.MemoryStream(,$bytes)
        $reader = New-Object RemoteX.V3ReplyQueue($stream)
        try {
            $until = [DateTime]::UtcNow.AddSeconds(2)
            while (-not $reader.Completed -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 10 }
            $line = ''
            Assert-True ($reader.TryTake([ref]$line)) 'The async reader lost its reply'
            Assert-True ($line -ceq '{}') 'The async reader changed its private frame'
            Assert-True (-not $reader.Failed) 'The bounded valid queue failed'
        } finally { $reader.Dispose(); $stream.Dispose() }
    }
    'queue-limit' {
        $bytes = [Text.Encoding]::ASCII.GetBytes(("{}`n" * 9))
        $stream = New-Object IO.MemoryStream(,$bytes)
        $reader = New-Object RemoteX.V3ReplyQueue($stream)
        try {
            $until = [DateTime]::UtcNow.AddSeconds(2)
            while (-not $reader.Completed -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 10 }
            Assert-True $reader.Failed 'The private queue exceeded eight replies'
            Assert-True ($reader.Count -le 8) 'The private queue is unbounded'
        } finally { $reader.Dispose(); $stream.Dispose() }
    }
    'line-limit' {
        $bytes = [Text.Encoding]::ASCII.GetBytes((('x' * 32769) + "`n"))
        $stream = New-Object IO.MemoryStream(,$bytes)
        $reader = New-Object RemoteX.V3ReplyQueue($stream)
        try {
            $until = [DateTime]::UtcNow.AddSeconds(2)
            while (-not $reader.Completed -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 10 }
            Assert-True $reader.Failed 'An oversized reply was buffered'
            Assert-True ($reader.Count -eq 0) 'An oversized reply entered the UI queue'
        } finally { $reader.Dispose(); $stream.Dispose() }
    }
    default { throw 'Unknown synthetic scenario' }
}
Write-Output 'PASS'
