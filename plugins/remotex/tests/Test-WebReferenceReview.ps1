param([Parameter(Mandatory=$true)][string]$Scenario)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\scripts\web_reference_review.ps1')
function Assert-True([bool]$Value,[string]$Message) { if (-not $Value) { throw $Message } }
function New-TestPublicPacket {
    return [ordered]@{schema='RemoteXPublicReview/v1'
        reference=[ordered]@{profile_id='json-utf8-v1';target_text='/init?mode=public';content_type='application/json'
            body_text='{"userSession":"PUBLIC_FIXED_VALUE"}';public_headers=@(@{name='accept';value='application/json'})}
        evidence=@{kind='source-review';source_ref='independent-synthetic-source';revision_ref='fixture-v1'
            deployment_ref='owned-loopback-fixture';basis='Reviewed fixture initialization handler and ready predicate'}
        cookie_evidence='Fixture cookie has no authentication authority'}
}
$packetMeta = [pscustomobject]@{item_id='setup.network.1';profile_id='json-utf8-v1';cookie_context_ref=('9'*32)
    locations=@([pscustomobject]@{ref=('8'*32);position=1;type='string';sensitive=$true})
    response_checks=@([pscustomobject]@{pointer='/ready';test='equals-boolean';expected=$true})}
$state = New-V3ReferenceState -RequestId ('a' * 32) -ItemId 'setup.network.1' -Nonce ('b' * 64) -RequestDigest ('c' * 64) -UnitCount 5
$state.check_id = 'd' * 32; $state.pending = $true
$frame = [pscustomobject]@{event='reference-result';request_id=('a'*32);nonce=('b'*64);request_digest=('c'*64);check_id=('d'*32);item_id='setup.network.1';edit_revision=1;review_ref=('e'*32);unit_count=5;code='ready'}
switch ($Scenario) {
    'public-packet' {
        $json = New-TestPublicPacket | ConvertTo-Json -Depth 12 -Compress
        $value = ConvertFrom-V3PublicReviewPacket -Text $json -ReferenceItem $packetMeta
        Assert-True ($value.reference.body_text -ceq '{"userSession":"PUBLIC_FIXED_VALUE"}') 'Import changed public wire text'
        Assert-True ($value.reference.public_headers -is [array]) 'Import lost single-header array shape'
        $invalid = @(
            $json.Replace('"schema":','"approved":true,"schema":'),
            $json.Replace('"kind":','"independently_reviewed":true,"kind":'),
            $json.Replace('"profile_id":"json-utf8-v1"','"profile_id":"form-utf8-v1"'),
            $json.Replace('"schema":','"schema":"duplicate","schema":'),
            $json.Replace('"source_ref":','"source_ref":"duplicate","source_ref":'),
            $json.Replace('"body_text":','"body_text":false,"body_text":'),
            $json.Replace('"cookie_evidence":','"cookie_context_ref":"spoof","cookie_evidence":')
        )
        foreach ($mutation in @('header-object','header-null','header-extra','header-number','evidence-empty','evidence-control','evidence-long','body-number','cookie-number')) {
            $bad = $json | ConvertFrom-Json
            switch ($mutation) {
                'header-object' {$bad.reference.public_headers=$bad.reference.public_headers[0]}
                'header-null' {$bad.reference.public_headers=$null}
                'header-extra' {$bad.reference.public_headers[0] | Add-Member NoteProperty secret 'forbidden'}
                'header-number' {$bad.reference.public_headers[0].value=12}
                'evidence-empty' {$bad.evidence.basis=''}
                'evidence-control' {$bad.evidence.basis="first`nsecond"}
                'evidence-long' {$bad.evidence.basis='x'*513}
                'body-number' {$bad.reference.body_text=123}
                'cookie-number' {$bad.cookie_evidence=123}
            }
            $invalid += ($bad | ConvertTo-Json -Depth 12 -Compress)
        }
        foreach ($text in $invalid) {
            $rejected=$false
            try {$null=ConvertFrom-V3PublicReviewPacket -Text $text -ReferenceItem $packetMeta} catch {$rejected=$true}
            Assert-True $rejected 'Invalid public review packet was accepted'
        }
        $empty = $json | ConvertFrom-Json; $empty.reference.public_headers=@()
        $value=ConvertFrom-V3PublicReviewPacket -Text ($empty | ConvertTo-Json -Depth 12) -ReferenceItem $packetMeta
        Assert-True ($value.reference.public_headers.Count -eq 0) 'Empty header array was rejected'
        $empty.reference.public_headers=@(@{name='second';value='2'},@{name='first';value='1'})
        $value=ConvertFrom-V3PublicReviewPacket -Text ($empty | ConvertTo-Json -Depth 12) -ReferenceItem $packetMeta
        Assert-True ($value.reference.public_headers[0].name -ceq 'second' -and $value.reference.public_headers[1].name -ceq 'first') 'Header order changed on import'
    }
    'public-packet-files' {
        $folder=Join-Path ([IO.Path]::GetTempPath()) ('remotex-public-packet-'+[Guid]::NewGuid().ToString('N'))
        $null=[IO.Directory]::CreateDirectory($folder)
        try {
            $path=Join-Path $folder 'public.json'
            $json=New-TestPublicPacket | ConvertTo-Json -Depth 12 -Compress
            [IO.File]::WriteAllText($path,$json,(New-Object Text.UTF8Encoding($false,$true)))
            Assert-True ((Read-V3PublicReviewFile $path) -ceq $json) 'Local UTF-8 packet was changed'
            [IO.File]::WriteAllText($path,$json,(New-Object Text.UTF8Encoding($true,$true)))
            Assert-True ((Read-V3PublicReviewFile $path) -ceq $json) 'UTF-8 BOM was not handled'
            $badPaths=@('\\server\share\public.json','\\?\C:\public.json','file:///C:/public.json',($path+':stream'),'.\public.json')
            foreach ($badPath in $badPaths) {
                $rejected=$false; try {$null=Read-V3PublicReviewFile $badPath} catch {$rejected=$true}
                Assert-True $rejected 'Unsupported packet path was accepted'
            }
            foreach ($bytes in @([Text.Encoding]::Unicode.GetBytes($json),[byte[]]@(0xff,0xfe,0x00),[byte[]]@(0xc0,0xaf),(New-Object byte[] 24001))) {
                [IO.File]::WriteAllBytes($path,$bytes)
                $rejected=$false; try {$null=Read-V3PublicReviewFile $path} catch {$rejected=$true}
                Assert-True $rejected 'Unsupported encoding or oversized packet was accepted'
            }
            $target=Join-Path $folder 'target'; $null=[IO.Directory]::CreateDirectory($target)
            [IO.File]::WriteAllText((Join-Path $target 'public.json'),$json,(New-Object Text.UTF8Encoding($false)))
            $link=Join-Path $folder 'linked'
            $null=New-Item -ItemType Junction -Path $link -Target $target
            try {
                $rejected=$false; try {$null=Read-V3PublicReviewFile (Join-Path $link 'public.json')} catch {$rejected=$true}
                Assert-True $rejected 'A parent junction bypassed local regular-file admission'
            } finally {[IO.Directory]::Delete($link)}
        } finally {[IO.Directory]::Delete($folder,$true)}
    }
    'public-packet-controls' {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $sent=New-Object Collections.ArrayList
        $clock=@{remaining=100}
        $state=New-V3ReferenceState -RequestId ('a'*32) -ItemId 'setup.network.1' -UnitCount 1
        $panel=New-V3PublicReferencePanel -State $state -ReferenceItem $packetMeta -Binding @{origin='https://fixture.example';account='operator'} `
            -SendFrame {param($value) $null=$sent.Add($value);return $true}.GetNewClosure() `
            -RemainingSeconds {return $clock.remaining}.GetNewClosure()
        try {
            $panel.Form.Show(); [Windows.Forms.Application]::DoEvents()
            $text=New-TestPublicPacket | ConvertTo-Json -Depth 12 -Compress
            Set-V3PublicReviewPacket -Panel $panel -Text $text
            Assert-True (-not $panel.PublicConfirmed.Checked -and -not $panel.Reviewed.Checked -and -not $panel.CookieConfirmed.Checked -and -not $panel.Sensitive.Checked) 'Import attested human review'
            Assert-True (-not $panel.Compare.Enabled -and $sent.Count -eq 0) 'Import compared or authorized'
            Assert-True ($panel.Summary.Text.Contains('https://fixture.example') -and $panel.Summary.Text.Contains('operator') -and $panel.Summary.Text.Contains('PUBLIC_FIXED_VALUE')) 'Summary omitted original binding or public fields'
            $panel.PublicConfirmed.Checked=$true; $panel.Reviewed.Checked=$true; $panel.CookieConfirmed.Checked=$true
            Assert-True $panel.Compare.Enabled 'Three explicit confirmations did not enable comparison'
            $panel.Role.SelectedIndex=0
            Assert-True (-not $panel.PublicConfirmed.Checked -and -not $panel.Compare.Enabled) 'Expert role edits left a misleading simple confirmation'
            $panel.PublicConfirmed.Checked=$true
            $panel.CookieRole.SelectedIndex=0
            Assert-True (-not $panel.CookieConfirmed.Checked -and -not $panel.Compare.Enabled) 'Expert cookie edits left a misleading simple confirmation'
            $panel.CookieConfirmed.Checked=$true
            $native=Get-V3NativeReferenceInput $panel $packetMeta
            Assert-True ($native.cookie_review.context_ref -ceq $packetMeta.cookie_context_ref -and $native.attestation.sensitive_ack_refs.Count -eq 1) 'Original private binding was not retained'
            $panel.Compare.PerformClick()
            Assert-True ($sent.Count -eq 1 -and $sent[0].event -ceq 'reference-check') 'Explicit compare did not use original private protocol'
            $state.pending=$false; $state.review_ref='e'*32; $state.matched_revision=$state.edit_revision; $state.status='ready'
            Set-V3PublicReviewPacket -Panel $panel -Text $text
            Assert-True (-not (Test-V3ReferenceDecisionReady $state) -and -not $panel.PublicConfirmed.Checked -and -not $panel.Reviewed.Checked -and -not $panel.CookieConfirmed.Checked) 'Reload reused a proof or confirmation'
            $before=$panel.PublicReference.Text; $revision=$state.edit_revision
            foreach ($bad in @('{"schema":"wrong"}',($text.Replace('"schema":','"approved":true,"schema":')))) {
                $rejected=$false; try {Set-V3PublicReviewPacket -Panel $panel -Text $bad} catch {$rejected=$true}
                Assert-True ($rejected -and $before -ceq $panel.PublicReference.Text -and $revision -eq $state.edit_revision) 'Failed import partially mutated controls'
            }
            $clock.remaining=0
            $rejected=$false; try {Set-V3PublicReviewPacket -Panel $panel -Text $text} catch {$rejected=$true}
            Assert-True ($rejected -and $revision -eq $state.edit_revision) 'Expired import altered the draft'
            $clock.remaining=100; $state.pending=$true
            $rejected=$false; try {Set-V3PublicReviewPacket -Panel $panel -Text $text} catch {$rejected=$true}
            Assert-True $rejected 'Pending comparison allowed a new import'
            $state.pending=$false
            $panel.PublicConfirmed.Checked=$true; $panel.Reviewed.Checked=$true; $panel.CookieConfirmed.Checked=$true
            $panel.Source.Text='changed-source'
            Assert-True (-not $panel.PublicConfirmed.Checked -and -not $panel.Reviewed.Checked -and -not $panel.CookieConfirmed.Checked -and -not $panel.Compare.Enabled) 'Editing provenance retained human confirmations'
            $noCookie=[pscustomobject]@{profile_id='json-utf8-v1';cookie_context_ref=$null;locations=@();response_checks=@()}
            $draft=New-TestPublicPacket; $draft.cookie_evidence=$null
            $value=ConvertFrom-V3PublicReviewPacket -Text ($draft | ConvertTo-Json -Depth 12) -ReferenceItem $noCookie
            Assert-True ($null -eq $value.cookie_evidence) 'No-cookie packet required a fabricated cookie assertion'
        } finally {$panel.Form.Close();$panel.Form.Dispose()}
    }
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
            $panel.EvidenceKind.SelectedItem = 'verified-record'
            $panel.Source.Text = 'independent-fixture-source'; $panel.Revision.Text = 'fixture-v1'
            $panel.Deployment.Text = 'owned-loopback-fixture'; $panel.Basis.Text = 'Reviewed independent handler and public response checks'
            $panel.DataStatus.SelectedItem = 'Public invariant'; $panel.Role.SelectedItem = 'Non-auth'
            $panel.Effect.SelectedItem = 'Initialization Read'
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
