param([Parameter(Mandatory=$true)][string]$Scenario)

$ErrorActionPreference = 'Stop'
[Console]::Error.WriteLine(('ui-stage: script-start;interactive={0};session={1}' -f [Environment]::UserInteractive,[Diagnostics.Process]::GetCurrentProcess().SessionId))
# Avoid hosted Windows PowerShell's blocked automatic module-discovery path.
foreach ($name in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {
    [Console]::Error.WriteLine('ui-stage: system-module-begin:' + $name)
    $module = [IO.Path]::Combine($PSHOME,'Modules',$name,($name + '.psd1'))
    Import-Module -Name $module -ErrorAction Stop
    [Console]::Error.WriteLine('ui-stage: system-module-end:' + $name)
}
if ($Scenario -eq 'host-prerequisite') {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    function Write-Stage([string]$Name) {
        [Console]::Error.WriteLine(('host-stage: {0};elapsedMs={1}' -f $Name,$watch.ElapsedMilliseconds))
    }
    [Console]::Error.WriteLine(('host: ps={0};clr={1};x64={2};apartment={3};stdinRedirected={4}' -f
        $PSVersionTable.PSVersion,[Environment]::Version,[Environment]::Is64BitProcess,
        [Threading.Thread]::CurrentThread.GetApartmentState(),[Console]::IsInputRedirected))
    Write-Stage 'eof-begin'
    $line = [Console]::ReadLine()
    Write-Stage 'eof-end'
    if ($null -ne $line) { throw 'Prerequisite inherited console input' }
    Write-Stage 'split-path-begin'
    $parent = Split-Path $PSScriptRoot -Parent
    Write-Stage 'split-path-end'
    Write-Stage 'join-path-begin'
    $path = Join-Path $parent 'scripts\web_approval_ui.ps1'
    Write-Stage 'join-path-end'
    Write-Stage 'test-path-begin'
    $exists = Test-Path -LiteralPath $path
    Write-Stage 'test-path-end'
    if (-not $exists) { throw 'Prerequisite helper is missing' }
    Write-Stage 'json-begin'
    $report = @{prerequisite=$true} | ConvertTo-Json -Compress
    Write-Stage 'json-end'
    Write-Stage 'modules-begin'
    Import-Module Microsoft.PowerShell.Management,Microsoft.PowerShell.Utility -ErrorAction Stop
    Write-Stage 'modules-end'
    Write-Stage 'forms-begin'
    Add-Type -AssemblyName System.Windows.Forms
    Write-Stage 'forms-end'
    Write-Stage 'control-begin'
    $control = New-Object Windows.Forms.DataGridView
    $control.Dispose()
    Write-Stage 'control-end'
    [Console]::WriteLine($report)
    exit 0
}
if ($Scenario -eq 'console-input-probe') {
    $line = [Console]::ReadLine()
    [Console]::WriteLine((@{consoleInputObserved=($null -ne $line)} | ConvertTo-Json -Compress))
    exit 0
}
$helper = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\web_approval_ui.ps1'
if (-not (Test-Path -LiteralPath $helper)) {
    [Console]::WriteLine('{"implemented":false}')
    exit 0
}
[Console]::Error.WriteLine('ui-stage: add-type-begin')
Add-Type -AssemblyName System.Windows.Forms
[Console]::Error.WriteLine('ui-stage: add-type-end')
. $helper
[Console]::Error.WriteLine('ui-stage: helper-imported')

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function New-Fixture([string[]]$Kinds) {
    [Console]::Error.WriteLine('ui-stage: controls-begin')
    $grid = New-Object Windows.Forms.DataGridView
    [Console]::Error.WriteLine('ui-stage: grid-created')
    $grid.AllowUserToAddRows = $false
    $check = New-Object Windows.Forms.DataGridViewCheckBoxColumn
    $check.Name = 'Approve'; $null = $grid.Columns.Add($check)
    $id = New-Object Windows.Forms.DataGridViewTextBoxColumn
    $id.Name = 'Item'; $id.ReadOnly = $true; $null = $grid.Columns.Add($id)
    $effect = New-Object Windows.Forms.DataGridViewComboBoxColumn
    $effect.Name = 'Effect Review'
    $effect.Items.AddRange(@('Not applicable','Unreviewed','Read','Business Write','Bootstrap','Login','Initialization Read'))
    $null = $grid.Columns.Add($effect)
    [Console]::Error.WriteLine('ui-stage: columns-created')
    $items = @()
    for ($index = 0; $index -lt $Kinds.Count; $index++) {
        $kind = $Kinds[$index]
        $parameters = if ($kind) { @{review_kind=$kind} } else { @{} }
        $label = if ($kind) { 'Unreviewed' } else { 'Not applicable' }
        $null = $grid.Rows.Add($false,"item.$index",$label)
        $items += [pscustomobject]@{
            item_id="item.$index"; capability='web.page_step'; fingerprint=('a'*64); page='#/'
            max_uses=2; depends_on=@(); targets=@(); parameters=[pscustomobject]$parameters
            output=[pscustomobject]@{rows=0;columns=0;bytes=0}
            display=[pscustomobject]@{label='Network: GET /assets/app.js';preview='{}'}
            effect=[pscustomobject]@{class='task-bounded';fields=@();digest=('b'*64)}
        }
    }
    [Console]::Error.WriteLine('ui-stage: fixture-ready')
    return [pscustomobject]@{Grid=$grid;Items=$items}
}

function Invoke-TestClick($Button) {
    Assert-True ($Button -is [Windows.Forms.Button]) 'The native batch button is absent'
    $method = [Windows.Forms.Button].GetMethod('OnClick',[Reflection.BindingFlags]'Instance,NonPublic')
    $null = $method.Invoke($Button,@([EventArgs]::Empty))
}

function Get-NativeFormConstruction {
    $sourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\web_approval.ps1'
    $source = Get-Content -LiteralPath $sourcePath -Raw
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'The actual native helper cannot be parsed'
    $begin = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Send-Frame' },$true))[0]
    $writers = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Send-PrivateFrame' },$true))
    Assert-True ($writers.Count -eq 1) 'The production private frame writer is not uniquely bound'
    $dialogs = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'ShowDialog' -and
        $node.Expression -is [Management.Automation.Language.VariableExpressionAst] -and $node.Expression.VariablePath.UserPath -eq 'form'
    },$true))
    Assert-True ($dialogs.Count -eq 1) 'The production main dialog is not uniquely bound'
    $dialog = $dialogs[0]
    $end = $dialog
    while ($end -and $end -isnot [Management.Automation.Language.AssignmentStatementAst]) { $end = $end.Parent }
    Assert-True ($null -ne $begin -and $null -ne $end) 'The native form construction cannot be exercised'
    return [scriptblock]::Create($writers[0].Extent.Text + "`r`n" + $source.Substring($begin.Extent.StartOffset,$end.Extent.StartOffset-$begin.Extent.StartOffset))
}

$fixture = $null
$console = [Console]::Out
$captured = New-Object IO.StringWriter
try {
    [Console]::Error.WriteLine('ui-stage: scenario-start')
    [Console]::SetOut($captured)
    switch ($Scenario) {
        { $_ -in @('recommend-mixed','recommend-unknown','recommend-fixed-read','recommend-fixed-action','recommend-v3-proof','recommend-unchecked','recommend-binding','recommend-display-tamper') } {
            $fixture = New-Fixture -Kinds @('bootstrap','login','initialization-read','unclassified','write','')
            $fixture.Items[5].capability = 'web.read_region'
            if ($Scenario -eq 'recommend-unknown') { $fixture.Items[1].parameters.review_kind = 'future-effect' }
            if ($Scenario -eq 'recommend-fixed-action') { $fixture.Items[5].capability = 'web.business_action' }
            if ($Scenario -eq 'recommend-v3-proof') {
                $fixture.Grid.Dispose(); $fixture = New-Fixture -Kinds @('initialization-read')
                . (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\web_reference_review.ps1')
            }
            $script:manifest = [pscustomobject]@{
                request_id=('a'*32);nonce=('b'*64);request_digest=('c'*64)
                binding=[pscustomobject]@{origin='https://console.example';account='operator'}
                items=$fixture.Items;ttl_seconds=300;wait_seconds=180
            }
            $script:v3 = $Scenario -eq 'recommend-v3-proof'
            $script:decisionSent=$false; $script:decided=$false; $script:approved=$false
            $script:loadingTargets=$false; $script:selectedId=$null; $script:targetSelections=@{}
            $script:v3ReviewStarted=[Diagnostics.Stopwatch]::StartNew()
            if ($script:v3) {
                $state=New-V3ReferenceState -RequestId $manifest.request_id -ItemId 'item.0' -UnitCount 5
                $script:v3States=@{'item.0'=$state}
            }
            . (Get-NativeFormConstruction)
            $before=$manifest | ConvertTo-Json -Depth 24 -Compress
            Assert-True ($recommendButton -is [Windows.Forms.Button]) 'No per-item recommendation command'
            Assert-True ($grid.Columns.Contains('Recommendation') -and $grid.Columns['Recommendation'].ReadOnly) 'Recommendations are not visible/read-only'
            Assert-True (@($grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true }).Count -eq 0) 'Recommendations selected items'
            Assert-True ($grid.Rows[0].Cells['Effect Review'].Value -ceq 'Unreviewed') 'Display accepted a recommendation automatically'
            switch ($Scenario) {
                'recommend-mixed' {
                    Invoke-TestClick $selectAllButton
                    Invoke-TestClick $recommendButton
                    $expected=@('Bootstrap','Login','Initialization Read','Read','Business Write','Read only (fixed)')
                    for ($i=0;$i -lt $expected.Count;$i++) {
                        Assert-True ($grid.Rows[$i].Cells['Effect Review'].Value -ceq $expected[$i]) 'Mixed recommendation applied another item classification'
                    }
                    Assert-True ($captured.ToString().Length -eq 0 -and -not $script:decided) 'Applying recommendations emitted authority'
                    Invoke-TestClick $approveButton
                    $decision=$captured.ToString() | ConvertFrom-Json
                    Assert-True ($decision.choices.Count -eq 6) 'Final explicit approval lost items'
                    $semantics=@('bootstrap','login','initialization-read','read','write')
                    for ($i=0;$i -lt $semantics.Count;$i++) {
                        Assert-True ($decision.choices[$i].semantic_classification -ceq $semantics[$i]) 'Final decision changed a recommended network effect'
                    }
                    Assert-True (-not ($decision.choices[5].PSObject.Properties.Name -contains 'semantic_classification')) 'Typed read gained a network classification'
                    Assert-True (-not $batchTools.Enabled) 'Active grant left recommendations editable'
                    $null=$captured.GetStringBuilder().Clear()
                }
                'recommend-unknown' {
                    Invoke-TestClick $selectAllButton
                    $result=Set-CheckedEffectRecommendations -Grid $grid -Items $manifest.items
                    Assert-True (-not $result.ok -and $result.changed -eq 0) 'Unknown recommendation silently inherited an effect'
                    Assert-True ($grid.Rows[1].Cells['Recommendation'].Value -ceq 'Needs review') 'Unknown type is not visibly unresolved'
                    Assert-True ($grid.Rows[0].Cells['Effect Review'].Value -ceq 'Unreviewed') 'Unknown batch partially changed reviewed state'
                }
                'recommend-fixed-read' {
                    Assert-True ($grid.Rows[5].Cells['Effect Review'].Value -ceq 'Read only (fixed)') 'Typed read still has an ambiguous label'
                    Assert-True ($grid.Rows[5].Cells['Effect Review'].ReadOnly) 'Typed read classification is editable'
                    $grid.ClearSelection(); $grid.Rows[5].Selected=$true
                    Assert-True ($rowHint.Text.Contains('No network-effect choice') -and $rowHint.Text.Contains('approval')) 'Typed read explanation omits its meaning or approval'
                }
                'recommend-fixed-action' {
                    Assert-True ($grid.Rows[5].Cells['Effect Review'].Value -ceq 'Business action (fixed)') 'A typed business action was labelled as a read'
                    Assert-True ($grid.Rows[5].Cells['Effect Review'].ReadOnly) 'Typed action gained an editable network classification'
                    foreach ($capability in @('web.navigate','web.page_step','web.query_input','web.business_action','web.unknown')) {
                        $fixture.Items[5].capability=$capability
                        $recommendation=Get-ApprovalRecommendation $fixture.Items[5]
                        Assert-True ($recommendation.label -cne 'Read only (fixed)' -and $null -eq $recommendation.classification) 'A non-read action inherited read semantics'
                    }
                    $fixture.Items[5].capability='web.business_action'
                }
                'recommend-v3-proof' {
                    Invoke-TestClick $selectAllButton
                    foreach ($phase in @('unreviewed','pending','stale')) {
                        $state.pending=$phase -eq 'pending'
                        if ($phase -eq 'stale') {
                            $state.status='ready'; $state.review_ref='e'*32; $state.matched_revision=1; $state.edit_revision=2
                        }
                        $proofBefore=$state | ConvertTo-Json -Compress
                        Invoke-TestClick $recommendButton
                        Update-V3ApprovalButton
                        Assert-True (-not $approveButton.Enabled -and -not (Test-V3ReferenceDecisionReady $state)) 'Recommendation bypassed independent public-reference proof'
                        Assert-True (($state | ConvertTo-Json -Compress) -ceq $proofBefore) 'Recommendation fabricated or changed a reference proof'
                    }
                }
                'recommend-unchecked' {
                    $grid.Rows[0].Cells['Approve'].Value=$true
                    Invoke-TestClick $recommendButton
                    Assert-True ($grid.Rows[0].Cells['Effect Review'].Value -ceq 'Bootstrap') 'Checked recommendation was not applied'
                    Assert-True ($grid.Rows[1].Cells['Effect Review'].Value -ceq 'Unreviewed') 'Unchecked item changed'
                    Assert-True ($grid.Rows[1].Cells['Approve'].Value -eq $false) 'Recommendation checked another item'
                }
                'recommend-binding' {
                    $grid.Rows[0].Cells['Approve'].Value=$true
                    $grid.Rows[1].Cells['Approve'].Value=$true
                    $duplicate=@($manifest.items)+@($manifest.items[1])
                    $result=Set-CheckedEffectRecommendations -Grid $grid -Items $duplicate
                    Assert-True (-not $result.ok -and $result.changed -eq 0) 'Ambiguous item binding was accepted'
                    $missing=@($manifest.items | Where-Object { $_.item_id -cne 'item.1' })
                    $result=Set-CheckedEffectRecommendations -Grid $grid -Items $missing
                    Assert-True (-not $result.ok -and $result.changed -eq 0) 'Missing item binding was accepted'
                    Assert-True ($grid.Rows[0].Cells['Effect Review'].Value -ceq 'Unreviewed') 'Failed binding partially classified another row'
                }
                'recommend-display-tamper' {
                    $grid.Rows[4].Cells['Approve'].Value=$true
                    $grid.Rows[4].Cells['Recommendation'].Value='Read'
                    Invoke-TestClick $recommendButton
                    Assert-True ($grid.Rows[4].Cells['Effect Review'].Value -ceq 'Business Write') 'Mutable display data overrode the source effect'
                }
            }
            Assert-True (($manifest | ConvertTo-Json -Depth 24 -Compress) -ceq $before) 'Recommendations changed scope or limits'
            Assert-True ([int]$ttl.Value -eq 300 -and [int]$manifest.wait_seconds -eq 180) 'Recommendations changed time limits'
        }
        'select-all' {
            $fixture = New-Fixture -Kinds (@('bootstrap') * 15)
            $noise = @(Set-ApprovalChecks -Grid $fixture.Grid -Checked $true)
            Assert-True ($noise.Count -eq 0) 'Selection emitted pipeline output'
            Assert-True (@($fixture.Grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true }).Count -eq 15) 'Not all rows were checked'
            Assert-True (@($fixture.Grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -ne 'Unreviewed' }).Count -eq 0) 'Selection inferred an effect classification'
        }
        'clear-selection' {
            $fixture = New-Fixture -Kinds @('bootstrap','bootstrap')
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Bootstrap'
            Assert-True $result.ok 'Fixture classification failed'
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $false
            Assert-True (@($fixture.Grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true }).Count -eq 0) 'Clear left checked rows'
            Assert-True (@($fixture.Grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -ne 'Bootstrap' }).Count -eq 0) 'Clear silently changed reviewed effects'
        }
        'apply-bootstrap' {
            $fixture = New-Fixture -Kinds (@('bootstrap') * 15)
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Bootstrap'
            Assert-True ($result.ok -and $result.changed -eq 15) 'Bulk effect choice did not cover the 15 checked rows'
            Assert-True (@($fixture.Grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -ne 'Bootstrap' }).Count -eq 0) 'Wrong effect label applied'
            Assert-True (@($fixture.Items | Where-Object { $_.max_uses -ne 2 -or $_.output.bytes -ne 0 }).Count -eq 0) 'Classification widened source limits'
        }
        'apply-initialization-read' {
            $fixture = New-Fixture -Kinds @('initialization-read','initialization-read')
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Initialization Read'
            Assert-True ($result.ok -and $result.changed -eq 2) 'Exact initialization reads cannot be independently classified'
            Assert-True (@($fixture.Grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -cne 'Initialization Read' }).Count -eq 0) 'Initialization classification is not explicit'
        }
        'mixed-init-refused' {
            $fixture = New-Fixture -Kinds @('bootstrap','initialization-read')
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Initialization Read'
            Assert-True (-not $result.ok -and $result.changed -eq 0) 'Mixed static/read items were silently reclassified'
            Assert-True (@($fixture.Grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -cne 'Unreviewed' }).Count -eq 0) 'Mixed refusal partially changed effects'
        }
        { $_ -in @('init-hint','replacement-scope','replacement-carried-required','replacement-lifetime') } {
            $fixture = New-Fixture -Kinds @('bootstrap','bootstrap')
            if ($Scenario -eq 'init-hint') {
                $fixture.Grid.Dispose(); $fixture = New-Fixture -Kinds @('initialization-read')
                $fixture.Items[0].display.label = 'Network: POST /init'
                $fixture.Items[0].display.preview = (@{purpose='initialization-read';required=$true;
                    phase_applicability=@('bootstrap','login-once');descriptor=@{method='POST';path='/init';body=@{cmd='info'}};
                    response_checks=@(@{pointer='/exist';test='equals-boolean';expected=$true})} | ConvertTo-Json -Depth 10 -Compress)
            }
            $script:manifest = [pscustomobject]@{
                request_id=('a'*32);nonce=('b'*64);request_digest=('c'*64)
                binding=[pscustomobject]@{origin='https://console.example';account='operator'}
                items=$fixture.Items;ttl_seconds=43200;wait_seconds=120
            }
            if ($Scenario -ne 'init-hint') {
                $manifest | Add-Member -NotePropertyName replacement -NotePropertyValue ([pscustomobject]@{
                    source_grant_ids=@('d'*32);source_expires_in_seconds=300
                    carried_items=[pscustomobject]@{'item.0'=[pscustomobject]@{remaining_uses=2;source_grant_id=('d'*32);source_item_id='root'}}})
            }
            $script:decided=$false; $script:approved=$false; $script:loadingTargets=$false
            $script:selectedId=$null; $script:targetSelections=@{}
            . (Get-NativeFormConstruction)
            switch ($Scenario) {
                'init-hint' {
                    $batchReview.SelectedItem='Initialization Read'
                    Assert-True ($batchHint.Text.Contains('Exact POST') -and $batchHint.Text.Contains('no authentication')) 'Initialization help is missing its boundary'
                    Assert-True ($grid.Rows[0].Cells['Scope'].Value.Contains('Required')) 'Required initialization status is not visible'
                    $grid.ClearSelection(); $grid.Rows[0].Selected=$true
                    Assert-True ($details.Text.Contains('/exist') -and $details.Text.Contains('pre-login')) 'Readiness and pre-login applicability are not readable'
                    Assert-True (-not $script:decided -and $captured.ToString().Length -eq 0) 'Viewing initialization help granted authority'
                }
                'replacement-scope' {
                    Assert-True ($heading.Text.Contains('d'*32) -and $heading.Text.Contains('carried')) 'Replacement sources/carried obligation are not visible'
                    Assert-True ($heading.Text.Contains('no renewal')) 'Replacement appears to extend source expiry'
                }
                'replacement-carried-required' {
                    $check=Test-ReplacementSelection -Manifest $manifest -Choices @(@{item_id='item.1'})
                    Assert-True (-not $check.ok) 'Omitted carried permissions can reach final approval'
                    $check=Test-ReplacementSelection -Manifest $manifest -Choices @(@{item_id='item.0'})
                    Assert-True $check.ok 'Partial new selection wrongly removed valid carried scope'
                }
                'replacement-lifetime' {
                    Assert-True ([int]$ttl.Maximum -eq 300 -and [int]$ttl.Value -eq 300) 'Replacement UI renewed the source lifetime'
                    Assert-True ([int]$manifest.ttl_seconds -eq 43200 -and [int]$manifest.wait_seconds -eq 120) 'Display changed original review/scope data'
                }
            }
        }
        'checked-only' {
            $fixture = New-Fixture -Kinds @('bootstrap','bootstrap','bootstrap','')
            foreach ($index in @(0,2,3)) { $fixture.Grid.Rows[$index].Cells['Approve'].Value = $true }
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Bootstrap'
            Assert-True ($result.ok -and $result.changed -eq 2) 'Non-network row was classified'
            Assert-True ($fixture.Grid.Rows[1].Cells['Effect Review'].Value -eq 'Unreviewed') 'Unchecked row changed'
            Assert-True ($fixture.Grid.Rows[3].Cells['Effect Review'].Value -eq 'Not applicable') 'Not-applicable row changed'
        }
        'mixed-refused' {
            $fixture = New-Fixture -Kinds @('bootstrap','unclassified','write')
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Bootstrap'
            Assert-True (-not $result.ok) 'Mixed effects were relabelled'
            Assert-True (@($fixture.Grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -ne 'Unreviewed' }).Count -eq 0) 'Refused mixed update partially changed rows'
        }
        'wrong-class-refused' {
            $fixture = New-Fixture -Kinds @('write')
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Read'
            Assert-True (-not $result.ok) 'Business write was labelled as a read'
            Assert-True ($fixture.Grid.Rows[0].Cells['Effect Review'].Value -eq 'Unreviewed') 'Refused effect changed the row'
        }
        'unreviewed-refused' {
            $fixture = New-Fixture -Kinds @('bootstrap')
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Unreviewed'
            Assert-True (-not $result.ok) 'Default dropdown value was accepted as a review'
        }
        'unknown-kind-refused' {
            $fixture = New-Fixture -Kinds @('future-effect')
            Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Read'
            Assert-True (-not $result.ok) 'Unknown network effect inherited read authority'
        }
        'no-checked-refused' {
            $fixture = New-Fixture -Kinds @('bootstrap')
            $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification 'Bootstrap'
            Assert-True (-not $result.ok) 'Unselected item was included'
            Assert-True ($fixture.Grid.Rows[0].Cells['Effect Review'].Value -eq 'Unreviewed') 'Unselected effect changed'
        }
        'scope-countdown' {
            $fixture = New-Fixture -Kinds @('bootstrap')
            Assert-True ((Get-ApprovalScopeText -Item $fixture.Items[0]) -ceq 'Network: GET /assets/app.js') 'Exact sanitized request label is not visible'
            Assert-True ((Get-ApprovalReviewText -WaitSeconds 120 -ElapsedSeconds 1.2 -Decided $false -Approved $false) -ceq 'Review expires in 01:59') 'Pending countdown is incorrect'
            Assert-True ((Get-ApprovalReviewText -WaitSeconds 120 -ElapsedSeconds 120 -Decided $false -Approved $false) -ceq 'Review expired') 'Expired review appears usable'
            Assert-True ((Get-ApprovalReviewText -WaitSeconds 120 -ElapsedSeconds 121 -Decided $true -Approved $true) -ceq 'Authorization active') 'Grant was confused with the pending-review timer'
            Assert-True ((Get-ApprovalReviewText -WaitSeconds 120 -ElapsedSeconds 1 -Decided $true -Approved $false) -ceq 'Review complete') 'Rejection appeared to be an active grant'
            $fixture.Items[0].display.label = 'x' * 3000
            Assert-True ((Get-ApprovalScopeText -Item $fixture.Items[0]).Length -eq 2051) 'Scope display was unbounded'
            Assert-True ($fixture.Items[0].display.label.Length -eq 3000) 'Display truncation changed the underlying scope'
        }
        'known-effects' {
            foreach ($case in @(@{kind='unclassified';label='Read'},@{kind='write';label='Business Write'},@{kind='login';label='Login'})) {
                $fixture = New-Fixture -Kinds @($case.kind)
                Set-ApprovalChecks -Grid $fixture.Grid -Checked $true
                $result = Set-CheckedEffectReview -Grid $fixture.Grid -Items $fixture.Items -Classification $case.label
                Assert-True ($result.ok -and $fixture.Grid.Rows[0].Cells['Effect Review'].Value -ceq $case.label) 'An explicitly matching effect was refused'
                $fixture.Grid.Dispose(); $fixture = $null
            }
        }
        'v3-awaiting-commit' {
            . (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\web_reference_review.ps1')
            $fixture = New-Fixture -Kinds @('initialization-read')
            $script:manifest = [pscustomobject]@{
                request_id=('a'*32);nonce=('b'*64);request_digest=('c'*64)
                binding=[pscustomobject]@{origin='https://fixture.example';account='operator'}
                items=$fixture.Items;ttl_seconds=300;wait_seconds=180
            }
            $script:v3=$true; $script:decisionSent=$false; $script:decided=$false; $script:approved=$false
            $script:loadingTargets=$false; $script:selectedId=$null; $script:targetSelections=@{}
            $script:v3ReviewStarted=[Diagnostics.Stopwatch]::StartNew()
            $state=New-V3ReferenceState -RequestId $manifest.request_id -ItemId 'item.0' -UnitCount 5
            $state.status='ready'; $state.review_ref='e'*32; $state.matched_revision=1
            $script:v3States=@{'item.0'=$state}
            . (Get-NativeFormConstruction)
            Invoke-TestClick $selectAllButton
            $batchReview.SelectedItem='Initialization Read'; Invoke-TestClick $applyCheckedButton
            Update-V3ApprovalButton
            Invoke-TestClick $approveButton
            $decision=$captured.ToString() | ConvertFrom-Json
            Assert-True ($decision.event -ceq 'decision') 'Synthetic final decision was not emitted'
            Assert-True (-not $script:decided -and -not $script:approved -and $script:decisionSent) 'A sent v3 decision became authority without acknowledgment'
            Assert-True ($form.Text.Contains('Awaiting') -and $heading.Text.Contains('Awaiting')) 'The native body did not wait for authority commit'
            Assert-True (-not $heading.Text.Contains('Authorization active')) 'The native body optimistically advertised active authority'
            Assert-True ((Get-ApprovalReviewText -WaitSeconds 180 -ElapsedSeconds 181 -Decided $false -Approved $false -PendingCommit $true) -ceq 'Review expired') 'Pending commit extended the original review'
            $null=$captured.GetStringBuilder().Clear()
        }
        'native-wiring' {
            $fixture = New-Fixture -Kinds (@('bootstrap') * 15)
            $script:manifest = [pscustomobject]@{
                request_id=('a'*32);nonce=('b'*64);request_digest=('c'*64)
                binding=[pscustomobject]@{origin='https://console.example';account='operator'}
                items=$fixture.Items;ttl_seconds=300;wait_seconds=120
            }
            $script:decided = $false; $script:approved = $false; $script:loadingTargets = $false
            $script:selectedId = $null; $script:targetSelections = @{}
            # Construct the production form in memory; never open or approve a real task.
            . (Get-NativeFormConstruction)
            Assert-True ($grid.Columns.Contains('Scope') -and $grid.Columns['Scope'].ReadOnly) 'The native form does not show read-only request scopes'
            Assert-True ($grid.Rows[0].Cells['Scope'].Value -ceq 'Network: GET /assets/app.js') 'The native scope label is absent'
            Assert-True ($heading.Text.Contains('Review expires in')) 'The native review countdown is absent'
            Assert-True ($batchReview.SelectedItem -ceq 'Unreviewed') 'The batch dropdown inferred a classification'
            Invoke-TestClick $selectAllButton
            Assert-True (@($grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true }).Count -eq 15) 'The Select All button is not wired'
            Invoke-TestClick $clearSelectionButton
            Assert-True (@($grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true }).Count -eq 0) 'The Clear Selection button is not wired'
            Invoke-TestClick $selectAllButton
            $batchReview.SelectedItem = 'Bootstrap'
            Invoke-TestClick $applyCheckedButton
            Assert-True (@($grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -ne 'Bootstrap' }).Count -eq 0) 'The Apply to Checked button is not wired'
            Assert-True ($captured.ToString().Length -eq 0 -and -not $script:approved) 'Batch controls approved or emitted a frame'
            $grid.Rows[14].Cells['Approve'].Value = $false
            Invoke-TestClick $approveButton
            $decision = $captured.ToString() | ConvertFrom-Json
            Assert-True ($decision.event -ceq 'decision' -and $decision.choices.Count -eq 14) 'Final native approval ignored partial selection'
            Assert-True ($decision.nonce -ceq ('b'*64) -and $decision.request_digest -ceq ('c'*64)) 'Final native decision lost its binding'
            Assert-True (@($decision.choices | Where-Object { $_.semantic_classification -cne 'bootstrap' -or $_.max_uses -ne 2 -or $_.item_id -ceq 'item.14' }).Count -eq 0) 'Final native decision widened or relabelled its checked scope'
            Assert-True ($script:approved -and -not $batchTools.Enabled -and $revokeButton.Enabled) 'Active approval left batch choices editable'
            $null = $captured.GetStringBuilder().Clear()
        }
        { $_ -in @('hint-selection','hint-row','hint-tooltips','hint-resize','hint-action-context') } {
            $fixture = New-Fixture -Kinds @('bootstrap','login','unclassified','write','')
            if ($Scenario -eq 'hint-action-context') {
                $fixture.Grid.Dispose()
                $fixture = New-Fixture -Kinds @('')
                $fixture.Items[0].capability = 'web.business_action'
                $fixture.Items[0].effect.class = 'action-time'
                $fixture.Items[0].max_uses = 1
                $fixture.Items[0].targets = @('node-1')
            }
            $script:manifest = [pscustomobject]@{
                request_id=('a'*32);nonce=('b'*64);request_digest=('c'*64)
                binding=[pscustomobject]@{origin='https://console.example';account='operator'}
                items=$fixture.Items;ttl_seconds=43200;wait_seconds=120
            }
            if ($Scenario -eq 'hint-action-context') { $manifest.ttl_seconds = 30 }
            $script:decided = $false; $script:approved = $false; $script:loadingTargets = $false
            $script:selectedId = $null; $script:targetSelections = @{}
            . (Get-NativeFormConstruction)
            $before = $manifest | ConvertTo-Json -Depth 24 -Compress
            Assert-True ($batchHint -is [Windows.Forms.Label]) 'The dropdown has no adjacent effect explanation'
            Assert-True ($rowHint -is [Windows.Forms.Label]) 'The selected item has no effect explanation'
            switch ($Scenario) {
                'hint-selection' {
                    foreach ($case in @(
                        @{label='Bootstrap';boundary='no POST'},
                        @{label='Login';boundary='sign-in'},
                        @{label='Read';boundary='no business changes'},
                        @{label='Business Write';boundary='preview'},
                        @{label='Unreviewed';boundary='no network permission'}
                    )) {
                        $batchReview.SelectedItem = $case.label
                        Assert-True ($batchHint.Text.StartsWith($case.label + ':')) 'Dropdown explanation is stale or has the wrong category'
                        Assert-True ($batchHint.Text.ToLowerInvariant().Contains($case.boundary.ToLowerInvariant())) 'The selected category does not explain its effect boundary'
                        Assert-True ($batchReview.SelectedItem -ceq $case.label) 'Showing help changed the chosen category'
                    }
                    Assert-True (@($grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true }).Count -eq 0) 'Showing help selected approval items'
                    Assert-True (@($grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -ne 'Unreviewed' -and $_.Cells['Effect Review'].Value -ne 'Page action (fixed)' }).Count -eq 0) 'Showing help classified request items'
                }
                'hint-row' {
                    $grid.ClearSelection(); $grid.Rows[0].Selected = $true
                    Assert-True ($rowHint.Text.Contains('Unreviewed:')) 'A newly selected network row appeared reviewed'
                    $grid.Rows[0].Cells['Effect Review'].Value = 'Bootstrap'
                    Assert-True ($rowHint.Text.Contains('Bootstrap:')) 'Editing the selected row left its explanation stale'
                    $grid.ClearSelection(); $grid.Rows[1].Selected = $true
                    Assert-True ($rowHint.Text.Contains('Unreviewed:')) 'Changing rows retained the previous classification explanation'
                    $grid.Rows[1].Cells['Effect Review'].Value = 'Login'
                    Assert-True ($rowHint.Text.Contains('Login:')) 'The sign-in row explanation is stale'
                    $grid.ClearSelection(); $grid.Rows[4].Selected = $true
                    Assert-True ($rowHint.Text.Contains('Page action (fixed):')) 'A non-network row inherited a network classification explanation'
                    $batchReview.SelectedItem = 'Read'
                    Assert-True ($rowHint.Text.Contains('Page action (fixed):')) 'The batch choice overwrote the selected row explanation'
                    $grid.ClearSelection()
                    Assert-True ($rowHint.Text.StartsWith('Select an item')) 'An empty selection retained another item explanation'
                }
                'hint-tooltips' {
                    foreach ($name in @('Uses','Rows','Columns','Bytes')) {
                        Assert-True ($grid.Columns[$name].HeaderCell.ToolTipText.Length -gt 20) 'A limit header has no explanation'
                        Assert-True ($grid.Rows[0].Cells[$name].ToolTipText.Length -gt 20) 'A limit cell has no explanation'
                    }
                    Assert-True ($helpTips.GetToolTip($ttl).Contains('12 hours')) 'The lifetime field does not explain its units and task bound'
                    Assert-True ($helpTips.GetToolTip($ttl).Contains('180-second')) 'The task lifetime is confused with the review deadline'
                    Assert-True ($helpTips.GetToolTip($applyCheckedButton).Contains('does not approve')) 'Batch classification help implies immediate authority'
                    Assert-True ($helpTips.GetToolTip($revokeButton).Contains('cannot undo')) 'Revocation help implies rollback'
                }
                'hint-action-context' {
                    Assert-True ([int]$ttl.Maximum -eq 30 -and [int]$ttl.Value -eq 30) 'An action confirmation gained task-grant lifetime'
                    Assert-True ($helpTips.GetToolTip($ttl).Contains('one-use action confirmations: up to 30 seconds')) 'Help does not distinguish the short action-confirmation lifetime'
                    Assert-True ($helpTips.GetToolTip($revokeButton).Contains('does not revoke its parent grant')) 'Help falsely implies cancelling a confirmation revokes the parent grant'
                    Assert-True ($helpTips.GetToolTip($revokeButton).Contains('in-flight')) 'Help omits the in-flight safety-fencing boundary'
                    $batchReview.SelectedItem = 'Business Write'
                    Assert-True ([int]$grid.Rows[0].Cells['Uses'].Value -eq 1) 'Help widened a one-use confirmation'
                }
                'hint-resize' {
                    $batchReview.SelectedItem = 'Business Write'
                    $grid.ClearSelection(); $grid.Rows[3].Selected = $true
                    $grid.Rows[3].Cells['Effect Review'].Value = 'Business Write'
                    $form.CreateControl()
                    foreach ($size in @(@(1050,720),@(1250,860),@(1600,1000),@(1050,720))) {
                        $form.Size = New-Object Drawing.Size($size[0],$size[1])
                        $form.PerformLayout(); $layout.PerformLayout(); $batchTools.PerformLayout(); $detailsPanel.PerformLayout()
                        foreach ($control in @($batchHint,$rowHint)) {
                            $preferred = $control.GetPreferredSize((New-Object Drawing.Size($control.Width,0)))
                            Assert-True ($control.Height -ge $preferred.Height) 'An effect explanation is vertically clipped'
                            Assert-True ($control.Left -ge 0 -and $control.Right -le $control.Parent.ClientSize.Width) 'An effect explanation extends beyond its panel'
                        }
                        foreach ($button in @($selectAllButton,$clearSelectionButton,$applyCheckedButton,$recommendButton)) {
                            Assert-True (-not $batchHint.Bounds.IntersectsWith($button.Bounds)) 'Help overlaps a batch command'
                            Assert-True ($button.Bottom -le $batchTools.ClientSize.Height) 'A wrapped command is clipped'
                        }
                        Assert-True ($details.Bounds.Top -ge $rowHint.Bottom) 'Selected-row help overlaps the request details'
                    }
                }
            }
            Assert-True (($manifest | ConvertTo-Json -Depth 24 -Compress) -ceq $before) 'Help changed the original scope or limits'
            Assert-True ([int]$ttl.Value -eq [int]$manifest.ttl_seconds -and [int]$manifest.wait_seconds -eq 120) 'Help changed a lifetime or review deadline'
            Assert-True (-not $script:approved -and -not $script:decided) 'Help granted authority'
        }
        default { throw 'Unknown test scenario' }
    }
    Assert-True ($captured.ToString().Length -eq 0) 'Selection/classification emitted a decision or unsolicited console output'
    [Console]::Error.WriteLine('ui-stage: scenario-end')
} finally {
    [Console]::SetOut($console)
    $captured.Dispose()
    if ($timer) { $timer.Stop(); $timer.Dispose() }
    if ($form) { $form.Dispose() }
    if ($helpTips) { $helpTips.Dispose() }
    if ($fixture) { $fixture.Grid.Dispose() }
}
[Console]::WriteLine('{"implemented":true,"passed":true}')
