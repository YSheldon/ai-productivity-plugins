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
    $effect.Items.AddRange(@('Not applicable','Unreviewed','Read','Business Write','Bootstrap','Login'))
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
    $dialog = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'ShowDialog' },$true))[0]
    $end = $dialog
    while ($end -and $end -isnot [Management.Automation.Language.AssignmentStatementAst]) { $end = $end.Parent }
    Assert-True ($null -ne $begin -and $null -ne $end) 'The native form construction cannot be exercised'
    return [scriptblock]::Create($source.Substring($begin.Extent.StartOffset,$end.Extent.StartOffset-$begin.Extent.StartOffset))
}

$fixture = $null
$console = [Console]::Out
$captured = New-Object IO.StringWriter
try {
    [Console]::Error.WriteLine('ui-stage: scenario-start')
    [Console]::SetOut($captured)
    switch ($Scenario) {
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
                    Assert-True (@($grid.Rows | Where-Object { $_.Cells['Effect Review'].Value -ne 'Unreviewed' -and $_.Cells['Effect Review'].Value -ne 'Not applicable' }).Count -eq 0) 'Showing help classified request items'
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
                    Assert-True ($rowHint.Text.Contains('Not applicable:')) 'A non-network row inherited a network classification explanation'
                    $batchReview.SelectedItem = 'Read'
                    Assert-True ($rowHint.Text.Contains('Not applicable:')) 'The batch choice overwrote the selected row explanation'
                    $grid.ClearSelection()
                    Assert-True ($rowHint.Text.StartsWith('Select an item')) 'An empty selection retained another item explanation'
                }
                'hint-tooltips' {
                    foreach ($name in @('Uses','Rows','Columns','Bytes')) {
                        Assert-True ($grid.Columns[$name].HeaderCell.ToolTipText.Length -gt 20) 'A limit header has no explanation'
                        Assert-True ($grid.Rows[0].Cells[$name].ToolTipText.Length -gt 20) 'A limit cell has no explanation'
                    }
                    Assert-True ($helpTips.GetToolTip($ttl).Contains('12 hours')) 'The lifetime field does not explain its units and task bound'
                    Assert-True ($helpTips.GetToolTip($ttl).Contains('120-second')) 'The task lifetime is confused with the review deadline'
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
                        foreach ($button in @($selectAllButton,$clearSelectionButton,$applyCheckedButton)) {
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
