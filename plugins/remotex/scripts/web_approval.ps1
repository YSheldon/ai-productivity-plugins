param([switch]$DescribeProtocol)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($DescribeProtocol) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        . (Join-Path $PSScriptRoot 'web_approval_ui.ps1')
        . (Join-Path $PSScriptRoot 'web_reference_review.ps1')
        foreach ($name in @('New-V3ReferenceState','Apply-V3ReferenceResult','New-V3PublicReferencePanel','New-ApprovalNotification')) {
            if (-not (Get-Command $name -CommandType Function -ErrorAction Stop)) { exit 1 }
        }
        if ($script:RemoteXReferenceProtocol.protocol_revision -ne 3 -or $script:RemoteXReferenceProtocol.reference_units -ne 32) { exit 1 }
        [Console]::WriteLine('{"protocol_revision":3,"reference_units":32,"review_seconds":180,"notification":"owned-native-v1"}')
        exit 0
    } catch { exit 1 }
}
$script:decided = $false
$script:approved = $false
$script:loadingTargets = $false
$script:selectedId = $null
$script:targetSelections = @{}
$script:manifestValidated = $false
$script:uiShown = $false
$script:uiCloseReason = 'window-closed'
$script:v3 = $false
$script:decisionSent = $false
$script:v3States = @{}
$script:v3ReplyReader = $null
$script:v3ReferenceAttempts = 0
$script:v3ProtocolFailed = $false
$script:approvalNotification = $null

function Send-UiReceipt([string]$eventName, [string]$reason) {
    if (-not $script:manifestValidated) { return }
    try {
        $frame = [ordered]@{ event = $eventName; request_id = $manifest.request_id; nonce = $manifest.nonce; request_digest = $manifest.request_digest; reason = $reason }
        [Console]::Error.WriteLine(($frame | ConvertTo-Json -Compress))
        [Console]::Error.Flush()
    } catch { }
}

try {
    if (-not [Environment]::UserInteractive) { exit 1 }
    [Console]::InputEncoding = New-Object Text.UTF8Encoding($false, $true)
    [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false, $true)
    $line = [Console]::ReadLine()
    if (-not $line -or $line.Length -gt 65536) { exit 1 }
    $script:manifest = $line | ConvertFrom-Json
    $script:v3ReviewStarted = [Diagnostics.Stopwatch]::StartNew()
    if ($manifest.request_id -notmatch '^[a-f0-9]{32}$' -or $manifest.nonce -notmatch '^[a-f0-9]{64}$' -or $manifest.request_digest -notmatch '^[a-f0-9]{64}$') { exit 1 }
    if (@($manifest.items).Count -gt 32) { exit 1 }
    $script:manifestValidated = $true
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    . (Join-Path $PSScriptRoot 'web_approval_ui.ps1')

    function Send-PrivateFrame($Frame) {
        $packet = $Frame | ConvertTo-Json -Depth 24 -Compress
        if ([Text.Encoding]::UTF8.GetByteCount($packet) + 1 -gt 32768) { throw 'Private frame capacity exceeded' }
        [Console]::WriteLine($packet); [Console]::Out.Flush()
    }

    if ($null -ne $manifest.protocol_revision) {
        if ($manifest.protocol_revision -ne 3 -or [Text.Encoding]::UTF8.GetByteCount($line) -gt 32768) { throw 'Unsupported private protocol' }
        $script:v3 = $true
        . (Join-Path $PSScriptRoot 'web_reference_review.ps1')
        $profiles = @('json-utf8-v1','form-utf8-v1','form-json-name-view-v1')
        if (@($manifest.reference_items).Count -ne @($manifest.items).Count -or @($manifest.reference_items).Count -lt 1) { throw 'Reference scope unavailable' }
        foreach ($meta in @($manifest.reference_items)) {
            $keys = @('item_id','profile_id','locations','cookie_context_ref','response_checks')
            $names = @($meta.PSObject.Properties.Name)
            if ($names.Count -ne $keys.Count -or @($names | Where-Object { $_ -cnotin $keys }).Count -gt 0 -or
                $meta.profile_id -cnotin $profiles -or $script:v3States.ContainsKey([string]$meta.item_id) -or
                @($manifest.items | Where-Object { $_.item_id -ceq $meta.item_id }).Count -ne 1 -or
                @($meta.locations).Count -lt 1 -or @($meta.locations).Count -gt 32) { throw 'Reference scope unavailable' }
            foreach ($location in @($meta.locations)) {
                if ($location.ref -isnot [string] -or $location.ref -cnotmatch '^[a-f0-9]{32}$' -or $location.sensitive -isnot [bool]) { throw 'Reference scope unavailable' }
            }
            if ($null -ne $meta.cookie_context_ref -and $meta.cookie_context_ref -cnotmatch '^[a-f0-9]{32}$') { throw 'Reference scope unavailable' }
            $script:v3States[[string]$meta.item_id] = New-V3ReferenceState -RequestId $manifest.request_id -ItemId $meta.item_id -Nonce $manifest.nonce -RequestDigest $manifest.request_digest -UnitCount @($meta.locations).Count
        }
        $script:v3ReplyReader = New-Object RemoteX.V3ReplyQueue([Console]::OpenStandardInput())
        Send-PrivateFrame ([ordered]@{event='helper-ready';request_id=$manifest.request_id;nonce=$manifest.nonce;request_digest=$manifest.request_digest;protocol_revision=3;profiles=$profiles})
    }

    function Send-Frame([string]$eventName, $choices, [int]$ttl) {
        $frame = [ordered]@{ event = $eventName; request_id = $manifest.request_id; nonce = $manifest.nonce; request_digest = $manifest.request_digest }
        if ($eventName -eq 'decision') { $frame.choices = @($choices); $frame.ttl_seconds = $ttl }
        Send-PrivateFrame $frame
    }

    function Get-V3RemainingSeconds {
        return [Math]::Max(0,[int][Math]::Floor([double]$manifest.wait_seconds - $script:v3ReviewStarted.Elapsed.TotalSeconds))
    }

    function Update-V3ApprovalButton {
        if (-not $script:v3) { return }
        $checked = @($grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true })
        $enabled = ($checked.Count -gt 0 -and -not $script:decisionSent -and (Get-V3RemainingSeconds) -gt 0)
        foreach ($row in $checked) {
            $state = $script:v3States[[string]$row.Cells['Item'].Value]
            if (-not $state -or -not (Test-V3ReferenceDecisionReady $state)) { $enabled = $false }
        }
        $approveButton.Enabled = $enabled
    }

    function Update-V3PrivateReplies {
        if (-not $script:v3) { return $true }
        if ($script:v3ReplyReader.Failed -or $script:v3ReplyReader.Completed) { return $false }
        $raw = ''
        for ($at = 0; $at -lt 8 -and $script:v3ReplyReader.TryTake([ref]$raw); $at++) {
            try {
                $reply = $raw | ConvertFrom-Json
                if ($reply.request_id -cne $manifest.request_id -or $reply.nonce -cne $manifest.nonce -or $reply.request_digest -cne $manifest.request_digest) { return $false }
                if ($reply.event -ceq 'reference-result') {
                    $state = $script:v3States[[string]$reply.item_id]
                    if (-not $state -or $reply.check_id -cne $state.check_id) { return $false }
                    $stale = $reply.edit_revision -ne $state.edit_revision
                    if (-not (Apply-V3ReferenceResult -State $state -Frame $reply) -and -not $stale) { return $false }
                } elseif ($reply.event -ceq 'decision-result') {
                    $keys = @('event','request_id','nonce','request_digest','state','grant_id','expires_in_seconds','effective_limits')
                    $names = @($reply.PSObject.Properties.Name)
                    if ($names.Count -ne $keys.Count -or @($names | Where-Object { $_ -cnotin $keys }).Count -gt 0 -or
                        -not $script:decisionSent -or $script:decided -or (Get-V3RemainingSeconds) -le 0) { return $false }
                    if ($reply.state -ceq 'active') {
                        if ($reply.grant_id -isnot [string] -or $reply.grant_id -cnotmatch '^[a-f0-9]{32}$' -or
                            ($reply.expires_in_seconds -isnot [int] -and $reply.expires_in_seconds -isnot [long]) -or
                            $reply.expires_in_seconds -lt 1 -or $reply.expires_in_seconds -gt [int]$ttl.Value) { return $false }
                        $limits = @($reply.effective_limits.PSObject.Properties)
                        if ($limits.Count -lt 1 -or $limits.Count -gt @($script:v3SentChoices).Count) { return $false }
                        foreach ($limit in $limits) {
                            $source = @($script:v3SentChoices | Where-Object { $_.item_id -ceq $limit.Name })
                            if ($source.Count -ne 1 -or $limit.Value.max_uses -lt 1 -or $limit.Value.max_uses -gt $source[0].max_uses) { return $false }
                        }
                        $script:decided = $true; $script:approved = $true
                        $form.Text = 'RemoteX Authorization Active - Revoke to stop'
                        $revokeButton.Enabled = $true
                        $details.Text += "`r`n`r`nCommitted effective limits:`r`n" + ($reply.effective_limits | ConvertTo-Json -Depth 16)
                    } elseif ($reply.state -cin @('rejected','cancelled')) {
                        $script:decided = $true; $script:uiCloseReason = 'operator-rejected'; $form.Close()
                    } else { return $false }
                } else { return $false }
            } catch { return $false }
        }
        Update-V3ApprovalButton
        return $true
    }

    function Save-Targets {
        if (-not $script:loadingTargets -and $script:selectedId) {
            $selected = @()
            for ($index = 0; $index -lt $targetList.Items.Count; $index++) {
                if ($targetList.GetItemChecked($index)) { $selected += [string]$targetList.Items[$index] }
            }
            $script:targetSelections[$script:selectedId] = $selected
        }
    }

    $form = New-Object Windows.Forms.Form
    $form.Text = 'RemoteX Task Authorization'
    $form.Size = New-Object Drawing.Size(1250, 860)
    $form.MinimumSize = New-Object Drawing.Size(1050, 720)
    $form.StartPosition = 'CenterScreen'
    $form.Font = [Drawing.SystemFonts]::MessageBoxFont
    $form.AcceptButton = $null
    $layout = New-Object Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.ColumnCount = 2; $layout.RowCount = 5
    # Standard output is reserved for decision and revocation frames.
    $null = $layout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 70)))
    $null = $layout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 30)))
    $null = $layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::AutoSize)))
    $null = $layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::AutoSize)))
    foreach ($height in @(55, 45)) { $null = $layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, $height))) }
    $null = $layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 76)))
    $form.Controls.Add($layout)
    $heading = New-Object Windows.Forms.Label
    $heading.AutoSize = $true; $heading.Dock = 'Top'; $heading.Padding = New-Object Windows.Forms.Padding(12)
    $heading.MaximumSize = New-Object Drawing.Size([Math]::Max(1, $form.ClientSize.Width - 24), 0)
    $contextHeading = Get-ApprovalContextText $manifest
    $heading.Text = $contextHeading + "`r`n" + (Get-ApprovalReviewText -WaitSeconds $manifest.wait_seconds -ElapsedSeconds 0 -Decided $false -Approved $false)
    $layout.Controls.Add($heading, 0, 0); $layout.SetColumnSpan($heading, 2)
    $layout.Add_SizeChanged({ $heading.MaximumSize = New-Object Drawing.Size([Math]::Max(1, $layout.ClientSize.Width - $heading.Margin.Horizontal), 0) })

    $grid = New-Object Windows.Forms.DataGridView
    $grid.Dock = 'Fill'; $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
    $grid.RowHeadersVisible = $false; $grid.MultiSelect = $false
    $grid.SelectionMode = 'FullRowSelect'; $grid.AutoSizeColumnsMode = 'Fill'
    $checkColumn = New-Object Windows.Forms.DataGridViewCheckBoxColumn
    $checkColumn.Name = 'Approve'; $checkColumn.FillWeight = 22; $null = $grid.Columns.Add($checkColumn)
    foreach ($columnName in @('Item', 'Capability', 'Scope', 'Uses', 'Rows', 'Columns', 'Bytes')) {
        $column = New-Object Windows.Forms.DataGridViewTextBoxColumn
        $column.Name = $columnName; $column.ReadOnly = ($columnName -in @('Item', 'Capability', 'Scope'))
        $null = $grid.Columns.Add($column)
    }
    $semanticColumn = New-Object Windows.Forms.DataGridViewComboBoxColumn
    $semanticColumn.Name = 'Effect Review'; $semanticColumn.FillWeight = 170
    $semanticColumn.Items.AddRange(@('Not applicable', 'Unreviewed', 'Read', 'Business Write', 'Bootstrap', 'Login', 'Initialization Read'))
    $semanticColumn.MinimumWidth = 145
    $null = $grid.Columns.Add($semanticColumn)
    $limitHints = @{
        Uses = 'Maximum executions for this item. You may reduce, but not increase, the requested count.'
        Rows = 'Maximum rows returned by an approved read, not the number of targets that may be changed.'
        Columns = 'Maximum columns returned by an approved read. Only the approved output is included.'
        Bytes = 'Maximum returned data in bytes. A lower value narrows the approved output budget.'
    }
    foreach ($name in $limitHints.Keys) { $grid.Columns[$name].HeaderCell.ToolTipText = $limitHints[$name] }
    foreach ($name in @('Uses', 'Rows', 'Columns', 'Bytes')) { $grid.Columns[$name].FillWeight = 45 }
    $grid.Columns['Item'].FillWeight = 120; $grid.Columns['Capability'].FillWeight = 140
    $grid.Columns['Scope'].FillWeight = 220; $grid.Columns['Scope'].MinimumWidth = 250
    foreach ($item in @($manifest.items)) {
        $effectReview = if ($item.parameters.review_kind) { 'Unreviewed' } else { 'Not applicable' }
        $rowIndex = $grid.Rows.Add($false, [string]$item.item_id, [string]$item.capability, (Get-ApprovalScopeText $item), [string]$item.max_uses,
            [string]$item.output.rows, [string]$item.output.columns, [string]$item.output.bytes, $effectReview)
        if (-not $item.parameters.review_kind) { $grid.Rows[$rowIndex].Cells['Effect Review'].ReadOnly = $true }
        $grid.Rows[$rowIndex].Cells['Scope'].ToolTipText = [string]$item.display.label
        foreach ($name in $limitHints.Keys) { $grid.Rows[$rowIndex].Cells[$name].ToolTipText = $limitHints[$name] }
        $script:targetSelections[[string]$item.item_id] = @($item.targets)
    }
    $layout.Controls.Add($grid, 0, 2); $layout.SetColumnSpan($grid, 2)
    $detailsPanel = New-Object Windows.Forms.TableLayoutPanel
    $detailsPanel.Dock = 'Fill'; $detailsPanel.ColumnCount = 1; $detailsPanel.RowCount = 2
    $null = $detailsPanel.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
    $null = $detailsPanel.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::AutoSize)))
    $null = $detailsPanel.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
    $layout.Controls.Add($detailsPanel, 0, 3)
    $rowHint = New-Object Windows.Forms.Label
    $rowHint.AutoSize = $true; $rowHint.Dock = 'Top'; $rowHint.Padding = New-Object Windows.Forms.Padding(3, 6, 3, 6)
    $rowHint.Text = 'Select an item to see its current effect classification and limits.'
    $detailsPanel.Controls.Add($rowHint, 0, 0)
    $detailsPanel.Add_SizeChanged({
        $rowHint.MaximumSize = New-Object Drawing.Size([Math]::Max(1, $detailsPanel.ClientSize.Width - $rowHint.Margin.Horizontal), 0)
    })
    $details = New-Object Windows.Forms.TextBox
    $details.Dock = 'Fill'; $details.Multiline = $true; $details.ReadOnly = $true
    $details.ScrollBars = 'Both'; $details.WordWrap = $false
    $detailsPanel.Controls.Add($details, 0, 1)
    $targetList = New-Object Windows.Forms.CheckedListBox
    $targetList.Dock = 'Fill'; $targetList.CheckOnClick = $true
    $layout.Controls.Add($targetList, 1, 3)
    $grid.Add_SelectionChanged({
        Save-Targets
        Update-SelectedEffectHint -Grid $grid -Hint $rowHint
        if ($grid.SelectedRows.Count -eq 0) { return }
        $script:selectedId = [string]$grid.SelectedRows[0].Cells['Item'].Value
        $item = @($manifest.items | Where-Object { $_.item_id -eq $script:selectedId })[0]
        $details.Text = Get-ApprovalDetailsText $item
        $script:loadingTargets = $true; $targetList.Items.Clear()
        foreach ($target in @($item.targets)) { $null = $targetList.Items.Add([string]$target, ($script:targetSelections[$script:selectedId] -contains $target)) }
        $script:loadingTargets = $false
    })
    $grid.Add_CurrentCellDirtyStateChanged({ if ($grid.IsCurrentCellDirty) { $null = $grid.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit) } })
    $batchTools = New-Object Windows.Forms.FlowLayoutPanel
    $batchTools.Dock = 'Fill'; $batchTools.WrapContents = $true; $batchTools.AutoSize = $true
    $batchTools.AutoSizeMode = 'GrowAndShrink'
    $batchTools.Padding = New-Object Windows.Forms.Padding(10, 4, 10, 4)
    $layout.Controls.Add($batchTools, 0, 1); $layout.SetColumnSpan($batchTools, 2)
    $selectAllButton = New-Object Windows.Forms.Button
    $selectAllButton.Text = 'Select All'; $selectAllButton.AutoSize = $true
    $batchTools.Controls.Add($selectAllButton)
    $clearSelectionButton = New-Object Windows.Forms.Button
    $clearSelectionButton.Text = 'Clear Selection'; $clearSelectionButton.AutoSize = $true
    $batchTools.Controls.Add($clearSelectionButton)
    $reviewLabel = New-Object Windows.Forms.Label
    $reviewLabel.Text = 'Effect Review'; $reviewLabel.AutoSize = $true; $reviewLabel.Padding = New-Object Windows.Forms.Padding(10, 6, 0, 0)
    $batchTools.Controls.Add($reviewLabel)
    $batchReview = New-Object Windows.Forms.ComboBox
    $batchReview.DropDownStyle = 'DropDownList'; $batchReview.Width = 170
    $batchReview.Items.AddRange(@('Unreviewed','Read','Business Write','Bootstrap','Login','Initialization Read'))
    $batchReview.SelectedIndex = 0
    $batchTools.Controls.Add($batchReview)
    $batchHint = New-Object Windows.Forms.Label
    $batchHint.AutoSize = $true; $batchHint.MaximumSize = New-Object Drawing.Size(320, 0)
    $batchHint.MinimumSize = New-Object Drawing.Size(0, ($form.Font.Height * 4))
    $batchHint.Text = Get-EffectReviewHint ([string]$batchReview.SelectedItem)
    $batchTools.Controls.Add($batchHint)
    $batchReview.Add_SelectedIndexChanged({ $batchHint.Text = Get-EffectReviewHint ([string]$batchReview.SelectedItem) })
    $applyCheckedButton = New-Object Windows.Forms.Button
    $applyCheckedButton.Text = 'Apply to Checked'; $applyCheckedButton.AutoSize = $true
    $batchTools.Controls.Add($applyCheckedButton)
    $selectionCount = New-Object Windows.Forms.Label
    $selectionCount.Text = "0 of $($grid.Rows.Count) checked"; $selectionCount.AutoSize = $true
    $selectionCount.Padding = New-Object Windows.Forms.Padding(10, 6, 0, 0)
    $batchTools.Controls.Add($selectionCount)
    if ($script:v3) {
        $referenceButton = New-Object Windows.Forms.Button
        $referenceButton.Text = 'Review Public Reference'; $referenceButton.AutoSize = $true
        $batchTools.Controls.Add($referenceButton)
        $referenceButton.Add_Click({
            if ($grid.SelectedRows.Count -ne 1 -or $script:decisionSent) { return }
            $itemId = [string]$grid.SelectedRows[0].Cells['Item'].Value
            $state = $script:v3States[$itemId]
            $meta = @($manifest.reference_items | Where-Object { $_.item_id -ceq $itemId })[0]
            if (-not $state -or @($script:v3States.Values | Where-Object { $_.pending }).Count -gt 0) { return }
            Invalidate-V3ReferenceState -State $state
            $panel = New-V3PublicReferencePanel -State $state -ReferenceItem $meta -RemainingSeconds { Get-V3RemainingSeconds } -SendFrame {
                param($frame)
                if ($script:v3ReferenceAttempts -ge 8 -or (Get-V3RemainingSeconds) -le 0) { return $false }
                $script:v3ReferenceAttempts++; Send-PrivateFrame $frame; return $true
            }
            try { $null = $panel.Form.ShowDialog($form) } finally { $panel.Form.Dispose() }
            Update-V3ApprovalButton
        })
    }
    $grid.Add_CellValueChanged({
        $checkedCount = @($grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true }).Count
        $selectionCount.Text = "$checkedCount of $($grid.Rows.Count) checked"
        Update-SelectedEffectHint -Grid $grid -Hint $rowHint
    })
    $selectAllButton.Add_Click({ Set-ApprovalChecks -Grid $grid -Checked $true })
    $clearSelectionButton.Add_Click({ Set-ApprovalChecks -Grid $grid -Checked $false })
    $applyCheckedButton.Add_Click({
        $result = Set-CheckedEffectReview -Grid $grid -Items $manifest.items -Classification ([string]$batchReview.SelectedItem)
        if (-not $result.ok) { $null = [Windows.Forms.MessageBox]::Show($result.reason, 'RemoteX'); return }
    })
    $buttons = New-Object Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Fill'; $buttons.Padding = New-Object Windows.Forms.Padding(10)
    $layout.Controls.Add($buttons, 0, 4); $layout.SetColumnSpan($buttons, 2)
    $ttlLabel = New-Object Windows.Forms.Label
    $ttlLabel.Text = 'Lifetime (seconds)'; $ttlLabel.AutoSize = $true
    $buttons.Controls.Add($ttlLabel)
    $ttl = New-Object Windows.Forms.NumericUpDown
    $lifetimeCap = [int]$manifest.ttl_seconds
    if ($manifest.replacement) { $lifetimeCap = [Math]::Min($lifetimeCap, [int]$manifest.replacement.source_expires_in_seconds) }
    if ($lifetimeCap -lt 1) { throw 'The original source lifetime is unavailable' }
    $ttl.Minimum = 1; $ttl.Maximum = $lifetimeCap; $ttl.Value = $lifetimeCap
    $buttons.Controls.Add($ttl)
    $approveButton = New-Object Windows.Forms.Button
    $approveButton.Text = 'Approve Selected'; $approveButton.AutoSize = $true
    $buttons.Controls.Add($approveButton)
    $rejectButton = New-Object Windows.Forms.Button
    $rejectButton.Text = 'Reject'; $rejectButton.AutoSize = $true
    $buttons.Controls.Add($rejectButton)
    $revokeButton = New-Object Windows.Forms.Button
    $revokeButton.Text = 'Revoke'; $revokeButton.AutoSize = $true; $revokeButton.Enabled = $false
    $buttons.Controls.Add($revokeButton)
    $helpTips = New-Object Windows.Forms.ToolTip
    $helpTips.AutoPopDelay = 15000; $helpTips.ShowAlways = $true
    $helpTips.SetToolTip($ttl, 'Lifetime in seconds, capped by this request/session/lease and original replacement source expiry. Task grants: up to 12 hours; one-use action confirmations: up to 30 seconds. Separate from the 180-second maximum review deadline, which may be narrowed. Replacement never renews a source deadline.')
    $helpTips.SetToolTip($ttlLabel, $helpTips.GetToolTip($ttl))
    $helpTips.SetToolTip($selectAllButton, 'Checks the requested items only; does not classify or approve them.')
    $helpTips.SetToolTip($clearSelectionButton, 'Unchecks items without changing their reviewed classification.')
    $helpTips.SetToolTip($applyCheckedButton, 'Sets a compatible classification on checked network items; does not approve them.')
    $helpTips.SetToolTip($approveButton, 'Approves only checked items with their reviewed effects, selected targets and reduced limits.')
    $helpTips.SetToolTip($rejectButton, 'Rejects this pending request; does not revoke independent active grants.')
    $helpTips.SetToolTip($revokeButton, 'Stops the authorization in this window; cancelling an action confirmation does not revoke its parent grant. An in-flight revocation may close the session. It cannot undo server-accepted work. Closing this active window has the same effect.')
    $approveButton.Add_Click({
        Save-Targets; $null = $grid.EndEdit()
        $choices = @()
        foreach ($row in $grid.Rows) {
            if ($row.Cells['Approve'].Value -ne $true) { continue }
            $itemId = [string]$row.Cells['Item'].Value
            $source = @($manifest.items | Where-Object { $_.item_id -eq $itemId })[0]
            $uses = 0
            if (-not [int]::TryParse([string]$row.Cells['Uses'].Value, [ref]$uses) -or $uses -lt 1 -or $uses -gt [int]$source.max_uses) {
                $null = [Windows.Forms.MessageBox]::Show('Choose a use count within the requested limit.', 'RemoteX'); return
            }
            $output = @{}
            foreach ($limit in @('Rows', 'Columns', 'Bytes')) {
                $number = 0; $key = $limit.ToLowerInvariant()
                if (-not [int]::TryParse([string]$row.Cells[$limit].Value, [ref]$number) -or $number -lt 0 -or $number -gt [int]$source.output.$key) {
                    $null = [Windows.Forms.MessageBox]::Show('Choose output limits within the requested bounds.', 'RemoteX'); return
                }
                $output[$key] = $number
            }
            $choice = @{ item_id = $itemId; max_uses = $uses; targets = @($script:targetSelections[$itemId]); output = $output }
            if ($source.parameters.review_kind) {
                $kind = [string]$source.parameters.review_kind
                $expected = Get-EffectReviewLabel $kind
                if (-not $expected -or [string]$row.Cells['Effect Review'].Value -ne $expected) {
                    $null = [Windows.Forms.MessageBox]::Show('Independently review this request effect and evidence. A business write needs a matching target/change draft, not a read label.', 'RemoteX'); return
                }
                $choice.semantic_classification = if ($kind -eq 'unclassified') { 'read' } else { $kind }
            }
            if ($script:v3) {
                $state = $script:v3States[$itemId]
                if (-not $state -or -not (Test-V3ReferenceDecisionReady $state) -or (Get-V3RemainingSeconds) -le 0) { return }
                $choice.review_ref = $state.review_ref; $choice.edit_revision = $state.edit_revision
            }
            $choices += $choice
        }
        if ($choices.Count -eq 0) { return }
        $replacementCheck = Test-ReplacementSelection -Manifest $manifest -Choices $choices
        if (-not $replacementCheck.ok) { $null = [Windows.Forms.MessageBox]::Show($replacementCheck.reason, 'RemoteX'); return }
        Send-Frame 'decision' $choices ([int]$ttl.Value)
        $script:decisionSent = $true
        Close-ApprovalNotification $script:approvalNotification
        if ($script:v3) { $script:v3SentChoices = $choices } else { $script:decided = $true; $script:approved = $true }
        $grid.Enabled = $false; $targetList.Enabled = $false; $ttl.Enabled = $false
        $batchTools.Enabled = $false
        $approveButton.Enabled = $false; $rejectButton.Enabled = $false; $revokeButton.Enabled = $true
        $form.Text = if ($script:v3) { 'RemoteX Awaiting Authority Commit' } else { 'RemoteX Authorization Active - Revoke to stop' }
        $heading.Text = $contextHeading + "`r`n" + (Get-ApprovalReviewText -WaitSeconds $manifest.wait_seconds -ElapsedSeconds $started.Elapsed.TotalSeconds -Decided $script:decided -Approved $script:approved -PendingCommit ($script:v3 -and $script:decisionSent -and -not $script:decided))
    })
    $rejectButton.Add_Click({ $script:uiCloseReason = 'operator-rejected'; Close-ApprovalNotification $script:approvalNotification; Send-Frame 'decision' @() 1; $script:decided = $true; $form.Close() })
    $revokeButton.Add_Click({ $form.Close() })
    $form.Add_FormClosing({ Close-ApprovalNotification $script:approvalNotification; if ($script:approved -or ($script:v3 -and $script:decisionSent)) { $script:uiCloseReason = 'operator-revoked'; Send-Frame 'revoke' @() 1 } })
    $form.Add_FormClosed({ Send-UiReceipt 'closed' $script:uiCloseReason })
    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 500
    $started = $script:v3ReviewStarted
    $script:approvalNotification = New-ApprovalNotification -Form $form -Digest $manifest.request_digest -RemainingSeconds {
        [Math]::Max(0,[int][Math]::Floor([double]$manifest.wait_seconds - $started.Elapsed.TotalSeconds))
    } -Pending { -not $script:decided -and -not $script:decisionSent } -Receipt { param($reason) Send-UiReceipt 'notification' $reason }
    $timer.Add_Tick({
        if (-not (Update-V3PrivateReplies)) { $script:v3ProtocolFailed = $true; $form.Close(); return }
        $heading.Text = $contextHeading + "`r`n" + (Get-ApprovalReviewText -WaitSeconds $manifest.wait_seconds -ElapsedSeconds $started.Elapsed.TotalSeconds -Decided $script:decided -Approved $script:approved -PendingCommit ($script:v3 -and $script:decisionSent -and -not $script:decided))
        if (-not $script:decided -and $started.Elapsed.TotalSeconds -ge [int]$manifest.wait_seconds) { $script:uiCloseReason = 'review-expired'; $form.Close() }
    })
    $timer.Start()
    Update-V3ApprovalButton
    $form.Add_Shown({ $grid.ClearSelection(); if ($grid.Rows.Count -gt 0) { $grid.Rows[0].Selected = $true }; $script:uiShown = $true; Send-UiReceipt 'shown' 'shown'; $form.Activate(); Show-ApprovalNotification $script:approvalNotification })
    $null = $form.ShowDialog()
    $timer.Stop(); $timer.Dispose(); $form.Dispose(); $helpTips.Dispose()
    Close-ApprovalNotification $script:approvalNotification
    if ($script:v3ReplyReader) { $script:v3ReplyReader.Dispose() }
    if ($script:v3ProtocolFailed) { throw 'Private protocol failed' }
} catch {
    if ($script:approvalNotification) { Close-ApprovalNotification $script:approvalNotification }
    if ($script:v3ReplyReader) { $script:v3ReplyReader.Dispose() }
    Send-UiReceipt 'error' $(if ($script:uiShown) { 'helper-ui-failed' } else { 'helper-startup-failed' })
    exit 1
}
