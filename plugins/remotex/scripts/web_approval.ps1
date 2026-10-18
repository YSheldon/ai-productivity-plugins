$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:decided = $false
$script:approved = $false
$script:loadingTargets = $false
$script:selectedId = $null
$script:targetSelections = @{}
$script:manifestValidated = $false
$script:uiShown = $false
$script:uiCloseReason = 'window-closed'

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
    $line = [Console]::ReadLine()
    if (-not $line -or $line.Length -gt 65536) { exit 1 }
    $script:manifest = $line | ConvertFrom-Json
    if ($manifest.request_id -notmatch '^[a-f0-9]{32}$' -or $manifest.nonce -notmatch '^[a-f0-9]{64}$' -or $manifest.request_digest -notmatch '^[a-f0-9]{64}$') { exit 1 }
    if (@($manifest.items).Count -gt 32) { exit 1 }
    $script:manifestValidated = $true
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    . (Join-Path $PSScriptRoot 'web_approval_ui.ps1')

    function Send-Frame([string]$eventName, $choices, [int]$ttl) {
        $frame = [ordered]@{ event = $eventName; request_id = $manifest.request_id; nonce = $manifest.nonce; request_digest = $manifest.request_digest }
        if ($eventName -eq 'decision') { $frame.choices = @($choices); $frame.ttl_seconds = $ttl }
        [Console]::WriteLine(($frame | ConvertTo-Json -Depth 24 -Compress))
        [Console]::Out.Flush()
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
    foreach ($height in @(90, 46)) { $null = $layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, $height))) }
    foreach ($height in @(55, 45)) { $null = $layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, $height))) }
    $null = $layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 76)))
    $form.Controls.Add($layout)
    $heading = New-Object Windows.Forms.Label
    $heading.Dock = 'Fill'; $heading.Padding = New-Object Windows.Forms.Padding(12)
    $contextHeading = "Origin: $($manifest.binding.origin)   Account: $($manifest.binding.account)`r`nRequest: $($manifest.request_digest)"
    $heading.Text = $contextHeading + "`r`n" + (Get-ApprovalReviewText -WaitSeconds $manifest.wait_seconds -ElapsedSeconds 0 -Decided $false -Approved $false)
    $layout.Controls.Add($heading, 0, 0); $layout.SetColumnSpan($heading, 2)

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
    $semanticColumn.Items.AddRange(@('Not applicable', 'Unreviewed', 'Read', 'Business Write', 'Bootstrap', 'Login'))
    $null = $grid.Columns.Add($semanticColumn)
    foreach ($name in @('Uses', 'Rows', 'Columns', 'Bytes')) { $grid.Columns[$name].FillWeight = 45 }
    $grid.Columns['Item'].FillWeight = 120; $grid.Columns['Capability'].FillWeight = 140
    $grid.Columns['Scope'].FillWeight = 220; $grid.Columns['Scope'].MinimumWidth = 250
    foreach ($item in @($manifest.items)) {
        $effectReview = if ($item.parameters.review_kind) { 'Unreviewed' } else { 'Not applicable' }
        $rowIndex = $grid.Rows.Add($false, [string]$item.item_id, [string]$item.capability, (Get-ApprovalScopeText $item), [string]$item.max_uses,
            [string]$item.output.rows, [string]$item.output.columns, [string]$item.output.bytes, $effectReview)
        if (-not $item.parameters.review_kind) { $grid.Rows[$rowIndex].Cells['Effect Review'].ReadOnly = $true }
        $grid.Rows[$rowIndex].Cells['Scope'].ToolTipText = [string]$item.display.label
        $script:targetSelections[[string]$item.item_id] = @($item.targets)
    }
    $layout.Controls.Add($grid, 0, 2); $layout.SetColumnSpan($grid, 2)
    $details = New-Object Windows.Forms.TextBox
    $details.Dock = 'Fill'; $details.Multiline = $true; $details.ReadOnly = $true
    $details.ScrollBars = 'Both'; $details.WordWrap = $false
    $layout.Controls.Add($details, 0, 3)
    $targetList = New-Object Windows.Forms.CheckedListBox
    $targetList.Dock = 'Fill'; $targetList.CheckOnClick = $true
    $layout.Controls.Add($targetList, 1, 3)
    $grid.Add_SelectionChanged({
        Save-Targets
        if ($grid.SelectedRows.Count -eq 0) { return }
        $script:selectedId = [string]$grid.SelectedRows[0].Cells['Item'].Value
        $item = @($manifest.items | Where-Object { $_.item_id -eq $script:selectedId })[0]
        $details.Text = $item | ConvertTo-Json -Depth 24
        $script:loadingTargets = $true; $targetList.Items.Clear()
        foreach ($target in @($item.targets)) { $null = $targetList.Items.Add([string]$target, ($script:targetSelections[$script:selectedId] -contains $target)) }
        $script:loadingTargets = $false
    })
    $grid.Add_CurrentCellDirtyStateChanged({ if ($grid.IsCurrentCellDirty) { $null = $grid.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit) } })
    $batchTools = New-Object Windows.Forms.FlowLayoutPanel
    $batchTools.Dock = 'Fill'; $batchTools.WrapContents = $false; $batchTools.AutoScroll = $true
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
    $batchReview.DropDownStyle = 'DropDownList'; $batchReview.Width = 130
    $batchReview.Items.AddRange(@('Unreviewed','Read','Business Write','Bootstrap','Login'))
    $batchReview.SelectedIndex = 0
    $batchTools.Controls.Add($batchReview)
    $applyCheckedButton = New-Object Windows.Forms.Button
    $applyCheckedButton.Text = 'Apply to Checked'; $applyCheckedButton.AutoSize = $true
    $batchTools.Controls.Add($applyCheckedButton)
    $selectionCount = New-Object Windows.Forms.Label
    $selectionCount.Text = "0 of $($grid.Rows.Count) checked"; $selectionCount.AutoSize = $true
    $selectionCount.Padding = New-Object Windows.Forms.Padding(10, 6, 0, 0)
    $batchTools.Controls.Add($selectionCount)
    $grid.Add_CellValueChanged({
        $checkedCount = @($grid.Rows | Where-Object { $_.Cells['Approve'].Value -eq $true }).Count
        $selectionCount.Text = "$checkedCount of $($grid.Rows.Count) checked"
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
    $ttl.Minimum = 1; $ttl.Maximum = [int]$manifest.ttl_seconds; $ttl.Value = [int]$manifest.ttl_seconds
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
            $choices += $choice
        }
        if ($choices.Count -eq 0) { return }
        Send-Frame 'decision' $choices ([int]$ttl.Value)
        $script:decided = $true; $script:approved = $true
        $grid.Enabled = $false; $targetList.Enabled = $false; $ttl.Enabled = $false
        $batchTools.Enabled = $false
        $approveButton.Enabled = $false; $rejectButton.Enabled = $false; $revokeButton.Enabled = $true
        $form.Text = 'RemoteX Authorization Active - Revoke to stop'
        $heading.Text = $contextHeading + "`r`n" + (Get-ApprovalReviewText -WaitSeconds $manifest.wait_seconds -ElapsedSeconds 0 -Decided $true -Approved $true)
    })
    $rejectButton.Add_Click({ $script:uiCloseReason = 'operator-rejected'; Send-Frame 'decision' @() 1; $script:decided = $true; $form.Close() })
    $revokeButton.Add_Click({ $form.Close() })
    $form.Add_FormClosing({ if ($script:approved) { $script:uiCloseReason = 'operator-revoked'; Send-Frame 'revoke' @() 1 } })
    $form.Add_FormClosed({ Send-UiReceipt 'closed' $script:uiCloseReason })
    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 500
    $started = [Diagnostics.Stopwatch]::StartNew()
    $timer.Add_Tick({
        $heading.Text = $contextHeading + "`r`n" + (Get-ApprovalReviewText -WaitSeconds $manifest.wait_seconds -ElapsedSeconds $started.Elapsed.TotalSeconds -Decided $script:decided -Approved $script:approved)
        if (-not $script:decided -and $started.Elapsed.TotalSeconds -ge [int]$manifest.wait_seconds) { $script:uiCloseReason = 'review-expired'; $form.Close() }
    })
    $timer.Start()
    $form.Add_Shown({ $grid.ClearSelection(); if ($grid.Rows.Count -gt 0) { $grid.Rows[0].Selected = $true }; $script:uiShown = $true; Send-UiReceipt 'shown' 'shown'; $form.Activate() })
    $null = $form.ShowDialog()
    $timer.Stop(); $timer.Dispose(); $form.Dispose()
} catch {
    Send-UiReceipt 'error' $(if ($script:uiShown) { 'helper-ui-failed' } else { 'helper-startup-failed' })
    exit 1
}
