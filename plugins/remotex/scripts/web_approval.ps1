$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:decided = $false
$script:approved = $false
$script:loadingTargets = $false
$script:selectedId = $null
$script:targetSelections = @{}

try {
    if (-not [Environment]::UserInteractive) { exit 1 }
    $line = [Console]::ReadLine()
    if (-not $line -or $line.Length -gt 65536) { exit 1 }
    $script:manifest = $line | ConvertFrom-Json
    if ($manifest.request_id -notmatch '^[a-f0-9]{32}$' -or $manifest.nonce -notmatch '^[a-f0-9]{64}$' -or $manifest.request_digest -notmatch '^[a-f0-9]{64}$') { exit 1 }
    if (@($manifest.items).Count -gt 32) { exit 1 }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()

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
    $form.Size = New-Object Drawing.Size(1050, 780)
    $form.MinimumSize = New-Object Drawing.Size(800, 640)
    $form.StartPosition = 'CenterScreen'
    $form.Font = [Drawing.SystemFonts]::MessageBoxFont
    $form.AcceptButton = $null
    $layout = New-Object Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.ColumnCount = 2; $layout.RowCount = 4
    $layout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 70)))
    $layout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 30)))
    foreach ($height in @(70, 210, 330, 70)) { $layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, $height))) }
    $form.Controls.Add($layout)
    $heading = New-Object Windows.Forms.Label
    $heading.Dock = 'Fill'; $heading.Padding = New-Object Windows.Forms.Padding(12)
    $heading.Text = "Origin: $($manifest.binding.origin)   Account: $($manifest.binding.account)`r`nRequest: $($manifest.request_digest)"
    $layout.Controls.Add($heading, 0, 0); $layout.SetColumnSpan($heading, 2)

    $grid = New-Object Windows.Forms.DataGridView
    $grid.Dock = 'Fill'; $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
    $grid.RowHeadersVisible = $false; $grid.MultiSelect = $false
    $grid.SelectionMode = 'FullRowSelect'; $grid.AutoSizeColumnsMode = 'Fill'
    $checkColumn = New-Object Windows.Forms.DataGridViewCheckBoxColumn
    $checkColumn.Name = 'Approve'; $checkColumn.FillWeight = 22; $null = $grid.Columns.Add($checkColumn)
    foreach ($columnName in @('Item', 'Capability', 'Uses', 'Rows', 'Columns', 'Bytes')) {
        $column = New-Object Windows.Forms.DataGridViewTextBoxColumn
        $column.Name = $columnName; $column.ReadOnly = ($columnName -in @('Item', 'Capability'))
        $null = $grid.Columns.Add($column)
    }
    foreach ($item in @($manifest.items)) {
        $null = $grid.Rows.Add($false, [string]$item.item_id, [string]$item.capability, [string]$item.max_uses,
            [string]$item.output.rows, [string]$item.output.columns, [string]$item.output.bytes)
        $script:targetSelections[[string]$item.item_id] = @($item.targets)
    }
    $layout.Controls.Add($grid, 0, 1); $layout.SetColumnSpan($grid, 2)
    $details = New-Object Windows.Forms.TextBox
    $details.Dock = 'Fill'; $details.Multiline = $true; $details.ReadOnly = $true
    $details.ScrollBars = 'Both'; $details.WordWrap = $false
    $layout.Controls.Add($details, 0, 2)
    $targetList = New-Object Windows.Forms.CheckedListBox
    $targetList.Dock = 'Fill'; $targetList.CheckOnClick = $true
    $layout.Controls.Add($targetList, 1, 2)
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
    $buttons = New-Object Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Fill'; $buttons.Padding = New-Object Windows.Forms.Padding(10)
    $layout.Controls.Add($buttons, 0, 3); $layout.SetColumnSpan($buttons, 2)
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
            $choices += @{ item_id = $itemId; max_uses = $uses; targets = @($script:targetSelections[$itemId]); output = $output }
        }
        if ($choices.Count -eq 0) { return }
        Send-Frame 'decision' $choices ([int]$ttl.Value)
        $script:decided = $true; $script:approved = $true
        $grid.Enabled = $false; $targetList.Enabled = $false; $ttl.Enabled = $false
        $approveButton.Enabled = $false; $rejectButton.Enabled = $false; $revokeButton.Enabled = $true
        $form.Text = 'RemoteX Authorization Active - Revoke to stop'
    })
    $rejectButton.Add_Click({ Send-Frame 'decision' @() 1; $script:decided = $true; $form.Close() })
    $revokeButton.Add_Click({ $form.Close() })
    $form.Add_FormClosing({ if ($script:approved) { Send-Frame 'revoke' @() 1 } })
    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 500
    $started = [Diagnostics.Stopwatch]::StartNew()
    $timer.Add_Tick({ if (-not $script:decided -and $started.Elapsed.TotalSeconds -ge [int]$manifest.wait_seconds) { $form.Close() } })
    $timer.Start()
    $form.Add_Shown({ $grid.ClearSelection(); if ($grid.Rows.Count -gt 0) { $grid.Rows[0].Selected = $true }; $form.Activate() })
    $null = $form.ShowDialog()
    $timer.Stop(); $timer.Dispose(); $form.Dispose()
} catch {
    exit 1
}
