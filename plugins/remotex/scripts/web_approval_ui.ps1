. (Join-Path $PSScriptRoot 'web_approval_notification.ps1')

function Get-EffectReviewLabel([string]$Kind) {
    switch ($Kind) {
        'unclassified' { return 'Read' }
        'write' { return 'Business Write' }
        'bootstrap' { return 'Bootstrap' }
        'login' { return 'Login' }
        'initialization-read' { return 'Initialization Read' }
        default { return '' }
    }
}

function Get-EffectReviewHint([string]$Classification) {
    switch ($Classification) {
        'Unreviewed' { return 'Unreviewed: inspect the exact effect and evidence; no network permission yet.' }
        'Read' { return 'Read: reviewed information retrieval; no business changes. HTTP method alone is not proof.' }
        'Business Write' { return 'Business Write: exact targets and a change preview required. High-risk actions also need one-use confirmation.' }
        'Bootstrap' { return 'Bootstrap: startup page/assets only. Exact GET/HEAD; no POST or business changes.' }
        'Login' { return 'Login: exact reviewed sign-in exchanges for this site/account only; no business-operation permission.' }
        'Initialization Read' { return 'Initialization Read: reviewed pre-login initialization only. Exact POST; no authentication, configuration changes or business writes.' }
        'Not applicable' { return 'Not applicable: no network-effect classification for this item. Explicit approval is still required.' }
        'Read only (fixed)' { return 'Read only (fixed): reads the approved page region, table, field or result within its output limits. No network-effect choice is needed; explicit approval is still required.' }
        'Navigation (fixed)' { return 'Navigation (fixed): only the scoped navigation action. Network requests still need their own authorization.' }
        'Page action (fixed)' { return 'Page action (fixed): only the scoped page action. This is not a read guarantee; network requests need their own authorization.' }
        'Field input (fixed)' { return 'Field input (fixed): only the exact scoped input action. This is not a read guarantee; network requests need their own authorization.' }
        'Business action (fixed)' { return 'Business action (fixed): review the exact targets and change preview. Required one-use confirmations and network authorization still apply.' }
        'Needs review' { return 'Needs review: the request type is unknown; no classification can be recommended.' }
        default { return 'Unknown classification: no implied permission. Inspect the exact item before approval.' }
    }
}

function Get-ApprovalRecommendation($Item) {
    $kind = [string]$Item.parameters.review_kind
    $classification = $null; $label = 'Needs review'
    $reason = 'Unknown request type. Inspect its scope and evidence; no recommendation is available.'
    if ($kind) {
        switch -CaseSensitive ($kind) {
            'bootstrap' { $classification='Bootstrap'; $reason='Declared startup page or static resource. Confirm the exact GET/HEAD scope.' }
            'login' { $classification='Login'; $reason='Declared sign-in exchange. Confirm this site/account and exact login scope.' }
            'initialization-read' { $classification='Initialization Read'; $reason='Declared pre-login read. Independently verify public data, non-auth role, effects and response predicates.' }
            'unclassified' { $classification='Read'; $reason='Proposed information retrieval. Independently verify its effects; HTTP method alone is not evidence.' }
            'write' { $classification='Business Write'; $reason='Declared business change. Review exact targets, values and the change preview.' }
        }
        if ($classification) { $label=$classification }
    } else {
        switch -CaseSensitive ([string]$Item.capability) {
            { $_ -cin @('web.read_region','web.read_table','web.read_result','web.inspect_action') } { $label='Read only (fixed)' }
            'web.navigate' { $label='Navigation (fixed)' }
            'web.page_step' { $label='Page action (fixed)' }
            'web.query_input' { $label='Field input (fixed)' }
            'web.business_action' { $label='Business action (fixed)' }
        }
        $reason=Get-EffectReviewHint $label
    }
    return [pscustomobject]@{classification=$classification;label=$label;reason=$reason;known=($label -cne 'Needs review')}
}

function Update-SelectedEffectHint($Grid, $Hint) {
    if ($Grid.SelectedRows.Count -eq 0) {
        $Hint.Text = 'Select an item to see its current effect classification and limits.'
        return
    }
    $Hint.Text = 'Selected item - ' + (Get-EffectReviewHint ([string]$Grid.SelectedRows[0].Cells['Effect Review'].Value))
    if ($Grid.Columns.Contains('Recommendation')) {
        $Hint.Text += "`r`n" + $Grid.SelectedRows[0].Cells['Recommendation'].ToolTipText
    }
}

function Set-ApprovalChecks($Grid, [bool]$Checked) {
    $null = $Grid.EndEdit()
    foreach ($row in $Grid.Rows) { $row.Cells['Approve'].Value = $Checked }
}

function Set-CheckedEffectReview($Grid, $Items, [string]$Classification) {
    $null = $Grid.EndEdit()
    if ($Classification -notin @('Read','Business Write','Bootstrap','Login','Initialization Read')) {
        return [pscustomobject]@{ok=$false;changed=0;reason='Choose an explicit effect classification first.'}
    }
    $selected = @()
    foreach ($row in $Grid.Rows) {
        if ($row.Cells['Approve'].Value -ne $true) { continue }
        $itemId = [string]$row.Cells['Item'].Value
        $sources = @($Items | Where-Object { $_.item_id -ceq $itemId })
        if ($sources.Count -ne 1) {
            return [pscustomobject]@{ok=$false;changed=0;reason='The checked item is not uniquely bound to this request.'}
        }
        $kind = [string]$sources[0].parameters.review_kind
        if (-not $kind) { continue }
        $expected = Get-EffectReviewLabel $kind
        if (-not $expected -or $Classification -cne $expected) {
            return [pscustomobject]@{ok=$false;changed=0;reason='Checked network items have incompatible effects. Review those items separately.'}
        }
        $selected += $row
    }
    if ($selected.Count -eq 0) {
        return [pscustomobject]@{ok=$false;changed=0;reason='Check at least one network item to classify.'}
    }
    # Validate the entire selection before changing any row.
    foreach ($row in $selected) { $row.Cells['Effect Review'].Value = $Classification }
    return [pscustomobject]@{ok=$true;changed=$selected.Count;reason=''}
}

function Set-CheckedEffectRecommendations($Grid, $Items) {
    $null = $Grid.EndEdit()
    $updates = @(); $checkedCount = 0
    foreach ($row in $Grid.Rows) {
        if ($row.Cells['Approve'].Value -ne $true) { continue }
        $checkedCount++
        $sources = @($Items | Where-Object { $_.item_id -ceq [string]$row.Cells['Item'].Value })
        if ($sources.Count -ne 1) {
            return [pscustomobject]@{ok=$false;changed=0;reason='The checked item is not uniquely bound to this request.'}
        }
        $recommendation = Get-ApprovalRecommendation $sources[0]
        if (-not $recommendation.known) {
            return [pscustomobject]@{ok=$false;changed=0;reason='A checked item needs review. No recommendations were applied; review or uncheck that item first.'}
        }
        if ($recommendation.classification) {
            $updates += @{row=$row;classification=$recommendation.classification}
        }
    }
    if ($checkedCount -eq 0) {
        return [pscustomobject]@{ok=$false;changed=0;reason='Check the items whose recommendations you have reviewed.'}
    }
    # Validate the whole selection before applying each original item's classification.
    foreach ($update in $updates) { $update.row.Cells['Effect Review'].Value = $update.classification }
    return [pscustomobject]@{ok=$true;changed=$updates.Count;reason=''}
}

function Get-ApprovalScopeText($Item) {
    $label = if ($Item.display.label -is [string]) { $Item.display.label } else { [string]$Item.capability }
    if ([string]$Item.parameters.review_kind -ceq 'initialization-read') { $label = 'Required pre-login read: ' + $label }
    if ($label.Length -gt 2048) { return $label.Substring(0,2048) + '...' }
    return $label
}

function Get-ApprovalDetailsText($Item) {
    if ($Item.display.preview -is [string] -and $Item.display.preview) {
        try {
            $preview = $Item.display.preview | ConvertFrom-Json
            $heading = if ($preview.phase_applicability) { 'Exact pre-login scope (Bootstrap and Login-once before credential insertion)' } else { 'Exact reviewed scope' }
            return $heading + "`r`n" + ($preview | ConvertTo-Json -Depth 24) + "`r`n`r`n" + ($Item | ConvertTo-Json -Depth 24)
        } catch { }
    }
    return ($Item | ConvertTo-Json -Depth 24)
}

function Get-ApprovalContextText($Manifest) {
    $text = "Origin: $($Manifest.binding.origin)   Account: $($Manifest.binding.account)`r`nRequest: $($Manifest.request_digest)"
    if ($Manifest.replacement) {
        $text += "`r`nReplacement sources: " + (@($Manifest.replacement.source_grant_ids) -join ', ')
        $text += "`r`nAll carried rows are required. Source cap: $($Manifest.replacement.source_expires_in_seconds) seconds at proposal; no renewal."
    }
    return $text
}

function Test-ReplacementSelection($Manifest, $Choices) {
    if (-not $Manifest.replacement) { return [pscustomobject]@{ok=$true;reason=''} }
    $names = if ($Manifest.replacement.carried_items -is [Collections.IDictionary]) {
        @($Manifest.replacement.carried_items.Keys)
    } else { @($Manifest.replacement.carried_items.PSObject.Properties.Name) }
    foreach ($name in $names) {
        if (@($Choices | Where-Object { [string]$_.item_id -ceq [string]$name }).Count -ne 1) {
            return [pscustomobject]@{ok=$false;reason='Select every carried permission to replace the source grants. New rows may be approved separately.'}
        }
    }
    return [pscustomobject]@{ok=$true;reason=''}
}

function Get-ApprovalReviewText([int]$WaitSeconds, [double]$ElapsedSeconds, [bool]$Decided, [bool]$Approved, [bool]$PendingCommit=$false) {
    if ($Decided) {
        if ($Approved) { return 'Authorization active' }
        return 'Review complete'
    }
    $remaining = [int][Math]::Ceiling([Math]::Max(0,$WaitSeconds - $ElapsedSeconds))
    if ($remaining -eq 0) { return 'Review expired' }
    if ($PendingCommit) { return 'Awaiting authority commit; review expires in ' + ([TimeSpan]::FromSeconds($remaining).ToString('mm\:ss')) }
    return 'Review expires in ' + ([TimeSpan]::FromSeconds($remaining).ToString('mm\:ss'))
}
