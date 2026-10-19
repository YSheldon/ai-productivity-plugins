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
        default { return 'Unknown classification: no implied permission. Inspect the exact item before approval.' }
    }
}

function Update-SelectedEffectHint($Grid, $Hint) {
    if ($Grid.SelectedRows.Count -eq 0) {
        $Hint.Text = 'Select an item to see its current effect classification and limits.'
        return
    }
    $Hint.Text = 'Selected item - ' + (Get-EffectReviewHint ([string]$Grid.SelectedRows[0].Cells['Effect Review'].Value))
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

function Get-ApprovalReviewText([int]$WaitSeconds, [double]$ElapsedSeconds, [bool]$Decided, [bool]$Approved) {
    if ($Decided) {
        if ($Approved) { return 'Authorization active' }
        return 'Review complete'
    }
    $remaining = [int][Math]::Ceiling([Math]::Max(0,$WaitSeconds - $ElapsedSeconds))
    if ($remaining -eq 0) { return 'Review expired' }
    return 'Review expires in ' + ([TimeSpan]::FromSeconds($remaining).ToString('mm\:ss'))
}
