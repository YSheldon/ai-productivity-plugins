function Get-EffectReviewLabel([string]$Kind) {
    switch ($Kind) {
        'unclassified' { return 'Read' }
        'write' { return 'Business Write' }
        'bootstrap' { return 'Bootstrap' }
        'login' { return 'Login' }
        default { return '' }
    }
}

function Set-ApprovalChecks($Grid, [bool]$Checked) {
    $null = $Grid.EndEdit()
    foreach ($row in $Grid.Rows) { $row.Cells['Approve'].Value = $Checked }
}

function Set-CheckedEffectReview($Grid, $Items, [string]$Classification) {
    $null = $Grid.EndEdit()
    if ($Classification -notin @('Read','Business Write','Bootstrap','Login')) {
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
    if ($label.Length -gt 2048) { return $label.Substring(0,2048) + '...' }
    return $label
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
