if (-not ('RemoteX.V3ReplyQueue' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace RemoteX {
    public static class PublicReviewFile {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);
        public static string Read(string path) {
            if (String.IsNullOrEmpty(path) || !System.Text.RegularExpressions.Regex.IsMatch(path, @"^[A-Za-z]:\\") ||
                path.IndexOf(':', 2) >= 0 || path.IndexOf('/') >= 0)
                throw new IOException("Unsupported public review file");
            string full = Path.GetFullPath(path);
            if (!String.Equals(full, path, StringComparison.OrdinalIgnoreCase) ||
                new DriveInfo(Path.GetPathRoot(full)).DriveType != DriveType.Fixed)
                throw new IOException("Unsupported public review file");
            for (string part = full; !String.IsNullOrEmpty(part); part = Path.GetDirectoryName(part)) {
                if ((File.GetAttributes(part) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Unsupported public review file");
            }
            using (var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                var final = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandle(stream.SafeFileHandle, final, (uint)final.Capacity, 0);
                if (length == 0 || length >= final.Capacity ||
                    !String.Equals(final.ToString(), @"\\?\" + full, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Unsupported public review file");
                var bytes = new byte[24001];
                int count = 0, read;
                while (count < bytes.Length && (read = stream.Read(bytes, count, bytes.Length-count)) > 0) count += read;
                if (count > 24000) throw new IOException("Public review file too large");
                int start = count >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf ? 3 : 0;
                string text = new UTF8Encoding(false, true).GetString(bytes, start, count-start);
                if (text.IndexOf('\0') >= 0) throw new IOException("Unsupported public review encoding");
                return text;
            }
        }
    }
    public sealed class V3ReplyQueue : IDisposable {
        private readonly StreamReader reader;
        private readonly ConcurrentQueue<string> queue = new ConcurrentQueue<string>();
        private volatile bool disposed;
        public volatile bool Failed;
        public volatile bool Completed;
        public int Count { get { return queue.Count; } }
        public V3ReplyQueue(Stream stream) {
            reader = new StreamReader(stream, new UTF8Encoding(false, true), false, 1024, true);
            Task.Run((Func<Task>)ReadLoop);
        }
        private async Task ReadLoop() {
            var buffer = new char[1024];
            var line = new StringBuilder();
            try {
                while (!disposed) {
                    int length = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (length == 0) { if (line.Length != 0) Failed = true; return; }
                    for (int i = 0; i < length; i++) {
                        char ch = buffer[i];
                        if (ch == '\n') {
                            if (queue.Count >= 8) { Failed = true; return; }
                            queue.Enqueue(line.ToString()); line.Clear();
                        } else {
                            if (ch > 127 || line.Length >= 32768) { Failed = true; return; }
                            line.Append(ch);
                        }
                    }
                }
            } catch { if (!disposed) Failed = true; }
            finally { Completed = true; }
        }
        public bool TryTake(out string value) { return queue.TryDequeue(out value); }
        public void Dispose() { disposed = true; reader.Dispose(); }
    }
}
'@
}

$script:RemoteXReferenceProtocol = @{protocol_revision=3;reference_units=32}

function New-V3ReferenceState {
    param([string]$RequestId,[string]$ItemId,[string]$Nonce='',[string]$RequestDigest='',[int]$UnitCount=0)
    return [pscustomobject]@{
        request_id=$RequestId; item_id=$ItemId; nonce=$Nonce; request_digest=$RequestDigest
        unit_count=$UnitCount; edit_revision=[long]1; matched_revision=[long]0
        check_id=$null; review_ref=$null; pending=$false; status='unreviewed'
    }
}

function Invalidate-V3ReferenceState {
    param($State)
    if ($State.edit_revision -ge 9007199254740991) { throw 'Reference revision limit reached' }
    $State.edit_revision = [long]$State.edit_revision + 1
    $State.matched_revision = [long]0
    $State.review_ref = $null
    $State.status = 'unreviewed'
    # Keep an outstanding check correlated until its reply. Edits never start another check.
}

function Apply-V3ReferenceResult {
    param($State,$Frame)
    $keys = @('event','request_id','nonce','request_digest','check_id','item_id','edit_revision','review_ref','unit_count','code')
    $names = @($Frame.PSObject.Properties.Name)
    if ($names.Count -ne $keys.Count -or @($names | Where-Object { $_ -notin $keys }).Count -ne 0) { return $false }
    if (($Frame.edit_revision -isnot [int] -and $Frame.edit_revision -isnot [long]) -or
        $Frame.edit_revision -lt 1 -or $Frame.edit_revision -gt 9007199254740991 -or
        ($Frame.unit_count -isnot [int] -and $Frame.unit_count -isnot [long])) { return $false }
    if ($Frame.event -cne 'reference-result' -or $Frame.request_id -cne $State.request_id -or
        $Frame.nonce -cne $State.nonce -or $Frame.request_digest -cne $State.request_digest -or
        $Frame.item_id -cne $State.item_id -or $Frame.check_id -cne $State.check_id -or -not $State.pending) { return $false }
    $State.pending = $false
    if ($Frame.edit_revision -ne $State.edit_revision) { return $false }
    if ($Frame.code -cnotin @('ready','reference-incomplete','reference-mismatch','ineligible','expired','stale-edit')) { return $false }
    if ($Frame.unit_count -lt 0 -or $Frame.unit_count -gt 32) { return $false }
    $State.review_ref = $null; $State.matched_revision = [long]0; $State.status = [string]$Frame.code
    if ($Frame.code -ceq 'ready') {
        if ($Frame.review_ref -isnot [string] -or $Frame.review_ref -cnotmatch '^[a-f0-9]{32}$' -or $Frame.unit_count -lt 1 -or
            $Frame.unit_count -ne $State.unit_count) { return $false }
        $State.review_ref = [string]$Frame.review_ref
        $State.matched_revision = [long]$Frame.edit_revision
    } elseif ($null -ne $Frame.review_ref) { return $false }
    return $true
}

function Test-V3ReferenceDecisionReady {
    param($State)
    return ($State.unit_count -ge 1 -and $State.unit_count -le 32 -and -not $State.pending -and $State.status -ceq 'ready' -and
        $State.review_ref -is [string] -and $State.review_ref -cmatch '^[a-f0-9]{32}$' -and
        $State.edit_revision -eq $State.matched_revision)
}

function New-V3ReviewCombo($Values) {
    $control = New-Object Windows.Forms.ComboBox
    $control.DropDownStyle = 'DropDownList'; $control.Dock = 'Fill'
    $control.Items.AddRange([object[]]$Values); $control.SelectedIndex = 0
    return $control
}

function ConvertFrom-UniqueReferenceJson([string]$Text) {
    Add-Type -AssemblyName System.Runtime.Serialization
    $encoding=New-Object Text.UTF8Encoding($false,$true)
    $bytes=$encoding.GetBytes($Text)
    if ($bytes.Length -gt 24000) { throw 'Reference capacity exceeded' }
    $quotas=New-Object Xml.XmlDictionaryReaderQuotas
    $quotas.MaxDepth=24; $quotas.MaxStringContentLength=24000; $quotas.MaxArrayLength=100
    $reader=[Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes,$quotas)
    $objects=@{}
    try {
        while ($reader.Read()) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                if ($reader.Depth -eq 0 -and $reader.GetAttribute('type') -cne 'object') { throw 'Reference object required' }
                $parent=$objects[$reader.Depth-1]
                if ($parent) {
                    $name=$reader.LocalName
                    if ($reader.NamespaceURI -ceq 'item') { $name=$reader.GetAttribute('item') }
                    if (-not $parent.Add($name)) { throw 'Ambiguous reference JSON' }
                }
                if ($reader.GetAttribute('type') -ceq 'object' -and -not $reader.IsEmptyElement) {
                    $objects[$reader.Depth]=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
                }
            } elseif ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement) { $objects.Remove($reader.Depth) }
        }
    } finally { $reader.Dispose() }
    return $Text | ConvertFrom-Json
}

function Read-V3PublicReviewFile([string]$Path) {
    try { return [RemoteX.PublicReviewFile]::Read($Path) }
    catch { throw 'Cannot load public review: use a local regular UTF-8 JSON file of at most 24000 bytes.' }
}

function Test-V3ExactObject($Value,[string[]]$Keys) {
    if ($Value -isnot [pscustomobject]) { return $false }
    $names=@($Value.PSObject.Properties.Name)
    return ($names.Count -eq $Keys.Count -and @($names | Where-Object {$_ -cnotin $Keys}).Count -eq 0)
}

function Test-V3EvidenceText($Value) {
    return ($Value -is [string] -and $Value.Length -gt 0 -and
        [Text.Encoding]::UTF8.GetByteCount($Value) -le 512 -and $Value -notmatch '[\x00-\x1f\x7f]')
}

function ConvertFrom-V3PublicReviewPacket {
    param([string]$Text,$ReferenceItem)
    try {
        $value=ConvertFrom-UniqueReferenceJson $Text
        if (-not (Test-V3ExactObject $value @('schema','reference','evidence','cookie_evidence')) -or
            $value.schema -isnot [string] -or $value.schema -cne 'RemoteXPublicReview/v1') { throw 'Invalid packet' }
        $reference=$value.reference
        if (-not (Test-V3ExactObject $reference @('profile_id','target_text','content_type','body_text','public_headers')) -or
            $reference.profile_id -isnot [string] -or $reference.profile_id -cne $ReferenceItem.profile_id -or
            $reference.profile_id -cnotin @('json-utf8-v1','form-utf8-v1','form-json-name-view-v1')) { throw 'Invalid reference' }
        foreach ($key in @('target_text','content_type','body_text')) {
            if ($reference.$key -isnot [string]) { throw 'Invalid wire text' }
        }
        if ($reference.public_headers -isnot [array] -or $reference.public_headers.Count -gt 32) { throw 'Invalid headers' }
        foreach ($header in $reference.public_headers) {
            if (-not (Test-V3ExactObject $header @('name','value')) -or $header.name -isnot [string] -or
                $header.name.Length -eq 0 -or $header.value -isnot [string]) { throw 'Invalid header' }
        }
        $evidence=$value.evidence
        if (-not (Test-V3ExactObject $evidence @('kind','source_ref','revision_ref','deployment_ref','basis')) -or
            $evidence.kind -isnot [string] -or $evidence.kind -cnotin @('source-review','api-document','verified-record','operator-inspected')) { throw 'Invalid evidence' }
        foreach ($key in @('source_ref','revision_ref','deployment_ref','basis')) {
            if (-not (Test-V3EvidenceText $evidence.$key)) { throw 'Invalid evidence text' }
        }
        if ($null -ne $value.cookie_evidence -and -not (Test-V3EvidenceText $value.cookie_evidence)) { throw 'Invalid cookie evidence' }
        if ($ReferenceItem.cookie_context_ref -and $null -eq $value.cookie_evidence) { throw 'Missing cookie evidence' }
        return $value
    } catch { throw 'Invalid public review packet. Check its schema, profile, public reference and evidence; no fields were loaded.' }
}

function Reset-V3PublicConfirmations($Panel) {
    $Panel.PublicConfirmed.Checked=$false; $Panel.Reviewed.Checked=$false; $Panel.CookieConfirmed.Checked=$false
    $Panel.Sensitive.Checked=$false
    foreach ($name in @('DataStatus','Role','Effect')) { $Panel[$name].SelectedIndex=0 }
    if ($Panel.ReferenceItem.cookie_context_ref) { $Panel.CookieRole.SelectedIndex=0 }
}

function Set-V3PublicReviewPacket {
    param($Panel,[string]$Text)
    if ($Panel.State.pending -or (& $Panel.RemainingSeconds) -le 0) { throw 'Review is unavailable or expired.' }
    $packet=ConvertFrom-V3PublicReviewPacket -Text $Text -ReferenceItem $Panel.ReferenceItem
    $referenceJson=$packet.reference | ConvertTo-Json -Depth 16
    if ($Panel.State.pending -or (& $Panel.RemainingSeconds) -le 0) { throw 'Review is unavailable or expired.' }
    # Parse everything before touching controls. Import never carries human attestations.
    Invalidate-V3ReferenceState $Panel.State
    $Panel.Loading=$true
    try {
        Reset-V3PublicConfirmations $Panel
        $Panel.PublicReference.Text=$referenceJson; $Panel.Profile.SelectedItem=$packet.reference.profile_id
        $Panel.EvidenceKind.SelectedItem=$packet.evidence.kind
        $Panel.Source.Text=$packet.evidence.source_ref; $Panel.Revision.Text=$packet.evidence.revision_ref
        $Panel.Deployment.Text=$packet.evidence.deployment_ref; $Panel.Basis.Text=$packet.evidence.basis
        $Panel.CookieEvidence.Text=if ($null -eq $packet.cookie_evidence) {''} else {$packet.cookie_evidence}
        $Panel.ImportStatus.Text='Public draft loaded. Confirm only what you independently verified.'
    } finally { $Panel.Loading=$false }
    & $Panel.Update
}

function Get-V3NativeReferenceInput {
    param($Panel,$ReferenceItem)
    if ($Panel.Profile.SelectedItem -cne $ReferenceItem.profile_id -or
        $Panel.DataStatus.SelectedItem -cne 'Public invariant' -or $Panel.Role.SelectedItem -cne 'Non-auth' -or
        $Panel.Effect.SelectedItem -cne 'Initialization Read' -or -not $Panel.Reviewed.Checked -or
        $Panel.EvidenceKind.SelectedItem -cnotin @('source-review','api-document','verified-record','operator-inspected')) { return $null }
    foreach ($control in @($Panel.Source,$Panel.Revision,$Panel.Deployment,$Panel.Basis)) {
        if (-not $control.Text -or [Text.Encoding]::UTF8.GetByteCount($control.Text) -gt 512 -or $control.Text -match '[\x00-\x1f\x7f]') { return $null }
    }
    try {
        $reference = ConvertFrom-UniqueReferenceJson $Panel.PublicReference.Text
        $names = @($reference.PSObject.Properties.Name)
        $keys = @('profile_id','target_text','content_type','body_text','public_headers')
        if ($names.Count -ne 5 -or @($names | Where-Object { $_ -cnotin $keys }).Count -gt 0 -or
            $reference.profile_id -cne $ReferenceItem.profile_id -or
            $reference.target_text -isnot [string] -or $reference.content_type -isnot [string] -or
            $reference.body_text -isnot [string] -or $null -eq $reference.public_headers) { return $null }
    } catch { return $null }
    $sensitive = @($ReferenceItem.locations | Where-Object { $_.sensitive -eq $true })
    if ($sensitive.Count -gt 0 -and -not $Panel.Sensitive.Checked) { return $null }
    $cookie = @{context_ref=$null;role='none';evidence_ref=$null}
    if ($ReferenceItem.cookie_context_ref) {
        if ($Panel.CookieRole.SelectedItem -cne 'Non-auth prelogin' -or -not $Panel.CookieEvidence.Text -or
            [Text.Encoding]::UTF8.GetByteCount($Panel.CookieEvidence.Text) -gt 512 -or
            $Panel.CookieEvidence.Text -match '[\x00-\x1f\x7f]') { return $null }
        $cookie = @{context_ref=$ReferenceItem.cookie_context_ref;role='non-auth-prelogin';evidence_ref=$Panel.CookieEvidence.Text}
    }
    return @{
        version=3;reference=$reference
        attestation=@{data_status='public-invariant';role='non-auth';effect='initialization-read'
            sensitive_ack_refs=@($sensitive | ForEach-Object { [string]$_.ref })
            evidence=@{kind=[string]$Panel.EvidenceKind.SelectedItem;source_ref=$Panel.Source.Text;revision_ref=$Panel.Revision.Text
                deployment_ref=$Panel.Deployment.Text;basis=$Panel.Basis.Text;independently_reviewed=$true}}
        cookie_review=$cookie
    }
}

function New-V3PublicReferencePanel {
    param($State,$ReferenceItem,[scriptblock]$SendFrame,[scriptblock]$RemainingSeconds,$Binding=$null)
    $form = New-Object Windows.Forms.Form
    $form.Text = 'RemoteX Independent Public Reference Review'
    $form.Size = New-Object Drawing.Size(1050, 760); $form.MinimumSize = New-Object Drawing.Size(900, 700)
    $form.StartPosition = 'CenterParent'; $form.Font = [Drawing.SystemFonts]::MessageBoxFont
    $scroll = New-Object Windows.Forms.Panel
    $scroll.Dock = 'Fill'; $scroll.AutoScroll = $true; $form.Controls.Add($scroll)
    $table = New-Object Windows.Forms.TableLayoutPanel
    $table.Dock = 'Top'; $table.AutoSize = $true; $table.ColumnCount = 2; $table.Padding = New-Object Windows.Forms.Padding(12)
    $null = $table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 28)))
    $null = $table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 72)))
    $scroll.Controls.Add($table)
    $panel = @{Form=$form;State=$State;ReferenceItem=$ReferenceItem;Table=$table;Timer=$null;Loading=$false;RemainingSeconds=$RemainingSeconds}
    $heading = New-Object Windows.Forms.Label
    $heading.AutoSize = $true; $heading.Dock = 'Top'
    $heading.Text = 'PUBLIC review only. Never load credentials. Imported evidence is a proposal, not verified authority.'
    if ($Binding) { $heading.Text = "Original request: $($Binding.origin) | Account: $($Binding.account) | POST`r`n" + $heading.Text }
    $table.Controls.Add($heading,0,0); $table.SetColumnSpan($heading,2)
    $form.Add_SizeChanged({ $heading.MaximumSize = New-Object Drawing.Size([Math]::Max(1,$form.ClientSize.Width - 48),0) }.GetNewClosure())
    $heading.MaximumSize = New-Object Drawing.Size(1000,0)
    $load = New-Object Windows.Forms.Button
    $load.Text='Load Public Review'; $load.AutoSize=$true; $panel.Load=$load
    $importStatus=New-Object Windows.Forms.Label
    $importStatus.Text='No public review loaded.'; $importStatus.AutoSize=$true; $panel.ImportStatus=$importStatus
    $loadBar=New-Object Windows.Forms.FlowLayoutPanel
    $loadBar.AutoSize=$true; $loadBar.Dock='Fill'; $loadBar.Controls.Add($load); $loadBar.Controls.Add($importStatus)
    $table.Controls.Add($loadBar,0,1); $table.SetColumnSpan($loadBar,2)
    $summary=New-Object Windows.Forms.TextBox
    $summary.Multiline=$true; $summary.ReadOnly=$true; $summary.ScrollBars='Vertical'; $summary.Dock='Fill'; $summary.Height=245
    $panel.Summary=$summary
    $table.Controls.Add($summary,0,2); $table.SetColumnSpan($summary,2)
    $panel.PublicConfirmed=New-Object Windows.Forms.CheckBox
    $panel.PublicConfirmed.AutoSize=$true
    $panel.PublicConfirmed.Text='I verified these public values do not authenticate anyone, including every sensitive-looking field.'
    $panel.CookieConfirmed=New-Object Windows.Forms.CheckBox
    $panel.CookieConfirmed.AutoSize=$true
    $panel.CookieConfirmed.Text='I verified the original prelogin cookie context has no authentication authority.'
    $panel.CookieConfirmed.Enabled=[bool]$ReferenceItem.cookie_context_ref
    if (-not $ReferenceItem.cookie_context_ref) { $panel.CookieConfirmed.Text='No original cookie context requires review.' }
    $public = New-Object Windows.Forms.TextBox
    $public.Multiline = $true; $public.ScrollBars = 'Both'; $public.WordWrap = $false
    $public.Dock = 'Fill'; $public.Height = 190; $public.MaxLength = 24000
    $public.Text = (@{profile_id=[string]$ReferenceItem.profile_id;target_text='';content_type='';body_text='';public_headers=@()} | ConvertTo-Json -Depth 8)
    $panel.PublicReference = $public
    $panel.Profile = New-V3ReviewCombo @('Unreviewed',[string]$ReferenceItem.profile_id)
    $panel.DataStatus = New-V3ReviewCombo @('Unreviewed','Public invariant')
    $panel.Role = New-V3ReviewCombo @('Unreviewed','Non-auth')
    $panel.Effect = New-V3ReviewCombo @('Unreviewed','Initialization Read')
    $panel.EvidenceKind = New-V3ReviewCombo @('Unreviewed','source-review','api-document','verified-record','operator-inspected')
    foreach ($name in @('Source','Revision','Deployment','Basis','CookieEvidence')) {
        $control = New-Object Windows.Forms.TextBox
        $control.Dock = 'Fill'; $control.MaxLength = 512; $panel[$name] = $control
    }
    $panel.Basis.Multiline = $true; $panel.Basis.Height = 60; $panel.Basis.ScrollBars = 'Vertical'
    $panel.Reviewed = New-Object Windows.Forms.CheckBox
    $panel.Reviewed.AutoSize = $true
    $panel.Reviewed.Text = 'I verified initialization only reads information, and the readiness checks match the independent source.'
    $panel.Sensitive = New-Object Windows.Forms.CheckBox
    $panel.Sensitive.AutoSize = $true
    $panel.Sensitive.Text = 'Non-auth role reviewed for every sensitive-looking key in this complete reference'
    $panel.Sensitive.Enabled = @($ReferenceItem.locations | Where-Object { $_.sensitive -eq $true }).Count -gt 0
    $panel.CookieRole = New-V3ReviewCombo @('Unreviewed','Non-auth prelogin')
    if (-not $ReferenceItem.cookie_context_ref) {
        $panel.CookieRole.Items.Clear(); $null = $panel.CookieRole.Items.Add('None'); $panel.CookieRole.SelectedIndex = 0
        $panel.CookieRole.Enabled = $false; $panel.CookieEvidence.Enabled = $false
    }
    $checks = New-Object Windows.Forms.TextBox
    $checks.Multiline = $true; $checks.ReadOnly = $true; $checks.Dock = 'Fill'; $checks.Height = 65; $checks.ScrollBars = 'Both'
    $checks.Text = (@($ReferenceItem.response_checks) | ConvertTo-Json -Depth 16)
    $advanced=New-Object Windows.Forms.TableLayoutPanel
    $advanced.AutoSize=$true; $advanced.Dock='Top'; $advanced.ColumnCount=2; $advanced.Visible=$false
    $null=$advanced.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,28)))
    $null=$advanced.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,72)))
    $panel.Advanced=$advanced
    $rows = @(
        @('Public wire reference JSON',$public),@('Representation',$panel.Profile),@('Data status',$panel.DataStatus),
        @('Security role',$panel.Role),@('Operation effect',$panel.Effect),@('Evidence kind',$panel.EvidenceKind),
        @('Independent source',$panel.Source),@('Source revision',$panel.Revision),@('Deployment applicability',$panel.Deployment),
        @('Review basis',$panel.Basis),@('Public readiness predicates',$checks),
        @('Sensitive-name acknowledgment',$panel.Sensitive),@('Original cookie-context role',$panel.CookieRole),
        @('Cookie-context evidence',$panel.CookieEvidence)
    )
    $index = 0
    foreach ($entry in $rows) {
        $label = New-Object Windows.Forms.Label
        $label.Text = [string]$entry[0]; $label.AutoSize = $false; $label.Height = 32; $label.Dock = 'Fill'
        $null = $advanced.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::AutoSize)))
        $advanced.Controls.Add($label,0,$index); $advanced.Controls.Add($entry[1],1,$index); $index++
    }
    $index=3
    foreach ($control in @($panel.PublicConfirmed,$panel.Reviewed,$panel.CookieConfirmed)) {
        $table.Controls.Add($control,0,$index); $table.SetColumnSpan($control,2); $index++
    }
    $form.Add_SizeChanged({
        foreach ($control in @($panel.PublicConfirmed,$panel.Reviewed,$panel.CookieConfirmed)) {
            $control.MaximumSize=New-Object Drawing.Size([Math]::Max(1,$form.ClientSize.Width-60),0)
        }
    }.GetNewClosure())
    $status = New-Object Windows.Forms.Label
    $status.AutoSize = $true; $status.Dock = 'Top'; $status.Text = 'Unreviewed. No authority.'; $panel.Status = $status
    $table.Controls.Add($status,0,$index); $table.SetColumnSpan($status,2); $index++
    $buttons = New-Object Windows.Forms.FlowLayoutPanel
    $buttons.AutoSize = $true; $buttons.Dock = 'Fill'
    $compare = New-Object Windows.Forms.Button
    $compare.Text = 'Compare Public Reference'; $compare.AutoSize = $true; $compare.Enabled = $false; $panel.Compare = $compare
    $back = New-Object Windows.Forms.Button
    $back.Text = 'Back to Request'; $back.AutoSize = $true
    $buttons.Controls.Add($compare); $buttons.Controls.Add($back)
    $table.Controls.Add($buttons,0,$index); $table.SetColumnSpan($buttons,2)
    $expand=New-Object Windows.Forms.Button
    $expand.Text='Show Full Reference / Expert Fields'; $expand.AutoSize=$true; $panel.Expand=$expand
    $buttons.Controls.Add($expand)
    $index++; $table.Controls.Add($advanced,0,$index); $table.SetColumnSpan($advanced,2)
    $update = {
        if ($panel.Loading) { return }
        $remaining = & $RemainingSeconds
        $panel.Load.Enabled=(-not $State.pending -and $remaining -gt 0)
        $panel.Compare.Enabled = (-not $State.pending -and $remaining -gt 0 -and $null -ne (Get-V3NativeReferenceInput -Panel $panel -ReferenceItem $ReferenceItem))
        $panel.Status.Text = "$($State.status). Review remaining: $remaining seconds. Comparison is not authorization."
        $reference=$null
        try {$reference=ConvertFrom-UniqueReferenceJson $panel.PublicReference.Text} catch {}
        $origin=if ($Binding) {[string]$Binding.origin} else {'Not supplied'}
        $account=if ($Binding) {[string]$Binding.account} else {'Not supplied'}
        $body=[string]$reference.body_text
        $bodyLabel='Public body'
        if ($reference.profile_id -cin @('form-utf8-v1','form-json-name-view-v1')) {
            try {$body=[Uri]::UnescapeDataString($body.Replace('+',' ')); $bodyLabel='Public form (decoded preview; exact wire text in full reference)'} catch {}
        }
        $predicates=@($ReferenceItem.response_checks | ForEach-Object {
            "$($_.pointer) $($_.test) $($_.expected | ConvertTo-Json -Depth 8 -Compress)"
        }) -join '; '
        $headers=@($reference.public_headers | ForEach-Object {"$($_.name): $($_.value)"}) -join "`r`n"
        $panel.Summary.Text=(@(
            "Original request: $origin | Account: $account | POST"
            "Proposed target: $($reference.target_text)"
            "${bodyLabel}: $body"
            "Content type: $($reference.content_type)"
            "Proposed effect: Initialization Read. No credential submission or business changes."
            "Original readiness checks: $predicates"
            "Evidence ($($panel.EvidenceKind.SelectedItem)): $($panel.Source.Text)"
            "Revision: $($panel.Revision.Text) | Deployment: $($panel.Deployment.Text)"
            "Basis: $($panel.Basis.Text)"
            "Original cookie context evidence: $($panel.CookieEvidence.Text)"
            "Public headers ($(@($reference.public_headers).Count)):`r`n$headers"
        ) -join "`r`n")
    }.GetNewClosure()
    $panel.Update=$update
    $changed = {
        if ($panel.Loading) { return }
        Invalidate-V3ReferenceState -State $State
        $panel.Loading=$true
        try { Reset-V3PublicConfirmations $panel } finally { $panel.Loading=$false }
        & $update
    }.GetNewClosure()
    foreach ($name in @('PublicReference','Source','Revision','Deployment','Basis','CookieEvidence')) { $panel[$name].Add_TextChanged($changed) }
    foreach ($name in @('Profile','EvidenceKind')) { $panel[$name].Add_SelectedIndexChanged($changed) }
    $confirmationChanged={
        if ($panel.Loading) {return}
        Invalidate-V3ReferenceState $State
        & $update
    }.GetNewClosure()
    $expertChanged={
        if ($panel.Loading) {return}
        $panel.Loading=$true
        try {
            $panel.PublicConfirmed.Checked=($panel.DataStatus.SelectedItem -ceq 'Public invariant' -and
                $panel.Role.SelectedItem -ceq 'Non-auth' -and (-not $panel.Sensitive.Enabled -or $panel.Sensitive.Checked))
            $panel.CookieConfirmed.Checked=($panel.CookieRole.SelectedItem -ceq 'Non-auth prelogin')
            if ($panel.Effect.SelectedItem -cne 'Initialization Read') {$panel.Reviewed.Checked=$false}
        } finally {$panel.Loading=$false}
        & $confirmationChanged
    }.GetNewClosure()
    foreach ($name in @('DataStatus','Role','Effect','CookieRole')) {$panel[$name].Add_SelectedIndexChanged($expertChanged)}
    $panel.Sensitive.Add_CheckedChanged($expertChanged)
    $panel.PublicConfirmed.Add_CheckedChanged({
        if ($panel.Loading) {return}
        $panel.Loading=$true
        try {
            $index=if ($panel.PublicConfirmed.Checked) {1} else {0}
            $panel.DataStatus.SelectedIndex=$index; $panel.Role.SelectedIndex=$index
            $panel.Sensitive.Checked=($panel.PublicConfirmed.Checked -and $panel.Sensitive.Enabled)
        } finally {$panel.Loading=$false}
        & $confirmationChanged
    }.GetNewClosure())
    $panel.Reviewed.Add_CheckedChanged({
        if ($panel.Loading) {return}
        $panel.Loading=$true
        try {$panel.Effect.SelectedIndex=if ($panel.Reviewed.Checked) {1} else {0}} finally {$panel.Loading=$false}
        & $confirmationChanged
    }.GetNewClosure())
    $panel.CookieConfirmed.Add_CheckedChanged({
        if ($panel.Loading) {return}
        if ($ReferenceItem.cookie_context_ref) {
            $panel.Loading=$true
            try {$panel.CookieRole.SelectedIndex=if ($panel.CookieConfirmed.Checked) {1} else {0}} finally {$panel.Loading=$false}
        }
        & $confirmationChanged
    }.GetNewClosure())
    $expand.Add_Click({
        $advanced.Visible=-not $advanced.Visible
        $expand.Text=if ($advanced.Visible) {'Hide Full Reference / Expert Fields'} else {'Show Full Reference / Expert Fields'}
    }.GetNewClosure())
    $load.Add_Click({
        if ($State.pending -or (& $RemainingSeconds) -le 0) {return}
        $picker=New-Object Windows.Forms.OpenFileDialog
        $picker.Title='Load independent PUBLIC review (no credentials)'
        $picker.Filter='Public review JSON (*.json)|*.json'; $picker.CheckFileExists=$true; $picker.Multiselect=$false
        try {
            if ($picker.ShowDialog($form) -ne [Windows.Forms.DialogResult]::OK) {return}
            if ($State.pending -or (& $RemainingSeconds) -le 0) {throw 'Review expired'}
            $text=Read-V3PublicReviewFile $picker.FileName
            Set-V3PublicReviewPacket -Panel $panel -Text $text
        } catch {$panel.ImportStatus.Text='Not loaded. Use valid local public JSON; the draft and original deadline are unchanged.'}
        finally {$picker.Dispose()}
    }.GetNewClosure())
    $compare.Add_Click({
        try {
            $native = Get-V3NativeReferenceInput -Panel $panel -ReferenceItem $ReferenceItem
            if ($null -eq $native -or $State.pending -or (& $RemainingSeconds) -le 0) { return }
            $State.check_id = [Guid]::NewGuid().ToString('N'); $State.pending = $true
            $State.review_ref = $null; $State.matched_revision = [long]0; $State.status = 'pending'
            $frame = @{event='reference-check';request_id=$State.request_id;nonce=$State.nonce;request_digest=$State.request_digest
                check_id=$State.check_id;item_id=$State.item_id;edit_revision=$State.edit_revision;native_input=$native}
            if (-not (& $SendFrame $frame)) { $State.pending = $false; $State.status = 'ineligible' }
        } catch { $State.pending = $false; $State.status = 'ineligible' }
        & $update
    }.GetNewClosure())
    $back.Add_Click({ $form.Close() }.GetNewClosure())
    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 250; $panel.Timer = $timer
    $timer.Add_Tick({ & $update; if ((& $RemainingSeconds) -le 0) { $form.Close() } }.GetNewClosure())
    $form.Add_Disposed({ $timer.Stop(); $timer.Dispose() }.GetNewClosure())
    $timer.Start()
    & $update
    return $panel
}
