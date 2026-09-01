[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Store')]
    [string]$Operation,

    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 512)]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [string]$ReceiptPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($Target.IndexOfAny([char[]]"`0`r`n") -ge 0) {
    throw 'Credential target is malformed.'
}

$nativeSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security;

public static class RemoteXCredentialNative
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public UInt32 Flags;
        public UInt32 Type;
        public string TargetName;
        public string Comment;
        public FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, UInt32 type, UInt32 flags, out IntPtr credential);

    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref CREDENTIAL credential, UInt32 flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = false)]
    private static extern void CredFree(IntPtr credential);

    public static bool Exists(string target)
    {
        IntPtr credential;
        if (!CredRead(target, 1, 0, out credential))
        {
            return false;
        }
        CredFree(credential);
        return true;
    }

    public static void Write(string target, string username, SecureString securePassword)
    {
        if (String.IsNullOrWhiteSpace(target) || String.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Credential target and username are required.");
        }

        IntPtr secret = IntPtr.Zero;
        try
        {
            secret = Marshal.SecureStringToCoTaskMemUnicode(securePassword);
            CREDENTIAL credential = new CREDENTIAL();
            credential.Type = 1;
            credential.TargetName = target;
            credential.UserName = username;
            credential.CredentialBlob = secret;
            credential.CredentialBlobSize = checked((UInt32)(securePassword.Length * 2));
            credential.Persist = 2;
            if (!CredWrite(ref credential, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            if (secret != IntPtr.Zero)
            {
                Marshal.ZeroFreeCoTaskMemUnicode(secret);
            }
        }
    }
}
'@

Add-Type -TypeDefinition $nativeSource -Language CSharp

$receipt = [ordered]@{
    schema = 'RemoteXCredentialSetupReceipt/v1'
    status = 'failed'
    existingBefore = $false
    referencePresent = $false
    targetSha256 = $null
}
$exitCode = 1

try {
    $targetBytes = [Text.Encoding]::UTF8.GetBytes($Target)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $receipt.targetSha256 = ([BitConverter]::ToString($sha.ComputeHash($targetBytes))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        [Array]::Clear($targetBytes, 0, $targetBytes.Length)
    }

    $receipt.existingBefore = [RemoteXCredentialNative]::Exists($Target)
    $credential = Get-Credential -Message ('RemoteX credential setup for configured reference ' + $receipt.targetSha256.Substring(0, 12))
    if ($null -eq $credential) {
        $receipt.status = 'cancelled'
        $exitCode = 2
    }
    else {
        [RemoteXCredentialNative]::Write($Target, $credential.UserName, $credential.Password)
        $receipt.referencePresent = [RemoteXCredentialNative]::Exists($Target)
        if (-not $receipt.referencePresent) {
            throw 'Credential presence readback failed.'
        }
        $receipt.status = 'stored'
        $exitCode = 0
    }
}
catch [System.Management.Automation.PipelineStoppedException] {
    $receipt.status = 'cancelled'
    $exitCode = 2
}
catch {
    $receipt.status = 'failed'
    $exitCode = 1
}
finally {
    $directory = [IO.Path]::GetDirectoryName($ReceiptPath)
    if ([string]::IsNullOrWhiteSpace($directory) -or -not [IO.Directory]::Exists($directory)) {
        throw 'Receipt directory is unavailable.'
    }
    $temporary = $ReceiptPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $json = $receipt | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($temporary, $json + "`n", (New-Object Text.UTF8Encoding($false)))
    [IO.File]::Move($temporary, $ReceiptPath)
}

exit $exitCode
