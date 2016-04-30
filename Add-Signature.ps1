param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()] 
    [string]$CertPath,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string]$Password,
        
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()] 
    [System.IO.FileInfo]$Path,
    
    [Parameter(Mandatory=$False)]
    [ValidateSet("sha1","sha256","sha512")]
    [string]$HashAlgorithm="sha512",
    
    [Parameter(Mandatory=$False)]
    [ValidateSet("8.0","8.1","10")]
    [string]$WindowsKitVersion="10",
    
    [Parameter(Mandatory=$False)]
    [ValidateSet("arm","arm64","x86","x64")]
    [string]$Architecture="x64"
)

$SignTool = "${env:ProgramFiles(x86)}\Windows Kits\${WindowsKitVersion}\bin\${Architecture}\SignTool.exe"

if (!(Test-Path $SignTool))
{
    Write-Error "Signtool not found. Windows Kit not installed or invalid combination of 'Architecture' and 'WindowsKitVersion'"
}

$TargetPath = $(Get-Item $Path).FullName
$X509Certificate2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

#DefaultKeySet: The default key set is used. The user key set is usually the default.
#Exportable: Imported keys are marked as exportable.
#MachineKeySet: Private keys are stored in the local computer store rather than the current user store.
#PersistKeySet: The key associated with a PFX file is persisted when importing a certificate.
#UserKeySet: Private keys are stored in the current user store rather than the local computer store. This occurs even if the certificate specifies that the keys should go in the local computer store.
#UserProtected: Notify the user through a dialog box or other method that the key is accessed. The Cryptographic Service Provider (CSP) in use defines the precise behavior.

$X509Certificate2.Import($CertPath, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
if (!$X509Certificate2.Verify())
{
    Write-Error "Invalid certificate detected"
    return
}

if (Test-Path $TargetPath -PathType Container)
{    
    $Binaries = $(Get-ChildItem -Recurse "${TargetPath}" -Include *.dll,*.exe).FullName
    if ($Binaries)
    {
        Write-Verbose "Signing binaries in $TargetPath"
        foreach ($p in $Binaries)
        {
            . $SignTool sign /fd $HashAlgorithm /a /f $CertPath /p $Password "$p"
        }    
    }
    
    $PowerShellScripts = $(Get-ChildItem -Recurse "${TargetPath}" -Include *.ps1,*.psm1).FullName
    if ($PowerShellScripts)
    {
        Write-Verbose "Signing PowerShell scripts in $TargetPath"
        foreach ($p in $PowerShellScripts)
        {
            Set-AuthenticodeSignature -Certificate $X509Certificate2 -FilePath $p -HashAlgorithm "$HashAlgorithm"
        }
        
    }    
}
elseif (Test-Path $TargetPath -PathType Leaf)
{
    Write-Verbose "Target is a Leaf."
    if (Test-Path $TargetPath -Include *.ps1,*.psm1)
    {
        Set-AuthenticodeSignature -Certificate $X509Certificate2 -FilePath $TargetPath -HashAlgorithm "$HashAlgorithm"
    }
    elseif (Test-Path $TargetPath -Include *.exe,*.dll)
    {
        . $SignTool sign /fd $HashAlgorithm /a /f $CertPath /p $Password "$TargetPath"
    }
}
$X509Certificate2.Dispose()
