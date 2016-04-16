# Set file system permissions using PowerShell

function New-FileSystemAccessRule
{
    param(
        [System.Security.Principal.NTAccount]$IdentityReference,
        [System.Security.AccessControl.FileSystemRights]$FileSystemRights,
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags,
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags,
        [System.Security.AccessControl.AccessControlType]$AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    )
    $SidReference = ($IdentityReference).Translate([System.Security.Principal.SecurityIdentifier])
    $ArgumentList = $SidReference, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType
    return New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $ArgumentList
}

function Set-DirectoryPermissions
{
    param(
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        [string]$Path,
        [string]$Owner,
        [switch]$PurgeAccessRules,
        [switch]$DisableInheritance,
        [Parameter(ParameterSetName = "OneRule")][System.Security.AccessControl.FileSystemAccessRule]$FileSystemAccessRule,
        [Parameter(ParameterSetName = "MultiRule")][System.Security.AccessControl.FileSystemAccessRule[]]$FileSystemAccessRules
    )
    $PathACL = Get-Acl $Path
    
    if ($Owner)
    {
        $PathACL.SetOwner(([System.Security.Principal.NTAccount]"$Owner").Translate([System.Security.Principal.SecurityIdentifier]))
    }
    
    if ($DisableInheritance)
    {
        $PathACL.SetAccessRuleProtection($True, $False)
    }
    
    if ($PurgeAccessRules)
    {
        $PathACL.Access | % { $PathACL.PurgeAccessRules(($_.IdentityReference)) }
    }

    if ($FileSystemAccessRules)
    {
        foreach ($accessRule in $FileSystemAccessRules)
        {
            $PathACL.SetAccessRule($accessRule)
        }
    }
    else
    {
        $PathACL.SetAccessRule($FileSystemAccessRule)
    }
    return ($PathACL | Set-Acl $Path)
}
