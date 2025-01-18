<#
.SYNOPSIS
  Creates a deep folder structure exceeding path length limits, including random files and names with special characters.
  Randomly breaks inheritance and modifies permissions (ACLs). Optionally creates up to five local accounts to demonstrate
  varied permissions.  

.NOTES
  Author: ChatGPT Example
  Requires: PowerShell 5.1+ with “long paths” support or Windows 10/11 with long path support enabled.
  Run As: Administrator
#>

# ---------------------------
# Configuration
# ---------------------------

# Maximum depth of nested folders.
$maxDepth = 35

# Number of folders to create at each level.
$foldersPerLevel = 1

# Number of files to create in each folder.
$filesPerFolder = 30

# Probability (0 to 1) of breaking inheritance in any given folder.
$breakInheritanceChance = 0.2

# Probability of adding an additional ACE when NOT breaking inheritance.
$addAceChance = 0.4

# Whether to create up to five local accounts.
$createLocalAccounts = $true

# Accounts will be named MyTestUser1..MyTestUser5 with a default password.
# Adjust if desired.
$testUserPassword = 'P@ssw0rd123!'

# Characters we will randomly pick from for folder/file names (including some special chars).
# - [char]8220 = “
# - [char]8221 = ”
# - [char]8222 = „
# - `$ = dollar sign
# - ` = grave accent/backtick
# Feel free to add or remove characters as needed.
$specialChars = @(
    [char]8220, # “
    [char]8221, # ”
    [char]8222, # „
    '`',        # backtick
    '$',
    '💯',
    '華',
    '語',
    '华',
    '语'
)
# We also include typical alphanumeric, underscore, and maybe some punctuation:
# Lowercase a-z = ASCII 97..122
$lowercase = 97..122 | ForEach-Object { [char]$_ }

# Uppercase A-Z = ASCII 65..90
$uppercase = 65..90  | ForEach-Object { [char]$_ }

# Digits 0-9 = ASCII 48..57
$digits = 48..57  | ForEach-Object { [char]$_ }

# Then combine them
$commonChars = $lowercase + $uppercase + $digits + '_' + '-'
# Combined character set for random names:
$charSet = $commonChars + $specialChars

# The base path, using the \\?\ prefix to support long paths in PowerShell/Windows.
# This will create folders inside your current directory.
# NOTE: (Get-Location).Path might already be quite long. If you want to ensure even longer paths,
# set an explicit parent path if desired.
$basePath = "\\?\$((Get-Location).Path)"


# ---------------------------
# Helper Functions
# ---------------------------

function Enable-LongPathsSupport {
    # Optionally enable the LongPathsEnabled registry key if you want to ensure
    # long paths are allowed on Windows 10/11. Requires a reboot to take full effect in some cases.
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force | Out-Null
        Write-Host "Enabled LongPathsEnabled in registry. A reboot may be required for full effect."
    }
    catch {
        Write-Warning "Failed to enable long paths in registry. Error: $_"
    }
}

function Get-RandomName {
    param(
        [int]$length = 8
    )
    # Builds a random string of the given length from $charSet.
    $name = -join (1..$length | ForEach-Object { $charSet | Get-Random })
    return $name
}

function Create-RandomFolders {
    param(
        [string]$parentPath,
        [int]$depth
    )

    if ($depth -le 0) {
        return
    }

    for ($i = 1; $i -le $foldersPerLevel; $i++) {
        # Generate a random name; in real usage, you might want to ensure it doesn't start/end with special chars
        $folderName = Get-RandomName -length (Get-Random -Minimum 6 -Maximum 12)

        # Build full path. Use \\?\ again in case of further length expansions.
        # $newFolderPath = Join-Path -Path $parentPath -ChildPath $folderName
        $newFolderPath = $parentPath + '\' + $folderName
        if ($newFolderPath.Substring(0, 4) -ne '\\?\') {
            $newFolderPath = "\\?\$newFolderPath"
        }

        # Create the folder
        New-Item -Path $newFolderPath -ItemType Directory -Force | Out-Null

        # Create random files in this folder
        for ($j = 1; $j -le $filesPerFolder; $j++) {
            $fileName = Get-RandomName -length (Get-Random -Minimum 6 -Maximum 12)
            # $filePath = Join-Path -Path $newFolderPath -ChildPath $fileName
            $filePath = $newFolderPath + '\' + $fileName
            if ($filePath.Substring(0, 4) -ne '\\?\') {
                $filePath = "\\?\$filePath"
            }
            New-Item -Path $filePath -ItemType File -Force | Out-Null
        }

        # Randomly decide whether to break inheritance here
        if ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt $breakInheritanceChance) {
            Break-InheritanceAndModifyAcl -targetPath $newFolderPath
        }
        else {
            # Possibly add an additional ACE if we did NOT break inheritance
            if ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt $addAceChance) {
                Add-RandomAce -targetPath $newFolderPath -inheritanceBroken:$false
            }
        }

        # Recurse deeper
        Create-RandomFolders -parentPath $newFolderPath -depth ($depth - 1)
    }
}

function Break-InheritanceAndModifyAcl {
    param(
        [string]$targetPath
    )
    try {
        $acl = Get-Acl -LiteralPath $targetPath
        # Break inheritance, copying current ACL entries
        $acl.SetAccessRuleProtection($true, $true)
        Set-Acl -LiteralPath $targetPath -AclObject $acl

        $acl = Get-Acl -LiteralPath $targetPath
        # Now optionally remove or add an ACE for demonstration.
        # Let’s remove “Everyone” if it exists, or add a random user ACE otherwise.
        $rules = $acl.Access | Where-Object { $_.IdentityReference -eq 'Everyone' -or $_.IdentityReference -eq 'NT AUTHORITY\SYSTEM' }
        if ($rules) {
            # Remove Everyone and NT AUTHORITY\SYSTEM ACEs
            foreach ($rule in $rules) {
                $acl.RemoveAccessRule($rule) | Out-Null
            }
            Set-Acl -LiteralPath $targetPath -AclObject $acl
            Write-Host "Removed 'Everyone' and 'NT AUTHORITY\SYSTEM' ACE on $targetPath"
        }
        else {
            # Add a random ACE (maybe for one of the created local users, or a built-in group)
            Add-RandomAce -targetPath $targetPath -inheritanceBroken:$true
        }
    }
    catch {
        Write-Warning "Failed to break inheritance or modify ACL on $targetPath. Error: $_"
    }
}

function Add-RandomAce {
    param(
        [string]$targetPath,
        [bool]$inheritanceBroken
    )
    try {
        $acl = Get-Acl -LiteralPath $targetPath

        # For demonstration, pick from local users or known principals
        $possiblePrincipals = @(
            'Everyone',
            'BUILTIN\Users',
            'BUILTIN\Administrators'
        ) + (Get-LocalUser | Select-Object -ExpandProperty Name | ForEach-Object { "$env:COMPUTERNAME\$_" })

        $randomPrincipal = $possiblePrincipals | Get-Random
        $fileSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]"None"
        $accessControlType = [System.Security.AccessControl.AccessControlType]"Allow"

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $randomPrincipal,
            $fileSystemRights,
            $inheritanceFlags,
            $propagationFlags,
            $accessControlType
        )

        $acl.AddAccessRule($rule) | Out-Null
        Set-Acl -LiteralPath $targetPath -AclObject $acl

        if ($inheritanceBroken) {
            Write-Host "Inheritance broken: added ACE for $randomPrincipal on $targetPath"
        }
        else {
            Write-Host "Inheritance intact: added ACE for $randomPrincipal on $targetPath"
        }
    }
    catch {
        Write-Warning "Failed to add random ACE on $targetPath. Error: $_"
    }
}

function Create-LocalAccounts {
    param(
        [int]$accountCount = 5,
        [string]$password = 'P@ssw0rd123!'
    )
    for ($i=1; $i -le $accountCount; $i++) {
        $userName = "MyTestUser$i"

        # Check if the user already exists
        if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) {
            Write-Host "User $userName already exists; skipping creation."
        }
        else {
            Write-Host "Creating local user: $userName"
            New-LocalUser -Name $userName `
                          -Password (ConvertTo-SecureString $password -AsPlainText -Force) `
                          -FullName "Local Test User $i" `
                          -Description "Created by script for random ACL testing" | Out-Null
        }
    }
}


# ---------------------------
# Main Script
# ---------------------------

# (Optional) Enable-LongPathsSupport  # Uncomment to try enabling long path support in the registry.

# 1. Create local accounts (up to 5) if enabled
if ($createLocalAccounts) {
    Create-LocalAccounts -accountCount 5 -password $testUserPassword
}

# 2. Create the nested folder structure
Write-Host "Creating nested folders and files starting at: $basePath"
Create-RandomFolders -parentPath $basePath -depth $maxDepth

Write-Host "Done! Folders and files have been created up to depth $maxDepth with random permissions changes."
Write-Host "Be aware of the extremely long path names if you try to manually navigate or remove them."
