$str = 'C:\Users\Administrator\Documents\yep`.txt'
$strCharacterOfInterest1 = '`'
$strCharacterOfInterest2 = $null

$strEscapeCharacter1 = '`'
$strEscapeCharacter2 = '\'

#region FunctionsToSupportErrorHandling
function Get-ReferenceToLastError {
    #region FunctionHeader ####################################################
    # Function returns $null if no errors on on the $error stack;
    # Otherwise, function returns a reference (memory pointer) to the last error that occurred.
    #
    # Version: 1.0.20210105.0
    #endregion FunctionHeader ####################################################

    #region License ####################################################
    # Copyright (c) 2021 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy of this
    # software and associated documentation files (the "Software"), to deal in the Software
    # without restriction, including without limitation the rights to use, copy, modify, merge,
    # publish, distribute, sublicense, and/or sell copies of the Software, and to permit
    # persons to whom the Software is furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in all copies or
    # substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
    # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
    # PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
    # FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    # DEALINGS IN THE SOFTWARE.
    #endregion License ####################################################

    #region DownloadLocationNotice ####################################################
    # The most up-to-date version of this script can be found on the author's GitHub repository
    # at https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice ####################################################

    if ($error.Count -gt 0) {
        [ref]($error[0])
    } else {
        $null
    }
}

function Test-ErrorOccurred {
    #region FunctionHeader ####################################################
    # Function accepts two positional arguments:
    #
    # The first argument is a reference (memory pointer) to the last error that had occurred
    #   prior to calling the command in question - that is, the command that we want to test
    #   to see if an error occurred.
    #
    # The second argument is a reference to the last error that had occurred as-of the
    #   completion of the command in question
    #
    # Function returns $true if it appears that an error occurred; $false otherwise
    #
    # Version: 1.0.20210105.0
    #endregion FunctionHeader ####################################################

    #region License ####################################################
    # Copyright (c) 2021 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy of this
    # software and associated documentation files (the "Software"), to deal in the Software
    # without restriction, including without limitation the rights to use, copy, modify, merge,
    # publish, distribute, sublicense, and/or sell copies of the Software, and to permit
    # persons to whom the Software is furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in all copies or
    # substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
    # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
    # PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
    # FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    # DEALINGS IN THE SOFTWARE.
    #endregion License ####################################################

    #region DownloadLocationNotice ####################################################
    # The most up-to-date version of this script can be found on the author's GitHub repository
    # at https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice ####################################################

    # TO-DO: Validate input

    $boolErrorOccurred = $false
    if (($null -ne ($args[0])) -and ($null -ne ($args[1]))) {
        # Both not $null
        if ((($args[0]).Value) -ne (($args[1]).Value)) {
            $boolErrorOccurred = $true
        }
    } else {
        # One is $null, or both are $null
        # NOTE: ($args[0]) could be non-null, while ($args[1])
        # could be null if $error was cleared; this does not indicate an error.
        # So:
        # If both are null, no error
        # If ($args[0]) is null and ($args[1]) is non-null, error
        # If ($args[0]) is non-null and ($args[1]) is null, no error
        if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
            $boolErrorOccurred
        }
    }

    $boolErrorOccurred
}
#endregion FunctionsToSupportErrorHandling

function Get-AclSafely {
    # Usage:
    # $objThisFolderPermission = $null
    # $objThis = $null
    # $strThisObjectPath = 'D:\Shares\Share\Accounting'
    # $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

    trap {
        # Intentionally left empty to prevent terminating errors from halting processing
    }

    $refOutputObjThisFolderPermission = $args[0]
    $refOutputObjThis = $args[1]
    $strThisObjectPath = $args[2]

    $objThisFolderPermission = $null
    $objThis = $null

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and then
    # continue on. Likewise, non-terminating errors will also not output anything, but they
    # do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # This needs to be a one-liner for error handling to work!:
    # if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) { $objThis = Get-Item ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force; $objThisFolderPermission = $objThis.GetAccessControl() } else { $objThisFolderPermission = Get-Acl $strThisObjectPath }
    $objThisFolderPermission = Get-Acl $strThisObjectPath
    # The above one-liner is a messy variant of the following, which had to be
    # converted to one line to prevent PowerShell v3 from throwing errors on the stack
    # when copy-pasted into the shell (despite there not being any apparent error):
    ###################################################################################
    # TODO: Get-Acl is slow if there is latency between the folder structure and the domain controller, probably because of SID lookups. See if there is a way to speed this up without introducing external dependencies.
    # if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) {
    #     # Can't use Get-Acl because Get-Acl doesn't support paths with brackets
    #     $versionPS = Get-PSVersion
    #     if ($versionPS.Major -ge 3) {
    #         # PowerShell v3 and newer supports -LiteralPath
    #         $objThis = Get-Item -LiteralPath $strThisObjectPath -Force # -Force parameter is required to get hidden items
    #     } else {
    #         $objThis = Get-Item ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force # -Force parameter is required to get hidden items
    #     }
    #
    #     # TODO: GetAccessControl() does not work and returns $null on PowerShell v1 for some reason
    #     $objThisFolderPermission = $objThis.GetAccessControl()
    # } else {
    #     # No square brackets; use Get-Acl
    #     $objThisFolderPermission = Get-Acl $strThisObjectPath
    # }
    ###################################################################################

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        if ($null -ne $objThis) {
            $refOutputObjThis.Value = $objThis
        }
        $false
    } else {
        $refOutputObjThisFolderPermission.Value = $objThisFolderPermission
        if ($null -ne $objThis) {
            $refOutputObjThis.Value = $objThis
        }
        $true
    }
}

function Get-ItemSafely {
    # Usage:
    # $objThisFolderPermission = $null
    # $objThis = $null
    # $strThisObjectPath = 'D:\Shares\Share\Accounting'
    # $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

    trap {
        # Intentionally left empty to prevent terminating errors from halting processing
    }

    $refOutputObjThisFolderPermission = $args[0]
    $refOutputObjThis = $args[1]
    $strThisObjectPath = $args[2]

    $objThisFolderPermission = $null
    $objThis = $null

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and then
    # continue on. Likewise, non-terminating errors will also not output anything, but they
    # do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # This needs to be a one-liner for error handling to work!:
    # if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) { $objThis = Get-Item ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force; $objThisFolderPermission = $objThis.GetAccessControl() } else { $objThisFolderPermission = Get-Acl $strThisObjectPath }
    $objThis = Get-Item $strThisObjectPath
    # The above one-liner is a messy variant of the following, which had to be
    # converted to one line to prevent PowerShell v3 from throwing errors on the stack
    # when copy-pasted into the shell (despite there not being any apparent error):
    ###################################################################################
    # TODO: Get-Acl is slow if there is latency between the folder structure and the domain controller, probably because of SID lookups. See if there is a way to speed this up without introducing external dependencies.
    # if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) {
    #     # Can't use Get-Acl because Get-Acl doesn't support paths with brackets
    #     $versionPS = Get-PSVersion
    #     if ($versionPS.Major -ge 3) {
    #         # PowerShell v3 and newer supports -LiteralPath
    #         $objThis = Get-Item -LiteralPath $strThisObjectPath -Force # -Force parameter is required to get hidden items
    #     } else {
    #         $objThis = Get-Item ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force # -Force parameter is required to get hidden items
    #     }
    #
    #     # TODO: GetAccessControl() does not work and returns $null on PowerShell v1 for some reason
    #     $objThisFolderPermission = $objThis.GetAccessControl()
    # } else {
    #     # No square brackets; use Get-Acl
    #     $objThisFolderPermission = Get-Acl $strThisObjectPath
    # }
    ###################################################################################

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        if ($null -ne $objThis) {
            $refOutputObjThis.Value = $objThis
        }
        $false
    } else {
        $refOutputObjThisFolderPermission.Value = $objThisFolderPermission
        if ($null -ne $objThis) {
            $refOutputObjThis.Value = $objThis
        }
        $true
    }
}

Write-Host '########################################################################################'
$intCounter = 1
$strWorking = $str
$foo = $null
$objThis = $null
$boolSuccess = Get-AclSafely ([ref]$foo) ([ref]$objThis) $strWorking
if ($boolSuccess -eq $true) {
Write-Host ('Get-Acl worked for attempt ' + $intCounter)
}
$foo = $null
$objThis = $null
$boolSuccess = Get-ItemSafely ([ref]$foo) ([ref]$objThis) $strWorking
if ($boolSuccess -eq $true) {
Write-Host ('Get-Item worked for attempt ' + $intCounter)
}
$strCommand = 'icacls.exe "' + $strWorking + '"'
Write-Host ('For attempt ' + $intCounter + ', about to run command: ' + $strCommand)
Invoke-Expression $strCommand

Write-Host '########################################################################################'
$intCounter = 2
$strWorking = $str.Replace($strCharacterOfInterest1, $strEscapeCharacter1 + $strCharacterOfInterest1)
if ([string]::IsNullOrEmpty($strCharacterOfInterest2) -eq $false) {
    $strWorking = $strWorking.Replace($strCharacterOfInterest2, $strEscapeCharacter1 + $strCharacterOfInterest2)
}
$foo = $null
$objThis = $null
$boolSuccess = Get-AclSafely ([ref]$foo) ([ref]$objThis) $strWorking
if ($boolSuccess -eq $true) {
Write-Host ('Get-Acl worked for attempt ' + $intCounter)
}
$foo = $null
$objThis = $null
$boolSuccess = Get-ItemSafely ([ref]$foo) ([ref]$objThis) $strWorking
if ($boolSuccess -eq $true) {
Write-Host ('Get-Item worked for attempt ' + $intCounter)
}
$strCommand = 'icacls.exe "' + $strWorking + '"'
Write-Host ('For attempt ' + $intCounter + ', about to run command: ' + $strCommand)
Invoke-Expression $strCommand

Write-Host '########################################################################################'
$intCounter = 3
$strWorking = $str.Replace($strCharacterOfInterest1, $strEscapeCharacter2 + $strCharacterOfInterest1)
if ([string]::IsNullOrEmpty($strCharacterOfInterest2) -eq $false) {
    $strWorking = $strWorking.Replace($strCharacterOfInterest2, $strEscapeCharacter2 + $strCharacterOfInterest2)
}
$foo = $null
$objThis = $null
$boolSuccess = Get-AclSafely ([ref]$foo) ([ref]$objThis) $strWorking
if ($boolSuccess -eq $true) {
Write-Host ('Get-Acl worked for attempt ' + $intCounter)
}
$foo = $null
$objThis = $null
$boolSuccess = Get-ItemSafely ([ref]$foo) ([ref]$objThis) $strWorking
if ($boolSuccess -eq $true) {
Write-Host ('Get-Item worked for attempt ' + $intCounter)
}
$strCommand = 'icacls.exe "' + $strWorking + '"'
Write-Host ('For attempt ' + $intCounter + ', about to run command: ' + $strCommand)
Invoke-Expression $strCommand

Write-Host '########################################################################################'
$intCounter = 4
$strWorking = [regex]::Escape($str)
$foo = $null
$objThis = $null
$boolSuccess = Get-AclSafely ([ref]$foo) ([ref]$objThis) $strWorking
if ($boolSuccess -eq $true) {
Write-Host ('Get-Acl worked for attempt ' + $intCounter)
}
$foo = $null
$objThis = $null
$boolSuccess = Get-ItemSafely ([ref]$foo) ([ref]$objThis) $strWorking
if ($boolSuccess -eq $true) {
Write-Host ('Get-Item worked for attempt ' + $intCounter)
}
$strCommand = 'icacls.exe "' + $strWorking + '"'
Write-Host ('For attempt ' + $intCounter + ', about to run command: ' + $strCommand)
Invoke-Expression $strCommand
