<#
.SYNOPSIS
Scans the permissions at the specified path and ensures that administrators and the
SYSTEM account have full control. Optionally, additional accounts/groups can be
specified to be granted full control or read-only access.

.DESCRIPTION
Scans the permissions at the specified path and ensures that local administrators and
the SYSTEM account have full control. Optionally, additional accounts/groups can be
specified to be granted full control or read-only access. The script will not remove
any existing permissions, but will add permissions as necessary to ensure that the
specified accounts/groups have the specified access.

This script is especially useful because taking ownership of a file or folder through
the Windows graphical interface can replace existing permissions, which can be
problematic if the existing permissions are not known or documented (and even if they
are known or documented, it can be time-consuming and disruptive to business to re-
apply them).

.PARAMETER PathToFix
Specifies the path to be fixed. This parameter is mandatory.

.PARAMETER NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls
Optionally, specifies the name of the local administrators group. This parameter is
optional; if not specified, the default value of 'Administrators' will be used.

Supplying this parameter may be necessary on non-English systems, where the name of
the local administrators group may be different. This parameter is used when taking
ownership of the file or folder and when applying permissions using icacls.exe.

.PARAMETER NameOfBuiltInAdministratorsGroupAccordingToGetAcl
Optionally, specifies the name of the local administrators group. This parameter is
optional; if not specified, the default value of 'BUILTIN\Administrators' will be
used.

Supplying this parameter may be necessary on non-English systems, where the name of
the local administrators group may be different. This parameter is used when getting
the ACL of the file or folder in PowerShell via Get-Acl.

.PARAMETER NameOfSYSTEMAccountAccordingToTakeOwnAndICacls
Optionally, specifies the name of the SYSTEM account. This parameter is optional; if
not specified, the default value of 'SYSTEM' will be used.

Supplying this parameter may be necessary on non-English systems, where the name of
the SYSTEM account may be different. This parameter is used when taking ownership of
the file or folder and when applying permissions using icacls.exe.

.PARAMETER NameOfSYSTEMAccountGroupAccordingToGetAcl
Optionally, specifies the name of the SYSTEM account. This parameter is optional; if
not specified, the default value of 'NT AUTHORITY\SYSTEM' will be used.

Supplying this parameter may be necessary on non-English systems, where the name of
the SYSTEM account may be different. This parameter is used when getting the ACL of
the file or folder in PowerShell via Get-Acl.

.PARAMETER NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls
Optionally, specifies the name of an additional account or group to be granted full
control. This parameter is optional; if not specified, the default value of $null will
be used and the script will not attempt to grant additional full control permissions.

This parameter is used when applying permissions using icacls.exe.

.PARAMETER NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl
Optionally, specifies the name of an additional account or group to be granted full
control. This parameter is optional; if not specified, the default value of $null will
be used and the script will not attempt to grant additional full control permissions.

This parameter is used when getting the ACL of the file or folder in PowerShell via
Get-Acl.

.PARAMETER NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls
Optionally, specifies the name of an additional account or group to be granted read-
only access. This parameter is optional; if not specified, the default value of $null
will be used and the script will not attempt to grant additional read-only permissions.

This parameter is used when applying permissions using icacls.exe.

.PARAMETER NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl
Optionally, specifies the name of an additional account or group to be granted read-
only access. This parameter is optional; if not specified, the default value of $null
will be used and the script will not attempt to grant additional read-only permissions.

This parameter is used when getting the ACL of the file or folder in PowerShell via
Get-Acl.

.EXAMPLE
PS C:\> .\Repair-NTFSPermissions.ps1 -PathToFix 'D:\Shares\Public'

This example will scan the permissions at D:\Shares\Public and ensure that local
administrators and the SYSTEM account have full control to the folder and all files
and subfolders. No additional accounts or groups will be granted permissions, and
existing permissions will not be removed.

.OUTPUTS
None

.NOTES
This script is useful because taking ownership of a file or folder through the Windows
graphical interface can replace existing permissions, which can be problematic if the
existing permissions are not known or documented (and even if they are known or
documented, it can be time-consuming and disruptive to business to re-apply them).
#>


[CmdletBinding()]

param (
    [Parameter(Mandatory = $true)][string]$PathToFix,
    [Parameter(Mandatory = $false)][string]$NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls = 'Administrators',
    [Parameter(Mandatory = $false)][string]$NameOfBuiltInAdministratorsGroupAccordingToGetAcl = 'BUILTIN\Administrators',
    [Parameter(Mandatory = $false)][string]$NameOfSYSTEMAccountAccordingToTakeOwnAndICacls = 'SYSTEM',
    [Parameter(Mandatory = $false)][string]$NameOfSYSTEMAccountGroupAccordingToGetAcl = 'NT AUTHORITY\SYSTEM',
    [Parameter(Mandatory = $false)][string]$NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls = $null,
    [Parameter(Mandatory = $false)][string]$NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl = $null,
    [Parameter(Mandatory = $false)][string]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls = $null,
    [Parameter(Mandatory = $false)][string]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = $null
)

#region License ####################################################################
# Copyright (c) 2023 Frank Lesniak
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion License ####################################################################

$strThisScriptVersionNumber = [version]'1.0.20230615.0'


$strPathToFix = $PathToFix
$strNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls = $NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls
$strNameOfBuiltInAdministratorsGroupAccordingToGetAcl = $NameOfBuiltInAdministratorsGroupAccordingToGetAcl
$strNameOfSYSTEMAccountAccordingToTakeOwnAndICacls = $NameOfSYSTEMAccountAccordingToTakeOwnAndICacls
$strNameOfSYSTEMAccountGroupAccordingToGetAcl = $NameOfSYSTEMAccountGroupAccordingToGetAcl
$strNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls = $NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls
$strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl = $NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl
$strNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls = $NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls
$strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = $NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl

# TODO: additional code/logic is necessary for adding a read-only account, see TODO markers below

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

function Get-PSVersion {
    <#
    .SYNOPSIS
    Returns the version of PowerShell that is running

    .DESCRIPTION
    Returns the version of PowerShell that is running, including on the original
    release of Windows PowerShell (version 1.0)

    .EXAMPLE
    Get-PSVersion

    This example returns the version of PowerShell that is running. On versions of
    PowerShell greater than or equal to version 2.0, this function returns the
    equivalent of $PSVersionTable.PSVersion

    .OUTPUTS
    A [version] object representing the version of PowerShell that is running

    .NOTES
    PowerShell 1.0 does not have a $PSVersionTable variable, so this function returns
    [version]('1.0') on PowerShell 1.0
    #>

    [CmdletBinding()]
    [OutputType([version])]

    param ()

    #region License ################################################################
    # Copyright (c) 2023 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy of
    # this software and associated documentation files (the "Software"), to deal in the
    # Software without restriction, including without limitation the rights to use,
    # copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
    # Software, and to permit persons to whom the Software is furnished to do so,
    # subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in all
    # copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    # FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    # COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
    # AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    # WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    #endregion License ################################################################

    $versionThisFunction = [version]('1.0.20230613.0')

    if (Test-Path variable:\PSVersionTable) {
        $PSVersionTable.PSVersion
    } else {
        [version]('1.0')
    }
}

function Test-Windows {
    <#
    .SYNOPSIS
    Returns a boolean ($true or $false) indicating whether the current PowerShell
    session is running on Windows

    .DESCRIPTION
    Returns a boolean ($true or $false) indicating whether the current PowerShell
    session is running on Windows. This function is useful for writing scripts that
    need to behave differently on Windows and non-Windows platforms (Linux, macOS,
    etc.). Additionally, this function is useful because it works on Windows PowerShell
    1.0 through 5.1, which do not have the $IsWindows global variable.

    .EXAMPLE
    Test-Windows

    This example returns $true if the current PowerShell session is running on Windows,
    and $false if the current PowerShell session is running on a non-Windows platform
    (Linux, macOS, etc.)

    .OUTPUTS
    A [bool] (boolean) object representing whether the current platform is Windows
    ($true) or non-Windows ($false)

    .NOTES
    PowerShell 1.0 through 5.1 do not have a built-in $IsWindows global variable,
    making the test for whether the current platform is Windows a bit more complicated
    #>

    [CmdletBinding()]
    [OutputType([bool])]

    param ()

    #region License ################################################################
    # Copyright (c) 2023 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy of
    # this software and associated documentation files (the "Software"), to deal in the
    # Software without restriction, including without limitation the rights to use,
    # copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
    # Software, and to permit persons to whom the Software is furnished to do so,
    # subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in all
    # copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    # FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    # COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
    # AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    # WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    #endregion License ################################################################

    $versionThisFunction = [version]('1.0.20230613.0')

    $versionPS = Get-PSVersion
    if ($versionPS.Major -ge 6) {
        $IsWindows
    } else {
        $true
    }
}

function Get-AvailableDriveLetter {
    <#
    .SYNOPSIS
    Returns an array of available (unused) drive letters

    .DESCRIPTION
    This function evaluates the list of drive letters that are in use on the local
    system and returns an array of those that are available. The list of available
    drive letters is returned as an array of uppercase letters

    .PARAMETER DoNotConsiderMappedDriveLettersAsInUse
    By default, if this function encounters a drive letter that is mapped to a network
    share, it will consider that drive letter to be in use. However, if this switch
    parameter is supplied, then mapped drives will be ignored and their drive letters
    will be considered available.

    .PARAMETER DoNotConsiderPSDriveLettersAsInUse
    By default, if this function encounters a drive letter that is mapped to a
    PowerShell drive, it will consider that drive letter to be in use. However, if this
    switch parameter is supplied, then PowerShell drives will be ignored and their
    drive letters will be considered available.

    .PARAMETER ConsiderFloppyDriveLettersAsEligible
    By default, this function will not consider A: or B: drive letters as available. If
    this switch parameter is supplied, then A: and B: drive letters will be considered
    available if they are not in use.

    .EXAMPLE
    $arrAvailableDriveLetters = @(Get-AvailableDriveLetter)

    This example returns an array of available drive letters, excluding A: and B:
    drive, and excluding drive letters that are mapped to network shares or PowerShell
    drives (PSDrives).

    To access the alphabetically-first available drive letter, use:
    $arrAvailableDriveLetters[0]

    To access the alphabetically-last available drive letter, use:
    $arrAvailableDriveLetters[-1]

    .OUTPUTS
    Array of uppercase letters (strings) representing available drive letters

    .NOTES
    It is conventional that A: and B: drives be reserved for floppy drives, and that C:
    be reserved for the system drive.

    This function depends on the functions Get-PSVersion and Test-Windows
    #>


    [CmdletBinding()]
    [OutputType([string[]])]

    param (
        [Parameter(Mandatory = $false)][switch]$DoNotConsiderMappedDriveLettersAsInUse,
        [Parameter(Mandatory = $false)][switch]$DoNotConsiderPSDriveLettersAsInUse,
        [Parameter(Mandatory = $false)][switch]$ConsiderFloppyDriveLettersAsEligible
    )

    #region License ################################################################
    # Copyright (c) 2023 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy of
    # this software and associated documentation files (the "Software"), to deal in the
    # Software without restriction, including without limitation the rights to use,
    # copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
    # Software, and to permit persons to whom the Software is furnished to do so,
    # subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in all
    # copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    # FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    # COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
    # AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    # WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    #endregion License ################################################################

    $versionThisFunction = [version]('1.0.20230615.0')

    #region Process Input ##########################################################
    if ($DoNotConsiderMappedDriveLettersAsInUse.IsPresent -eq $true) {
        $boolExcludeMappedDriveLetters = $false
    } else {
        $boolExcludeMappedDriveLetters = $true
    }

    if ($DoNotConsiderPSDriveLettersAsInUse.IsPresent -eq $true) {
        $boolExcludePSDriveLetters = $false
    } else {
        $boolExcludePSDriveLetters = $true
    }

    if ($ConsiderFloppyDriveLettersAsEligible.IsPresent -eq $true) {
        $boolExcludeFloppyDriveLetters = $false
    } else {
        $boolExcludeFloppyDriveLetters = $true
    }
    #endregion Process Input ##########################################################

    if ((Test-Windows) -eq $true) {

        $arrAllPossibleLetters = 65..90 | ForEach-Object { [char]$_ }

        $versionPS = Get-PSVersion

        If ($versionPS.Major -ge 3) {
            $arrUsedLogicalDriveLetters = Get-CimInstance -ClassName 'Win32_LogicalDisk' |
                ForEach-Object { $_.DeviceID } | Where-Object { $_.Length -eq 2 } |
                Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                ForEach-Object { $_[0] } | Where-Object { $arrAllPossibleLetters -contains $_ }
            # fifth-, fourth-, and third-to-last bits of pipeline ensures that we have a device ID like
            # "C:" second-to-last bit of pipeline strips off the ':', leaving just the capital drive
            # letter last bit of pipeline ensure that the drive letter is actually a letter; addresses
            # legacy Netware edge cases

            if ($boolExcludeMappedDriveLetters -eq $true) {
                $arrUsedMappedDriveLetters = Get-CimInstance -ClassName 'Win32_NetworkConnection' |
                    ForEach-Object { $_.LocalName } | Where-Object { $_.Length -eq 2 } |
                    Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                    ForEach-Object { $_[0] } |
                    Where-Object { $private.arrAllPossibleLetters -contains $_ }
                # fifth-, fourth-, and third-to-last bits of pipeline ensures that we have a LocalName like "C:"
                # second-to-last bit of pipeline strips off the ':', leaving just the capital drive letter
                # last bit of pipeline ensure that the drive letter is actually a letter; addresses legacy
                # Netware edge cases
            } else {
                $arrUsedMappedDriveLetters = $null
            }
        } else {
            $arrUsedLogicalDriveLetters = Get-WmiObject -Class 'Win32_LogicalDisk' |
                ForEach-Object { $_.DeviceID } | Where-Object { $_.Length -eq 2 } |
                Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                ForEach-Object { $_[0] } | Where-Object { $arrAllPossibleLetters -contains $_ }
            # fifth-, fourth-, and third-to-last bits of pipeline ensures that we have a device ID like
            # "C:" second-to-last bit of pipeline strips off the ':', leaving just the capital drive
            # letter last bit of pipeline ensure that the drive letter is actually a letter; addresses
            # legacy Netware edge cases

            if ($boolExcludeMappedDriveLetters -eq $true) {
                $arrUsedMappedDriveLetters = Get-WmiObject -Class 'Win32_NetworkConnection' |
                    ForEach-Object { $_.LocalName } | Where-Object { $_.Length -eq 2 } |
                    Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                    ForEach-Object { $_[0] } |
                    Where-Object { $private.arrAllPossibleLetters -contains $_ }
                # fifth-, fourth-, and third-to-last bits of pipeline ensures that we have a LocalName like "C:"
                # second-to-last bit of pipeline strips off the ':', leaving just the capital drive letter
                # last bit of pipeline ensure that the drive letter is actually a letter; addresses legacy
                # Netware edge cases
            } else {
                $arrUsedMappedDriveLetters = $null
            }
        }

        if ($boolExcludePSDriveLetters -eq $true) {
            $arrUsedPSDriveLetters = Get-PSDrive | ForEach-Object { $_.Name } | `
                    Where-Object { $_.Length -eq 1 } | ForEach-Object { $_.ToUpper() } | `
                    Where-Object { $private.arrAllPossibleLetters -contains $_ }
            # Checking for a length of 1 strips out most PSDrives that are not drive letters
            # Making sure that each item in the resultant set matches something in
            # $arrAllPossibleLetters filters out edge cases, like a PSDrive named '1'
        } else {
            $arrUsedPSDriveLetters = $null
        }

        if ($boolExcludeFloppyDriveLetters -eq $true) {
            $arrFloppyDriveLetters = @('A', 'B')
        } else {
            $arrFloppyDriveLetters = $null
        }

        $arrAllPossibleLetters | Where-Object { $arrUsedLogicalDriveLetters -notcontains $_ } |
            Where-Object { $arrUsedMappedDriveLetters -notcontains $_ } |
            Where-Object { $arrUsedPSDriveLetters -notcontains $_ } |
            Where-Object { $arrFloppyDriveLetters -notcontains $_ } |
            Where-Object { $arrBlacklistedDriveLetters -notcontains $_ }
    } else {
        Write-Warning "This function is only supported on Windows."
    }
}

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
    if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) { $objThis = Get-Item ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force; $objThisFolderPermission = $objThis.GetAccessControl() } else { $objThisFolderPermission = Get-Acl $strThisObjectPath }
    # The above one-liner is a messy variant of the following, which had to be
    # converted to one line to prevent PowerShell v3 from throwing errors on the stack
    # when copy-pasted into the shell (despite there not being any apparent error):
    ###################################################################################
    # TODO: Get-Acl is slow if there is latency between the folder structure and the domain controller, probably because of SID lookups. See if there is a way to speed this up without introducing external dependencies.
    # if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) {
    #     # Can't use Get-Acl because Get-Acl doesn't support paths with brackets
    #
    #     $objThis = Get-Item ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force # -Force parameter is required to get hidden items
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

function Join-PathSafely {
    # Usage:
    # $strParentPartOfPath = 'Z:'
    # $strChildPartOfPath = '####FAKE####'
    # $strJoinedPath = $null
    # $boolSuccess = Join-PathSafely ([ref]$strJoinedPath) $strParentPartOfPath $strChildPartOfPath

    trap {
        # Intentionally left empty to prevent terminating errors from halting processing
    }

    $refOutputJoinedPath = $args[0]
    $strParentPartOfPath = $args[1]
    $strChildPartOfPath = $args[2]

    $strJoinedPath = $null

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and then
    # continue on. Likewise, non-terminating errors will also not output anything, but they
    # do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    $strJoinedPath = Join-Path $strParentPartOfPath $strChildPartOfPath

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        $false
    } else {
        $true
        $refOutputJoinedPath.Value = $strJoinedPath
    }
}

function Get-ChildItemSafely {
    # Usage:
    # $objThisFolderItem = Get-Item 'D:\Shares\Share\Data'
    # $arrChildObjects = @()
    # $boolSuccess = Get-ChildItemSafely ([ref]$arrChildObjects) ([ref]$objThisFolderItem)

    trap {
        # Intentionally left empty to prevent terminating errors from halting processing
    }

    $refOutputArrChildObjects = $args[0]
    $refObjThisFolderItem = $args[1]

    $arrChildObjects = @()

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and then
    # continue on. Likewise, non-terminating errors will also not output anything, but they
    # do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    $arrChildObjects = @(($refObjThisFolderItem.Value) | Get-ChildItem -Force)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        $false
    } else {
        $true
        $refOutputArrChildObjects.Value = @($arrChildObjects)
    }
}

function Repair-NTFSPermissionsRecursively {
    # Syntax: Repair-NTFSPermissionsRecursively 'D:\Shares\Corporate'

    $strThisObjectPath = $args[0]
    $boolAllowRecursiveRun = $args[1]

    $FILEPATHLIMIT = 260
    $FOLDERPATHLIMIT = 248

    $objThis = $null
    $objThisFolderPermission = $null

    # We don't know if $strThisObjectPath is pointing to a folder or a file, so use the folder
    # (shorter) length limit
    if ($strThisObjectPath.Length -ge $FOLDERPATHLIMIT) {
        if ($boolAllowRecursiveRun -eq $false) {
            Write-Error "Despite attempts to mitigate, the path length of $strThisObjectPath exceeds the maximum length of $FOLDERPATHLIMIT characters."
            return
        } else {
            $intAttemptNumber = 0
            $boolPossibleAttemptsExceeded = $false
            $boolTenablePathFound = $false

            # Get path separator
            # $strTempPathToAdd = '###FAKE###'
            # $strTempPath = Join-Path $strThisObjectPath $strTempPathToAdd
            # $strPathSeparator = $strTempPath.Substring($strTempPath.Length - $strTempPathToAdd.Length - ($strTempPath.Length - $strTempPathToAdd.Length - $strThisObjectPath.Length), $strTempPath.Length - $strTempPathToAdd.Length - $strThisObjectPath.Length)

            $arrPathElements = @(Split-Path -Path $strThisObjectPath)
            # $arrPathElements = Split-StringOnLiteralString $strThisObjectPath $strPathSeparator

            while (($boolPossibleAttemptsExceeded -eq $false) -and ($boolTenablePathFound -eq $false)) {
                $strParentFolder = $arrPathElements[0]
                for ($intCounter = 1; $intCounter -le ($arrPathElements.Count - 2 - $intAttemptNumber); $intCounter++) {
                    $strParentFolder = Join-Path -Path $strParentFolder -ChildPath $arrPathElements[$intCounter]
                    # $strParentFolder += $strPathSeparator + $arrPathElements[$intCounter]
                }
                if ($strParentFolder -eq $arrPathElements[0]) {
                    $boolPossibleAttemptsExceeded = $true
                }
                if ($strParentFolder -eq $strThisObjectPath) {
                    # This shouldn't be possible
                    $boolPossibleAttemptsExceeded = $true
                } else {
                    if ($strParentFolder.Length -lt $FOLDERPATHLIMIT) {
                        $boolTenablePathFound = $true
                    } else {
                        # Parent folder still exceeds length limit
                        # Try again
                        $intAttemptNumber++
                    }
                }
            }

            if ($boolTenablePathFound) {
                $arrAvailableDriveLetters = @(Get-AvailableDriveLetter)
                if ($arrAvailableDriveLetters.Count -gt 0) {
                    $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                    $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strParentFolder.Replace('$', '`$') + '"'
                    Write-Verbose ('About to run command: ' + $strCommand)
                    $null = Invoke-Expression $strCommand

                    $strRemainderOfPath = $strThisObjectPath.Substring($strParentFolder.Length + 1, $strThisObjectPath.Length - $strParentFolder.Length - 1)

                    $doubleSecondsCounter = 0
                    $boolErrorOccurredUsingDriveLetter = $true

                    # Try Join-Path and sleep for up to 10 seconds until it's successful
                    while ($doubleSecondsCounter -le 10 -and $boolErrorOccurredUsingDriveLetter -eq $true) {
                        if (Test-Path ($strDriveLetterToUse + ':')) {
                            $strJoinedPath = $null
                            $boolSuccess = Join-PathSafely ([ref]$strJoinedPath) ($strDriveLetterToUse + ":") $strRemainderOfPath

                            if ($boolSuccess -eq $false) {
                                Start-Sleep 0.2
                                $doubleSecondsCounter += 0.2
                            } else {
                                $boolErrorOccurredUsingDriveLetter = $false
                            }
                        } else {
                            Start-Sleep 0.2
                            $doubleSecondsCounter += 0.2
                        }
                    }

                    if ($boolErrorOccurredUsingDriveLetter -eq $true) {
                        Write-Error ('Unable to process the path "' + $strParentFolder.Replace('$', '`$') + '" because running the following command to mitigate path length failed: ' + $strCommand)
                    } else {
                        Repair-NTFSPermissionsRecursively $strNewPath $true
                    }

                    $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                    Write-Verbose ('About to run command: ' + $strCommand)
                    $null = Invoke-Expression $strCommand
                } else {
                    Write-Error ('Cannot process the following path because it is too long and there are no drive letters available to use as a mount point: ' + $strThisObjectPath)
                }
            } elseif ($boolPossibleAttemptsExceeded -eq $true) {
                Write-Error ('Cannot process the following path because it contains no parent folder element that is of an acceptable length to connect to a mount point: ' + $strThisObjectPath)
            }
        }
    } else {
        $boolCriticalErrorOccurred = $false

        $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

        if ($boolSuccess -eq $false) {
            # Error occurred reading the ACL

            # Take ownership
            # TODO: This does not work if $strThisObjectPath is over 260 characters. Look at https://serverfault.com/questions/232986/overcoming-maximum-file-path-length-restrictions-in-windows
            $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strThisObjectPath.Replace('$', '`$') + '" /A'
            Write-Verbose ('About to run command: ' + $strCommand)
            $null = Invoke-Expression $strCommand

            # Should now be able to read permissions

            $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

            if ($boolSuccess -eq $false) {
                Write-Error ('Despite taking ownership of the folder/file "' + $strThisObjectPath + '" on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand)
                $boolCriticalErrorOccurred = $true
            }
        } else {
            # Able to read the permissions of the parent folder, continue

            if ($null -eq $objThisFolderPermission) {
                # An error did not occur retrieving permissions; however no permissions were retrieved
                # Either Get-Acl did not work as expected, or there are in fact no access control entries on the object

                # Take ownership
                # TODO: This does not work if $strThisObjectPath is over 260 characters. Look at https://serverfault.com/questions/232986/overcoming-maximum-file-path-length-restrictions-in-windows
                $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strThisObjectPath.Replace('$', '`$') + '" /A'
                Write-Verbose ('About to run command: ' + $strCommand)
                $null = Invoke-Expression $strCommand

                # Should now be able to read permissions

                $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

                if ($boolSuccess -eq $false) {
                    # We had success reading permissions before, but now that we took
                    # ownership, we suddenly cannot read them. This is a critical error.
                    Write-Error ('After taking ownership of the folder/file "' + $strThisObjectPath + '" on behalf of administrators, the script is unable to read permissions from the folder/file using Get-Acl. The command used to take ownership was:' + "`n`n" + $strCommand)
                    $boolCriticalErrorOccurred = $true
                }
            }
        }

        if ($boolCriticalErrorOccurred -eq $false) {
            if ($null -eq $objThis) {
                # -Force parameter is required to get hidden items
                $objThis = Get-Item $strThisObjectPath -Force
            }

            if ($null -eq $objThisFolderPermission) {
                $arrACEs = @()
            } else {
                $arrACEs = @($objThisFolderPermission.Access)
            }

            $boolBuiltInAdministratorsDenyEntryFound = $false
            $boolBuiltInAdministratorsHaveSufficientAccess = $false
            $boolSYSTEMAccountDenyEntryFound = $false
            $boolSYSTEMAccountHasSufficientAccess = $false
            $boolAdditionalAdministratorAccountOrGroupDenyEntryFound = $false
            if ([string]::IsNullOrEmpty($strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) -eq $false) {
                $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $false
            }
            $boolAdditionalReadOnlyAccountOrGroupDenyEntryFound = $false
            if ([string]::IsNullOrEmpty($strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) -eq $false) {
                $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $false
            }

            $arrACEs | ForEach-Object {
                $objThisACE = $_
                if ($objThisACE.IdentityReference.Value -eq $strNameOfBuiltInAdministratorsGroupAccordingToGetAcl) {
                    if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                        $boolBuiltInAdministratorsDenyEntryFound = $true
                    } else {
                        # assume 'Allow'
                        if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                            $boolBuiltInAdministratorsHaveSufficientAccess = $true
                        }
                    }
                } elseif ($objThisACE.IdentityReference.Value -eq $strNameOfSYSTEMAccountGroupAccordingToGetAcl) {
                    if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                        $boolSYSTEMAccountDenyEntryFound = $true
                    } else {
                        # assume 'Allow'
                        if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                            $boolSYSTEMAccountHasSufficientAccess = $true
                        }
                    }
                } else {
                    # check additional accounts
                    $boolFoundGroup = $false

                    if ($boolFoundGroup -eq $false) {
                        if ([string]::IsNullOrEmpty($strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) -eq $false) {
                            # Check the additional administrator account/group
                            if ($objThisACE.IdentityReference.Value -eq $strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) {
                                $boolFoundGroup = $true
                                if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                    $boolAdditionalAdministratorAccountOrGroupDenyEntryFound = $true
                                } else {
                                    # assume 'Allow'
                                    if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                        $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $true
                                    }
                                }
                            }
                        }
                    }

                    if ($boolFoundGroup -eq $false) {
                        if ([string]::IsNullOrEmpty($strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) -eq $false) {
                            # Check the additional administrator account/group
                            if ($objThisACE.IdentityReference.Value -eq $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) {
                                $boolFoundGroup = $true
                                if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                    $boolAdditionalReadOnlyAccountOrGroupDenyEntryFound = $true
                                } else {
                                    # assume 'Allow'
                                    # TODO: This needs to be fixed to convert ReadAndExecute permissions to a string, then look for the string in the FileSystemRights property, which is a comma-separated list. The read only account could also have elevated permissions (something beyond read and execute), which would also be acceptable
                                    if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                        $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $true
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ([string]::IsNullOrEmpty($strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) -eq $true) {
                $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $true
            }
            if ([string]::IsNullOrEmpty($strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) -eq $true) {
                $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $true
            }

            if ($boolBuiltInAdministratorsDenyEntryFound) {
                Write-Warning ('The built-in Administrators group ("' + $strNameOfBuiltInAdministratorsGroupAccordingToGetAcl + '") is denied access to the folder "' + $strThisObjectPath + '". Please remove this deny permission or update this script to do so.')
                $boolBuiltInAdministratorsHaveSufficientAccess = $false
            }
            if ($boolSYSTEMAccountDenyEntryFound) {
                Write-Warning ('The SYSTEM account ("' + $strNameOfSYSTEMAccountGroupAccordingToGetAcl + '") is denied access to the folder "' + $strThisObjectPath + '". Please remove this deny permission or update this script to do so.')
                $boolSYSTEMAccountHasSufficientAccess = $false
            }
            if ($boolAdditionalAdministratorAccountOrGroupDenyEntryFound) {
                Write-Warning ('The account "' + $strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl + '" is denied access to the folder "' + $strThisObjectPath + '". Please remove this deny permission or update this script to do so.')
                $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $false
            }
            if ($boolAdditionalReadOnlyAccountOrGroupDenyEntryFound) {
                Write-Warning ('The account "' + $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl + '" is denied access to the folder "' + $strThisObjectPath + '". Please remove this deny permission or update this script to do so.')
                $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $false
            }

            if ($boolBuiltInAdministratorsHaveSufficientAccess -eq $false -or $boolSYSTEMAccountHasSufficientAccess -eq $false -or $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess -eq $false -or $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess -eq $false) {
                $boolPermissionAdjustmentNecessary = $true
                Write-Verbose ('Permission adjustment necessary for "' + $strThisObjectPath + '".')
            } else {
                $boolPermissionAdjustmentNecessary = $false
            }

            $strAllCommandsInThisSection = ''

            if ($boolBuiltInAdministratorsHaveSufficientAccess -eq $false) {
                Write-Verbose ('The built-in Administrators group ("' + $strNameOfBuiltInAdministratorsGroupAccordingToGetAcl + '") does not have sufficient access to the folder "' + $strThisObjectPath + '".')
                # Write-Debug ($arrACEs | ForEach-Object { $_.IdentityReference } | Out-String)
                # Add ACE for administrators
                if ($objThis.PSIsContainer) {
                    # Is a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strThisObjectPath.Replace('$', '`$') + '" /grant "' + $strNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls + ':(NP)(F)"'
                } else {
                    # Is not a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strThisObjectPath.Replace('$', '`$') + '" /grant "' + $strNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls + ':(F)"'
                }
                if ($boolAllowRecursiveRun -eq $true) {
                    $strCommand += ' 2>&1'
                }
                $strAllCommandsInThisSection += "`n" + $strCommand
                Write-Verbose ('About to run command: ' + $strCommand)
                $null = Invoke-Expression $strCommand
            }

            if ($boolSYSTEMAccountHasSufficientAccess -eq $false) {
                Write-Verbose ('The SYSTEM account ("' + $strNameOfSYSTEMAccountGroupAccordingToGetAcl + '") does not have sufficient access to the folder "' + $strThisObjectPath + '".')
                # Write-Debug ($arrACEs | ForEach-Object { $_.IdentityReference } | Out-String)
                # Add ACE for SYSTEM
                if ($objThis.PSIsContainer) {
                    # Is a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strThisObjectPath.Replace('$', '`$') + '" /grant "' + $strNameOfSYSTEMAccountAccordingToTakeOwnAndICacls + ':(NP)(F)"'
                } else {
                    # Is not a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strThisObjectPath.Replace('$', '`$') + '" /grant "' + $strNameOfSYSTEMAccountAccordingToTakeOwnAndICacls + ':(F)"'
                }
                if ($boolAllowRecursiveRun -eq $true) {
                    $strCommand += ' 2>&1'
                }
                $strAllCommandsInThisSection += "`n" + $strCommand
                Write-Verbose ('About to run command: ' + $strCommand)
                $null = Invoke-Expression $strCommand
            }

            if ($boolAdditionalAdministratorAccountOrGroupHasSufficientAccess -eq $false) {
                Write-Verbose ('The account "' + $strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl + '" does not have sufficient access to the folder "' + $strThisObjectPath + '".')
                # Write-Debug ($arrACEs | ForEach-Object { $_.IdentityReference } | Out-String)
                # Add ACE for additional administrator
                if ($objThis.PSIsContainer) {
                    # Is a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strThisObjectPath.Replace('$', '`$') + '" /grant "' + $strNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls + ':(NP)(F)"'
                } else {
                    # Is not a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strThisObjectPath.Replace('$', '`$') + '" /grant "' + $strNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls + ':(F)"'
                }
                if ($boolAllowRecursiveRun -eq $true) {
                    $strCommand += ' 2>&1'
                }
                $strAllCommandsInThisSection += "`n" + $strCommand
                Write-Verbose ('About to run command: ' + $strCommand)
                $null = Invoke-Expression $strCommand
            }

            if ($boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess -eq $false) {
                Write-Verbose ('The account "' + $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl + '" does not have sufficient access to the folder "' + $strThisObjectPath + '".')
                # Write-Debug ($arrACEs | ForEach-Object { $_.IdentityReference } | Out-String)
                # Add ACE for additional read only account
                if ($objThis.PSIsContainer) {
                    # Is a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strThisObjectPath.Replace('$', '`$') + '" /grant "' + $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls + ':(NP)(RX)"'
                } else {
                    # Is not a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strThisObjectPath.Replace('$', '`$') + '" /grant "' + $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls + ':(RX)"'
                }
                if ($boolAllowRecursiveRun -eq $true) {
                    $strCommand += ' 2>&1'
                }
                $strAllCommandsInThisSection += "`n" + $strCommand
                Write-Verbose ('About to run command: ' + $strCommand)
                $null = Invoke-Expression $strCommand
            }

            if ($boolPermissionAdjustmentNecessary) {
                # Permissions should be fixed. Check them again.

                $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath
                if ($boolSuccess -eq $false) {
                    # An error occurred reading permissions with Get-Acl
                    #
                    # We had success reading permissions before, but now that we
                    # granted accounts permission, we suddenly cannot read them. This
                    # is a critical error.
                    Write-Error ('After granting permissions to the folder/file "' + $strThisObjectPath + '", the script is unable to read permissions from the folder/file using Get-Acl. The command(s) used to grant permissions were:' + "`n`n" + $strAllCommandsInThisSection)
                    $boolCriticalErrorOccurred = $true
                } else {
                    $arrACEs = @($objThisFolderPermission.Access)

                    $boolBuiltInAdministratorsDenyEntryFound = $false
                    $boolBuiltInAdministratorsHaveSufficientAccess = $false
                    $boolSYSTEMAccountDenyEntryFound = $false
                    $boolSYSTEMAccountHasSufficientAccess = $false
                    $boolAdditionalAdministratorAccountOrGroupDenyEntryFound = $false
                    if ([string]::IsNullOrEmpty($strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) -eq $false) {
                        $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $false
                    }
                    $boolAdditionalReadOnlyAccountOrGroupDenyEntryFound = $false
                    if ([string]::IsNullOrEmpty($strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) -eq $false) {
                        $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $false
                    }

                    $arrACEs | ForEach-Object {
                        $objThisACE = $_
                        if ($objThisACE.IdentityReference.Value -eq $strNameOfBuiltInAdministratorsGroupAccordingToGetAcl) {
                            if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                $boolBuiltInAdministratorsDenyEntryFound = $true
                            } else {
                                # assume 'Allow'
                                if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                    $boolBuiltInAdministratorsHaveSufficientAccess = $true
                                }
                            }
                        } elseif ($objThisACE.IdentityReference.Value -eq $strNameOfSYSTEMAccountGroupAccordingToGetAcl) {
                            if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                $boolSYSTEMAccountDenyEntryFound = $true
                            } else {
                                # assume 'Allow'
                                if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                    $boolSYSTEMAccountHasSufficientAccess = $true
                                }
                            }
                        } else {
                            # check additional accounts
                            $boolFoundGroup = $false

                            if ($boolFoundGroup -eq $false) {
                                if ([string]::IsNullOrEmpty($strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) -eq $false) {
                                    # Check the additional administrator account/group
                                    if ($objThisACE.IdentityReference.Value -eq $strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) {
                                        $boolFoundGroup = $true
                                        if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                            $boolAdditionalAdministratorAccountOrGroupDenyEntryFound = $true
                                        } else {
                                            # assume 'Allow'
                                            if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                                $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $true
                                            }
                                        }
                                    }
                                }
                            }

                            if ($boolFoundGroup -eq $false) {
                                if ([string]::IsNullOrEmpty($strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) -eq $false) {
                                    # Check the additional administrator account/group
                                    if ($objThisACE.IdentityReference.Value -eq $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) {
                                        $boolFoundGroup = $true
                                        if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                            $boolAdditionalReadOnlyAccountOrGroupDenyEntryFound = $true
                                        } else {
                                            # assume 'Allow'
                                            # TODO: This needs to be fixed to convert ReadAndExecute permissions to a string, then look for the string in the FileSystemRights property, which is a comma-separated list. The read only account could also have elevated permissions (something beyond read and execute), which would also be acceptable
                                            if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                                $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $true
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if ($null -eq $strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) {
                        $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $true
                    }
                    if ($null -eq $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) {
                        $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $true
                    }

                    if ($boolBuiltInAdministratorsDenyEntryFound) {
                        Write-Warning ('The built-in Administrators group ("' + $strNameOfBuiltInAdministratorsGroupAccordingToGetAcl + '") is denied access to the folder "' + $strThisObjectPath + '". Please remove this deny permission or update this script to do so.')
                        $boolBuiltInAdministratorsHaveSufficientAccess = $false
                    }
                    if ($boolSYSTEMAccountDenyEntryFound) {
                        Write-Warning ('The SYSTEM account ("' + $strNameOfSYSTEMAccountGroupAccordingToGetAcl + '") is denied access to the folder "' + $strThisObjectPath + '". Please remove this deny permission or update this script to do so.')
                        $boolSYSTEMAccountHasSufficientAccess = $false
                    }
                    if ($boolAdditionalAdministratorAccountOrGroupDenyEntryFound) {
                        Write-Warning ('The account "' + $strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl + '" is denied access to the folder "' + $strThisObjectPath + '". Please remove this deny permission or update this script to do so.')
                        $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $false
                    }
                    if ($boolAdditionalReadOnlyAccountOrGroupDenyEntryFound) {
                        Write-Warning ('The account "' + $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl + '" is denied access to the folder "' + $strThisObjectPath + '". Please remove this deny permission or update this script to do so.')
                        $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $false
                    }

                    if ($boolBuiltInAdministratorsHaveSufficientAccess -eq $false -or $boolSYSTEMAccountHasSufficientAccess -eq $false -or $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess -eq $false -or $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess -eq $false) {
                        Write-Verbose ('Despite attempting to apply permissions to the folder/file, the permissions are not present as expected. This can occur because of a lack of ownership over the folder/file.')
                        # Write-Debug ($arrACEs | ForEach-Object { $_.IdentityReference } | Out-String)
                        if ($boolAllowRecursiveRun -eq $true) {
                            # Try taking ownership of the folder/file

                            # Take ownership
                            # TODO: This does not work if $strThisObjectPath is over 260 characters. Look at https://serverfault.com/questions/232986/overcoming-maximum-file-path-length-restrictions-in-windows
                            $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strThisObjectPath.Replace('$', '`$') + '" /A'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand
                            # Restart process without recursion flag
                            Repair-NTFSPermissionsRecursively $strThisObjectPath $false
                        } else {
                            Write-Warning ('The permissions on the folder "' + $strThisObjectPath + '" could not be repaired. Please repair them manually.')
                        }
                    }
                }
            }
        }

        if ($objThis.PSIsContainer) {
            # This object is a folder, not a file

            $arrChildObjects = $null
            $boolSuccess = Get-ChildItemSafely ([ref]$arrChildObjects) ([ref]$objThis)

            if ($boolSuccess -eq $false) {
                # Error occurred probably because the path length is too long
                if ($boolAllowRecursiveRun -eq $false) {
                    Write-Warning ('The path "' + $strPathToFix + '" threw an error when getting child objects - probably because the path is too long. Please shorten it and try again.')
                } else {
                    $arrAvailableDriveLetters = @(Get-AvailableDriveLetter)
                    if ($arrAvailableDriveLetters.Count -gt 0) {
                        $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                        $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strThisObjectPath.Replace('$', '`$') + '"'
                        Write-Verbose ('About to run command: ' + $strCommand)
                        $null = Invoke-Expression $strCommand

                        #############Get path to drive root
                        $strTempPathToAdd = '###FAKE###'

                        $doubleSecondsCounter = 0
                        $boolErrorOccurredUsingDriveLetter = $true

                        # Try Join-Path and sleep for up to 10 seconds until it's successful
                        while ($doubleSecondsCounter -le 10 -and $boolErrorOccurredUsingDriveLetter -eq $true) {
                            if (Test-Path ($strDriveLetterToUse + ':')) {
                                $strTempPath = $null
                                $boolSuccess = Join-PathSafely ([ref]$strTempPath) ($strDriveLetterToUse + ':') $strTempPathToAdd

                                if ($boolSuccess -eq $false) {
                                    Start-Sleep 0.2
                                    $doubleSecondsCounter += 0.2
                                } else {
                                    $boolErrorOccurredUsingDriveLetter = $false
                                }
                            } else {
                                Start-Sleep 0.2
                                $doubleSecondsCounter += 0.2
                            }
                        }

                        if ($boolErrorOccurredUsingDriveLetter -eq $true) {
                            Write-Error ('Unable to process the path "' + $strThisObjectPath.Replace('$', '`$') + '" because running the following command to mitigate path length failed: ' + $strCommand)
                        } else {
                            $strPathSeparator = $strTempPath.Substring($strTempPath.Length - $strTempPathToAdd.Length - ($strTempPath.Length - $strTempPathToAdd.Length - ($strDriveLetterToUse + ':').Length), $strTempPath.Length - $strTempPathToAdd.Length - ($strDriveLetterToUse + ':').Length)
                            $strPathToRootOfDrive = $strDriveLetterToUse + ':' + $strPathSeparator
                        }
                        #############Done getting path to drive root

                        if ($boolErrorOccurredUsingDriveLetter -eq $false) {
                            Repair-NTFSPermissionsRecursively $strPathToRootOfDrive $true
                        }

                        $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                        Write-Verbose ('About to run command: ' + $strCommand)
                        $null = Invoke-Expression $strCommand
                    } else {
                        Write-Error ('An error occurred enumerating subfolders and files within the following folder, and a mount point could not be created to compensate because there are no drive letters available: ' + $strThisObjectPath)
                    }
                }
            } else {
                # No error occurred
                $boolLengthOfChildrenOK = $true

                # Check the length of all child objects first
                $arrChildObjects | ForEach-Object {
                    $objDirectoryOrFileInfoChild = $_

                    # We don't know if $strThisObjectPath is pointing to a folder or a file, so use the folder
                    # (shorter) length limit
                    if (($objDirectoryOrFileInfoChild.FullName).Length -ge $FOLDERPATHLIMIT) {
                        $boolLengthOfChildrenOK = $false
                    }
                }

                if ($boolLengthOfChildrenOK -eq $false) {
                    if ($boolAllowRecursiveRun -eq $false) {
                        Write-Error 'The path length of one or more child objects is too long. Please shorten the path length of the child objects and try again.'
                    } else {
                        $arrAvailableDriveLetters = @(Get-AvailableDriveLetter)
                        if ($arrAvailableDriveLetters.Count -gt 0) {
                            $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                            $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strThisObjectPath.Replace('$', '`$') + '"'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand

                            #############Get path to drive root
                            $strTempPathToAdd = '###FAKE###'

                            $doubleSecondsCounter = 0
                            $boolErrorOccurredUsingDriveLetter = $true

                            # Try Join-Path and sleep for up to 10 seconds until it's successful
                            while ($doubleSecondsCounter -le 10 -and $boolErrorOccurredUsingDriveLetter -eq $true) {
                                if (Test-Path ($strDriveLetterToUse + ':')) {
                                    $strTempPath = $null
                                    $boolSuccess = Join-PathSafely ([ref]$strTempPath) ($strDriveLetterToUse + ':') $strTempPathToAdd

                                    if ($boolSuccess -eq $false) {
                                        Start-Sleep 0.2
                                        $doubleSecondsCounter += 0.2
                                    } else {
                                        $boolErrorOccurredUsingDriveLetter = $false
                                    }
                                } else {
                                    Start-Sleep 0.2
                                    $doubleSecondsCounter += 0.2
                                }
                            }

                            if ($boolErrorOccurredUsingDriveLetter -eq $true) {
                                Write-Error ('Unable to process the path "' + $strThisObjectPath.Replace('$', '`$') + '" because running the following command to mitigate path length failed: ' + $strCommand)
                            } else {
                                $strPathSeparator = $strTempPath.Substring($strTempPath.Length - $strTempPathToAdd.Length - ($strTempPath.Length - $strTempPathToAdd.Length - ($strDriveLetterToUse + ':').Length), $strTempPath.Length - $strTempPathToAdd.Length - ($strDriveLetterToUse + ':').Length)
                                $strPathToRootOfDrive = $strDriveLetterToUse + ':' + $strPathSeparator
                            }
                            #############Done getting path to drive root

                            if ($boolErrorOccurredUsingDriveLetter -eq $false) {
                                Repair-NTFSPermissionsRecursively $strPathToRootOfDrive $true
                            }

                            $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand
                        } else {
                            Write-Error ('One of the subfolders or files within the following folder was too long, and a mount point could not be created to compensate because there are no drive letters available: ' + $strThisObjectPath)
                        }
                    }
                } else {
                    $arrChildObjects | ForEach-Object {
                        $objDirectoryOrFileInfoChild = $_
                        if ($boolAllowRecursiveRun -eq $true) {
                            Repair-NTFSPermissionsRecursively ($objDirectoryOrFileInfoChild.FullName) $true
                        }
                    }
                }
            }
        }
    }
}

Repair-NTFSPermissionsRecursively $strPathToFix $true
