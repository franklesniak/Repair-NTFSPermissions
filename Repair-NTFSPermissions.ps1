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

# TODO: Function header, [CmdletBinding()], and param() block format are not supported
# by PowerShell 1.0. Need to investigate an alternative format that will work with
# PowerShell 1.0.

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

$strThisScriptVersionNumber = [version]'1.0.20230619.0'

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

    $versionThisFunction = [version]('1.0.20230619.0')

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

    $VerbosePreferenceAtStartOfFunction = $VerbosePreference

    if ((Test-Windows) -eq $true) {

        $arrAllPossibleLetters = 65..90 | ForEach-Object { [char]$_ }

        $versionPS = Get-PSVersion

        If ($versionPS.Major -ge 3) {
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            $arrUsedLogicalDriveLetters = Get-CimInstance -ClassName 'Win32_LogicalDisk' |
                ForEach-Object { $_.DeviceID } | Where-Object { $_.Length -eq 2 } |
                Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                ForEach-Object { $_[0] } | Where-Object { $arrAllPossibleLetters -contains $_ }
            # fifth-, fourth-, and third-to-last bits of pipeline ensures that we have a device ID like
            # "C:" second-to-last bit of pipeline strips off the ':', leaving just the capital drive
            # letter last bit of pipeline ensure that the drive letter is actually a letter; addresses
            # legacy Netware edge cases
            $VerbosePreference = $VerbosePreferenceAtStartOfFunction

            if ($boolExcludeMappedDriveLetters -eq $true) {
                $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $arrUsedMappedDriveLetters = Get-CimInstance -ClassName 'Win32_NetworkConnection' |
                    ForEach-Object { $_.LocalName } | Where-Object { $_.Length -eq 2 } |
                    Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                    ForEach-Object { $_[0] } |
                    Where-Object { $private.arrAllPossibleLetters -contains $_ }
                # fifth-, fourth-, and third-to-last bits of pipeline ensures that we have a LocalName like "C:"
                # second-to-last bit of pipeline strips off the ':', leaving just the capital drive letter
                # last bit of pipeline ensure that the drive letter is actually a letter; addresses legacy
                # Netware edge cases
                $VerbosePreference = $VerbosePreferenceAtStartOfFunction
            } else {
                $arrUsedMappedDriveLetters = $null
            }
        } else {
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            $arrUsedLogicalDriveLetters = Get-WmiObject -Class 'Win32_LogicalDisk' |
                ForEach-Object { $_.DeviceID } | Where-Object { $_.Length -eq 2 } |
                Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                ForEach-Object { $_[0] } | Where-Object { $arrAllPossibleLetters -contains $_ }
            # fifth-, fourth-, and third-to-last bits of pipeline ensures that we have a device ID like
            # "C:" second-to-last bit of pipeline strips off the ':', leaving just the capital drive
            # letter last bit of pipeline ensure that the drive letter is actually a letter; addresses
            # legacy Netware edge cases
            $VerbosePreference = $VerbosePreferenceAtStartOfFunction

            if ($boolExcludeMappedDriveLetters -eq $true) {
                $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $arrUsedMappedDriveLetters = Get-WmiObject -Class 'Win32_NetworkConnection' |
                    ForEach-Object { $_.LocalName } | Where-Object { $_.Length -eq 2 } |
                    Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                    ForEach-Object { $_[0] } |
                    Where-Object { $private.arrAllPossibleLetters -contains $_ }
                # fifth-, fourth-, and third-to-last bits of pipeline ensures that we have a LocalName like "C:"
                # second-to-last bit of pipeline strips off the ':', leaving just the capital drive letter
                # last bit of pipeline ensure that the drive letter is actually a letter; addresses legacy
                # Netware edge cases
                $VerbosePreference = $VerbosePreferenceAtStartOfFunction
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

function Wait-PathToBeReady {
    <#
    .SYNOPSIS
    Waits for the specified path to be available. Also tests that a join-path operation
    can be performed on the specified path and a child item

    .DESCRIPTION
    This function evaluates the list of drive letters that are in use on the local
    system and returns an array of those that are available. The list of available
    drive letters is returned as an array of uppercase letters

    .PARAMETER ReferenceToJoinedPath
    This parameter is a memory reference to a string variable that will be populated
    with the joined path (parent path + child path). If no child path was specified,
    then the parent path will be populated in the referenced variable.

    .PARAMETER ReferenceToUseGetPSDriveWorkaround
    This parameter is a memory reference to a boolean variable that indicates whether
    or not the Get-PSDrive workaround should be used. If the Get-PSDrive workaround is
    used, then the function will use the Get-PSDrive cmdlet to refresh PowerShell's
    "understanding" of the available drive letters. This variable is passed by
    reference to ensure that this function can set the variable to $true if the
    Get-PSDrive workaround is successful - which improves performance of subsequent
    runs.

    .PARAMETER Path
    This parameter is the path to be tested for availability, and the parent path to
    be used in the join-path operation. If no child path is specified, then the
    this path will populated into the variable referenced in the parameter
    ReferenceToJoinedPath

    .PARAMETER ChildItemPath
    This parameter is the child path to be used in the join-path operation. If no
    child path is specified, then the path specified by the Path parameter will be
    populated into the variable referenced in the parameter ReferenceToJoinedPath.
    However, if a ChildItemPath is specified, then the path specified by the Path
    parameter will be used as the parent path in the join-path operation, and the
    ChildItemPath will be used as the child path in the join-path operation. The
    joined path will be populated into the variable referenced in the parameter
    ReferenceToJoinedPath.

    .PARAMETER MaximumWaitTimeInSeconds
    This parameter is the maximum amount of seconds to wait for the path to be ready.
    If the path is not ready within this time, then the function will return $false.
    By default, this parameter is set to 10 seconds.

    .PARAMETER DoNotAttemptGetPSDriveWorkaround
    This parameter is a switch that indicates whether or not the Get-PSDrive
    workaround should be attempted. If this switch is specified, then the Get-PSDrive
    workaround will not be attempted. This switch is useful if you know that the
    Get-PSDrive workaround will not work on your system, or if you know that the
    Get-PSDrive workaround is not necessary on your system.

    .EXAMPLE
    $strJoinedPath = ''
    $boolUseGetPSDriveWorkaround = $false
    $boolPathAvailable = Wait-PathToBeReady -Path 'D:\Shares\Share\Data' -ChildItemPath 'Subfolder' -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

    .OUTPUTS
    A boolean value indiciating whether the path is available
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]

    param (
        [Parameter(Mandatory = $false)][System.Management.Automation.PSReference]$ReferenceToJoinedPath = ([ref]$null),
        [Parameter(Mandatory = $false)][System.Management.Automation.PSReference]$ReferenceToUseGetPSDriveWorkaround = ([ref]$null),
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][string]$ChildItemPath = '',
        [Parameter(Mandatory = $false)][int]$MaximumWaitTimeInSeconds = 10,
        [Parameter(Mandatory = $false)][switch]$DoNotAttemptGetPSDriveWorkaround
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

    $versionThisFunction = [version]('1.0.20230619.0')

    #region Process Input ##########################################################
    if ($DoNotAttemptGetPSDriveWorkaround.IsPresent -eq $true) {
        $boolAttemptGetPSDriveWorkaround = $false
    } else {
        $boolAttemptGetPSDriveWorkaround = $true
    }
    #endregion Process Input ##########################################################

    $NONEXISTENT_CHILD_FOLDER = '###FAKE###'
    $boolFunctionReturn = $false

    if ([string]::IsNullOrEmpty($ChildItemPath) -eq $true) {
        $strWorkingChildItemPath = $NONEXISTENT_CHILD_FOLDER
    } else {
        $strWorkingChildItemPath = $ChildItemPath
    }

    if ($null -ne ($ReferenceToUseGetPSDriveWorkaround.Value)) {
        if (($ReferenceToUseGetPSDriveWorkaround.Value) -eq $true) {
            # Use workaround for drives not refreshing in current PowerShell session
            Get-PSDrive | Out-Null
        }
    }

    $doubleSecondsCounter = 0

    # Try Join-Path and sleep for up to $MaximumWaitTimeInSeconds seconds until it's successful
    while ($doubleSecondsCounter -le $MaximumWaitTimeInSeconds -and $boolFunctionReturn -eq $false) {
        if (Test-Path $Path) {
            $strJoinedPath = $null
            $boolSuccess = Join-PathSafely ([ref]$strJoinedPath) $Path $strWorkingChildItemPath

            if ($boolSuccess -eq $false) {
                Start-Sleep 0.2
                $doubleSecondsCounter += 0.2
            } else {
                $boolFunctionReturn = $true
            }
        } else {
            Start-Sleep 0.2
            $doubleSecondsCounter += 0.2
        }
    }

    if ($boolFunctionReturn -eq $false) {
        if ($null -eq ($ReferenceToUseGetPSDriveWorkaround.Value) -or ($ReferenceToUseGetPSDriveWorkaround.Value) -eq $false) {
            # Either a variable was not passed in, or the variable was passed in and it was set to false
            if ($boolAttemptGetPSDriveWorkaround -eq $true) {
                # Try workaround for drives not refreshing in current PowerShell session
                Get-PSDrive | Out-Null

                # Restart counter and try waiting again
                $doubleSecondsCounter = 0

                # Try Join-Path and sleep for up to $MaximumWaitTimeInSeconds seconds until it's successful
                while ($doubleSecondsCounter -le $MaximumWaitTimeInSeconds -and $boolFunctionReturn -eq $false) {
                    if (Test-Path $Path) {
                        $strJoinedPath = $null
                        $boolSuccess = Join-PathSafely ([ref]$strJoinedPath) $Path $strWorkingChildItemPath

                        if ($boolSuccess -eq $false) {
                            Start-Sleep 0.2
                            $doubleSecondsCounter += 0.2
                        } else {
                            $boolFunctionReturn = $true
                            if ($null -ne ($ReferenceToUseGetPSDriveWorkaround.Value)) {
                                $ReferenceToUseGetPSDriveWorkaround.Value = $true
                            }
                        }
                    } else {
                        Start-Sleep 0.2
                        $doubleSecondsCounter += 0.2
                    }
                }
            }
        }
    }

    if ([string]::IsNullOrEmpty($strChildFolderOfTarget) -eq $true) {
        $strJoinedPath = $Path
    }

    if ($null -ne $ReferenceToJoinedPath.Value) {
        $ReferenceToJoinedPath.Value = $strJoinedPath
    }

    return $boolFunctionReturn
}

function Repair-NTFSPermissionsRecursively {
    # Syntax: $intReturnCode = Repair-NTFSPermissionsRecursively 'D:\Shares\Corporate' $true 0 $false ''

    $strThisObjectPath = $args[0]
    $boolAllowRecursion = $args[1]
    $intIterativeRepairState = $args[2]
    $boolUseGetPSDriveWorkaround = $args[3]
    $strLastSubstitutedPath = $args[4]

    $strVerboseMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters:' + "`n" + 'Path: ' + $strThisObjectPath + "`n" + 'Allow recursion: ' + $boolAllowRecursion + "`n" + 'Iterative repair state: ' + $intIterativeRepairState + "`n" + 'Use Get-Path workaround: ' + $boolUseGetPSDriveWorkaround + "`n" + 'Last substituted path: ' + $strLastSubstitutedPath
    Write-Verbose $strVerboseMessage

    # $intIterativeRepairState:
    # 0 = Allow recursion (default)
    # 1 = Do not allow recursion, but allow ownership to be taken via Set-Acl
    # 2 = Do not allow recursion, and do not allow ownership to be taken via Set-Acl

    $FILEPATHLIMIT = 260
    $FOLDERPATHLIMIT = 248

    $intFunctionReturn = 0

    $objThis = $null
    $objThisFolderPermission = $null
    $versionPS = Get-PSVersion

    # We don't know if $strThisObjectPath is pointing to a folder or a file, so use the folder
    # (shorter) length limit
    if ($strThisObjectPath.Length -ge $FOLDERPATHLIMIT) {
        Write-Verbose ($strThisObjectPath + ' is too long.')
        if ($intIterativeRepairState -ge 1) {
            Write-Error ('Despite attempts to mitigate, the path length of ' + $strThisObjectPath + ' exceeds the maximum length of ' + $FOLDERPATHLIMIT + ' characters.')
            $intFunctionReturn = -1
            return $intFunctionReturn
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
                $strRemainderOfPath = $strThisObjectPath.Substring($strParentFolder.Length + 1, $strThisObjectPath.Length - $strParentFolder.Length - 1)

                $strFolderTarget = $strParentFolder
                $strChildFolderOfTarget = $strRemainderOfPath

                #region Mitigate Path Length with Drive Substitution ###############
                # Inputs:
                # $strFolderTarget
                # $strChildFolderOfTarget

                $boolSubstWorked = $false
                $arrAvailableDriveLetters = @(Get-AvailableDriveLetter)
                if ($arrAvailableDriveLetters.Count -gt 0) {
                    $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                    $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strFolderTarget.Replace('$', '`$') + '"'
                    Write-Verbose ('About to run command: ' + $strCommand)
                    $null = Invoke-Expression $strCommand

                    # Confirm the path is ready
                    $strJoinedPath = ''
                    $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                    if ($boolPathAvailable -eq $false) {
                        Write-Verbose ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...')
                        $intReturnCode = -1
                    } else {
                        $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround ($strDriveLetterToUse + ':')
                    }

                    $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                    Write-Verbose ('About to run command: ' + $strCommand)
                    $null = Invoke-Expression $strCommand

                    if ($boolUseGetPSDriveWorkaround -eq $true) {
                        # Use workaround for drives not refreshing in current PowerShell session
                        Get-PSDrive | Out-Null
                    }

                    if ($intReturnCode -eq 0) {
                        $boolSubstWorked = $true
                    }
                }
                #endregion Mitigate Path Length with Drive Substitution ###############

                #region Mitigate Path Length with Symbolic Link ####################
                # Inputs:
                # $strFolderTarget
                # $strChildFolderOfTarget

                # If a substituted drive failed, try a symbolic link instead
                $boolSymbolicLinkWorked = $false
                if ($boolSubstWorked -eq $false) {
                    # Use a GUID to avoid name collisions
                    $strGUID = [System.Guid]::NewGuid().ToString()

                    # Create the symbolic link
                    $versionPS = Get-PSVersion
                    if ($versionPS -ge ([version]'5.0')) {
                        # PowerShell 5.0 and newer can make symbolic links in PowerShell
                        Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via PowerShell:' + "`n" + 'Symbolic link path: ' + 'C:\' + $strGUID + "`n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$'))
                        # TODO: Test this with a path containing a dollar sign ($)
                        New-Item -ItemType SymbolicLink -Path ('C:\' + $strGUID) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                    } else {
                        # Need to use mklink command in command prompt instead
                        # TODO: Test this with a path containing a dollar sign ($)
                        $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "C:\' + $strGUID + '" "' + $strFolderTarget.Replace('$', '`$') + '"'
                        Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via command: ' + $strCommand)
                        $null = Invoke-Expression $strCommand
                    }

                    # Confirm the path is ready
                    $strJoinedPath = ''
                    $boolPathAvailable = Wait-PathToBeReady -Path ('C:\' + $strGUID) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                    if ($boolErrorOccurredUsingNewPath -eq $true) {
                        Write-Error ('Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.')
                        $intReturnCode = -2
                    } else {
                        $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround ('C:\' + $strGUID)
                    }

                    if ($intReturnCode -lt 0) {
                        # -2 if drive substitution and symbolic link failed
                        $intFunctionReturn = $intReturnCode
                        return $intFunctionReturn
                    } elseif ($intReturnCode -eq 0) {
                        $boolSymbolicLinkWorked = $true
                    }

                    # Remove Symbolic Link
                    Write-Verbose ('Removing symbolic link: ' + ('C:\' + $strGUID))
                    # TODO: Build error handling for this deletion:
                    (Get-Item ('C:\' + $strGUID)).Delete()

                    if ($boolUseGetPSDriveWorkaround -eq $true) {
                        # Use workaround for drives not refreshing in current PowerShell session
                        Get-PSDrive | Out-Null
                    }
                }
                #endregion Mitigate Path Length with Symbolic Link ####################

                if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                    Write-Error ('Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $strThisObjectPath)
                    $intFunctionReturn = -3
                    return $intFunctionReturn
                }
            } elseif ($boolPossibleAttemptsExceeded -eq $true) {
                Write-Error ('Cannot process the following path because it contains no parent folder element that is of an acceptable length with which to perform drive substitution or creation of a symbolic link: ' + $strThisObjectPath)
                $intFunctionReturn = -4
                return $intFunctionReturn
            }
        }
    } else {
        # Path is not too long
        $boolCriticalErrorOccurred = $false

        $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

        if ($boolSuccess -eq $false) {
            # Error occurred reading the ACL

            # Take ownership
            $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strThisObjectPath.Replace('$', '`$') + '" /A'
            Write-Verbose ('About to run command: ' + $strCommand)
            $null = Invoke-Expression $strCommand

            # Should now be able to read permissions

            $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

            if ($boolSuccess -eq $false) {
                Write-Verbose ('Despite attempting to take ownership of the folder/file "' + $strThisObjectPath + '" on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'This may occur if subst.exe was used to mitigate path length issues; if so, the function should retry...')
                $intFunctionReturn = -5
                return $intFunctionReturn
            }
        } else {
            # Able to read the permissions of the parent folder, continue

            if ($versionPS -eq ([version]'1.0')) {
                # The object returned from Get-Acl is not copy-able on PowerShell 1.0
                # Not sure why...
                # So, we need to get the ACL directly and hope that we don't have an error this time
                $objThisFolderPermission = Get-Acl
            }

            if ($null -eq $objThisFolderPermission) {
                # An error did not occur retrieving permissions; however no permissions were retrieved
                # Either Get-Acl did not work as expected, or there are in fact no access control entries on the object

                # Take ownership
                $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strThisObjectPath.Replace('$', '`$') + '" /A'
                Write-Verbose ('About to run command: ' + $strCommand)
                $null = Invoke-Expression $strCommand

                # Should now be able to read permissions

                $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

                if ($boolSuccess -eq $false) {
                    # We had success reading permissions before, but now that we took
                    # ownership, we suddenly cannot read them. This is a critical error.
                    Write-Error ('After taking ownership of the folder/file "' + $strThisObjectPath + '" on behalf of administrators, the script is unable to read permissions from the folder/file using Get-Acl. The command used to take ownership was:' + "`n`n" + $strCommand)
                    $intFunctionReturn = -6
                    $boolCriticalErrorOccurred = $true
                    return $intFunctionReturn
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
                        } else {
                            # See if the FileSystemRights is an integer value that
                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                            $intFileSystemRights = [int]($objThisACE.FileSystemRights)
                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                $boolBuiltInAdministratorsHaveSufficientAccess = $true
                            }
                        }
                    }
                } elseif ($objThisACE.IdentityReference.Value -eq $strNameOfSYSTEMAccountGroupAccordingToGetAcl) {
                    if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                        $boolSYSTEMAccountDenyEntryFound = $true
                    } else {
                        # assume 'Allow'
                        if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                            $boolSYSTEMAccountHasSufficientAccess = $true
                        } else {
                            # See if the FileSystemRights is an integer value that
                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                            $intFileSystemRights = [int]($objThisACE.FileSystemRights)
                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                $boolSYSTEMAccountHasSufficientAccess = $true
                            }
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
                                    } else {
                                        # See if the FileSystemRights is an integer value that
                                        # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                        $intFileSystemRights = [int]($objThisACE.FileSystemRights)
                                        if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                            $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $true
                                        }
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
                                    } else {
                                        # See if the FileSystemRights is an integer value that
                                        # includes ReadAndExecute (131241) or GENERIC_EXECUTE (536870912)
                                        # TODO: determine if GENERIC_EXECUTE is the correct value
                                        $intFileSystemRights = [int]($objThisACE.FileSystemRights)
                                        if (($intFileSystemRights -band 131241) -eq 131241 -or ($intFileSystemRights -band 536870912) -eq 536870912) {
                                            $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $true
                                        }
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
                if ($intIterativeRepairState -le 1) {
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
                if ($intIterativeRepairState -le 1) {
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
                if ($intIterativeRepairState -le 1) {
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
                if ($intIterativeRepairState -le 1) {
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
                    $intFunctionReturn = -7
                    $boolCriticalErrorOccurred = $true
                    return $intFunctionReturn
                } else {
                    if ($versionPS -eq ([version]'1.0')) {
                        # The object returned from Get-Acl is not copy-able on
                        # PowerShell 1.0
                        # Not sure why...
                        # So, we need to get the ACL directly and hope that we don't
                        # have an error this time
                        $objThisFolderPermission = Get-Acl
                    }

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
                                } else {
                                    # See if the FileSystemRights is an integer value that
                                    # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                    $intFileSystemRights = [int]($objThisACE.FileSystemRights)
                                    if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                        $boolBuiltInAdministratorsHaveSufficientAccess = $true
                                    }
                                }
                            }
                        } elseif ($objThisACE.IdentityReference.Value -eq $strNameOfSYSTEMAccountGroupAccordingToGetAcl) {
                            if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                $boolSYSTEMAccountDenyEntryFound = $true
                            } else {
                                # assume 'Allow'
                                if ($objThisACE.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                    $boolSYSTEMAccountHasSufficientAccess = $true
                                } else {
                                    # See if the FileSystemRights is an integer value that
                                    # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                    $intFileSystemRights = [int]($objThisACE.FileSystemRights)
                                    if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                        $boolSYSTEMAccountHasSufficientAccess = $true
                                    }
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
                                            } else {
                                                # See if the FileSystemRights is an integer value that
                                                # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                                $intFileSystemRights = [int]($objThisACE.FileSystemRights)
                                                if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                    $boolAdditionalAdministratorAccountOrGroupHasSufficientAccess = $true
                                                }
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
                                            } else {
                                                # See if the FileSystemRights is an integer value that
                                                # includes ReadAndExecute (131241) or GENERIC_EXECUTE (536870912)
                                                # TODO: determine if GENERIC_EXECUTE is the correct value
                                                $intFileSystemRights = [int]($objThisACE.FileSystemRights)
                                                if (($intFileSystemRights -band 131241) -eq 131241 -or ($intFileSystemRights -band 536870912) -eq 536870912) {
                                                    $boolAdditionalReadOnlyAccountOrGroupHasSufficientAccess = $true
                                                }
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
                        if ($intIterativeRepairState -eq 0) {
                            # Try taking ownership of the folder/file

                            # Take ownership
                            $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strThisObjectPath.Replace('$', '`$') + '" /A'
                            $strCommand += ' 2>&1'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand
                            # Restart process without recursion flag, phase 1
                            $intReturnCode = Repair-NTFSPermissionsRecursively $strThisObjectPath $false 1 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath

                            if ($intReturnCode -ne 0) {
                                $intFunctionReturn = $intReturnCode
                                return $intFunctionReturn
                            }

                            # If we are still here, the repair was successful after
                            # taking ownership. Carry on with child objects
                        } elseif ($intIterativeRepairState -eq 1) {
                            # Try taking ownership of the folder/file with Set-Acl

                            # Take ownership
                            $objThisFolderPermission.SetOwner([System.Security.Principal.NTAccount]$NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls)
                            # TODO: Create Set-ACLSafely function to suppress errors
                            Set-Acl -Path $strThisObjectPath -AclObject $objThisFolderPermission
                            # Restart process without recursion flag, phase 2
                            $intReturnCode = Repair-NTFSPermissionsRecursively $strThisObjectPath $false 2 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath

                            if ($intReturnCode -ne 0) {
                                $intFunctionReturn = $intReturnCode
                                return $intFunctionReturn
                            }

                            # If we are still here, the repair was successful after
                            # taking ownership. Carry on with child objects
                        } else {
                            Write-Warning ('The permissions on the folder "' + $strThisObjectPath + '" could not be repaired. Please repair them manually.')
                        }
                    }
                }
            }
        }

        if ($objThis.PSIsContainer) {
            # This object is a folder, not a file

            if ($boolAllowRecursion -eq $true) {
                # Recursion is allowed

                # Get the child objects
                $arrChildObjects = $null
                $boolSuccess = Get-ChildItemSafely ([ref]$arrChildObjects) ([ref]$objThis)

                if ($boolSuccess -eq $false) {
                    # Error occurred probably because the path length is too long

                    if ($strThisObjectPath -eq $strLastSubstitutedPath) {
                        Write-Error ('Unable to enumerate child objects in path "' + $strThisObjectPath + '". This can occur if path length is too long. However, its path length has already been shortened, so there is nothing further for this script to try. Please repair the permissions on this folder manually.')
                        $intFunctionReturn = -8
                        return $intFunctionReturn
                    } else {
                        # Try again with a shorter path
                        $strFolderTarget = $strThisObjectPath
                        $strChildFolderOfTarget = ''

                        #region Mitigate Path Length with Drive Substitution ###############
                        # Inputs:
                        # $strFolderTarget
                        # $strChildFolderOfTarget

                        $boolSubstWorked = $false
                        $arrAvailableDriveLetters = @(Get-AvailableDriveLetter)
                        if ($arrAvailableDriveLetters.Count -gt 0) {
                            $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                            $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strFolderTarget.Replace('$', '`$') + '"'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand

                            # Confirm the path is ready
                            $strJoinedPath = ''
                            $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                            if ($boolPathAvailable -eq $false) {
                                Write-Verbose ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...')
                                $intReturnCode = -1
                            } else {
                                $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround ($strDriveLetterToUse + ':')
                            }

                            $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand

                            if ($boolUseGetPSDriveWorkaround -eq $true) {
                                # Use workaround for drives not refreshing in current PowerShell session
                                Get-PSDrive | Out-Null
                            }

                            if ($intReturnCode -eq 0) {
                                $boolSubstWorked = $true
                            }
                        }
                        #endregion Mitigate Path Length with Drive Substitution ###############

                        #region Mitigate Path Length with Symbolic Link ####################
                        # Inputs:
                        # $strFolderTarget
                        # $strChildFolderOfTarget

                        # If a substituted drive failed, try a symbolic link instead
                        $boolSymbolicLinkWorked = $false
                        if ($boolSubstWorked -eq $false) {
                            # Use a GUID to avoid name collisions
                            $strGUID = [System.Guid]::NewGuid().ToString()

                            # Create the symbolic link
                            $versionPS = Get-PSVersion
                            if ($versionPS -ge ([version]'5.0')) {
                                # PowerShell 5.0 and newer can make symbolic links in PowerShell
                                Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via PowerShell:' + "`n" + 'Symbolic link path: ' + 'C:\' + $strGUID + "`n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$'))
                                # TODO: Test this with a path containing a dollar sign ($)
                                New-Item -ItemType SymbolicLink -Path ('C:\' + $strGUID) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                            } else {
                                # Need to use mklink command in command prompt instead
                                # TODO: Test this with a path containing a dollar sign ($)
                                $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "C:\' + $strGUID + '" "' + $strFolderTarget.Replace('$', '`$') + '"'
                                Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via command: ' + $strCommand)
                                $null = Invoke-Expression $strCommand
                            }

                            # Confirm the path is ready
                            $strJoinedPath = ''
                            $boolPathAvailable = Wait-PathToBeReady -Path ('C:\' + $strGUID) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                            if ($boolErrorOccurredUsingNewPath -eq $true) {
                                Write-Error ('Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.')
                                $intReturnCode = -2
                            } else {
                                $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround ('C:\' + $strGUID)
                            }

                            if ($intReturnCode -lt 0) {
                                # -2 if drive substitution and symbolic link failed
                                $intFunctionReturn = $intReturnCode
                                return $intFunctionReturn
                            } elseif ($intReturnCode -eq 0) {
                                $boolSymbolicLinkWorked = $true
                            }

                            # Remove Symbolic Link
                            Write-Verbose ('Removing symbolic link: ' + ('C:\' + $strGUID))
                            # TODO: Build error handling for this deletion:
                            (Get-Item ('C:\' + $strGUID)).Delete()

                            if ($boolUseGetPSDriveWorkaround -eq $true) {
                                # Use workaround for drives not refreshing in current PowerShell session
                                Get-PSDrive | Out-Null
                            }
                        }
                        #endregion Mitigate Path Length with Symbolic Link ####################

                        if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                            Write-Error ('Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $strThisObjectPath)
                            $intFunctionReturn = -9
                            return $intFunctionReturn
                        }
                    }
                } else {
                    # No error occurred getting child items
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
                        # One or more child objects are too long

                        if ($strThisObjectPath -eq $strLastSubstitutedPath) {
                            Write-Error ('The path length on one or more child objects in folder "' + $strThisObjectPath + '" exceeds the maximum number of characters. A drive substitution or synbolic link should be used to mitigate this, however this mitigation has already been performed, so there is nothing further for this script to try. Please repair the permissions on this folder manually.')
                            $intFunctionReturn = -10
                            return $intFunctionReturn
                        } else {
                            # Try again with a shorter path
                            $strFolderTarget = $strThisObjectPath
                            $strChildFolderOfTarget = ''

                            #region Mitigate Path Length with Drive Substitution ###############
                            # Inputs:
                            # $strFolderTarget
                            # $strChildFolderOfTarget

                            $boolSubstWorked = $false
                            $arrAvailableDriveLetters = @(Get-AvailableDriveLetter)
                            if ($arrAvailableDriveLetters.Count -gt 0) {
                                $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                                $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strFolderTarget.Replace('$', '`$') + '"'
                                Write-Verbose ('About to run command: ' + $strCommand)
                                $null = Invoke-Expression $strCommand

                                # Confirm the path is ready
                                $strJoinedPath = ''
                                $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                if ($boolPathAvailable -eq $false) {
                                    Write-Verbose ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...')
                                    $intReturnCode = -1
                                } else {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround ($strDriveLetterToUse + ':')
                                }

                                $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                                Write-Verbose ('About to run command: ' + $strCommand)
                                $null = Invoke-Expression $strCommand

                                if ($boolUseGetPSDriveWorkaround -eq $true) {
                                    # Use workaround for drives not refreshing in current PowerShell session
                                    Get-PSDrive | Out-Null
                                }

                                if ($intReturnCode -eq 0) {
                                    $boolSubstWorked = $true
                                }
                            }
                            #endregion Mitigate Path Length with Drive Substitution ###############

                            #region Mitigate Path Length with Symbolic Link ####################
                            # Inputs:
                            # $strFolderTarget
                            # $strChildFolderOfTarget

                            # If a substituted drive failed, try a symbolic link instead
                            $boolSymbolicLinkWorked = $false
                            if ($boolSubstWorked -eq $false) {
                                # Use a GUID to avoid name collisions
                                $strGUID = [System.Guid]::NewGuid().ToString()

                                # Create the symbolic link
                                $versionPS = Get-PSVersion
                                if ($versionPS -ge ([version]'5.0')) {
                                    # PowerShell 5.0 and newer can make symbolic links in PowerShell
                                    Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via PowerShell:' + "`n" + 'Symbolic link path: ' + 'C:\' + $strGUID + "`n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$'))
                                    # TODO: Test this with a path containing a dollar sign ($)
                                    New-Item -ItemType SymbolicLink -Path ('C:\' + $strGUID) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                                } else {
                                    # Need to use mklink command in command prompt instead
                                    # TODO: Test this with a path containing a dollar sign ($)
                                    $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "C:\' + $strGUID + '" "' + $strFolderTarget.Replace('$', '`$') + '"'
                                    Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via command: ' + $strCommand)
                                    $null = Invoke-Expression $strCommand
                                }

                                # Confirm the path is ready
                                $strJoinedPath = ''
                                $boolPathAvailable = Wait-PathToBeReady -Path ('C:\' + $strGUID) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                if ($boolErrorOccurredUsingNewPath -eq $true) {
                                    Write-Error ('Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.')
                                    $intReturnCode = -2
                                } else {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround ('C:\' + $strGUID)
                                }

                                if ($intReturnCode -lt 0) {
                                    # -2 if drive substitution and symbolic link failed
                                    $intFunctionReturn = $intReturnCode
                                    return $intFunctionReturn
                                } elseif ($intReturnCode -eq 0) {
                                    $boolSymbolicLinkWorked = $true
                                }

                                # Remove Symbolic Link
                                Write-Verbose ('Removing symbolic link: ' + ('C:\' + $strGUID))
                                # TODO: Build error handling for this deletion:
                                (Get-Item ('C:\' + $strGUID)).Delete()

                                if ($boolUseGetPSDriveWorkaround -eq $true) {
                                    # Use workaround for drives not refreshing in current PowerShell session
                                    Get-PSDrive | Out-Null
                                }
                            }
                            #endregion Mitigate Path Length with Symbolic Link ####################

                            if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                                Write-Error ('Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $strThisObjectPath)
                                $intFunctionReturn = -11
                                return $intFunctionReturn
                            }
                        }
                    } else {
                        # The length of all child objects was OK
                        $arrChildObjects | ForEach-Object {
                            $objDirectoryOrFileInfoChild = $_
                            $intReturnCode = Repair-NTFSPermissionsRecursively ($objDirectoryOrFileInfoChild.FullName) $true 0 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath

                            if ($intReturnCode -ne 0) {
                                Write-Warning ('There was an issue processing the path "' + $objDirectoryOrFileInfoChild.FullName + '" The error code returned was: ' + $intReturnCode)
                                $intFunctionReturn = $intReturnCode
                            }
                        }
                    }
                }
            }
        }
    }
    return $intFunctionReturn
}

$intReturnCode = Repair-NTFSPermissionsRecursively $strPathToFix $true 0 $false ''
if ($intReturnCode -eq 0) {
    Write-Host ('Successfully processed path: ' + $strPathToFix)
} else {
    Write-Error ('There were one or more issues processing the path "' + $strPathToFix + '" One error code returned was: ' + $intReturnCode)
}
