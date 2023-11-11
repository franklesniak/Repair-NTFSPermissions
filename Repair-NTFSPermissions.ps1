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

.PARAMETER RemoveUnresolvedSIDs
Optionally, specifies that unresolved SIDs should be removed from the ACL. This
parameter is optional; if not specified,  the script will not attempt to remove
unresolved SIDs.

.PARAMETER PathToCSVContainingKnownSIDs
Optionally, specifies the path to a CSV file containing a list of known SIDs. This
parameter is optional in general. However, if the RemoveUnresolvedSIDs switch parameter
is specified, then this parameter must also be specified. If specified, this parameter
must be a string containing a valid path to a CSV file. The CSV file must contain a
column named 'SID' that contains the SIDs to be considered "known,", i.e., SIDs that
should not be removed from the ACL. The CSV file may contain additional columns, but
they will be ignored.

If unresolved SIDs are to be removed, this CSV is required because it provides
protection from the scenario where, for example, connectivity between a member server
and Active Directory Domain Services is lost and the member server is unable to resolve
SIDs to names. In this scenario, if this protection were not in place, then the script
would remove all unresolved SIDs from the ACL, including SIDs that are not resolved
because of the lost connectivity. This could result in the loss of access to the file
or folder.

Therefore, in the specified CSV, it is highly recommended to provide a list of *all
SIDs* in the environment. This should include SIDs for all user accounts, groups, and
computer accounts.

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
    [Parameter(Mandatory = $false)][string]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = $null,
    [Parameter(Mandatory = $false)][switch]$RemoveUnresolvedSIDs,
    [Parameter(Mandatory = $false)][string]$PathToCSVContainingKnownSIDs = $null
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

$strThisScriptVersionNumber = [version]'1.1.20231110.0'

#region Convert Param Block Inputs to More-Traditional Variables ###################
# This makes it easier to run this script on PowerShell v1.0, which does not support
# the [CmdletBinding()] attribute and the param() block format.
$strPathToFix = $PathToFix
$strNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls = $NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls
$strNameOfBuiltInAdministratorsGroupAccordingToGetAcl = $NameOfBuiltInAdministratorsGroupAccordingToGetAcl
$strNameOfSYSTEMAccountAccordingToTakeOwnAndICacls = $NameOfSYSTEMAccountAccordingToTakeOwnAndICacls
$strNameOfSYSTEMAccountGroupAccordingToGetAcl = $NameOfSYSTEMAccountGroupAccordingToGetAcl
$strNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls = $NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls
$strNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl = $NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl
$strNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls = $NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls
$strNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = $NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl
if ($null -eq $RemoveUnresolvedSIDs) {
    $boolRemoveUnresolvedSIDs = $false
} else {
    if ($RemoveUnresolvedSIDs.IsPresent -eq $false) {
        $boolRemoveUnresolvedSIDs = $false
    } else {
        $boolRemoveUnresolvedSIDs = $true
    }
}
$strPathToCSVContainingKnownSIDs = $PathToCSVContainingKnownSIDs
#endregion Convert Param Block Inputs to More-Traditional Variables ###################

# TODO: additional code/logic is necessary for adding a read-only account, see TODO markers below

#region FunctionsToSupportErrorHandling
function Get-ReferenceToLastError {
    #region FunctionHeader #########################################################
    # Function returns $null if no errors on on the $error stack;
    # Otherwise, function returns a reference (memory pointer) to the last error that occurred.
    #
    # Version: 1.0.20230709.0
    #endregion FunctionHeader #########################################################

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

    #region DownloadLocationNotice #################################################
    # The most up-to-date version of this script can be found on the author's GitHub
    # repository at https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #################################################

    if ($error.Count -gt 0) {
        [ref]($error[0])
    } else {
        $null
    }
}

function Test-ErrorOccurred {
    #region FunctionHeader #########################################################
    # Function accepts two positional arguments:
    #
    # The first argument is a reference (memory pointer) to the last error that had
    # occurred prior to calling the command in question - that is, the command that we
    # want to test to see if an error occurred.
    #
    # The second argument is a reference to the last error that had occurred as-of the
    # completion of the command in question
    #
    # Function returns $true if it appears that an error occurred; $false otherwise
    #
    # Version: 1.0.20230709.0
    #endregion FunctionHeader #########################################################

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

    #region DownloadLocationNotice #################################################
    # The most up-to-date version of this script can be found on the author's GitHub
    # repository at https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #################################################

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
    # Returns the version of PowerShell that is running, including on the original
    # release of Windows PowerShell (version 1.0)
    #
    # Example:
    # Get-PSVersion
    #
    # This example returns the version of PowerShell that is running. On versions of
    # PowerShell greater than or equal to version 2.0, this function returns the
    # equivalent of $PSVersionTable.PSVersion
    #
    # The function outputs a [version] object representing the version of PowerShell
    # that is running
    #
    # PowerShell 1.0 does not have a $PSVersionTable variable, so this function returns
    # [version]('1.0') on PowerShell 1.0

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

    #region DownloadLocationNotice #################################################
    # The most up-to-date version of this script can be found on the author's GitHub
    # repository at https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #################################################

    $versionThisFunction = [version]('1.0.20230709.0')

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
    if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) { $versionPS = Get-PSVersion; if ($versionPS.Major -ge 3) { $objThis = Get-Item -LiteralPath $strThisObjectPath -Force; if ($versionPS -ge ([version]'7.3')) { if (@(Get-Module Microsoft.PowerShell.Security).Count -eq 0) { Import-Module Microsoft.PowerShell.Security } $objThisFolderPermission = [System.IO.FileSystemAclExtensions]::GetAccessControl($objThis) } else { $objThisFolderPermission = $objThis.GetAccessControl() } } elseif ($versionPS.Major -eq 2) { $objThis = Get-Item -Path ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force; $objThisFolderPermission = $objThis.GetAccessControl() } else { $objThisFolderPermission = Get-Acl -Path ($strThisObjectPath.Replace('`', '``')) } } else { $objThisFolderPermission = Get-Acl -Path $strThisObjectPath }
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
    #         if ($versionPS -ge ([version]'7.3')) {
    #             # PowerShell v7.3 and newer do not have Microsoft.PowerShell.Security
    #             # automatically loaded; likewise, the .GetAccessControl() method of
    #             # a folder or file object is missing. So, we need to load the
    #             # Microsoft.PowerShell.Security module and then call
    #             # [System.IO.FileSystemAclExtensions]::GetAccessControl()
    #             if (@(Get-Module Microsoft.PowerShell.Security).Count -eq 0) {
    #                 Import-Module Microsoft.PowerShell.Security
    #             }
    #             $objThisFolderPermission = [System.IO.FileSystemAclExtensions]::GetAccessControl($objThis)
    #         } else {
    #             # PowerShell v3 through v7.2
    #             $objThisFolderPermission = $objThis.GetAccessControl()
    #         }
    #     } elseif ($versionPS.Major -eq 2) {
    #         # We don't need to escape the right square bracket based on testing, but
    #         # we do need to escape the left square bracket. Nevertheless, escaping
    #         # both brackets does work and seems like the safest option.
    #         $objThis = Get-Item -Path ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force # -Force parameter is required to get hidden items
    #         $objThisFolderPermission = $objThis.GetAccessControl()
    #     } else {
    #         # PowerShell v1
    #         # Get-Item -> GetAccessControl() does not work and returns $null on
    #         # PowerShell v1 for some reason.
    #         # And, unfortunately, there is no apparent way to escape left square
    #         # brackets with Get-Acl
    #         $objThisFolderPermission = Get-Acl -Path ($strThisObjectPath.Replace('`', '``'))
    #     }
    # } else {
    #     # No square brackets; use Get-Acl
    #     $objThisFolderPermission = Get-Acl -Path $strThisObjectPath
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
    Waits for the specified path to be available. Also tests that a Join-Path operation
    can be performed on the specified path and a child item

    .DESCRIPTION
    This function waits for the specified path to be available. It also tests that a
    Join-Path operation can be performed on the specified path and a child item

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

    $versionThisFunction = [version]('1.0.20230619.1')

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

function Wait-PathToBeNotReady {
    <#
    .SYNOPSIS
    Waits for the specified path to be unavailable. Also tests that a Join-Path
    operation can be performed on the specified path and a child item

    .DESCRIPTION
    This function waits for the specified path to be unavailable. It also tests that a
    Join-Path operation can be performed on the specified path and a child item

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
    $boolUseGetPSDriveWorkaround = $false
    $boolPathUnavailable = Wait-PathToBeNotReady -Path 'D:\Shares\Share\Data' -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

    .OUTPUTS
    A boolean value indiciating whether the path is unavailable
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]

    param (
        [Parameter(Mandatory = $false)][System.Management.Automation.PSReference]$ReferenceToUseGetPSDriveWorkaround = ([ref]$null),
        [Parameter(Mandatory = $true)][string]$Path,
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

    $versionThisFunction = [version]('1.0.20231111.0')

    #region Process Input ##########################################################
    if ($DoNotAttemptGetPSDriveWorkaround.IsPresent -eq $true) {
        $boolAttemptGetPSDriveWorkaround = $false
    } else {
        $boolAttemptGetPSDriveWorkaround = $true
    }
    #endregion Process Input ##########################################################

    $boolFunctionReturn = $false

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
            Start-Sleep 0.2
            $doubleSecondsCounter += 0.2
        } else {
            $boolFunctionReturn = $true
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
                        Start-Sleep 0.2
                        $doubleSecondsCounter += 0.2
                    } else {
                        $boolFunctionReturn = $true
                    }
                }
            }
        }
    }

    return $boolFunctionReturn
}

function Get-ScriptingFileSystemObjectSafely {
    # Usage:
    # $objScriptingFileSystemObject = $null
    # $boolSuccess = Get-ScriptingFileSystemObjectSafely ([ref]$objScriptingFileSystemObject)

    trap {
        # Intentionally left empty to prevent terminating errors from halting processing
    }

    $refScriptingFileSystemObject = $args[0]

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and then
    # continue on. Likewise, non-terminating errors will also not output anything, but they
    # do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        $false
    } else {
        $true
        $refScriptingFileSystemObject.Value = $objScriptingFileSystemObject
    }
}

function Get-FolderObjectSafelyUsingScriptingFileSystemObject {
    # Usage:
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe'
    # $objScriptingFileSystemObject = $null
    # $boolSuccess = Get-FolderDOS83Path ([ref]$objScriptingFileSystemObject)
    # if ($boolSuccess -eq $true) {
    #   $objFSOFolderObject = $null
    #   $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject ([ref]$objFSOFolderObject) ([ref]$objScriptingFileSystemObject) $strPath
    # }

    trap {
        # Intentionally left empty to prevent terminating errors from halting processing
    }

    $refFSOFolderObject = $args[0]
    $refScriptingFileSystemObject = $args[1]
    $strPath = $args[2]

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and then
    # continue on. Likewise, non-terminating errors will also not output anything, but they
    # do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    $objFSOFolderObject = ($refScriptingFileSystemObject.Value).GetFolder($strPath)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        $false
    } else {
        $true
        $refFSOFolderObject.Value = $objFSOFolderObject
    }
}

function Get-FileObjectSafelyUsingScriptingFileSystemObject {
    # Usage:
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe.docx'
    # $objScriptingFileSystemObject = $null
    # $boolSuccess = Get-FileDOS83Path ([ref]$objScriptingFileSystemObject)
    # if ($boolSuccess -eq $true) {
    #   $objFSOFileObject = $null
    #   $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject ([ref]$objFSOFileObject) ([ref]$objScriptingFileSystemObject) $strPath
    # }

    trap {
        # Intentionally left empty to prevent terminating errors from halting processing
    }

    $refFSOFileObject = $args[0]
    $refScriptingFileSystemObject = $args[1]
    $strPath = $args[2]

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and then
    # continue on. Likewise, non-terminating errors will also not output anything, but they
    # do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    $objFSOFileObject = ($refScriptingFileSystemObject.Value).GetFile($strPath)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        $false
    } else {
        $true
        $refFSOFileObject.Value = $objFSOFileObject
    }
}

function Get-DOS83Path {
    # Usage:
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe.docx'
    # $strDOS83Path = ''
    # $boolSuccess = Get-DOS83Path ([ref]$strDOS83Path) $strPath

    $refDOS83Path = $args[0]
    $strPath = $args[1]

    $objScriptingFileSystemObject = $null
    $boolSuccess = Get-ScriptingFileSystemObjectSafely ([ref]$objScriptingFileSystemObject)
    if ($boolSuccess -ne $true) {
        return $false
    } else {
        # Try folder first
        $objFSOFolderObject = $null
        $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject ([ref]$objFSOFolderObject) ([ref]$objScriptingFileSystemObject) $strPath
        if ($boolSuccess -eq $false) {
            # Try file next
            $objFSOFileObject = $null
            $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject ([ref]$objFSOFileObject) ([ref]$objScriptingFileSystemObject) $strPath
            if ($boolSuccess -eq $false) {
                return $false
            } else {
                $refDOS83Path.Value = $objFSOFileObject.ShortPath
                return $true
            }
        } else {
            $refDOS83Path.Value = $objFSOFolderObject.ShortPath
            return $true
        }
    }
}

function Test-ValidSID {
    #region FunctionHeader #########################################################
    # This function tests whether the supplied arugment is a security identifier (SID).
    # If the supplied argument is a SID, the function returns $true. If the supplied
    # argument is not a SID, the function returns $false.
    #
    # One positional argument is required: an object to be evaluated to determine
    # whether it is a SID
    #
    # The function returns $true if the supplied object is a SID; $false otherwise
    #
    # Example usage:
    # $boolResult = Test-ValidSID 'S-1-5-21-1234567890-1234567890-1234567890-1000'
    #
    # Version: 2.0.20230719.0
    #endregion FunctionHeader #########################################################

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

    #region Acknowledgements #######################################################
    # Thanks to Friedrich Weinmann who suggested an alternative way to test for a SID:
    # https://twitter.com/FredWeinmann/status/1675513443615404032?s=20
    # retrieved on 2023-07-19
    #endregion Acknowledgements #######################################################

    #region FunctionsToSupportErrorHandling ########################################
    function Get-ReferenceToLastError {
        #region FunctionHeader #####################################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last error
        # that occurred.
        #
        # Version: 1.0.20230709.0
        #endregion FunctionHeader #####################################################

        #region License ############################################################
        # Copyright (c) 2023 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a copy
        # of this software and associated documentation files (the "Software"), to deal
        # in the Software without restriction, including without limitation the rights
        # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        # copies of the Software, and to permit persons to whom the Software is
        # furnished to do so, subject to the following conditions:
        #
        # The above copyright notice and this permission notice shall be included in
        # all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ############################################################

        #region DownloadLocationNotice #############################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #############################################

        if ($error.Count -gt 0) {
            [ref]($error[0])
        } else {
            $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #####################################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error that had
        # occurred prior to calling the command in question - that is, the command that
        # we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had occurred as-of
        # the completion of the command in question
        #
        # Function returns $true if it appears that an error occurred; $false otherwise
        #
        # Version: 1.0.20230709.0
        #endregion FunctionHeader #####################################################

        #region License ############################################################
        # Copyright (c) 2023 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a copy
        # of this software and associated documentation files (the "Software"), to deal
        # in the Software without restriction, including without limitation the rights
        # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        # copies of the Software, and to permit persons to whom the Software is
        # furnished to do so, subject to the following conditions:
        #
        # The above copyright notice and this permission notice shall be included in
        # all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ############################################################

        #region DownloadLocationNotice #################################################
        # The most up-to-date version of this script can be found on the author's GitHub
        # repository at https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #################################################

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
    #endregion FunctionsToSupportErrorHandling ########################################

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    $objSID = $null

    # Retrieve the newest error on the stack prior to running the command to determine
    # if the object is a SID
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we call the command
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and
    # then continue on. Likewise, non-terminating errors will also not output anything,
    # but they do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Run the command to determine if the object is a SID
    $objSID = ($args[0]) -as [System.Security.Principal.SecurityIdentifier]

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        return $false
    } else {
        return ($null -ne $objSID)
    }
}

function Remove-SpecificAccessRuleRobust {
    #region FunctionHeader #########################################################
    # This function removes a specific access rule from a
    # System.Security.AccessControl.DirectorySecurity or similar object safely and in a
    # way that automaticaly retries if an error occurs.
    #
    # Four positional arguments are required:
    #
    # The first argument is an integer indicating the current attempt number. When
    # calling this function for the first time, it should be 1
    #
    # The second argument is an integer representing the maximum number of attempts that
    # the function will observe before giving up
    #
    # The third argument is a reference to a
    # System.Security.AccessControl.DirectorySecurity or similar object that the access
    # control entry will be removed from
    #
    # The fourth argument is a reference to a
    # System.Security.AccessControl.FileSystemAccessRule or similar object that will be
    # removed from the access control list
    #
    # The function returns $true if the process completed successfully; $false
    # otherwise
    #
    # Example usage:
    # $item = Get-Item 'D:\Shared\Human_Resources'
    # $directorySecurity = $item.GetAccessControl()
    # $arrFileSystemAccessRules = @($directorySecurity.Access)
    # $boolSuccess = Remove-SpecificAccessRuleRobust 1 8 ([ref]$directorySecurity) ([ref]($arrFileSystemAccessRules[0]))
    #
    # Version: 1.0.20230731.0
    #endregion FunctionHeader #########################################################

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

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    $intCurrentAttemptNumber = $args[0]
    $intMaximumAttempts = $args[1]
    $refAccessControlSecurity = $args[2]
    $refAccessControlAccessRule = $args[3]

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of this
    # function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and
    # then continue on. Likewise, non-terminating errors will also not output anything,
    # but they do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Do the work of this function...
    ($refAccessControlSecurity.Value).RemoveAccessRuleSpecific($refAccessControlAccessRule.Value)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        # Error occurred
        if ($intCurrentAttemptNumber -lt $intMaximumAttempts) {
            Start-Sleep -Seconds ([math]::Pow(2, $intCurrentAttemptNumber))

            $objResultIndicator = Remove-SpecificAccessRuleRobust ($intCurrentAttemptNumber + 1) $intMaximumAttempts $refAccessControlSecurity $refAccessControlAccessRule
            $objResultIndicator
        } else {
            # Number of attempts exceeded maximum

            # Return failure indicator:
            return $false
        }
    } else {
        # No error occurred

        # Return success indicator:
        return $true
    }
}

function Write-ACLToDisk {
    #region FunctionHeader #########################################################
    # This function removes a specific access rule from a
    # System.Security.AccessControl.DirectorySecurity or similar object safely and in a
    # way that automaticaly retries if an error occurs.
    #
    # Four positional arguments are required:
    #
    # The first argument is an integer indicating the current attempt number. When
    # calling this function for the first time, it should be 1
    #
    # The second argument is an integer representing the maximum number of attempts that
    # the function will observe before giving up
    #
    # The third argument is a reference to a System.IO.DirectoryInfo,
    # System.IO.FileInfo, or similar object where the access control list (ACL) will be
    # written
    #
    # The fourth argument is a reference to a
    # System.Security.AccessControl.DirectorySecurity,
    # System.Security.AccessControl.FileSecurity, or similar object that will be
    # removed from the access control list
    #
    # The function returns $true if the process completed successfully; $false
    # otherwise
    #
    # Example usage:
    # $item = Get-Item 'D:\Shared\Human_Resources'
    # $directorySecurity = $item.GetAccessControl()
    # # <Do something to modify $directorySecurity here...>
    # $boolSuccess = Write-ACLToDisk 1 8 ([ref]$item) ([ref]$directorySecurity)
    #
    # Version: 1.0.20231110.0
    #endregion FunctionHeader #########################################################

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

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    $intCurrentAttemptNumber = $args[0]
    $intMaximumAttempts = $args[1]
    $refItem = $args[2]
    $refAccessControlSecurity = $args[3]

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of this
    # function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error output.
    # Terminating errors will not output anything, kick to the empty trap statement and
    # then continue on. Likewise, non-terminating errors will also not output anything,
    # but they do not kick to the trap statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Do the work of this function...
    ($refItem.Value).SetAccessControl($refAccessControlSecurity.Value)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        # Error occurred
        if ($intCurrentAttemptNumber -lt $intMaximumAttempts) {
            Start-Sleep -Seconds ([math]::Pow(2, $intCurrentAttemptNumber))

            $objResultIndicator = Write-ACLToDisk ($intCurrentAttemptNumber + 1) $intMaximumAttempts $refAccessControlSecurity $refAccessControlAccessRule
            $objResultIndicator
        } else {
            # Number of attempts exceeded maximum

            # Return failure indicator:
            return $false
        }
    } else {
        # No error occurred

        # Return success indicator:
        return $true
    }
}

function Repair-NTFSPermissionsRecursively {
    # Syntax: $intReturnCode = Repair-NTFSPermissionsRecursively 'D:\Shares\Corporate' $true 0 $false '' $false $false ([ref]$hashtableKnownSIDs)

    $strThisObjectPath = $args[0]
    $boolAllowRecursion = $args[1]
    $intIterativeRepairState = $args[2]
    $boolUseGetPSDriveWorkaround = $args[3]
    $strLastSubstitutedPath = $args[4]
    $boolUseTemporaryPathLenghIgnoringAltMode = $args[5]
    $boolRelaunchAttemptedWithDOS83Path = $args[6]
    $refHashtableKnownSIDs = $args[7]

    if ($null -eq $refHashtableKnownSIDs) {
        $strVerboseMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters:' + "`n" + 'Path: ' + $strThisObjectPath + "`n" + 'Allow recursion: ' + $boolAllowRecursion + "`n" + 'Iterative repair state: ' + $intIterativeRepairState + "`n" + 'Use Get-Path workaround: ' + $boolUseGetPSDriveWorkaround + "`n" + 'Last substituted path: ' + $strLastSubstitutedPath + "`n" + 'Use temporary path length ignoring alt mode: ' + $boolUseTemporaryPathLenghIgnoringAltMode + "`n" + 'Relaunch attempted with DOS 8.3 path: ' + $boolRelaunchAttemptedWithDOS83Path + "`n" + 'Known SIDs: not specified (unresolved SIDs will not be removed)'
    } else {
        if ($null -eq $refHashtableKnownSIDs.Value) {
            $strVerboseMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters:' + "`n" + 'Path: ' + $strThisObjectPath + "`n" + 'Allow recursion: ' + $boolAllowRecursion + "`n" + 'Iterative repair state: ' + $intIterativeRepairState + "`n" + 'Use Get-Path workaround: ' + $boolUseGetPSDriveWorkaround + "`n" + 'Last substituted path: ' + $strLastSubstitutedPath + "`n" + 'Use temporary path length ignoring alt mode: ' + $boolUseTemporaryPathLenghIgnoringAltMode + "`n" + 'Relaunch attempted with DOS 8.3 path: ' + $boolRelaunchAttemptedWithDOS83Path + "`n" + 'Known SIDs: not specified (unresolved SIDs will not be removed)'
        } else {
            $strVerboseMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters:' + "`n" + 'Path: ' + $strThisObjectPath + "`n" + 'Allow recursion: ' + $boolAllowRecursion + "`n" + 'Iterative repair state: ' + $intIterativeRepairState + "`n" + 'Use Get-Path workaround: ' + $boolUseGetPSDriveWorkaround + "`n" + 'Last substituted path: ' + $strLastSubstitutedPath + "`n" + 'Use temporary path length ignoring alt mode: ' + $boolUseTemporaryPathLenghIgnoringAltMode + "`n" + 'Relaunch attempted with DOS 8.3 path: ' + $boolRelaunchAttemptedWithDOS83Path + "`n" + 'Known SIDs: yes (unresolved SIDs unmatched to SIDs in the hashtable will be removed)'
        }
    }
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
    if ($strThisObjectPath.Length -ge $FOLDERPATHLIMIT -and $boolUseTemporaryPathLenghIgnoringAltMode -ne $true) {
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
                if ($strParentFolder -eq $strLastSubstitutedPath) {
                    # Don't attempt another substitution since we already did that
                    #
                    # We are not in temporary path length ignoring mode yet, so try
                    # again with temporary path length ignoring mode enabled and
                    # recursion turned off
                    Write-Verbose ('The path length of item "' + $strThisObjectPath + '" exceeds the maximum number of characters. A drive substitution or synbolic link should be used to mitigate this, however this mitigation has already been performed, so trying again with temporary path length ignoring mode enabled.')
                    $intReturnCode = Repair-NTFSPermissionsRecursively $strThisObjectPath $false 0 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $true $false $refHashtableKnownSIDs
                    $intFunctionReturn = $intReturnCode
                    return $intFunctionReturn
                } else {
                    if ($strParentFolder.Length -le 3) {
                        # We are already working with the shortest possible path; no
                        # need to try a substitution
                        #
                        # We are not in temporary path length ignoring mode yet, so try
                        # again with temporary path length ignoring mode enabled and
                        # recursion turned off
                        Write-Verbose ('The path length of item "' + $strThisObjectPath + '" exceeds the maximum number of characters. A drive substitution or synbolic link cannot be used to mitigate this because this item''s parent folder is already the root of a drive, so trying again with temporary path length ignoring mode enabled.')
                        $intReturnCode = Repair-NTFSPermissionsRecursively $strThisObjectPath $false 0 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $true $false $refHashtableKnownSIDs
                        $intFunctionReturn = $intReturnCode
                        return $intFunctionReturn
                    } else {
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
                            $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                            $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strEscapedPathForInvokeExpression + '"'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand

                            # Confirm the path is ready
                            $strJoinedPath = ''
                            $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                            if ($boolPathAvailable -eq $false) {
                                Write-Verbose ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...')
                                $intReturnCode = -1
                            } else {
                                $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround (Join-Path ($strDriveLetterToUse + ':') '') $false $false $refHashtableKnownSIDs
                            }

                            $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand

                            if ($boolUseGetPSDriveWorkaround -eq $true) {
                                # Use workaround for drives not refreshing in current PowerShell session
                                Get-PSDrive | Out-Null
                            }

                            $boolPathUnavailable = Wait-PathToBeNotReady -Path ($strDriveLetterToUse + ':') -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                            if ($boolPathUnavailable -eq $false) {
                                Write-Warning ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand)
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
                            $boolSymbolicLinkTargetFound = $false
                            $strSymbolicLinkFolderName = ''
                            if ($strFolderTarget.Length -gt 35) {
                                # Use a GUID to avoid name collisions
                                $strSymbolicLinkFolderName = [System.Guid]::NewGuid().ToString()
                                $strSymbolicLinkFolderName = $strSymbolicLinkFolderName.Replace('-', '')
                                $boolSymbolicLinkTargetFound = $true
                            } elseif ($strFolderTarget.Length -gt 5) {
                                # Use a single character folder path to keep the name as short as possible
                                for ($intCounter = 97; $intCounter -le 122; $intCounter++) {
                                    $strPossibleSymbolicLinkFolder = [string]([char]$intCounter)
                                    $strTestPath = Join-Path 'C:' $strPossibleSymbolicLinkFolder
                                    if ((Test-Path $strTestPath) -eq $false) {
                                        # This path is available
                                        $strSymbolicLinkFolderName = $strPossibleSymbolicLinkFolder
                                        $boolSymbolicLinkTargetFound = $true
                                        break
                                    }
                                }
                            } else {
                                # The path is already short enough; cannot create a symbolic link
                                # $boolSymbolicLinkTargetFound = $false
                            }

                            if ($boolSymbolicLinkTargetFound -eq $true) {
                                # Create the symbolic link
                                $versionPS = Get-PSVersion
                                if ($versionPS -ge ([version]'5.0')) {
                                    # PowerShell 5.0 and newer can make symbolic links in PowerShell
                                    Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via PowerShell:' + "`n" + 'Symbolic link path: ' + 'C:\' + $strSymbolicLinkFolderName + "`n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$'))
                                    # TODO: Test this with a path containing a dollar sign ($)
                                    New-Item -ItemType SymbolicLink -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                                } else {
                                    # Need to use mklink command in command prompt instead
                                    # TODO: Test this with a path containing a dollar sign ($)
                                    $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                    $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "' + (Join-Path 'C:' $strSymbolicLinkFolderName) + '" "' + $strEscapedPathForInvokeExpression + '"'
                                    Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via command: ' + $strCommand)
                                    $null = Invoke-Expression $strCommand
                                }

                                # Confirm the path is ready
                                $strJoinedPath = ''
                                $boolPathAvailable = Wait-PathToBeReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                if ($boolErrorOccurredUsingNewPath -eq $true) {
                                    Write-Error ('Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.')
                                    $intReturnCode = -2
                                } else {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround (Join-Path 'C:' $strSymbolicLinkFolderName) $false $false $refHashtableKnownSIDs
                                }

                                if ($intReturnCode -lt 0) {
                                    # -2 if drive substitution and symbolic link failed
                                    $intFunctionReturn = $intReturnCode
                                    return $intFunctionReturn
                                } elseif ($intReturnCode -eq 0) {
                                    $boolSymbolicLinkWorked = $true
                                }

                                # Remove Symbolic Link
                                Write-Verbose ('Removing symbolic link: ' + (Join-Path 'C:' $strSymbolicLinkFolderName))
                                # TODO: Build error handling for this deletion:
                                (Get-Item (Join-Path 'C:' $strSymbolicLinkFolderName)).Delete()

                                if ($boolUseGetPSDriveWorkaround -eq $true) {
                                    # Use workaround for drives not refreshing in current PowerShell session
                                    Get-PSDrive | Out-Null
                                }

                                $boolPathUnavailable = Wait-PathToBeNotReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                if ($boolPathUnavailable -eq $false) {
                                    Write-Warning ('There was an issue processing the path "' + $strThisObjectPath + '". A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.')
                                }
                            }
                        }
                        #endregion Mitigate Path Length with Symbolic Link ####################

                        if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                            Write-Error ('Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $strThisObjectPath)
                            $intFunctionReturn = -3
                            return $intFunctionReturn
                        }
                    }
                }
            } elseif ($boolPossibleAttemptsExceeded -eq $true) {
                Write-Error ('Cannot process the following path because it contains no parent folder element that is of an acceptable length with which to perform drive substitution or creation of a symbolic link: ' + $strThisObjectPath)
                $intFunctionReturn = -4
                return $intFunctionReturn
            } else {
                Write-Error ('While working on the path "' + $strThisObjectPath + '", the path was too long, and an acceptable parent folder element with which path substitution should be performed could not be found. This is unexpected.')
                $intFunctionReturn = -10
                return $intFunctionReturn
            }
        }
    } else {
        # Path is not too long, or we are in "TemporaryPathLenghIgnoringAltMode"
        $boolCriticalErrorOccurred = $false

        $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

        if ($boolSuccess -eq $false) {
            # Error occurred reading the ACL

            # Take ownership
            $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
            $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strEscapedPathForInvokeExpression + '" /A'
            Write-Verbose ('About to run command: ' + $strCommand)
            $null = Invoke-Expression $strCommand

            # Should now be able to read permissions

            $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath

            if ($boolSuccess -eq $false) {
                if ($boolRelaunchAttemptedWithDOS83Path -eq $true) {
                    # We already tried a DOS 8.3 path, and it didn't work; nothing else
                    # we can do
                    Write-Verbose ('Despite attempting to take ownership of the folder/file "' + $strThisObjectPath + '" on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'This may occur if subst.exe was used to mitigate path length issues; if so, the function should retry...')
                    $intFunctionReturn = -5
                    return $intFunctionReturn
                } else {
                    # Get the DOS 8.3 path and try again
                    $strDOS83Path = ''
                    $boolSuccess = Get-DOS83Path ([ref]$strDOS83Path) $strThisObjectPath
                    if ($boolSuccess -eq $false) {
                        Write-Verbose ('Despite attempting to take ownership of the folder/file "' + $strThisObjectPath + '" on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'As a potential workaround, the script was going to try again with using the DOS 8.3 path. However, the script was unable to get the DOS 8.3 folder/file name.')
                        $intFunctionReturn = -13
                        return $intFunctionReturn
                    } else {
                        Write-Verbose ('Despite attempting to take ownership of the folder/file "' + $strThisObjectPath + '" on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'As a potential workaround, the script is going to try again with using the DOS 8.3 path: ' + $strDOS83Path)
                        $intReturnCode = Repair-NTFSPermissionsRecursively $strDOS83Path $true 0 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $boolUseTemporaryPathLenghIgnoringAltMode $true $refHashtableKnownSIDs
                        return $intReturnCode
                    }
                }
            }
        } else {
            # Able to read the permissions of the parent folder, continue

            if ($versionPS -eq ([version]'1.0')) {
                # The object returned from Get-Acl is not copy-able on PowerShell 1.0
                # Not sure why...
                # So, we need to get the ACL directly and hope that we don't have an error this time
                if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) {
                    # PowerShell v1
                    # GetAccessControl() does not work and returns $null on PowerShell v1 for some reason
                    # So, we need to use Get-Acl
                    #
                    # Unfortunately, there does not seem to be any way to escape a left
                    # square bracket in a path passed to Get-Acl. But those paths
                    # should have already thrown an error - so we stick with only
                    # escaping a grave accent mark/backtick.
                    $objThisFolderPermission = Get-Acl -Path ($strThisObjectPath.Replace('`', '``'))
                } else {
                    # No square brackets; use Get-Acl
                    $objThisFolderPermission = Get-Acl -Path $strThisObjectPath
                }
            }

            if ($null -eq $objThisFolderPermission) {
                # An error did not occur retrieving permissions; however no permissions were retrieved
                # Either Get-Acl did not work as expected, or there are in fact no access control entries on the object

                # Take ownership
                $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strEscapedPathForInvokeExpression + '" /A'
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
                if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) {
                    # Need to escape characters
                    if ($versionPS.Major -ge 3) {
                        # PowerShell v3 and newer supports -LiteralPath
                        # -Force parameter is required to get hidden items
                        $objThis = Get-Item -LiteralPath $strThisObjectPath -Force
                    } else {
                        # -Force parameter is required to get hidden items
                        $objThis = Get-Item -Path ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force
                    }
                } else {
                    # -Force parameter is required to get hidden items
                    $objThis = Get-Item $strThisObjectPath -Force
                }
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
                $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                if ($objThis.PSIsContainer) {
                    # Is a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $strNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls + ':(NP)(F)"'
                } else {
                    # Is not a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $strNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls + ':(F)"'
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
                $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                if ($objThis.PSIsContainer) {
                    # Is a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $strNameOfSYSTEMAccountAccordingToTakeOwnAndICacls + ':(NP)(F)"'
                } else {
                    # Is not a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $strNameOfSYSTEMAccountAccordingToTakeOwnAndICacls + ':(F)"'
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
                $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                if ($objThis.PSIsContainer) {
                    # Is a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $strNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls + ':(NP)(F)"'
                } else {
                    # Is not a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $strNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls + ':(F)"'
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
                $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                if ($objThis.PSIsContainer) {
                    # Is a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls + ':(NP)(RX)"'
                } else {
                    # Is not a folder
                    $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $strNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls + ':(RX)"'
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
                            $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                            $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strEscapedPathForInvokeExpression + '" /A'
                            $strCommand += ' 2>&1'
                            Write-Verbose ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand
                            # Restart process without recursion flag, phase 1
                            $intReturnCode = Repair-NTFSPermissionsRecursively $strThisObjectPath $false 1 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $false $false $refHashtableKnownSIDs

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
                            $intReturnCode = Repair-NTFSPermissionsRecursively $strThisObjectPath $false 2 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $false $false $refHashtableKnownSIDs

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

        #region Programmatically Change Permissions via PowerShell #################
        # $arrACEs is already initialized (and refreshed if permission changes were
        # made above)

        # Check to see if we are supposed to make any changes
        if ($null -eq $refHashtableKnownSIDs) {
            $boolRemoveUnresolvedSIDs = $false
        } else {
            $boolRemoveUnresolvedSIDs = ($null -ne ($refHashtableKnownSIDs.Value))
        }

        if ($boolRemoveUnresolvedSIDs -eq $true) {
            # Changes are potentially required

            # Make a copy of $arrACEs and store it in $arrWorkingACEs
            $arrWorkingACEs = @($arrACEs | Where-Object { $_.IsInherited -eq $false } |
                    ForEach-Object {
                        $strIdentityReference = $_.IdentityReference.Value
                        $intFileSystemRights = [int]($_.FileSystemRights)
                        $fileSystemRights = [System.Security.AccessControl.FileSystemRights]$intFileSystemRights
                        $intInheritanceFlags = [int]($_.InheritanceFlags)
                        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]$intInheritanceFlags
                        $intPropagationFlags = [int]($_.PropagationFlags)
                        $propagationFlags = [System.Security.AccessControl.PropagationFlags]$intPropagationFlags
                        $intAccessControlType = [int]($_.AccessControlType)
                        $accessControlType = [System.Security.AccessControl.AccessControlType]$intAccessControlType

                        New-Object System.Security.AccessControl.FileSystemAccessRule($strIdentityReference, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType)
                    })

            $intNumberOfItems = $arrWorkingACEs.Count
            $intLastNumberOfItems = $arrACEs.Count

            $arrACETracking = New-Object bool[] $intNumberOfItems
            for ($intCounterA = 0; $intCounterA -lt $intNumberOfItems; $intCounterA++) {
                $arrACETracking[$intCounterA] = $false
            }

            $boolACLChangeMade = $false

            for ($intCounterA = 0; $intCounterA -lt $intNumberOfItems; $intCounterA++) {
                if (($arrWorkingACEs[$intCounterA]).IsInherited -eq $false) {
                    # ACE is not inherited
                    Write-Verbose ('Found non-inherited ACE in path "' + $strThisObjectPath + '". AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".')
                    if ($null -ne ($arrWorkingACEs[$intCounterA]).IdentityReference) {
                        if (($arrWorkingACEs[$intCounterA]).IdentityReference.GetType().Name -eq 'SecurityIdentifier') {
                            # ACE is a SID
                            if ($boolRemoveUnresolvedSIDs -eq $true) {
                                if (($refHashtableKnownSIDs.Value).ContainsKey(($arrWorkingACEs[$intCounterA]).IdentityReference.Value) -eq $true) {
                                    Write-Warning ('...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $strThisObjectPath + '" because it is associated with a known SID. Is the connection to the domain down?')
                                } else {
                                    # Not a protected SID
                                    if ($arrACETracking[$intCounterA] -eq $true) {
                                        Write-Warning ('Removing ACE from path "' + $strThisObjectPath + '" that was already been used in an operation.')
                                    }
                                    Write-Verbose ('Removing unresolved SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $strThisObjectPath + '".')
                                    $boolSuccess = Remove-SpecificAccessRuleRobust 1 2 ([ref]$objThisFolderPermission) ([ref]($arrWorkingACEs[$intCounterA]))
                                    if ($boolSuccess -eq $false) {
                                        # Permissions were not removed
                                        Write-Verbose ('...the unresolved SID was not removed (.NET call failed)...')
                                    } else {
                                        $arrACETracking[$intCounterA] = $true
                                        # Test to see if permissions were removed by comparing the ACE count
                                        $intCurrentNumberOfItems = $objThisFolderPermission.Access.Count
                                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                                            # Permissions were removed
                                            Write-Verbose ('...the unresolved SID was removed...')
                                            $intLastNumberOfItems = $intCurrentNumberOfItems
                                            $boolACLChangeMade = $true
                                        } else {
                                            # Permissions were not removed
                                            Write-Verbose ('...the unresolved SID was not removed...')
                                        }
                                    }
                                }
                            }
                        } elseif ((Test-ValidSID (($arrWorkingACEs[$intCounterA]).IdentityReference.Value)) -eq $true) {
                            # ACE is a SID (string)
                            if ($boolRemoveUnresolvedSIDs -eq $true) {
                                if (($refHashtableKnownSIDs.Value).ContainsKey(($arrWorkingACEs[$intCounterA]).IdentityReference.Value) -eq $true) {
                                    Write-Warning ('...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $strThisObjectPath + '" because it is associated with a known SID. Is the connection to the domain down?')
                                } else {
                                    # Not a protected SID
                                    if ($arrACETracking[$intCounterA] -eq $true) {
                                        Write-Warning ('Removing ACE from path "' + $strThisObjectPath + '" that was already been used in an operation.')
                                    }
                                    Write-Verbose ('Removing unresolved SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $strThisObjectPath + '".')
                                    $accessControlType = ($arrWorkingACEs[$intCounterA]).AccessControlType
                                    $fileSystemRights = ($arrWorkingACEs[$intCounterA]).FileSystemRights
                                    $inheritanceFlags = ($arrWorkingACEs[$intCounterA]).InheritanceFlags
                                    $propagationFlags = ($arrWorkingACEs[$intCounterA]).PropagationFlags
                                    $SID = New-Object System.Security.Principal.SecurityIdentifier(($arrWorkingACEs[$intCounterA]).IdentityReference.Value)
                                    $fileSystemAccessRuleOld = New-Object System.Security.AccessControl.FileSystemAccessRule($SID, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType)
                                    $boolSuccess = Remove-SpecificAccessRuleRobust 1 2 ([ref]$objThisFolderPermission) ([ref]($fileSystemAccessRuleOld))
                                    if ($boolSuccess -eq $false) {
                                        # Permissions were not removed
                                        Write-Verbose ('...the unresolved SID was not removed (.NET call failed)...')
                                    } else {
                                        $arrACETracking[$intCounterA] = $true
                                        # Test to see if permissions were removed by comparing the ACE count
                                        $intCurrentNumberOfItems = $objThisFolderPermission.Access.Count
                                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                                            # Permissions were removed
                                            Write-Verbose ('...the unresolved SID was removed...')
                                            $intLastNumberOfItems = $intCurrentNumberOfItems
                                            $boolACLChangeMade = $true
                                        } else {
                                            # Permissions were not removed
                                            Write-Verbose ('...the unresolved SID was not removed...')
                                        }
                                    }
                                }
                            }
                        } else {
                            # Presumably ACE is an NTAccount per
                            # https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.identityreference?view=net-7.0
                        }
                    }
                } else {
                    # ACE is inherited
                    if ($null -ne ($arrWorkingACEs[$intCounterA]).IdentityReference) {
                        if (($arrWorkingACEs[$intCounterA]).IdentityReference.GetType().Name -eq 'SecurityIdentifier') {
                            # ACE is a SID
                            if ($boolRemoveUnresolvedSIDs -eq $true) {
                                if (($refHashtableKnownSIDs.Value).ContainsKey(($arrWorkingACEs[$intCounterA]).IdentityReference.Value) -eq $true) {
                                    Write-Warning ('...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $strThisObjectPath + '" because it is associated with a known SID. Is the connection to the domain down?')
                                } else {
                                    # Not a protected SID
                                    Write-Warning ('An unresolved SID was found at the path ' + $strThisObjectPath + '. However, it is inherited and therefore will not be removed. Please remove it from the parent folder.')
                                }
                            }
                        } elseif ((Test-ValidSID (($arrWorkingACEs[$intCounterA]).IdentityReference.Value)) -eq $true) {
                            # ACE is a SID (string)
                            if ($boolRemoveUnresolvedSIDs -eq $true) {
                                if (($refHashtableKnownSIDs.Value).ContainsKey(($arrWorkingACEs[$intCounterA]).IdentityReference.Value) -eq $true) {
                                    Write-Warning ('...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $strThisObjectPath + '" because it is associated with a known SID. Is the connection to the domain down?')
                                } else {
                                    # Not a protected SID
                                    Write-Warning ('An unresolved SID was found at the path ' + $strThisObjectPath + '. However, it is inherited and therefore will not be removed. Please remove it from the parent folder.')
                                }
                            }
                        } else {
                            # Presumably ACE is an NTAccount per
                            # https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.identityreference?view=net-7.0
                        }
                    }
                }
            }

            # Write ACL changes to disk
            if ($boolACLChangeMade -eq $true) {
                Write-Verbose ('Writing ACL changes to disk for path "' + $strThisObjectPath + '".')
                $boolSuccess = Write-ACLToDisk 1 2 ([ref]$objThis) ([ref]$objThisFolderPermission)
                if ($boolSuccess -eq $false) {
                    # TODO: Capture $_.Exception.Message from failure in Write-ACLToDisk
                    # Write-Warning ('Unable to write ACL changes to disk for path "' + $strThisObjectPath + '". Error: ' + $_.Exception.Message + '; child folders and files will not be processed!')
                    Write-Warning ('Unable to write ACL changes to disk for path "' + $strThisObjectPath + '". Child folders and files will not be processed!')
                    intFunctionReturn = -14
                    return $intFunctionReturn
                }
            }
        }
        #endregion Programmatically Change Permissions via PowerShell #################

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
                        if ($strThisObjectPath.Length -le 3) {
                            # The path is already as short as it can be, so there is
                            # nothing further for this script to try
                            Write-Error ('Unable to enumerate child objects in path "' + $strThisObjectPath + '". This can occur if path length is too long. However, in this case, its path length is already as short as possible, so there is nothing further for this script to try. Please investigate and then repair the permissions on this folder manually.')
                            $intFunctionReturn = -12
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
                                $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strEscapedPathForInvokeExpression + '"'
                                Write-Verbose ('About to run command: ' + $strCommand)
                                $null = Invoke-Expression $strCommand

                                # Confirm the path is ready
                                $strJoinedPath = ''
                                $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                if ($boolPathAvailable -eq $false) {
                                    Write-Verbose ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...')
                                    $intReturnCode = -1
                                } else {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround (Join-Path ($strDriveLetterToUse + ':') '') $false $false $refHashtableKnownSIDs
                                }

                                $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                                Write-Verbose ('About to run command: ' + $strCommand)
                                $null = Invoke-Expression $strCommand

                                if ($boolUseGetPSDriveWorkaround -eq $true) {
                                    # Use workaround for drives not refreshing in current PowerShell session
                                    Get-PSDrive | Out-Null
                                }

                                $boolPathUnavailable = Wait-PathToBeNotReady -Path ($strDriveLetterToUse + ':') -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                if ($boolPathUnavailable -eq $false) {
                                    Write-Warning ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand)
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
                                $boolSymbolicLinkTargetFound = $false
                                $strSymbolicLinkFolderName = ''
                                if ($strFolderTarget.Length -gt 35) {
                                    # Use a GUID to avoid name collisions
                                    $strSymbolicLinkFolderName = [System.Guid]::NewGuid().ToString()
                                    $strSymbolicLinkFolderName = $strSymbolicLinkFolderName.Replace('-', '')
                                    $boolSymbolicLinkTargetFound = $true
                                } elseif ($strFolderTarget.Length -gt 5) {
                                    # Use a single character folder path to keep the name as short as possible
                                    for ($intCounter = 97; $intCounter -le 122; $intCounter++) {
                                        $strPossibleSymbolicLinkFolder = [string]([char]$intCounter)
                                        $strTestPath = Join-Path 'C:' $strPossibleSymbolicLinkFolder
                                        if ((Test-Path $strTestPath) -eq $false) {
                                            # This path is available
                                            $strSymbolicLinkFolderName = $strPossibleSymbolicLinkFolder
                                            $boolSymbolicLinkTargetFound = $true
                                            break
                                        }
                                    }
                                } else {
                                    # The path is already short enough; cannot create a symbolic link
                                    # $boolSymbolicLinkTargetFound = $false
                                }

                                if ($boolSymbolicLinkTargetFound -eq $true) {
                                    # Create the symbolic link
                                    $versionPS = Get-PSVersion
                                    if ($versionPS -ge ([version]'5.0')) {
                                        # PowerShell 5.0 and newer can make symbolic links in PowerShell
                                        Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via PowerShell:' + "`n" + 'Symbolic link path: ' + 'C:\' + $strSymbolicLinkFolderName + "`n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$'))
                                        # TODO: Test this with a path containing a dollar sign ($)
                                        New-Item -ItemType SymbolicLink -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                                    } else {
                                        # Need to use mklink command in command prompt instead
                                        # TODO: Test this with a path containing a dollar sign ($)
                                        $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                        $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "' + (Join-Path 'C:' $strSymbolicLinkFolderName) + '" "' + $strEscapedPathForInvokeExpression + '"'
                                        Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via command: ' + $strCommand)
                                        $null = Invoke-Expression $strCommand
                                    }

                                    # Confirm the path is ready
                                    $strJoinedPath = ''
                                    $boolPathAvailable = Wait-PathToBeReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                    if ($boolErrorOccurredUsingNewPath -eq $true) {
                                        Write-Error ('Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.')
                                        $intReturnCode = -2
                                    } else {
                                        $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround (Join-Path 'C:' $strSymbolicLinkFolderName) $false $false $refHashtableKnownSIDs
                                    }

                                    if ($intReturnCode -lt 0) {
                                        # -2 if drive substitution and symbolic link failed
                                        $intFunctionReturn = $intReturnCode
                                        return $intFunctionReturn
                                    } elseif ($intReturnCode -eq 0) {
                                        $boolSymbolicLinkWorked = $true
                                    }

                                    # Remove Symbolic Link
                                    Write-Verbose ('Removing symbolic link: ' + (Join-Path 'C:' $strSymbolicLinkFolderName))
                                    # TODO: Build error handling for this deletion:
                                    (Get-Item (Join-Path 'C:' $strSymbolicLinkFolderName)).Delete()

                                    if ($boolUseGetPSDriveWorkaround -eq $true) {
                                        # Use workaround for drives not refreshing in current PowerShell session
                                        Get-PSDrive | Out-Null
                                    }

                                    $boolPathUnavailable = Wait-PathToBeNotReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                    if ($boolPathUnavailable -eq $false) {
                                        Write-Warning ('There was an issue processing the path "' + $strThisObjectPath + '". A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.')
                                    }
                                }
                            }
                            #endregion Mitigate Path Length with Symbolic Link ####################

                            if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                                Write-Error ('Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $strThisObjectPath)
                                $intFunctionReturn = -9
                                return $intFunctionReturn
                            }
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

                    if ($boolLengthOfChildrenOK -eq $false -and $boolUseTemporaryPathLenghIgnoringAltMode -ne $true) {
                        # One or more child objects are too long and we are not in
                        # temporary path length ignoring mode yet, so try again with
                        # temporary path length ignoring mode enabled

                        if ($strThisObjectPath -eq $strLastSubstitutedPath) {
                            # We are not in temporary path length ignoring mode
                            # yet, so try again with temporary path length
                            # ignoring mode enabled
                            Write-Verbose ('The path length on one or more child objects in folder "' + $strThisObjectPath + '" exceeds the maximum number of characters. A drive substitution or synbolic link should be used to mitigate this, however this mitigation has already been performed, so trying again with temporary path length ignoring mode enabled.')
                            $intReturnCode = Repair-NTFSPermissionsRecursively $strThisObjectPath $true 0 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $true $false $refHashtableKnownSIDs
                            $intFunctionReturn = $intReturnCode
                            return $intFunctionReturn
                        } else {
                            if ($strThisObjectPath.Length -le 3) {
                                # The path is already as short as it can be, so there
                                # is nothing further to do to mitigate path length
                                #
                                # We are not in temporary path length ignoring mode
                                # yet, so try again with temporary path length
                                # ignoring mode enabled
                                Write-Verbose ('The path length on one or more child objects in folder "' + $strThisObjectPath + '" exceeds the maximum number of characters. Normally, a drive substitution or symbolic link should be used to mitigate this, however the path is already as short as possible. Therefore, there is nothing further to do to mitigate path length. Trying again with temporary path length ignoring mode enabled.')
                                $intReturnCode = Repair-NTFSPermissionsRecursively $strThisObjectPath $true 0 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $true $false $refHashtableKnownSIDs
                                $intFunctionReturn = $intReturnCode
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
                                    $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                    $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strEscapedPathForInvokeExpression + '"'
                                    Write-Verbose ('About to run command: ' + $strCommand)
                                    $null = Invoke-Expression $strCommand

                                    # Confirm the path is ready
                                    $strJoinedPath = ''
                                    $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                    if ($boolPathAvailable -eq $false) {
                                        Write-Verbose ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...')
                                        $intReturnCode = -1
                                    } else {
                                        $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround (Join-Path ($strDriveLetterToUse + ':') '') $boolUseTemporaryPathLenghIgnoringAltMode $false $refHashtableKnownSIDs
                                    }

                                    $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                                    Write-Verbose ('About to run command: ' + $strCommand)
                                    $null = Invoke-Expression $strCommand

                                    if ($boolUseGetPSDriveWorkaround -eq $true) {
                                        # Use workaround for drives not refreshing in current PowerShell session
                                        Get-PSDrive | Out-Null
                                    }

                                    $boolPathUnavailable = Wait-PathToBeNotReady -Path ($strDriveLetterToUse + ':') -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                    if ($boolPathUnavailable -eq $false) {
                                        Write-Warning ('There was an issue processing the path "' + $strThisObjectPath + '" because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand)
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
                                    $boolSymbolicLinkTargetFound = $false
                                    $strSymbolicLinkFolderName = ''
                                    if ($strFolderTarget.Length -gt 35) {
                                        # Use a GUID to avoid name collisions
                                        $strSymbolicLinkFolderName = [System.Guid]::NewGuid().ToString()
                                        $strSymbolicLinkFolderName = $strSymbolicLinkFolderName.Replace('-', '')
                                        $boolSymbolicLinkTargetFound = $true
                                    } elseif ($strFolderTarget.Length -gt 5) {
                                        # Use a single character folder path to keep the name as short as possible
                                        for ($intCounter = 97; $intCounter -le 122; $intCounter++) {
                                            $strPossibleSymbolicLinkFolder = [string]([char]$intCounter)
                                            $strTestPath = Join-Path 'C:' $strPossibleSymbolicLinkFolder
                                            if ((Test-Path $strTestPath) -eq $false) {
                                                # This path is available
                                                $strSymbolicLinkFolderName = $strPossibleSymbolicLinkFolder
                                                $boolSymbolicLinkTargetFound = $true
                                                break
                                            }
                                        }
                                    } else {
                                        # The path is already short enough; cannot create a symbolic link
                                        # $boolSymbolicLinkTargetFound = $false
                                    }

                                    if ($boolSymbolicLinkTargetFound -eq $true) {
                                        # Create the symbolic link
                                        $versionPS = Get-PSVersion
                                        if ($versionPS -ge ([version]'5.0')) {
                                            # PowerShell 5.0 and newer can make symbolic links in PowerShell
                                            Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via PowerShell:' + "`n" + 'Symbolic link path: ' + 'C:\' + $strSymbolicLinkFolderName + "`n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$'))
                                            # TODO: Test this with a path containing a dollar sign ($)
                                            New-Item -ItemType SymbolicLink -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                                        } else {
                                            # Need to use mklink command in command prompt instead
                                            # TODO: Test this with a path containing a dollar sign ($)
                                            $strEscapedPathForInvokeExpression = (((($strThisObjectPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                            $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "' + (Join-Path 'C:' $strSymbolicLinkFolderName) + '" "' + $strEscapedPathForInvokeExpression + '"'
                                            Write-Verbose ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via command: ' + $strCommand)
                                            $null = Invoke-Expression $strCommand
                                        }

                                        # Confirm the path is ready
                                        $strJoinedPath = ''
                                        $boolPathAvailable = Wait-PathToBeReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                        if ($boolErrorOccurredUsingNewPath -eq $true) {
                                            Write-Error ('Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.')
                                            $intReturnCode = -2
                                        } else {
                                            $intReturnCode = Repair-NTFSPermissionsRecursively $strJoinedPath $true 0 $boolUseGetPSDriveWorkaround (Join-Path 'C:' $strSymbolicLinkFolderName) $false $false $refHashtableKnownSIDs
                                        }

                                        if ($intReturnCode -lt 0) {
                                            # -2 if drive substitution and symbolic link failed
                                            $intFunctionReturn = $intReturnCode
                                            return $intFunctionReturn
                                        } elseif ($intReturnCode -eq 0) {
                                            $boolSymbolicLinkWorked = $true
                                        }

                                        # Remove Symbolic Link
                                        Write-Verbose ('Removing symbolic link: ' + (Join-Path 'C:' $strSymbolicLinkFolderName))
                                        # TODO: Build error handling for this deletion:
                                        (Get-Item (Join-Path 'C:' $strSymbolicLinkFolderName)).Delete()

                                        if ($boolUseGetPSDriveWorkaround -eq $true) {
                                            # Use workaround for drives not refreshing in current PowerShell session
                                            Get-PSDrive | Out-Null
                                        }

                                        $boolPathUnavailable = Wait-PathToBeNotReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)

                                        if ($boolPathUnavailable -eq $false) {
                                            Write-Warning ('There was an issue processing the path "' + $strThisObjectPath + '". A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.')
                                        }
                                    }
                                }
                                #endregion Mitigate Path Length with Symbolic Link ####################

                                if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                                    Write-Error ('Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $strThisObjectPath)
                                    $intFunctionReturn = -11
                                    return $intFunctionReturn
                                }
                            }
                        }
                    } else {
                        # The length of all child objects was OK, or we are in
                        # temporary path length ignoring mode

                        # Process files first
                        $arrChildObjects | Where-Object { $_.PSIsContainer -eq $false } | ForEach-Object {
                            $objDirectoryOrFileInfoChild = $_
                            # Process the file
                            # Pass-through temporary path length ignoring mode
                            $intReturnCode = Repair-NTFSPermissionsRecursively ($objDirectoryOrFileInfoChild.FullName) $false 0 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $boolUseTemporaryPathLenghIgnoringAltMode $false $refHashtableKnownSIDs
                            if ($intReturnCode -ne 0) {
                                Write-Warning ('There was an issue processing the path "' + $objDirectoryOrFileInfoChild.FullName + '" The error code returned was: ' + $intReturnCode)
                                $intFunctionReturn = $intReturnCode
                            }
                        }

                        # Next, process folders/directories/containers
                        $arrChildObjects | Where-Object { $_.PSIsContainer -eq $true } | ForEach-Object {
                            $objDirectoryOrFileInfoChild = $_
                            # Recursively process the child directory
                            $intReturnCode = Repair-NTFSPermissionsRecursively ($objDirectoryOrFileInfoChild.FullName) $true 0 $boolUseGetPSDriveWorkaround $strLastSubstitutedPath $false $false $refHashtableKnownSIDs
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

$hashtableKnownSIDs = $null
if ($boolRemoveUnresolvedSIDs -eq $true) {
    # If the user requested that we remove unresolved SIDs, make sure they've specified
    # a CSV file containing all known SIDs in the environment. This protects against
    # situation where an AD outage or domain connectivity disruption causes the script
    # to remove all permissions from a folder/file because it cannot resolve the SIDs
    # in the ACLs.

    if ([string]::IsNullOrEmpty($strPathToCSVContainingKnownSIDs) -eq $true) {
        Write-Warning 'The -RemoveUnresolvedSIDs parameter was specified, but no path to a CSV file containing all known SIDs in the environment was specified. Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
        return
    } else {
        if ((Test-Path $strPathToCSVContainingKnownSIDs) -eq $false) {
            Write-Warning 'The -RemoveUnresolvedSIDs parameter was specified, but the path specified for the CSV file containing all known SIDs in the environment does not exist. Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
            return
        } else {
            $arrSIDsFromCSV = @()
            $arrSIDsFromCSV = @(Import-Csv $strPathToCSVContainingKnownSIDs)
            if ($arrSIDsFromCSV.Count -eq 0) {
                Write-Warning 'The -RemoveUnresolvedSIDs parameter was specified, but the CSV file specified for the CSV file containing all known SIDs in the environment is empty. Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
                return
            } else {
                $strKnownSID = ($arrSIDsFromCSV[0]).SID
                if ([string]::IsNullOrEmpty($strKnownSID) -eq $true) {
                    Write-Warning 'The -RemoveUnresolvedSIDs parameter was specified, but the CSV file specified for the CSV file containing all known SIDs in the environment contains an empty value for the "SID" column (or does not contain the SID column at all). Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
                    return
                } else {
                    # The CSV file specified for the CSV file containing all known SIDs in the environment appears to be valid
                    # Build these into a $hashtable for fast lookup later
                    Write-Verbose 'Loading known SIDs from the specified CSV file into memory...'
                    $hashtableKnownSIDs = @{}
                    $arrSIDsFromCSV | ForEach-Object {
                        $strSID = $_.SID
                        if ([string]::IsNullOrEmpty($strSID) -eq $false) {
                            if ($hashtableKnownSIDs.ContainsKey($strSID) -eq $false) {
                                $hashtableKnownSIDs.Add($strSID, $null)
                            }
                        }
                    }
                    Write-Verbose 'Finished loading known SIDs from the specified CSV file into memory'

                    # Make sure the count of SIDs is not zero in the hashtable
                    if ($hashtableKnownSIDs.Count -eq 0) {
                        Write-Warning 'The -RemoveUnresolvedSIDs parameter was specified, but the CSV file specified for the CSV file containing all known SIDs in the environment contains an empty value for the "SID" column (or does not contain the SID column at all). Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
                        return
                    }
                }
            }
        }
    }
}

$intReturnCode = Repair-NTFSPermissionsRecursively $strPathToFix $true 0 $false '' $false $false ([ref]$hashtableKnownSIDs)
if ($intReturnCode -eq 0) {
    Write-Host ('Successfully processed path: ' + $strPathToFix)
} else {
    Write-Error ('There were one or more issues processing the path "' + $strPathToFix + '" One error code returned was: ' + $intReturnCode)
}
