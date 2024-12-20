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

.EXAMPLE
PS C:\> .\Repair-NTFSPermissions.ps1 -PathToFix 'D:\Shares\Public' -RemoveUnresolvedSIDs -PathToCSVContainingKnownSIDs 'C:\Scripts\KnownSIDs.csv'

This example will scan the permissions at D:\Shares\Public and ensure that local
administrators and the SYSTEM account have full control to the folder and all files
and subfolders. Additionally, it will remove any unresolved SIDs from the ACL, except
for those SIDs that are listed in the CSV file at C:\Scripts\KnownSIDs.csv.

.OUTPUTS
None

.NOTES
This script is useful because taking ownership of a file or folder through the Windows
graphical interface can replace existing permissions, which can be problematic if the
existing permissions are not known or documented (and even if they are known or
documented, it can be time-consuming and disruptive to business to re-apply them).
#>

# Version 1.1.202411010.0

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

# TODO: Comment-based help, [CmdletBinding()], and [Parameter()] type statements in the
# param() block format are not supported by PowerShell 1.0. Need to investigate an
# alternative format that will work with PowerShell 1.0.

#region License ####################################################################
# Copyright (c) 2024 Frank Lesniak
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
    #region FunctionHeader #############################################
    # Function returns $null if no errors on on the $error stack;
    # Otherwise, function returns a reference (memory pointer) to the last
    # error that occurred.
    #
    # Version: 1.0.20241211.0
    #endregion FunctionHeader #############################################

    #region License ####################################################
    # Copyright (c) 2024 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining
    # a copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to
    # permit persons to whom the Software is furnished to do so, subject to
    # the following conditions:
    #
    # The above copyright notice and this permission notice shall be
    # included in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
    # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
    # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    # SOFTWARE.
    #endregion License ####################################################

    #region DownloadLocationNotice #####################################
    # The most up-to-date version of this script can be found on the
    # author's GitHub repository at:
    # https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #####################################

    if ($Error.Count -gt 0) {
        return ([ref]($Error[0]))
    } else {
        return $null
    }
}

function Test-ErrorOccurred {
    #region FunctionHeader #############################################
    # Function accepts two positional arguments:
    #
    # The first argument is a reference (memory pointer) to the last error
    # that had occurred prior to calling the command in question - that is,
    # the command that we want to test to see if an error occurred.
    #
    # The second argument is a reference to the last error that had
    # occurred as-of the completion of the command in question.
    #
    # Function returns $true if it appears that an error occurred; $false
    # otherwise
    #
    # Version: 1.0.20241211.0
    #endregion FunctionHeader #############################################

    #region License ####################################################
    # Copyright (c) 2024 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining
    # a copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to
    # permit persons to whom the Software is furnished to do so, subject to
    # the following conditions:
    #
    # The above copyright notice and this permission notice shall be
    # included in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
    # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
    # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    # SOFTWARE.
    #endregion License ####################################################

    #region DownloadLocationNotice #####################################
    # The most up-to-date version of this script can be found on the
    # author's GitHub repository at:
    # https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #####################################

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
        # could be null if $error was cleared; this does not indicate an
        # error.
        # So:
        # If both are null, no error
        # If ($args[0]) is null and ($args[1]) is non-null, error
        # If ($args[0]) is non-null and ($args[1]) is null, no error
        if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
            $boolErrorOccurred = $true
        }
    }

    return $boolErrorOccurred
}
#endregion FunctionsToSupportErrorHandling

function Get-PSVersion {
    #region FunctionHeader #################################################
    # Returns the version of PowerShell that is running, including on the
    # original release of Windows PowerShell (version 1.0)
    #
    # Example:
    # Get-PSVersion
    #
    # This example returns the version of PowerShell that is running. On
    # versions of PowerShell greater than or equal to version 2.0, this
    # function returns the equivalent of $PSVersionTable.PSVersion
    #
    # The function outputs a [version] object representing the version of
    # PowerShell that is running
    #
    # PowerShell 1.0 does not have a $PSVersionTable variable, so this function
    # returns [version]('1.0') on PowerShell 1.0
    #
    # Version 1.0.20241105.0
    #endregion FunctionHeader #################################################

    #region License ########################################################
    # Copyright (c) 2024 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a
    # copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to permit
    # persons to whom the Software is furnished to do so, subject to the
    # following conditions:
    #
    # The above copyright notice and this permission notice shall be included
    # in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    # USE OR OTHER DEALINGS IN THE SOFTWARE.
    #endregion License ########################################################

    #region DownloadLocationNotice #########################################
    # The most up-to-date version of this script can be found on the author's
    # GitHub repository at:
    # https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #########################################

    if (Test-Path variable:\PSVersionTable) {
        return ($PSVersionTable.PSVersion)
    } else {
        return ([version]('1.0'))
    }
}

function Test-Windows {
    #region FunctionHeader #################################################
    # Returns a boolean ($true or $false) indicating whether the current
    # PowerShell session is running on Windows. This function is useful for
    # writing scripts that need to behave differently on Windows and non-
    # Windows platforms (Linux, macOS, etc.). Additionally, this function is
    # useful because it works on Windows PowerShell 1.0 through 5.1, which do
    # not have the $IsWindows global variable.
    #
    # Example:
    # $boolIsWindows = Test-Windows
    #
    # This example returns $true if the current PowerShell session is running
    # on Windows, and $false if the current PowerShell session is running on a
    # non-Windows platform (Linux, macOS, etc.)
    #
    # Version 1.0.20241105.0
    #endregion FunctionHeader #################################################

    #region License ########################################################
    # Copyright (c) 2024 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a
    # copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to permit
    # persons to whom the Software is furnished to do so, subject to the
    # following conditions:
    #
    # The above copyright notice and this permission notice shall be included
    # in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    # USE OR OTHER DEALINGS IN THE SOFTWARE.
    #endregion License ########################################################

    #region DownloadLocationNotice #########################################
    # The most up-to-date version of this script can be found on the author's
    # GitHub repository at:
    # https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #########################################

    function Get-PSVersion {
        #region FunctionHeader #################################################
        # Returns the version of PowerShell that is running, including on the
        # original release of Windows PowerShell (version 1.0)
        #
        # Example:
        # Get-PSVersion
        #
        # This example returns the version of PowerShell that is running. On
        # versions of PowerShell greater than or equal to version 2.0, this
        # function returns the equivalent of $PSVersionTable.PSVersion
        #
        # The function outputs a [version] object representing the version of
        # PowerShell that is running
        #
        # PowerShell 1.0 does not have a $PSVersionTable variable, so this function
        # returns [version]('1.0') on PowerShell 1.0
        #
        # Version 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

        if (Test-Path variable:\PSVersionTable) {
            return ($PSVersionTable.PSVersion)
        } else {
            return ([version]('1.0'))
        }
    }

    $versionPS = Get-PSVersion
    if ($versionPS.Major -ge 6) {
        $IsWindows
    } else {
        $true
    }
}

function Get-AvailableDriveLetter {
    #region FunctionHeader #####################################################
    # This function evaluates the list of drive letters that are in use on the
    # local system and returns an array of those that are available. The list of
    # available drive letters is returned as an array of uppercase letters
    #
    # The function returns an array of uppercase letters (strings) representing
    # available drive letters
    #
    # This function supports three parameters:
    #
    # Parameter 1: DoNotConsiderMappedDriveLettersAsInUse
    # By default, if this function encounters a drive letter that is mapped to a
    # network share, it will consider that drive letter to be in use. However, if
    # this switch parameter is supplied, then mapped drives will be ignored and
    # their drive letters will be considered available.
    #
    # Parameter 2: DoNotConsiderPSDriveLettersAsInUse
    # By default, if this function encounters a drive letter that is mapped to a
    # PowerShell drive, it will consider that drive letter to be in use. However,
    # if this switch parameter is supplied, then PowerShell drives will be ignored
    # and their drive letters will be considered available.
    #
    # Parameter 3: ConsiderFloppyDriveLettersAsEligible
    # By default, this function will not consider A: or B: drive letters as
    # available. If this switch parameter is supplied, then A: and B: drive letters
    # will be considered available if they are not in use.
    #
    # Example:
    # $arrAvailableDriveLetters = @(Get-AvailableDriveLetter)
    # This example returns an array of available drive letters, excluding A: and B:
    # drive, and excluding drive letters that are mapped to network shares or
    # PowerShell drives (PSDrives).
    #
    # In this example, to access the alphabetically-first available drive letter,
    # use:
    # $arrAvailableDriveLetters[0]
    # To access the alphabetically-last available drive letter, use:
    # $arrAvailableDriveLetters[-1]
    #
    # Note: it is conventional that A: and B: drives be reserved for floppy drives,
    # and that C: be reserved for the system drive.
    #
    # Version 1.0.20241112.0
    #endregion FunctionHeader #####################################################

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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

    param (
        [switch]$DoNotConsiderMappedDriveLettersAsInUse,
        [switch]$DoNotConsiderPSDriveLettersAsInUse,
        [switch]$ConsiderFloppyDriveLettersAsEligible
    )

    function Get-PSVersion {
        #region FunctionHeader #################################################
        # Returns the version of PowerShell that is running, including on the
        # original release of Windows PowerShell (version 1.0)
        #
        # Example:
        # Get-PSVersion
        #
        # This example returns the version of PowerShell that is running. On
        # versions of PowerShell greater than or equal to version 2.0, this
        # function returns the equivalent of $PSVersionTable.PSVersion
        #
        # The function outputs a [version] object representing the version of
        # PowerShell that is running
        #
        # PowerShell 1.0 does not have a $PSVersionTable variable, so this function
        # returns [version]('1.0') on PowerShell 1.0
        #
        # Version 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

        if (Test-Path variable:\PSVersionTable) {
            return ($PSVersionTable.PSVersion)
        } else {
            return ([version]('1.0'))
        }
    }

    function Test-Windows {
        #region FunctionHeader #################################################
        # Returns a boolean ($true or $false) indicating whether the current
        # PowerShell session is running on Windows. This function is useful for
        # writing scripts that need to behave differently on Windows and non-
        # Windows platforms (Linux, macOS, etc.). Additionally, this function is
        # useful because it works on Windows PowerShell 1.0 through 5.1, which do
        # not have the $IsWindows global variable.
        #
        # Example:
        # $boolIsWindows = Test-Windows
        #
        # This example returns $true if the current PowerShell session is running
        # on Windows, and $false if the current PowerShell session is running on a
        # non-Windows platform (Linux, macOS, etc.)
        #
        # Version 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

        function Get-PSVersion {
            #region FunctionHeader #################################################
            # Returns the version of PowerShell that is running, including on the
            # original release of Windows PowerShell (version 1.0)
            #
            # Example:
            # Get-PSVersion
            #
            # This example returns the version of PowerShell that is running. On
            # versions of PowerShell greater than or equal to version 2.0, this
            # function returns the equivalent of $PSVersionTable.PSVersion
            #
            # The function outputs a [version] object representing the version of
            # PowerShell that is running
            #
            # PowerShell 1.0 does not have a $PSVersionTable variable, so this function
            # returns [version]('1.0') on PowerShell 1.0
            #
            # Version 1.0.20241105.0
            #endregion FunctionHeader #################################################

            #region License ########################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining a
            # copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to permit
            # persons to whom the Software is furnished to do so, subject to the
            # following conditions:
            #
            # The above copyright notice and this permission notice shall be included
            # in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
            # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
            # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
            # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
            # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
            # USE OR OTHER DEALINGS IN THE SOFTWARE.
            #endregion License ########################################################

            #region DownloadLocationNotice #########################################
            # The most up-to-date version of this script can be found on the author's
            # GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #########################################

            if (Test-Path variable:\PSVersionTable) {
                return ($PSVersionTable.PSVersion)
            } else {
                return ([version]('1.0'))
            }
        }

        $versionPS = Get-PSVersion
        if ($versionPS.Major -ge 6) {
            $IsWindows
        } else {
            $true
        }
    }

    #region Process Input ######################################################
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
    #endregion Process Input ######################################################

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
            # fifth-, fourth-, and third-to-last bits of pipeline ensures that we
            # have a device ID like "C:"; second-to-last bit of pipeline strips off
            # the ':', leaving just the capital drive letter; last bit of pipeline
            # ensure that the drive letter is actually a letter; addresses legacy
            # Netware edge cases
            $VerbosePreference = $VerbosePreferenceAtStartOfFunction

            if ($boolExcludeMappedDriveLetters -eq $true) {
                $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $arrUsedMappedDriveLetters = Get-CimInstance -ClassName 'Win32_NetworkConnection' |
                    ForEach-Object { $_.LocalName } | Where-Object { $_.Length -eq 2 } |
                    Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                    ForEach-Object { $_[0] } |
                    Where-Object { $arrAllPossibleLetters -contains $_ }
                # fifth-, fourth-, and third-to-last bits of pipeline ensures that
                # we have a LocalName like "C:"; second-to-last bit of pipeline
                # strips off the ':', leaving just the capital drive letter; last
                # bit of pipeline ensure that the drive letter is actually a
                # letter; addresses legacy Netware edge cases
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
            # fifth-, fourth-, and third-to-last bits of pipeline ensures that we
            # have a device ID like "C:"; second-to-last bit of pipeline strips off
            # the ':', leaving just the capital drive letter; last bit of pipeline
            # ensure that the drive letter is actually a letter; addresses legacy
            # Netware edge cases
            $VerbosePreference = $VerbosePreferenceAtStartOfFunction

            if ($boolExcludeMappedDriveLetters -eq $true) {
                $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $arrUsedMappedDriveLetters = Get-WmiObject -Class 'Win32_NetworkConnection' |
                    ForEach-Object { $_.LocalName } | Where-Object { $_.Length -eq 2 } |
                    Where-Object { $_[1] -eq ':' } | ForEach-Object { $_.ToUpper() } |
                    ForEach-Object { $_[0] } |
                    Where-Object { $arrAllPossibleLetters -contains $_ }
                # fifth-, fourth-, and third-to-last bits of pipeline ensures that
                # we have a LocalName like "C:"; second-to-last bit of pipeline
                # strips off the ':', leaving just the capital drive letter; last
                # bit of pipeline ensure that the drive letter is actually a
                # letter; addresses legacy Netware edge cases
                $VerbosePreference = $VerbosePreferenceAtStartOfFunction
            } else {
                $arrUsedMappedDriveLetters = $null
            }
        }

        if ($boolExcludePSDriveLetters -eq $true) {
            $arrUsedPSDriveLetters = Get-PSDrive | ForEach-Object { $_.Name } |
                Where-Object { $_.Length -eq 1 } | ForEach-Object { $_.ToUpper() } |
                Where-Object { $arrAllPossibleLetters -contains $_ }
            # Checking for a length of 1 strips out most PSDrives that are not
            # drive letters; making sure that each item in the resultant set
            # matches something in $arrAllPossibleLetters filters out edge cases,
            # like a PSDrive named '1'
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
    #region FunctionHeader #####################################################
    # Gets and returns the access control list (ACL) from a path or object. This
    # function is intended to be used in situations where the Get-Acl cmdlet may
    # fail due to a variety of reasons. This function is designed to suppress
    # errors and return a boolean value indicating whether the operation was
    # successful.
    #
    # Three positional arguments are required:
    #
    # The first argument is a reference to an object (the specific object type will
    # vary depending on the type of object/path supplied in the third argument). If
    # the operation was successful, the referenced object will be populated with
    # the object resulting from Get-Acl. If the operation was unsuccessful, the
    # referenced object will be left unchanged.
    #
    # The second argument is a reference to an object (the specific object type
    # will vary depending on the type of object/path supplied in the third
    # argument). In cases where this function needs to retrieve the object (using
    # Get-Item) to retrieve the access control entry (ACL), the referenced object
    # will be populated with the object resulting from Get-Item. If the function
    # did not need to use Get-Item, the referenced object will be left unchanged.
    #
    # The third argument is a string representing the path to the object for which
    # the ACL is to be retrieved. This path can be a file or folder path, or it can
    # be a registry path (for example).
    #
    # The function returns a boolean value indicating whether the operation was
    # successful. If the operation was successful, the object referenced in the
    # first argument will be populated with the ACL (otherwise the object
    # referenced in the first argument is not changed). If the function needed to
    # retrieve the object (using Get-Item) to get its access control list (ACL),
    # the object referenced in the second argument will be populated with the
    # object (from Get-Item), otherwise the object referenced in the second
    # argument is not changed.
    #
    # Example usage:
    # $objThisFolderPermission = $null
    # $objThis = $null
    # $strThisObjectPath = 'D:\Shares\Share\Accounting'
    # $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath
    #
    # Version 1.0.20241211.0
    #endregion FunctionHeader #####################################################

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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

    #region DownloadLocationNotice #########################################
    # The most up-to-date version of this script can be found on the author's
    # GitHub repository at:
    # https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #########################################

    function Get-ReferenceToLastError {
        #region FunctionHeader #############################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #############################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error
        # that had occurred prior to calling the command in question - that is,
        # the command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had
        # occurred as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

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
            # could be null if $error was cleared; this does not indicate an
            # error.
            # So:
            # If both are null, no error
            # If ($args[0]) is null and ($args[1]) is non-null, error
            # If ($args[0]) is non-null and ($args[1]) is null, no error
            if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }

    function Get-PSVersion {
        #region FunctionHeader #################################################
        # Returns the version of PowerShell that is running, including on the
        # original release of Windows PowerShell (version 1.0)
        #
        # Example:
        # Get-PSVersion
        #
        # This example returns the version of PowerShell that is running. On
        # versions of PowerShell greater than or equal to version 2.0, this
        # function returns the equivalent of $PSVersionTable.PSVersion
        #
        # The function outputs a [version] object representing the version of
        # PowerShell that is running
        #
        # PowerShell 1.0 does not have a $PSVersionTable variable, so this function
        # returns [version]('1.0') on PowerShell 1.0
        #
        # Version 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

        if (Test-Path variable:\PSVersionTable) {
            return ($PSVersionTable.PSVersion)
        } else {
            return ([version]('1.0'))
        }
    }

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
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

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # This needs to be a one-liner for error handling to work!:
    if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) { $versionPS = Get-PSVersion; if ($versionPS.Major -ge 3) { $objThis = Get-Item -LiteralPath $strThisObjectPath -Force; if ($versionPS -ge ([version]'7.3')) { if (@(Get-Module Microsoft.PowerShell.Security).Count -eq 0) { Import-Module Microsoft.PowerShell.Security } $objThisFolderPermission = [System.IO.FileSystemAclExtensions]::GetAccessControl($objThis) } else { $objThisFolderPermission = $objThis.GetAccessControl() } } elseif ($versionPS.Major -eq 2) { $objThis = Get-Item -Path ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force; $objThisFolderPermission = $objThis.GetAccessControl() } else { $objThisFolderPermission = Get-Acl -Path ($strThisObjectPath.Replace('`', '``')) } } else { $objThisFolderPermission = Get-Acl -Path $strThisObjectPath }
    # The above one-liner is a messy variant of the following, which had to be
    # converted to one line to prevent PowerShell v3 from throwing errors on the
    # stack when copy-pasted into the shell (despite there not being any apparent
    # error):
    ###############################################################################
    # TODO: Get-Acl is slow if there is latency between the folder structure and
    # the domain controller, probably because of SID lookups. See if there is a way
    # to speed this up without introducing external dependencies.
    # TODO: Get-Acl allegedly does not exist on PowerShell on Linux (specifically
    # at least not on PowerShell Core v6.2.4 on Ubuntu 18.04.4 or PowerShell v7.0.0
    # on Ubuntu 18.04.4). Confirm this and then re-work the below to get around the
    # issue.
    # if ($strThisObjectPath.Contains('[') -or $strThisObjectPath.Contains(']') -or $strThisObjectPath.Contains('`')) {
    #     # Can't use Get-Acl because Get-Acl doesn't support paths with brackets
    #     # or grave accent marks (backticks)
    #     $versionPS = Get-PSVersion
    #     if ($versionPS.Major -ge 3) {
    #         # PowerShell v3 and newer supports -LiteralPath
    #         $objThis = Get-Item -LiteralPath $strThisObjectPath -Force # -Force parameter is required to get hidden items
    #         if ($versionPS -ge ([version]'7.3')) {
    #             # PowerShell v7.3 and newer do not have
    #             # Microsoft.PowerShell.Security automatically loaded; likewise,
    #             # the .GetAccessControl() method of a folder or file object is
    #             # missing. So, we need to load the Microsoft.PowerShell.Security
    #             # module and then call
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
    #         # We don't need to escape the right square bracket based on testing,
    #         # but we do need to escape the left square bracket. Nevertheless,
    #         # escaping both brackets does work and seems like the safest option.
    #         # Additionally, escape the grave accent mark (backtick).
    #         $objThis = Get-Item -Path ((($strThisObjectPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force # -Force parameter is required to get hidden items
    #         $objThisFolderPermission = $objThis.GetAccessControl()
    #     } else {
    #         # PowerShell v1
    #         # Get-Item -> GetAccessControl() does not work and returns $null on
    #         # PowerShell v1 for some reason.
    #         # And, unfortunately, there is no apparent way to escape left square
    #         # brackets with Get-Acl. However, we can escape the grave accent mark
    #         # (backtick).
    #         $objThisFolderPermission = Get-Acl -Path ($strThisObjectPath.Replace('`', '``'))
    #     }
    # } else {
    #     # No square brackets or grave accent marks (backticks); use Get-Acl
    #     $objThisFolderPermission = Get-Acl -Path $strThisObjectPath
    # }
    ###############################################################################

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        if ($null -ne $objThis) {
            $refOutputObjThis.Value = $objThis
        }
        return $false
    } else {
        $refOutputObjThisFolderPermission.Value = $objThisFolderPermission
        if ($null -ne $objThis) {
            $refOutputObjThis.Value = $objThis
        }
        return $true
    }
}

function Join-PathSafely {
    #region FunctionHeader #################################################
    # Combines two paths into a single path. This function is intended to be
    # used in situations where the Join-Path cmdlet may fail due to a variety
    # of reasons. This function is designed to suppress errors and return a
    # boolean value indicating whether the operation was successful.
    #
    # Three positional arguments are required:
    #
    # The first argument is a reference to a string object that will be
    # populated with the joined path (parent path + child path). If the
    # operation was successful, the referenced string object will be populated
    # with the joined path. If the operation was unsuccessful, the referenced
    # string will be left unchanged.
    #
    # The second argument is a string representing the parent part of the path.
    #
    # The third argument is the child part of the path.
    #
    # The function returns a boolean value indicating whether the operation was
    # successful. If the operation was successful, the joined path will be
    # populated in the string object referenced in the first argument. If the
    # operation was unsuccessful, the referenced string object will be left
    # unchanged.
    #
    # Example usage:
    # $strParentPartOfPath = 'Z:'
    # $strChildPartOfPath = '####FAKE####'
    # $strJoinedPath = $null
    # $boolSuccess = Join-PathSafely ([ref]$strJoinedPath) $strParentPartOfPath $strChildPartOfPath
    #
    # Version 1.0.20241211.1
    #endregion FunctionHeader #################################################

    #region License ########################################################
    # Copyright (c) 2024 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a
    # copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to permit
    # persons to whom the Software is furnished to do so, subject to the
    # following conditions:
    #
    # The above copyright notice and this permission notice shall be included
    # in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    # USE OR OTHER DEALINGS IN THE SOFTWARE.
    #endregion License ########################################################

    #region DownloadLocationNotice #########################################
    # The most up-to-date version of this script can be found on the author's
    # GitHub repository at:
    # https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #########################################

    function Get-ReferenceToLastError {
        #region FunctionHeader #############################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #############################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error
        # that had occurred prior to calling the command in question - that is,
        # the command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had
        # occurred as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

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
            # could be null if $error was cleared; this does not indicate an
            # error.
            # So:
            # If both are null, no error
            # If ($args[0]) is null and ($args[1]) is non-null, error
            # If ($args[0]) is non-null and ($args[1]) is null, no error
            if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    $refOutputJoinedPath = $args[0]
    $strParentPartOfPath = $args[1]
    $strChildPartOfPath = $args[2]

    $strJoinedPath = $null

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty
    # trap statement and then continue on. Likewise, non-terminating errors
    # will also not output anything, but they do not kick to the trap
    # statement; they simply continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Attempt to join the path
    $strJoinedPath = Join-Path $strParentPartOfPath $strChildPartOfPath

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        return $false
    } else {
        $refOutputJoinedPath.Value = $strJoinedPath
        return $true
    }
}

function Get-ChildItemUsingObjectSafely {
    #region FunctionHeader #####################################################
    # Gets the child items of an object in a way that suppresses errors. This
    # function replaces: $obj | Get-ChildItem (see example)
    #
    # Two positional arguments are required:
    #
    # The first argument is a reference to an array of child objects. If the
    # operation was successful, the referenced array will be populated with the
    # child objects returned from Get-ChildItem. If the operation was unsuccessful,
    # the referenced array may be modified, but its contents would be undefined.
    #
    # The second argument is a reference to the parent object. The parent object
    # will be passed to Get-ChildItem.
    #
    # The function returns a boolean value indicating whether the operation was
    # successful. If the operation was successful, the child items will be
    # populated in the array object referenced in the first argument. If the
    # operation was unsuccessful, the referenced array object may still be
    # modified, but its contents should be considered undefined.
    #
    # Example usage:
    # $objThisFolderItem = Get-Item 'D:\Shares\Share\Data'
    # $arrChildObjects = @()
    # $boolSuccess = Get-ChildItemUsingObjectSafely ([ref]$arrChildObjects) ([ref]$objThisFolderItem)
    #
    # Version 1.1.20241211.0
    #endregion FunctionHeader #####################################################

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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
    # GitHub repository at:
    # https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #############################################

    function Get-ReferenceToLastError {
        #region FunctionHeader #############################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #############################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error
        # that had occurred prior to calling the command in question - that is,
        # the command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had
        # occurred as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

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
            # could be null if $error was cleared; this does not indicate an
            # error.
            # So:
            # If both are null, no error
            # If ($args[0]) is null and ($args[1]) is non-null, error
            # If ($args[0]) is non-null and ($args[1]) is null, no error
            if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    $refOutputArrChildObjects = $args[0]
    $refObjThisFolderItem = $args[1]

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do our work
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    $refOutputArrChildObjects.Value = @(($refObjThisFolderItem.Value) | Get-ChildItem -Force)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        return $false
    } else {
        return $true
    }
}

function Wait-PathToBeReady {
    # .SYNOPSIS
    # Waits for the specified path to be available. Also tests that a Join-Path
    # operation can be performed on the specified path and a child item
    #
    # .DESCRIPTION
    # This function waits for the specified path to be available. It also tests that a
    # Join-Path operation can be performed on the specified path and a child item
    #
    # .PARAMETER ReferenceToJoinedPath
    # This parameter is a memory reference to a string variable that will be populated
    # with the joined path (parent path + child path). If no child path was specified,
    # then the parent path will be populated in the referenced variable.
    #
    # .PARAMETER ReferenceToUseGetPSDriveWorkaround
    # This parameter is a memory reference to a boolean variable that indicates whether
    # or not the Get-PSDrive workaround should be used. If the Get-PSDrive workaround
    # is used, then the function will use the Get-PSDrive cmdlet to refresh
    # PowerShell's "understanding" of the available drive letters. This variable is
    # passed by reference to ensure that this function can set the variable to $true if
    # the Get-PSDrive workaround is successful - which improves performance of
    # subsequent runs.
    #
    # .PARAMETER Path
    # This parameter is a string containing the path to be tested for availability, and
    # the parent path to be used in the Join-Path operation. If no child path is
    # specified in the parameter ChildItemPath, then the contents of the Path parameter
    # will populated into the variable referenced in the parameter
    # ReferenceToJoinedPath
    #
    # .PARAMETER ChildItemPath
    # This parameter is a string containing the child path to be used in the Join-Path
    # operation. If ChildItemPath is not specified, or if it contains $null or a blank
    # string, then the path specified by the Path parameter will be populated into the
    # variable referenced in the parameter ReferenceToJoinedPath. However, if
    # ChildItemPath contains a string containing data, then the path specified by the
    # Path parameter will be used as the parent path in the Join-Path operation, and
    # the ChildItemPath will be used as the child path in the Join-Path operation. The
    # joined path will be populated into the variable referenced in the parameter
    # ReferenceToJoinedPath.
    #
    # .PARAMETER MaximumWaitTimeInSeconds
    # This parameter is the maximum amount of seconds to wait for the path to be ready.
    # If the path is not ready within this time, then the function will return $false.
    # By default, this parameter is set to 10 seconds.
    #
    # .PARAMETER DoNotAttemptGetPSDriveWorkaround
    # This parameter is a switch that indicates that the Get-PSDrive workaround should
    # not be attempted. This switch is useful if you know that the Get-PSDrive
    # workaround will not work on your system, or if you know that the Get-PSDrive
    # workaround is not necessary on your system.
    #
    # .EXAMPLE
    # $strJoinedPath = ''
    # $boolUseGetPSDriveWorkaround = $false
    # $boolPathAvailable = Wait-PathToBeReady -Path 'D:\Shares\Share\Data' -ChildItemPath 'Subfolder' -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)
    #
    # .OUTPUTS
    # A boolean value indiciating whether the path is available

    # Version: 1.0.20241216.1

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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
    # GitHub repository at:
    # https://github.com/franklesniak/PowerShell_Resources
    #endregion DownloadLocationNotice #############################################

    param (
        [System.Management.Automation.PSReference]$ReferenceToJoinedPath = ([ref]$null),
        [System.Management.Automation.PSReference]$ReferenceToUseGetPSDriveWorkaround = ([ref]$null),
        [string]$Path,
        [string]$ChildItemPath = '',
        [int]$MaximumWaitTimeInSeconds = 10,
        [switch]$DoNotAttemptGetPSDriveWorkaround
    )

    function Join-PathSafely {
        #region FunctionHeader #################################################
        # Combines two paths into a single path. This function is intended to be
        # used in situations where the Join-Path cmdlet may fail due to a variety
        # of reasons. This function is designed to suppress errors and return a
        # boolean value indicating whether the operation was successful.
        #
        # Three positional arguments are required:
        #
        # The first argument is a reference to a string object that will be
        # populated with the joined path (parent path + child path). If the
        # operation was successful, the referenced string object will be populated
        # with the joined path. If the operation was unsuccessful, the referenced
        # string will be left unchanged.
        #
        # The second argument is a string representing the parent part of the path.
        #
        # The third argument is the child part of the path.
        #
        # The function returns a boolean value indicating whether the operation was
        # successful. If the operation was successful, the joined path will be
        # populated in the string object referenced in the first argument. If the
        # operation was unsuccessful, the referenced string object will be left
        # unchanged.
        #
        # Example usage:
        # $strParentPartOfPath = 'Z:'
        # $strChildPartOfPath = '####FAKE####'
        # $strJoinedPath = $null
        # $boolSuccess = Join-PathSafely ([ref]$strJoinedPath) $strParentPartOfPath $strChildPartOfPath
        #
        # Version 1.0.20241211.1
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

        function Get-ReferenceToLastError {
            #region FunctionHeader #############################################
            # Function returns $null if no errors on on the $error stack;
            # Otherwise, function returns a reference (memory pointer) to the last
            # error that occurred.
            #
            # Version: 1.0.20241211.0
            #endregion FunctionHeader #############################################

            #region License ####################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining
            # a copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
            # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
            # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
            # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            # SOFTWARE.
            #endregion License ####################################################

            #region DownloadLocationNotice #####################################
            # The most up-to-date version of this script can be found on the
            # author's GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #####################################

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return $null
            }
        }

        function Test-ErrorOccurred {
            #region FunctionHeader #############################################
            # Function accepts two positional arguments:
            #
            # The first argument is a reference (memory pointer) to the last error
            # that had occurred prior to calling the command in question - that is,
            # the command that we want to test to see if an error occurred.
            #
            # The second argument is a reference to the last error that had
            # occurred as-of the completion of the command in question.
            #
            # Function returns $true if it appears that an error occurred; $false
            # otherwise
            #
            # Version: 1.0.20241211.0
            #endregion FunctionHeader #############################################

            #region License ####################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining
            # a copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
            # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
            # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
            # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            # SOFTWARE.
            #endregion License ####################################################

            #region DownloadLocationNotice #####################################
            # The most up-to-date version of this script can be found on the
            # author's GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #####################################

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
                # could be null if $error was cleared; this does not indicate an
                # error.
                # So:
                # If both are null, no error
                # If ($args[0]) is null and ($args[1]) is non-null, error
                # If ($args[0]) is non-null and ($args[1]) is null, no error
                if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                    $boolErrorOccurred = $true
                }
            }

            return $boolErrorOccurred
        }

        trap {
            # Intentionally left empty to prevent terminating errors from halting
            # processing
        }

        $refOutputJoinedPath = $args[0]
        $strParentPartOfPath = $args[1]
        $strChildPartOfPath = $args[2]

        $strJoinedPath = $null

        # Retrieve the newest error on the stack prior to doing work
        $refLastKnownError = Get-ReferenceToLastError

        # Store current error preference; we will restore it after we do our work
        $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

        # Set ErrorActionPreference to SilentlyContinue; this will suppress error
        # output. Terminating errors will not output anything, kick to the empty
        # trap statement and then continue on. Likewise, non-terminating errors
        # will also not output anything, but they do not kick to the trap
        # statement; they simply continue on.
        $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

        # Attempt to join the path
        $strJoinedPath = Join-Path $strParentPartOfPath $strChildPartOfPath

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
            return $false
        } else {
            $refOutputJoinedPath.Value = $strJoinedPath
            return $true
        }
    }

    #region Process Input ######################################################
    if ([string]::IsNullOrEmpty($Path) -eq $true) {
        Write-Error 'When calling Wait-PathToBeReady, the Path parameter cannot be null or empty'
        return $false
    }

    if ($DoNotAttemptGetPSDriveWorkaround.IsPresent -eq $true) {
        $boolAttemptGetPSDriveWorkaround = $false
    } else {
        $boolAttemptGetPSDriveWorkaround = $true
    }
    #endregion Process Input ######################################################

    $NONEXISTENT_CHILD_FOLDER = '###FAKE###'
    $boolFunctionReturn = $false

    if ([string]::IsNullOrEmpty($ChildItemPath) -eq $true) {
        $strWorkingChildItemPath = $NONEXISTENT_CHILD_FOLDER
    } else {
        $strWorkingChildItemPath = $ChildItemPath
    }

    if ($null -ne ($ReferenceToUseGetPSDriveWorkaround.Value)) {
        if (($ReferenceToUseGetPSDriveWorkaround.Value) -eq $true) {
            # Use workaround for drives not refreshing in current PowerShell
            # session
            Get-PSDrive | Out-Null
        }
    }

    $doubleSecondsCounter = 0

    # Try Join-Path and sleep for up to $MaximumWaitTimeInSeconds seconds until
    # it's successful
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
            # Either a variable was not passed in, or the variable was passed in
            # and it was set to false
            if ($boolAttemptGetPSDriveWorkaround -eq $true) {
                # Try workaround for drives not refreshing in current PowerShell
                # session
                Get-PSDrive | Out-Null

                # Restart counter and try waiting again
                $doubleSecondsCounter = 0

                # Try Join-Path and sleep for up to $MaximumWaitTimeInSeconds
                # seconds until it's successful
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
    # .SYNOPSIS
    # Waits for the specified path to be unavailable.
    #
    # .DESCRIPTION
    # This function waits for the specified path to be unavailable, e.g., after
    # removing a PSDrive, it may take a few seconds for the drive to be removed
    # from the system. This function will wait for the path to be unavailable for
    # up to the specified number of seconds.
    #
    # .PARAMETER ReferenceToUseGetPSDriveWorkaround
    # This parameter is a memory reference to a boolean variable that indicates
    # whether or not the Get-PSDrive workaround should be used. If the Get-PSDrive
    # workaround is used, then the function will use the Get-PSDrive cmdlet to
    # refresh PowerShell's "understanding" of the available drive letters. This
    # variable is passed by reference to ensure that this function can set the
    # variable to $true if the Get-PSDrive workaround is successful - which
    # improves performance of subsequent runs.
    #
    # .PARAMETER Path
    # This parameter is a string containing the path to be tested for availability.
    #
    # .PARAMETER MaximumWaitTimeInSeconds
    # This parameter is the maximum amount of seconds to wait for the path to be
    # ready. If the path is not ready within this time, then the function will
    # return $false. By default, this parameter is set to 10 seconds.
    #
    # .PARAMETER DoNotAttemptGetPSDriveWorkaround
    # This parameter is a switch that indicates whether or not the Get-PSDrive
    # workaround should be attempted. If this switch is specified, then the
    # Get-PSDrive workaround will not be attempted. This switch is useful if you
    # know that the Get-PSDrive workaround will not work on your system, or if you
    # know that the Get-PSDrive workaround is not necessary on your system.
    #
    # .EXAMPLE
    # $boolUseGetPSDriveWorkaround = $false
    # $boolPathUnavailable = Wait-PathToBeNotReady -Path 'D:\Shares\Share\Data' -ReferenceToUseGetPSDriveWorkaround ([ref]$boolUseGetPSDriveWorkaround)
    #
    # .OUTPUTS
    # A boolean value indiciating whether the path is unavailable
    #
    # .NOTES
    # Version: 1.0.20241216.0

    param (
        [System.Management.Automation.PSReference]$ReferenceToUseGetPSDriveWorkaround = ([ref]$null),
        [string]$Path,
        [int]$MaximumWaitTimeInSeconds = 10,
        [switch]$DoNotAttemptGetPSDriveWorkaround
    )

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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

    #region Process Input ######################################################
    if ([string]::IsNullOrEmpty($Path) -eq $true) {
        Write-Error 'When calling Wait-PathToBeNotReady, the Path parameter cannot be null or empty'
        return $false
    }

    if ($DoNotAttemptGetPSDriveWorkaround.IsPresent -eq $true) {
        $boolAttemptGetPSDriveWorkaround = $false
    } else {
        $boolAttemptGetPSDriveWorkaround = $true
    }
    #endregion Process Input ######################################################

    $boolFunctionReturn = $false

    if ($null -ne ($ReferenceToUseGetPSDriveWorkaround.Value)) {
        if (($ReferenceToUseGetPSDriveWorkaround.Value) -eq $true) {
            # Use workaround for drives not refreshing in current PowerShell session
            Get-PSDrive | Out-Null
        }
    }

    $doubleSecondsCounter = 0

    # Try Test-Path and sleep for up to $MaximumWaitTimeInSeconds seconds until
    # it's successful
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
            # Either a variable was not passed in, or the variable was passed in
            # and it was set to false
            if ($boolAttemptGetPSDriveWorkaround -eq $true) {
                # Try workaround for drives not refreshing in current PowerShell
                # session
                Get-PSDrive | Out-Null

                # Restart counter and try waiting again
                $doubleSecondsCounter = 0

                # Try Test-Path and sleep for up to $MaximumWaitTimeInSeconds
                # seconds until it's successful
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
    # .SYNOPSIS
    # Creates a COM object for Scripting.FileSystemObject.
    #
    # .DESCRIPTION
    # Creates a COM object for Scripting.FileSystemObject. If the object cannot be
    # created, then the function will return $false. If the object is created
    # successfully, then the function will return $true.
    #
    # .PARAMETER ReferenceToStoreObject
    # This parameter is required; it is a reference to an object that will become
    # the FileSystemObject COM object. If the object is created successfully, then
    # the referenced object will be updated, storing the FileSystemObject COM
    # object. If the object is not created successfully, then the referenced
    # variable becomes undefined.
    #
    # .EXAMPLE
    # $objScriptingFileSystemObject = $null
    # $boolSuccess = Get-ScriptingFileSystemObjectSafely -ReferenceToStoreObject ([ref]$objScriptingFileSystemObject)
    #
    # .EXAMPLE
    # $objScriptingFileSystemObject = $null
    # $boolSuccess = Get-ScriptingFileSystemObjectSafely ([ref]$objScriptingFileSystemObject)
    #
    # .INPUTS
    # None. You can't pipe objects to Get-ScriptingFileSystemObjectSafely.
    #
    # .OUTPUTS
    # System.Boolean. Get-ScriptingFileSystemObjectSafely returns a boolean value
    # indiciating whether the Scripting.FileSystemObject object was created
    # successfully. $true means the object was created successfully; $false means
    # there was an error.
    #
    # .NOTES
    # This function also supports the use of an argument, which can be used
    # instead of the parameter.
    #
    # The first argument and only argument is a reference to an object that will
    # become the FileSystemObject COM object. If the object is created
    # successfully, then the referenced object will be updated, storing the
    # FileSystemObject COM object. If the object is not created successfully, then
    # the referenced variable becomes undefined.
    #
    # Version: 1.1.20241216.1

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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

    param (
        [ref]$ReferenceToStoreObject = ([ref]$null)
    )

    #region FunctionsToSupportErrorHandling ####################################
    function Get-ReferenceToLastError {
        #region FunctionHeader #################################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #################################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error that
        # had occurred prior to calling the command in question - that is, the
        # command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had occurred
        # as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

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
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }
    #endregion FunctionsToSupportErrorHandling ####################################

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    #region Assign Parameters and Arguments to Internally-Used Variables #######
    $boolUseArguments = $false
    if ($args.Count -eq 1) {
        # Arguments may have been supplied instead of parameters
        if ($null -eq $ReferenceToStoreObject.Value) {
            # We have one argument and nothing supplied in the parameter
            $boolUseArguments = $true
        }
    }

    if (-not $boolUseArguments) {
        # Use parameters
        $refOutput = $ReferenceToStoreObject
    } else {
        # Use positional arguments
        $refOutput = $args[0]
    }
    #endregion Assign Parameters and Arguments to Internally-Used Variables #######

    # TODO: Validate input

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of
    # this function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Do the work of this function...
    $refOutput.Value = New-Object -ComObject Scripting.FileSystemObject

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        # Error occurred; return failure indicator:
        return $false
    } else {
        # No error occurred; return success indicator:
        return $true
    }
}

function Get-FolderObjectSafelyUsingScriptingFileSystemObject {
    # .SYNOPSIS
    # Get's a Folder object using the Scripting.FileSystemObject COM object.
    #
    # .DESCRIPTION
    # This function gets a Folder object using the Scripting.FileSystemObject COM
    # object. If the Folder object is successfully created, then the function
    # returns $true; otherwise, the function returns $false. If the function
    # returns $false, then the Folder object is not created, and the referenced
    # Folder object is undefined.
    #
    # .PARAMETER ReferenceToFolderObject
    # This parameter is required; it is a reference to an object that will become
    # the Folder COM object created using Scripting.FileSystemObject. If the object
    # is created successfully, then the referenced object will be updated, storing
    # the Folder COM object. If the object is not created successfully, then the
    # referenced variable becomes undefined.
    #
    # .PARAMETER ReferenceToScriptingFileSystemObject
    # This parameter is required; it is a reference to a Scripting.FileSystemObject
    # COM object, which has already been initialized.
    #
    # .PARAMETER Path
    # This parameter is required; it is a string containing the path to the folder
    # for which this function will obtain the Folder COM object.
    #
    # .EXAMPLE
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe'
    # $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject
    # $objFSOFolderObject = $null
    # $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject -ReferenceToFolderObject ([ref]$objFSOFolderObject) -ReferenceToScriptingFileSystemObject ([ref]$objScriptingFileSystemObject) -Path $strPath
    #
    # .EXAMPLE
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe'
    # $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject
    # $objFSOFolderObject = $null
    # $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject ([ref]$objFSOFolderObject) ([ref]$objScriptingFileSystemObject) $strPath
    #
    # .INPUTS
    # None. You can't pipe objects to
    # Get-FolderObjectSafelyUsingScriptingFileSystemObject.
    #
    # .OUTPUTS
    # System.Boolean. Get-FolderObjectSafelyUsingScriptingFileSystemObject returns
    # a boolean value indiciating whether the process completed successfully. $true
    # means the process completed successfully; $false means there was an error.
    #
    # .NOTES
    # This function also supports the use of arguments, which can be used
    # instead of parameters. If arguments are used instead of parameters, then
    # three positional arguments are required:
    #
    # The first argument is a reference to an object that will become the Folder
    # COM object created using Scripting.FileSystemObject. If the object is created
    # successfully, then the referenced object will be updated, storing the Folder
    # COM object. If the object is not created successfully, then the referenced
    # variable becomes undefined.
    #
    # The second argument is a reference to a Scripting.FileSystemObject COM
    # object, which has already been initialized.
    #
    # The third argument is a string containing the path to the folder for which
    # this function will obtain the Folder COM object.
    #
    # Version: 1.1.20241216.0

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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

    param (
        [ref]$ReferenceToFolderObject = ([ref]$null),
        [ref]$ReferenceToScriptingFileSystemObject = ([ref]$null),
        [string]$Path = ''
    )

    #region FunctionsToSupportErrorHandling ####################################
    function Get-ReferenceToLastError {
        #region FunctionHeader #################################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #################################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error that
        # had occurred prior to calling the command in question - that is, the
        # command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had occurred
        # as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

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
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }
    #endregion FunctionsToSupportErrorHandling ####################################

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    #region Assign Parameters and Arguments to Internally-Used Variables #######
    $boolUseArguments = $false
    if ($args.Count -eq 3) {
        # Arguments may have been supplied instead of parameters
        if (($null -eq $ReferenceToFolderObject.Value) -and ($null -eq $ReferenceToScriptingFileSystemObject.Value) -and [string]::IsNullOrEmpty($Path)) {
            # Parameters were not supplied; use arguments
            $boolUseArguments = $true
        }
    }

    if (-not $boolUseArguments) {
        # Use parameters
        $refFSOFolderObject = $ReferenceToFolderObject
        $refScriptingFileSystemObject = $ReferenceToScriptingFileSystemObject
        $strPath = $Path
    } else {
        # Use positional arguments
        $refFSOFolderObject = $args[0]
        $refScriptingFileSystemObject = $args[1]
        $strPath = $args[2]
    }
    #endregion Assign Parameters and Arguments to Internally-Used Variables #######

    # TODO: Validate input

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of
    # this function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Get the folder object
    $refFSOFolderObject.Value = ($refScriptingFileSystemObject.Value).GetFolder($strPath)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        # Error occurred; return failure indicator:
        return $false
    } else {
        # No error occurred; return success indicator:
        return $true
    }
}

function Get-FileObjectSafelyUsingScriptingFileSystemObject {
    # .SYNOPSIS
    # Get's a File object using the Scripting.FileSystemObject COM object.
    #
    # .DESCRIPTION
    # This function gets a File object using the Scripting.FileSystemObject COM
    # object. If the File object is successfully created, then the function
    # returns $true; otherwise, the function returns $false. If the function
    # returns $false, then the File object is not created, and the referenced File
    # object is undefined.
    #
    # .PARAMETER ReferenceToFileObject
    # This parameter is required; it is a reference to an object that will become
    # the File COM object created using Scripting.FileSystemObject. If the object
    # is created successfully, then the referenced object will be updated, storing
    # the File COM object. If the object is not created successfully, then the
    # referenced variable becomes undefined.
    #
    # .PARAMETER ReferenceToScriptingFileSystemObject
    # This parameter is required; it is a reference to a Scripting.FileSystemObject
    # COM object, which has already been initialized.
    #
    # .PARAMETER Path
    # This parameter is required; it is a string containing the path to the file
    # for which this function will obtain the File COM object.
    #
    # .EXAMPLE
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe\Expenses.xlsx'
    # $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject
    # $objFSOFileObject = $null
    # $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject -ReferenceToFileObject ([ref]$objFSOFileObject) -ReferenceToScriptingFileSystemObject ([ref]$objScriptingFileSystemObject) -Path $strPath
    #
    # .EXAMPLE
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe\Expenses.xlsx'
    # $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject
    # $objFSOFileObject = $null
    # $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject ([ref]$objFSOFileObject) ([ref]$objScriptingFileSystemObject) $strPath
    #
    # .INPUTS
    # None. You can't pipe objects to
    # Get-FileObjectSafelyUsingScriptingFileSystemObject.
    #
    # .OUTPUTS
    # System.Boolean. Get-FileObjectSafelyUsingScriptingFileSystemObject returns a
    # boolean value indiciating whether the process completed successfully. $true
    # means the process completed successfully; $false means there was an error.
    #
    # .NOTES
    # This function also supports the use of arguments, which can be used
    # instead of parameters. If arguments are used instead of parameters, then
    # three positional arguments are required:
    #
    # The first argument is a reference to an object that will become the File COM
    # object created using Scripting.FileSystemObject. If the object is created
    # successfully, then the referenced object will be updated, storing the File
    # COM object. If the object is not created successfully, then the referenced
    # variable becomes undefined.
    #
    # The second argument is a reference to a Scripting.FileSystemObject COM
    # object, which has already been initialized.
    #
    # The third argument is a string containing the path to the file for which this
    # function will obtain the File COM object.
    #
    # Version: 1.1.20241216.0

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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

    param (
        [ref]$ReferenceToFileObject = ([ref]$null),
        [ref]$ReferenceToScriptingFileSystemObject = ([ref]$null),
        [string]$Path = ''
    )

    #region FunctionsToSupportErrorHandling ####################################
    function Get-ReferenceToLastError {
        #region FunctionHeader #################################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #################################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error that
        # had occurred prior to calling the command in question - that is, the
        # command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had occurred
        # as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241105.0
        #endregion FunctionHeader #################################################

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region DownloadLocationNotice #########################################
        # The most up-to-date version of this script can be found on the author's
        # GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #########################################

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
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }
    #endregion FunctionsToSupportErrorHandling ####################################

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    #region Assign Parameters and Arguments to Internally-Used Variables #######
    $boolUseArguments = $false
    if ($args.Count -eq 3) {
        # Arguments may have been supplied instead of parameters
        if (($null -eq $ReferenceToFileObject.Value) -and ($null -eq $ReferenceToScriptingFileSystemObject.Value) -and [string]::IsNullOrEmpty($Path)) {
            # Parameters were not supplied; use arguments
            $boolUseArguments = $true
        }
    }

    if (-not $boolUseArguments) {
        # Use parameters
        $refFSOFileObject = $ReferenceToFileObject
        $refScriptingFileSystemObject = $ReferenceToScriptingFileSystemObject
        $strPath = $Path
    } else {
        # Use positional arguments
        $refFSOFileObject = $args[0]
        $refScriptingFileSystemObject = $args[1]
        $strPath = $args[2]
    }
    #endregion Assign Parameters and Arguments to Internally-Used Variables #######

    # TODO: Validate input

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of
    # this function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Get the file object
    $refFSOFileObject.Value = ($refScriptingFileSystemObject.Value).GetFile($strPath)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        # Error occurred; return failure indicator:
        return $false
    } else {
        # No error occurred; return success indicator:
        return $true
    }
}

function Get-DOS83Path {
    # .SYNOPSIS
    # Retrieves the DOS 8.3 path (short path) for a given file or folder path.
    #
    # .DESCRIPTION
    # Given a path to a folder or file, translates the path to its DOS-
    # compatible "8.3" formatted path. DOS did not support long file/folder
    # paths, so, since long file paths were introduced, by default, Windows
    # maintains a DOS-compatible 8.3 file name side-by-side with modern long
    # file/folder names. This function gets the short 8.3 path.
    #
    # .PARAMETER ReferenceToDOS8Dot3Path
    # This parameter is required; it is a reference to a string. If the process
    # was successful, the referenced string will be updated to contain the
    # short DOS 8.3 path. If the process is not successful, then the contents
    # of the string are undefined.
    #
    # .PARAMETER Path
    # This parameter is required; it is a string containing the path of the
    # folder or file for which we want to retrieve its DOS 8.3 file path.
    #
    # .PARAMETER ReferenceToScriptingFileSystemObject
    # This parameter is optional; if specified, it is a reference to a
    # Scripting.FileSystemObject object. Supplying this parameter can speed up
    # performance by avoiding to have to create the Scripting.FileSystemObject
    # every time this function is called.
    #
    # .EXAMPLE
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe.docx'
    # $strDOS83Path = ''
    # $boolSuccess = Get-DOS83Path -ReferenceToDOS8Dot3Path ([ref]$strDOS83Path) -Path $strPath
    #
    # .EXAMPLE
    # $objFSO = New-Object -ComObject Scripting.FileSystemObject
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe.docx'
    # $strDOS83Path = ''
    # $boolSuccess = Get-DOS83Path -ReferenceToDOS8Dot3Path ([ref]$strDOS83Path) -Path $strPath -ReferenceToScriptingFileSystemObject ([ref]$objFSO)
    #
    # .EXAMPLE
    # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe.docx'
    # $strDOS83Path = ''
    # $boolSuccess = Get-DOS83Path ([ref]$strDOS83Path) $strPath
    #
    # .INPUTS
    # None. You can't pipe objects to Get-DOS83Path.
    #
    # .OUTPUTS
    # System.Boolean. Get-DOS83Path returns a boolean value indiciating
    # whether the process completed successfully. $true means the process
    # completed successfully; $false means there was an error.
    #
    # .NOTES
    # This function also supports the use of arguments, which can be used
    # instead of parameters. If arguments are used instead of parameters, then
    # two or three positional arguments are required:
    #
    # The first argument is a reference to a string. If the process was
    # successful, the referenced string will be updated to contain the short
    # DOS 8.3 path. If the process is not successful, then the contents of the
    # string are undefined.
    #
    # The second argument is a string containing the path of the folder or file
    # for which we want to retrieve its DOS 8.3 file path.
    #
    # The third argument is optional. If supplied, it is a reference to a
    # Scripting.FileSystemObject object. Supplying this parameter can speed up
    # performance by avoiding to have to create the Scripting.FileSystemObject
    # every time this function is called.
    #
    # Version: 1.1.20241217.0

    #region License ########################################################
    # Copyright (c) 2024 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a
    # copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to permit
    # persons to whom the Software is furnished to do so, subject to the
    # following conditions:
    #
    # The above copyright notice and this permission notice shall be included
    # in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    # USE OR OTHER DEALINGS IN THE SOFTWARE.
    #endregion License ########################################################

    param (
        [ref]$ReferenceToDOS8Dot3Path = ([ref]$null),
        [string]$Path = '',
        [ref]$ReferenceToScriptingFileSystemObject = ([ref]$null)
    )

    #region FunctionsToSupportErrorHandling ####################################
    function Get-ReferenceToLastError {
        #region FunctionHeader #############################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #############################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error
        # that had occurred prior to calling the command in question - that is,
        # the command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had
        # occurred as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

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
            # could be null if $error was cleared; this does not indicate an
            # error.
            # So:
            # If both are null, no error
            # If ($args[0]) is null and ($args[1]) is non-null, error
            # If ($args[0]) is non-null and ($args[1]) is null, no error
            if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }
    #endregion FunctionsToSupportErrorHandling ####################################

    function Get-ScriptingFileSystemObjectSafely {
        # .SYNOPSIS
        # Creates a COM object for Scripting.FileSystemObject.
        #
        # .DESCRIPTION
        # Creates a COM object for Scripting.FileSystemObject. If the object cannot be
        # created, then the function will return $false. If the object is created
        # successfully, then the function will return $true.
        #
        # .PARAMETER ReferenceToStoreObject
        # This parameter is required; it is a reference to an object that will become
        # the FileSystemObject COM object. If the object is created successfully, then
        # the referenced object will be updated, storing the FileSystemObject COM
        # object. If the object is not created successfully, then the referenced
        # variable becomes undefined.
        #
        # .EXAMPLE
        # $objScriptingFileSystemObject = $null
        # $boolSuccess = Get-ScriptingFileSystemObjectSafely -ReferenceToStoreObject ([ref]$objScriptingFileSystemObject)
        #
        # .EXAMPLE
        # $objScriptingFileSystemObject = $null
        # $boolSuccess = Get-ScriptingFileSystemObjectSafely ([ref]$objScriptingFileSystemObject)
        #
        # .INPUTS
        # None. You can't pipe objects to Get-ScriptingFileSystemObjectSafely.
        #
        # .OUTPUTS
        # System.Boolean. Get-ScriptingFileSystemObjectSafely returns a boolean value
        # indiciating whether the Scripting.FileSystemObject object was created
        # successfully. $true means the object was created successfully; $false means
        # there was an error.
        #
        # .NOTES
        # This function also supports the use of an argument, which can be used
        # instead of the parameter.
        #
        # The first argument and only argument is a reference to an object that will
        # become the FileSystemObject COM object. If the object is created
        # successfully, then the referenced object will be updated, storing the
        # FileSystemObject COM object. If the object is not created successfully, then
        # the referenced variable becomes undefined.
        #
        # Version: 1.1.20241217.0

        #region License ############################################################
        # Copyright (c) 2024 Frank Lesniak
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

        param (
            [ref]$ReferenceToStoreObject = ([ref]$null)
        )

        #region FunctionsToSupportErrorHandling ####################################
        function Get-ReferenceToLastError {
            #region FunctionHeader #############################################
            # Function returns $null if no errors on on the $error stack;
            # Otherwise, function returns a reference (memory pointer) to the last
            # error that occurred.
            #
            # Version: 1.0.20241211.0
            #endregion FunctionHeader #############################################

            #region License ####################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining
            # a copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
            # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
            # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
            # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            # SOFTWARE.
            #endregion License ####################################################

            #region DownloadLocationNotice #####################################
            # The most up-to-date version of this script can be found on the
            # author's GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #####################################

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return $null
            }
        }

        function Test-ErrorOccurred {
            #region FunctionHeader #############################################
            # Function accepts two positional arguments:
            #
            # The first argument is a reference (memory pointer) to the last error
            # that had occurred prior to calling the command in question - that is,
            # the command that we want to test to see if an error occurred.
            #
            # The second argument is a reference to the last error that had
            # occurred as-of the completion of the command in question.
            #
            # Function returns $true if it appears that an error occurred; $false
            # otherwise
            #
            # Version: 1.0.20241211.0
            #endregion FunctionHeader #############################################

            #region License ####################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining
            # a copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
            # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
            # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
            # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            # SOFTWARE.
            #endregion License ####################################################

            #region DownloadLocationNotice #####################################
            # The most up-to-date version of this script can be found on the
            # author's GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #####################################

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
                # could be null if $error was cleared; this does not indicate an
                # error.
                # So:
                # If both are null, no error
                # If ($args[0]) is null and ($args[1]) is non-null, error
                # If ($args[0]) is non-null and ($args[1]) is null, no error
                if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                    $boolErrorOccurred = $true
                }
            }

            return $boolErrorOccurred
        }
        #endregion FunctionsToSupportErrorHandling ####################################

        trap {
            # Intentionally left empty to prevent terminating errors from halting
            # processing
        }

        #region Assign Parameters and Arguments to Internally-Used Variables #######
        $boolUseArguments = $false
        if ($args.Count -eq 1) {
            # Arguments may have been supplied instead of parameters
            if ($null -eq $ReferenceToStoreObject.Value) {
                # We have one argument and nothing supplied in the parameter
                $boolUseArguments = $true
            }
        }

        if (-not $boolUseArguments) {
            # Use parameters
            $refOutput = $ReferenceToStoreObject
        } else {
            # Use positional arguments
            $refOutput = $args[0]
        }
        #endregion Assign Parameters and Arguments to Internally-Used Variables #######

        # TODO: Validate input

        # Retrieve the newest error on the stack prior to doing work
        $refLastKnownError = Get-ReferenceToLastError

        # Store current error preference; we will restore it after we do the work of
        # this function
        $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

        # Set ErrorActionPreference to SilentlyContinue; this will suppress error
        # output. Terminating errors will not output anything, kick to the empty trap
        # statement and then continue on. Likewise, non-terminating errors will also
        # not output anything, but they do not kick to the trap statement; they simply
        # continue on.
        $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

        # Do the work of this function...
        $refOutput.Value = New-Object -ComObject Scripting.FileSystemObject

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
            # Error occurred; return failure indicator:
            return $false
        } else {
            # No error occurred; return success indicator:
            return $true
        }
    }

    function Get-FolderObjectSafelyUsingScriptingFileSystemObject {
        # .SYNOPSIS
        # Get's a Folder object using the Scripting.FileSystemObject COM object.
        #
        # .DESCRIPTION
        # This function gets a Folder object using the Scripting.FileSystemObject
        # COM object. If the Folder object is successfully created, then the
        # function returns $true; otherwise, the function returns $false. If the
        # function returns $false, then the Folder object is not created, and the
        # referenced Folder object is undefined.
        #
        # .PARAMETER ReferenceToFolderObject
        # This parameter is required; it is a reference to an object that will
        # become the Folder COM object created using Scripting.FileSystemObject. If
        # the object is created successfully, then the referenced object will be
        # updated, storing the Folder COM object. If the object is not created
        # successfully, then the referenced variable becomes undefined.
        #
        # .PARAMETER ReferenceToScriptingFileSystemObject
        # This parameter is required; it is a reference to a
        # Scripting.FileSystemObject COM object, which has already been
        # initialized.
        #
        # .PARAMETER Path
        # This parameter is required; it is a string containing the path to the
        # folder for which this function will obtain the Folder COM object.
        #
        # .EXAMPLE
        # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe'
        # $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject
        # $objFSOFolderObject = $null
        # $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject -ReferenceToFolderObject ([ref]$objFSOFolderObject) -ReferenceToScriptingFileSystemObject ([ref]$objScriptingFileSystemObject) -Path $strPath
        #
        # .EXAMPLE
        # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe'
        # $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject
        # $objFSOFolderObject = $null
        # $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject ([ref]$objFSOFolderObject) ([ref]$objScriptingFileSystemObject) $strPath
        #
        # .INPUTS
        # None. You can't pipe objects to
        # Get-FolderObjectSafelyUsingScriptingFileSystemObject.
        #
        # .OUTPUTS
        # System.Boolean. Get-FolderObjectSafelyUsingScriptingFileSystemObject
        # returns a boolean value indiciating whether the process completed
        # successfully. $true means the process completed successfully; $false
        # means there was an error.
        #
        # .NOTES
        # This function also supports the use of arguments, which can be used
        # instead of parameters. If arguments are used instead of parameters, then
        # three positional arguments are required:
        #
        # The first argument is a reference to an object that will become the
        # Folder COM object created using Scripting.FileSystemObject. If the object
        # is created successfully, then the referenced object will be updated,
        # storing the Folder COM object. If the object is not created successfully,
        # then the referenced variable becomes undefined.
        #
        # The second argument is a reference to a Scripting.FileSystemObject COM
        # object, which has already been initialized.
        #
        # The third argument is a string containing the path to the folder for
        # which this function will obtain the Folder COM object.
        #
        # Version: 1.1.20241217.0

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        param (
            [ref]$ReferenceToFolderObject = ([ref]$null),
            [ref]$ReferenceToScriptingFileSystemObject = ([ref]$null),
            [string]$Path = ''
        )

        #region FunctionsToSupportErrorHandling ################################
        function Get-ReferenceToLastError {
            #region FunctionHeader #############################################
            # Function returns $null if no errors on on the $error stack;
            # Otherwise, function returns a reference (memory pointer) to the last
            # error that occurred.
            #
            # Version: 1.0.20241211.0
            #endregion FunctionHeader #############################################

            #region License ####################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining
            # a copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
            # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
            # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
            # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            # SOFTWARE.
            #endregion License ####################################################

            #region DownloadLocationNotice #####################################
            # The most up-to-date version of this script can be found on the
            # author's GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #####################################

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return $null
            }
        }

        function Test-ErrorOccurred {
            #region FunctionHeader #############################################
            # Function accepts two positional arguments:
            #
            # The first argument is a reference (memory pointer) to the last error
            # that had occurred prior to calling the command in question - that is,
            # the command that we want to test to see if an error occurred.
            #
            # The second argument is a reference to the last error that had
            # occurred as-of the completion of the command in question.
            #
            # Function returns $true if it appears that an error occurred; $false
            # otherwise
            #
            # Version: 1.0.20241211.0
            #endregion FunctionHeader #############################################

            #region License ####################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining
            # a copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
            # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
            # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
            # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            # SOFTWARE.
            #endregion License ####################################################

            #region DownloadLocationNotice #####################################
            # The most up-to-date version of this script can be found on the
            # author's GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #####################################

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
                # could be null if $error was cleared; this does not indicate an
                # error.
                # So:
                # If both are null, no error
                # If ($args[0]) is null and ($args[1]) is non-null, error
                # If ($args[0]) is non-null and ($args[1]) is null, no error
                if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                    $boolErrorOccurred = $true
                }
            }

            return $boolErrorOccurred
        }
        #endregion FunctionsToSupportErrorHandling ################################

        trap {
            # Intentionally left empty to prevent terminating errors from halting
            # processing
        }

        #region Assign Parameters and Arguments to Internally-Used Variables ###
        $boolUseArguments = $false
        if ($args.Count -eq 3) {
            # Arguments may have been supplied instead of parameters
            if (($null -eq $ReferenceToFolderObject.Value) -and ($null -eq $ReferenceToScriptingFileSystemObject.Value) -and [string]::IsNullOrEmpty($Path)) {
                # Parameters were not supplied; use arguments
                $boolUseArguments = $true
            }
        }

        if (-not $boolUseArguments) {
            # Use parameters
            $refFSOFolderObject = $ReferenceToFolderObject
            $refScriptingFileSystemObject = $ReferenceToScriptingFileSystemObject
            $strPath = $Path
        } else {
            # Use positional arguments
            $refFSOFolderObject = $args[0]
            $refScriptingFileSystemObject = $args[1]
            $strPath = $args[2]
        }
        #endregion Assign Parameters and Arguments to Internally-Used Variables ###

        # TODO: Validate input

        # Retrieve the newest error on the stack prior to doing work
        $refLastKnownError = Get-ReferenceToLastError

        # Store current error preference; we will restore it after we do the work
        # of this function
        $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

        # Set ErrorActionPreference to SilentlyContinue; this will suppress error
        # output. Terminating errors will not output anything, kick to the empty
        # trap statement and then continue on. Likewise, non-terminating errors
        # will also not output anything, but they do not kick to the trap
        # statement; they simply continue on.
        $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

        # Get the folder object
        $refFSOFolderObject.Value = ($refScriptingFileSystemObject.Value).GetFolder($strPath)

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
            # Error occurred; return failure indicator:
            return $false
        } else {
            # No error occurred; return success indicator:
            return $true
        }
    }

    function Get-FileObjectSafelyUsingScriptingFileSystemObject {
        # .SYNOPSIS
        # Get's a File object using the Scripting.FileSystemObject COM object.
        #
        # .DESCRIPTION
        # This function gets a File object using the Scripting.FileSystemObject COM
        # object. If the File object is successfully created, then the function
        # returns $true; otherwise, the function returns $false. If the function
        # returns $false, then the File object is not created, and the referenced
        # File object is undefined.
        #
        # .PARAMETER ReferenceToFileObject
        # This parameter is required; it is a reference to an object that will
        # become the File COM object created using Scripting.FileSystemObject. If
        # the object is created successfully, then the referenced object will be
        # updated, storing the File COM object. If the object is not created
        # successfully, then the referenced variable becomes undefined.
        #
        # .PARAMETER ReferenceToScriptingFileSystemObject
        # This parameter is required; it is a reference to a
        # Scripting.FileSystemObject COM object, which has already been
        # initialized.
        #
        # .PARAMETER Path
        # This parameter is required; it is a string containing the path to the
        # file for which this function will obtain the File COM object.
        #
        # .EXAMPLE
        # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe\Expenses.xlsx'
        # $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject
        # $objFSOFileObject = $null
        # $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject -ReferenceToFileObject ([ref]$objFSOFileObject) -ReferenceToScriptingFileSystemObject ([ref]$objScriptingFileSystemObject) -Path $strPath
        #
        # .EXAMPLE
        # $strPath = 'D:\Shares\Human Resources\Personnel Information\Employee Files\John Doe\Expenses.xlsx'
        # $objScriptingFileSystemObject = New-Object -ComObject Scripting.FileSystemObject
        # $objFSOFileObject = $null
        # $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject ([ref]$objFSOFileObject) ([ref]$objScriptingFileSystemObject) $strPath
        #
        # .INPUTS
        # None. You can't pipe objects to
        # Get-FileObjectSafelyUsingScriptingFileSystemObject.
        #
        # .OUTPUTS
        # System.Boolean. Get-FileObjectSafelyUsingScriptingFileSystemObject
        # returns a boolean value indiciating whether the process completed
        # successfully. $true means the process completed successfully; $false
        # means there was an error.
        #
        # .NOTES
        # This function also supports the use of arguments, which can be used
        # instead of parameters. If arguments are used instead of parameters, then
        # three positional arguments are required:
        #
        # The first argument is a reference to an object that will become the File
        # COM object created using Scripting.FileSystemObject. If the object is
        # created successfully, then the referenced object will be updated, storing
        # the File COM object. If the object is not created successfully, then the
        # referenced variable becomes undefined.
        #
        # The second argument is a reference to a Scripting.FileSystemObject COM
        # object, which has already been initialized.
        #
        # The third argument is a string containing the path to the file for which
        # this function will obtain the File COM object.
        #
        # Version: 1.1.20241217.0

        #region License ########################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to permit
        # persons to whom the Software is furnished to do so, subject to the
        # following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
        # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
        # USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        param (
            [ref]$ReferenceToFileObject = ([ref]$null),
            [ref]$ReferenceToScriptingFileSystemObject = ([ref]$null),
            [string]$Path = ''
        )

        #region FunctionsToSupportErrorHandling ################################
        function Get-ReferenceToLastError {
            #region FunctionHeader #############################################
            # Function returns $null if no errors on on the $error stack;
            # Otherwise, function returns a reference (memory pointer) to the last
            # error that occurred.
            #
            # Version: 1.0.20241211.0
            #endregion FunctionHeader #############################################

            #region License ####################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining
            # a copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
            # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
            # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
            # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            # SOFTWARE.
            #endregion License ####################################################

            #region DownloadLocationNotice #####################################
            # The most up-to-date version of this script can be found on the
            # author's GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #####################################

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return $null
            }
        }

        function Test-ErrorOccurred {
            #region FunctionHeader #############################################
            # Function accepts two positional arguments:
            #
            # The first argument is a reference (memory pointer) to the last error
            # that had occurred prior to calling the command in question - that is,
            # the command that we want to test to see if an error occurred.
            #
            # The second argument is a reference to the last error that had
            # occurred as-of the completion of the command in question.
            #
            # Function returns $true if it appears that an error occurred; $false
            # otherwise
            #
            # Version: 1.0.20241211.0
            #endregion FunctionHeader #############################################

            #region License ####################################################
            # Copyright (c) 2024 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining
            # a copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
            # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
            # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
            # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            # SOFTWARE.
            #endregion License ####################################################

            #region DownloadLocationNotice #####################################
            # The most up-to-date version of this script can be found on the
            # author's GitHub repository at:
            # https://github.com/franklesniak/PowerShell_Resources
            #endregion DownloadLocationNotice #####################################

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
                # could be null if $error was cleared; this does not indicate an
                # error.
                # So:
                # If both are null, no error
                # If ($args[0]) is null and ($args[1]) is non-null, error
                # If ($args[0]) is non-null and ($args[1]) is null, no error
                if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                    $boolErrorOccurred = $true
                }
            }

            return $boolErrorOccurred
        }
        #endregion FunctionsToSupportErrorHandling ################################

        trap {
            # Intentionally left empty to prevent terminating errors from halting
            # processing
        }

        #region Assign Parameters and Arguments to Internally-Used Variables ###
        $boolUseArguments = $false
        if ($args.Count -eq 3) {
            # Arguments may have been supplied instead of parameters
            if (($null -eq $ReferenceToFileObject.Value) -and ($null -eq $ReferenceToScriptingFileSystemObject.Value) -and [string]::IsNullOrEmpty($Path)) {
                # Parameters were not supplied; use arguments
                $boolUseArguments = $true
            }
        }

        if (-not $boolUseArguments) {
            # Use parameters
            $refFSOFileObject = $ReferenceToFileObject
            $refScriptingFileSystemObject = $ReferenceToScriptingFileSystemObject
            $strPath = $Path
        } else {
            # Use positional arguments
            $refFSOFileObject = $args[0]
            $refScriptingFileSystemObject = $args[1]
            $strPath = $args[2]
        }
        #endregion Assign Parameters and Arguments to Internally-Used Variables ###

        # TODO: Validate input

        # Retrieve the newest error on the stack prior to doing work
        $refLastKnownError = Get-ReferenceToLastError

        # Store current error preference; we will restore it after we do the work
        # of this function
        $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

        # Set ErrorActionPreference to SilentlyContinue; this will suppress error
        # output. Terminating errors will not output anything, kick to the empty
        # trap statement and then continue on. Likewise, non-terminating errors
        # will also not output anything, but they do not kick to the trap
        # statement; they simply continue on.
        $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

        # Get the file object
        $refFSOFileObject.Value = ($refScriptingFileSystemObject.Value).GetFile($strPath)

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
            # Error occurred; return failure indicator:
            return $false
        } else {
            # No error occurred; return success indicator:
            return $true
        }
    }

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    #region Assign Parameters and Arguments to Internally-Used Variables #######
    $boolUseArguments = $false
    if (($args.Count -ge 2) -or ($args.Count -le 3)) {
        # Arguments may have been supplied instead of parameters
        if (($null -eq $ReferenceToDOS8Dot3Path.Value) -and ([string]::IsNullOrEmpty($Path)) -and ($null -eq $ReferenceToScriptingFileSystemObject.Value)) {
            # All parameters are uninitialized; arguments were definitely used
            $boolUseArguments = $true
        }
    }

    if (-not $boolUseArguments) {
        # Use parameters
        $refDOS83Path = $ReferenceToDOS8Dot3Path
        $strPath = $Path
        $refScriptingFileSystemObject = $ReferenceToScriptingFileSystemObject
    } else {
        # Use positional arguments
        $refDOS83Path = $args[0]
        $strPath = $args[1]
        if ($args.Count -gt 2) {
            $refScriptingFileSystemObject = $args[2]
        }
    }
    #endregion Assign Parameters and Arguments to Internally-Used Variables #######

    # Get the Scripting.FileSystemObject if necessary
    if ($null -eq $refScriptingFileSystemObject.Value) {
        $boolUseReferencedFSO = $false
        $objScriptingFileSystemObject = $null
        $boolSuccess = Get-ScriptingFileSystemObjectSafely -ReferenceToStoreObject ([ref]$objScriptingFileSystemObject)
        if ($boolSuccess -eq $false) {
            # Error occurred
            # TODO: Use alternate method following P/invoke - see below
            return $false
        }
    } else {
        $boolUseReferencedFSO = $true
    }

    # Get the folder or file object from Scripting.FileSystemObject
    $objFSOFolderOrFileObject = $null
    # Try to retrieve a folder object first
    if ($boolUseReferencedFSO) {
        $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject -ReferenceToFolderObject ([ref]$objFSOFolderOrFileObject) -ReferenceToScriptingFileSystemObject $refScriptingFileSystemObject -Path $strPath
    } else {
        $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject -ReferenceToFolderObject ([ref]$objFSOFolderOrFileObject) -ReferenceToScriptingFileSystemObject ([ref]$objScriptingFileSystemObject) -Path $strPath
    }
    if ($boolSuccess -eq $false) {
        # Failed to retrieve folder object; perhaps it's a file?
        if ($boolUseReferencedFSO) {
            $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject -ReferenceToFileObject ([ref]$objFSOFolderOrFileObject) -ReferenceToScriptingFileSystemObject $refScriptingFileSystemObject -Path $strPath
        } else {
            $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject -ReferenceToFileObject ([ref]$objFSOFolderOrFileObject) -ReferenceToScriptingFileSystemObject ([ref]$objScriptingFileSystemObject) -Path $strPath
        }
        if ($boolSuccess -eq $false) {
            # Error occurred
            # TODO: Use alternate method following P/invoke - see below
            return $false
        }
    }

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of
    # this function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Access the short path
    $refDOS83Path.Value = $objFSOFolderOrFileObject.ShortPath

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        # TODO: Try P/invoke approach
        # if (-not ([System.Management.Automation.PSTypeName]'Util.NativeMethods').Type) {
        # Add-Type -Namespace Util -Name NativeMethods -MemberDefinition @"
        #     using System;
        #     using System.Text;
        #     using System.Runtime.InteropServices;

        #     public static class NativeMethods {
        #         [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        #         public static extern int GetShortPathName(string lpszLongPath, StringBuilder lpszShortPath, int cchBuffer);

        #         public static string GetShortPath(string longPath) {
        #             if (string.IsNullOrEmpty(longPath))
        #                 throw new ArgumentException("Path cannot be null or empty.", nameof(longPath));

        #             // First call to get the required buffer size
        #             int size = GetShortPathName(longPath, null, 0);
        #             if (size == 0)
        #                 throw new System.ComponentModel.Win32Exception();

        #             StringBuilder shortPath = new StringBuilder(size);
        #             int result = GetShortPathName(longPath, shortPath, shortPath.Capacity);
        #             if (result == 0)
        #                 throw new System.ComponentModel.Win32Exception();

        #             return shortPath.ToString();
        #         }
        #     }
        #     "@
        # }
        # # Add-Type steps moved out of the function to a separate script or module for clarity and performance.

        # <#
        # .SYNOPSIS
        # Retrieves the DOS 8.3 short path for a given file or folder.

        # .DESCRIPTION
        # This function uses the Win32 GetShortPathName API to return the DOS 8.3 format of a given path.
        # The path must exist on the filesystem. If the path does not exist, an exception will be thrown.

        # .PARAMETER Path
        # The full path to a file or directory.

        # .EXAMPLE
        # Get-ShortPathName -Path "C:\Program Files\Microsoft Office"

        # .EXAMPLE
        # Get-ShortPathName -Path "C:\Windows\System32"

        # .NOTES
        # Requires the Util.NativeMethods class to be defined beforehand.
        # #>
        # function Get-ShortPathName {
        #     [CmdletBinding()]
        #     param(
        #         [Parameter(Mandatory=$true)]
        #         [string]$Path
        #     )

        #     # Validate input
        #     if ([string]::IsNullOrWhiteSpace($Path)) {
        #         throw [System.ArgumentException]::new("Path cannot be empty or whitespace.", "Path")
        #     }

        #     # Ensure path exists before attempting to retrieve short path
        #     if (-not (Test-Path $Path)) {
        #         throw [System.IO.FileNotFoundException]::new("The specified path does not exist.", $Path)
        #     }

        #     # Retrieve and return the short path
        #     try {
        #         return [Util.NativeMethods]::GetShortPath($Path)
        #     }
        #     catch [System.ComponentModel.Win32Exception] {
        #         # Provide a more descriptive error if the native call fails
        #         throw [System.InvalidOperationException]::new("Failed to retrieve the short path name for the specified path.", $_.Exception)
        #     }
        # }

        # Error occurred; return failure indicator:
        return $false
    } else {
        # No error occurred; return success indicator:
        return $true
    }
}

function Test-ValidSID {
    # .SYNOPSIS
    # Tests to see if the supplied, referenced object is a SID
    #
    # .DESCRIPTION
    # Validates whether the referenced object is a security identifier (SID).
    # An object is considered to be a SID if it is or can be converted to type
    # System.Security.Principal.SecurityIdentifier. If an object is a SID, this
    # function returns $true; otherwise, it returns $false.
    #
    # .PARAMETER ReferenceToObject
    # This parameter is required; it is a reference to an object that will be
    # tested to determine if it is a SID.
    #
    # .EXAMPLE
    # $boolResult = Test-ValidSID -ReferenceToObject ([ref]'S-1-5-21-1234567890-1234567890-1234567890-1000')
    #
    # .EXAMPLE
    # $boolResult = Test-ValidSID ([ref]'S-1-5-21-1234567890-1234567890-1234567890-1000')
    #
    # .INPUTS
    # None. You can't pipe objects to Test-ValidSID.
    #
    # .OUTPUTS
    # System.Boolean. Test-ValidSID returns a boolean value indiciating
    # whether the supplied object was a SID. $true means the object was a SID;
    # $false means the supplied object was not a SID.
    #
    # .NOTES
    # This function also supports the use of an argument instead of a
    # parameter. If an argument is supplied instead of the parameter, then one
    # positional argument is required: it is a reference to an object that will
    # be tested to determine if it is a SID.
    #
    # Version: 3.0.20241217.0

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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

    #region Acknowledgements ###################################################
    # Thanks to Friedrich Weinmann who suggested an alternative way to test for a
    # SID:
    # https://twitter.com/FredWeinmann/status/1675513443615404032?s=20
    # retrieved on 2023-07-19
    #endregion Acknowledgements ###################################################

    param (
        [ref]$ReferenceToObject = ([ref]$null)
    )

    #region FunctionsToSupportErrorHandling ####################################
    function Get-ReferenceToLastError {
        #region FunctionHeader #############################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #############################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error
        # that had occurred prior to calling the command in question - that is,
        # the command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had
        # occurred as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

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
            # could be null if $error was cleared; this does not indicate an
            # error.
            # So:
            # If both are null, no error
            # If ($args[0]) is null and ($args[1]) is non-null, error
            # If ($args[0]) is non-null and ($args[1]) is null, no error
            if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }
    #endregion FunctionsToSupportErrorHandling ####################################

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    #region Assign Parameters and Arguments to Internally-Used Variables #######
    $boolUseArguments = $false
    if ($args.Count -eq 1) {
        # Arguments may have been supplied instead of parameters
        if ($null -eq $ReferenceToObject.Value) {
            # No valid data was supplied via a parameter, so assume arguments
            # were used
            $boolUseArguments = $true
        }
    }

    if (-not $boolUseArguments) {
        # Use parameters
        $refObjectToTest = $ReferenceToObject
    } else {
        # Use positional arguments
        $refObjectToTest = $args[0]
    }
    #endregion Assign Parameters and Arguments to Internally-Used Variables #######

    # TODO: Validate input

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of
    # this function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # This shouldn't error, even if the referenced object is not a SID, but we play
    # it safe and store the result in $objSID. $objSID should be $null if the
    # referenced object is not a SID
    $objSID = ($refObjectToTest.Value) -as [System.Security.Principal.SecurityIdentifier]

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        # Error occurred; return indicator that object is not a SID:
        return $false
    } else {
        # No error occurred
        # If $objSID is not $null, then the referenced object was a SID
        # If $objSID is $null, then the referenced object was not a SID
        return ($null -ne $objSID)
    }
}

function Remove-SpecificAccessRuleRobust {
    # .SYNOPSIS
    # Removes an access rule from an object.
    #
    # .DESCRIPTION
    # This function removes a specific access rule from a
    # System.Security.AccessControl.DirectorySecurity or similar object "safely"
    # (i.e., without throwing any errors should the process fail) and in a way that
    # automaticaly retries if an error occurs.
    #
    # .PARAMETER CurrentAttemptNumber
    # This parameter is required; it is an integer indicating the current attempt
    # number. When calling this function for the first time, it should be 1.
    #
    # .PARAMETER MaxAttempts
    # This parameter is required; it is an integer representing the maximum number
    # of attempts that the function will observe before giving up.
    #
    # .PARAMETER ReferenceToAccessControlListObject
    # This parameter is required; it is a reference to a
    # System.Security.AccessControl.DirectorySecurity or similar object from
    # which the access control entry will be removed.
    #
    # .PARAMETER ReferenceToAccessRuleObject
    # This parameter is required; it is a reference to a
    # System.Security.AccessControl.FileSystemAccessRule or similar object that
    # will be removed from the access control list.
    #
    # .EXAMPLE
    # $item = Get-Item 'D:\Shared\Human_Resources'
    # $directorySecurity = $item.GetAccessControl()
    # $arrFileSystemAccessRules = @($directorySecurity.Access)
    # $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 8 -ReferenceToAccessControlListObject ([ref]$directorySecurity) -ReferenceToAccessRuleObject ([ref]($arrFileSystemAccessRules[0]))
    #
    # .EXAMPLE
    # $item = Get-Item 'D:\Shared\Human_Resources'
    # $directorySecurity = $item.GetAccessControl()
    # $arrFileSystemAccessRules = @($directorySecurity.Access)
    # $boolSuccess = Remove-SpecificAccessRuleRobust 1 8 ([ref]$directorySecurity) ([ref]($arrFileSystemAccessRules[0]))
    #
    # .INPUTS
    # None. You can't pipe objects to Remove-SpecificAccessRuleRobust.
    #
    # .OUTPUTS
    # System.Boolean. Remove-SpecificAccessRuleRobust returns a boolean value
    # indiciating whether the process completed successfully. $true means the
    # process completed successfully; $false means there was an error.
    #
    # .NOTES
    # This function also supports the use of arguments, which can be used
    # instead of parameters. If arguments are used instead of parameters, then
    # four positional arguments are required:
    #
    # The first argument is an integer indicating the current attempt number. When
    # calling this function for the first time, it should be 1.
    #
    # The second argument is an integer representing the maximum number of attempts
    # that the function will observe before giving up.
    #
    # The third argument is a reference to a
    # System.Security.AccessControl.DirectorySecurity or similar object from which
    # the access control entry will be removed.
    #
    # The fourth argument is a reference to a
    # System.Security.AccessControl.FileSystemAccessRule or similar object that
    # will be removed from the access control list.
    #
    # Version: 1.1.20241217.0

    #region License ############################################################
    # Copyright (c) 2024 Frank Lesniak
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

    param (
        [int]$CurrentAttemptNumber = 1,
        [int]$MaxAttempts = 1,
        [ref]$ReferenceToAccessControlListObject = ([ref]$null),
        [ref]$ReferenceToAccessRuleObject = ([ref]$null)
    )

    #region FunctionsToSupportErrorHandling ####################################
    function Get-ReferenceToLastError {
        #region FunctionHeader #############################################
        # Function returns $null if no errors on on the $error stack;
        # Otherwise, function returns a reference (memory pointer) to the last
        # error that occurred.
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return $null
        }
    }

    function Test-ErrorOccurred {
        #region FunctionHeader #############################################
        # Function accepts two positional arguments:
        #
        # The first argument is a reference (memory pointer) to the last error
        # that had occurred prior to calling the command in question - that is,
        # the command that we want to test to see if an error occurred.
        #
        # The second argument is a reference to the last error that had
        # occurred as-of the completion of the command in question.
        #
        # Function returns $true if it appears that an error occurred; $false
        # otherwise
        #
        # Version: 1.0.20241211.0
        #endregion FunctionHeader #############################################

        #region License ####################################################
        # Copyright (c) 2024 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        #region DownloadLocationNotice #####################################
        # The most up-to-date version of this script can be found on the
        # author's GitHub repository at:
        # https://github.com/franklesniak/PowerShell_Resources
        #endregion DownloadLocationNotice #####################################

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
            # could be null if $error was cleared; this does not indicate an
            # error.
            # So:
            # If both are null, no error
            # If ($args[0]) is null and ($args[1]) is non-null, error
            # If ($args[0]) is non-null and ($args[1]) is null, no error
            if (($null -eq ($args[0])) -and ($null -ne ($args[1]))) {
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }
    #endregion FunctionsToSupportErrorHandling ####################################

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    #region Assign Parameters and Arguments to Internally-Used Variables #######
    $boolUseArguments = $false
    if ($args.Count -eq 4) {
        # Arguments may have been supplied instead of parameters
        if (($CurrentAttemptNumber -eq 1) -and ($MaxAttempts -eq 1) -and ($null -eq $ReferenceToAccessControlListObject.Value) -and ($null -eq $ReferenceToAccessRuleObject.Value)) {
            # Parameters all match default values, so it's safe to say that
            # arguments were used instead of parameters
            $boolUseArguments = $true
        }
    }

    if (-not $boolUseArguments) {
        # Use parameters
        $intCurrentAttemptNumber = $CurrentAttemptNumber
        $intMaximumAttempts = $MaxAttempts
        $refAccessControlSecurity = $ReferenceToAccessControlListObject
        $refAccessControlAccessRule = $ReferenceToAccessRuleObject
    } else {
        # Use positional arguments
        $intCurrentAttemptNumber = $args[0]
        $intMaximumAttempts = $args[1]
        $refAccessControlSecurity = $args[2]
        $refAccessControlAccessRule = $args[3]
    }
    #endregion Assign Parameters and Arguments to Internally-Used Variables #######

    # TODO: Validate input

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of
    # this function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Remove the access rule/access control entry from the list
    ($refAccessControlSecurity.Value).RemoveAccessRuleSpecific($refAccessControlAccessRule.Value)

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
        # Error occurred
        if ($intCurrentAttemptNumber -lt $intMaximumAttempts) {
            Start-Sleep -Seconds ([math]::Pow(2, $intCurrentAttemptNumber))

            $objResultIndicator = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber ($intCurrentAttemptNumber + 1) -MaxAttempts $intMaximumAttempts -ReferenceToAccessControlListObject $refAccessControlSecurity -ReferenceToAccessRuleObject $refAccessControlAccessRule
            return $objResultIndicator
        } else {
            # Number of attempts exceeded maximum; return failure indicator:
            return $false
        }
    } else {
        # No error occurred; return success indicator:
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
        $strVerboseMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Path: "' + $strThisObjectPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $intIterativeRepairState + '; Use Get-Path workaround: ' + $boolUseGetPSDriveWorkaround + '; Last substituted path: "' + $strLastSubstitutedPath + '"; Use temporary path length ignoring alt mode: ' + $boolUseTemporaryPathLenghIgnoringAltMode + '; Relaunch attempted with DOS 8.3 path: ' + $boolRelaunchAttemptedWithDOS83Path + '; Known SIDs: not specified (unresolved SIDs will not be removed)'
    } else {
        if ($null -eq $refHashtableKnownSIDs.Value) {
            $strVerboseMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Path: "' + $strThisObjectPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $intIterativeRepairState + '; Use Get-Path workaround: ' + $boolUseGetPSDriveWorkaround + '; Last substituted path: "' + $strLastSubstitutedPath + '"; Use temporary path length ignoring alt mode: ' + $boolUseTemporaryPathLenghIgnoringAltMode + '; Relaunch attempted with DOS 8.3 path: ' + $boolRelaunchAttemptedWithDOS83Path + '; Known SIDs: not specified (unresolved SIDs will not be removed)'
        } else {
            $strVerboseMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Path: "' + $strThisObjectPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $intIterativeRepairState + '; Use Get-Path workaround: ' + $boolUseGetPSDriveWorkaround + '; Last substituted path: "' + $strLastSubstitutedPath + '"; Use temporary path length ignoring alt mode: ' + $boolUseTemporaryPathLenghIgnoringAltMode + '; Relaunch attempted with DOS 8.3 path: ' + $boolRelaunchAttemptedWithDOS83Path + '; Known SIDs: yes (unresolved SIDs unmatched to SIDs in the hashtable will be removed)'
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
                    $boolSuccess = Get-DOS83Path -ReferenceToDOS8Dot3Path ([ref]$strDOS83Path) -Path $strThisObjectPath
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
                                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisFolderPermission) -ReferenceToAccessRuleObject ([ref]($arrWorkingACEs[$intCounterA]))
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
                        } elseif ((Test-ValidSID (($arrWorkingACEs[$intCounterA]).IdentityReference)) -eq $true) {
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
                                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisFolderPermission) -ReferenceToAccessRuleObject ([ref]($fileSystemAccessRuleOld))
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
                        } elseif ((Test-ValidSID (($arrWorkingACEs[$intCounterA]).IdentityReference)) -eq $true) {
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
                $boolSuccess = Get-ChildItemUsingObjectSafely ([ref]$arrChildObjects) ([ref]$objThis)

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
