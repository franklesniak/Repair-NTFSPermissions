# .SYNOPSIS
# Scans the permissions at the specified path and ensures that administrators and the
# SYSTEM account have full control. Optionally, additional accounts/groups can be
# specified to be granted full control or read-only access, and, optionally, the script
# can remove unresolved ("dead") security identifiers (SIDs).
#
# .DESCRIPTION
# Scans the permissions at the specified path and ensures that local administrators and
# the SYSTEM account have full control. Optionally, additional accounts/groups can be
# specified to be granted full control or read-only access. In general, the script will
# not remove any existing permissions, but will add permissions as necessary to ensure
# that the specified accounts/groups have the specified access.
#
# This script is especially useful because taking ownership of a file or folder through
# the Windows graphical interface can replace existing permissions, which can be
# problematic if the existing permissions are not known or documented (and even if they
# are known or documented, it can be time-consuming and disruptive to business to re-
# apply them).
#
# Optionally, the script can also be used to remove unresolved ("dead") security
# identifiers (SIDs) from the NTFS permissions on the specified path and all subfolders
# and files. This is useful when, for example, users and groups have been deleted from
# Active Directory but their NTFS permissions are left behind. Removing these SIDs can
# help to clean up the permissions and make them easier to manage.
#
# .PARAMETER PathToFix
# Specifies the path to be fixed. This parameter is mandatory.
#
# .PARAMETER NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls
# Optionally, specifies the name of the local administrators group. If not specified,
# the default value of 'Administrators' will be used.
#
# Supplying this parameter may be necessary on non-English systems, where the name of
# the local administrators group may be different. This parameter is used when taking
# ownership of the file or folder using takeown.exe and when applying permissions using
# icacls.exe.
#
# To determine the value that should be supplied for this parameter, apply the local
# administrators group to a test file or folder. Then, at the command prompt, type:
# icacls "C:\Path\To\Test\FileOrFolder"
# Inspect the results. You should see something like:
# BUILTIN\Administrators:(OI)(CI)(F)
# The part before the colon (BUILTIN\Administrators) is the group name according to
# icacls.exe.
#
# .PARAMETER NameOfBuiltInAdministratorsGroupAccordingToGetAcl
# Optionally, specifies the name of the local administrators group. This parameter is
# optional; if not specified, the default value of 'BUILTIN\Administrators' will be
# used.
#
# Supplying this parameter may be necessary on non-English systems, where the name of
# the local administrators group may be different. This parameter is used when getting
# the ACL of the file or folder in PowerShell via Get-Acl or setting it with Set-Acl or
# SetAccessControl().
#
# To determine the value that should be supplied for this parameter, apply the local
# administrators group to a test file or folder. Then, at the PowerShell prompt, type:
# $acl = Get-Acl 'C:\Path\To\Test\FileOrFolder'; $acl.Access
# Inspect the results. You should see something like:
# IdentityReference : BUILTIN\Administrators
# The part after the colon (BUILTIN\Administrators) is the group name according to
# Get-Acl.
#
# .PARAMETER NameOfSYSTEMAccountAccordingToTakeOwnAndICacls
# Optionally, specifies the name of the SYSTEM account. This parameter is optional; if
# not specified, the default value of 'SYSTEM' will be used.
#
# Supplying this parameter may be necessary on non-English systems, where the name of
# the SYSTEM account may be different. This parameter is used when taking
# ownership of the file or folder using takeown.exe and when applying permissions using
# icacls.exe.
#
# To determine the value that should be supplied for this parameter, apply the SYSTEM
# account to a test file or folder. Then, at the command prompt, type:
# icacls "C:\Path\To\Test\FileOrFolder"
# Inspect the results. You should see something like:
# NT AUTHORITY\SYSTEM:(OI)(CI)(F)
# The part before the colon (NT AUTHORITY\SYSTEM) is the SYSTEM account name according
# to icacls.exe.
#
# .PARAMETER NameOfSYSTEMAccountAccordingToGetAcl
# Optionally, specifies the name of the SYSTEM account. This parameter is optional; if
# not specified, the default value of 'NT AUTHORITY\SYSTEM' will be used.
#
# Supplying this parameter may be necessary on non-English systems, where the name of
# the SYSTEM account may be different. This parameter is used when getting
# the ACL of the file or folder in PowerShell via Get-Acl or setting it with Set-Acl or
# SetAccessControl().
#
# To determine the value that should be supplied for this parameter, apply the SYSTEM
# account to a test file or folder. Then, at the PowerShell prompt, type:
# $acl = Get-Acl 'C:\Path\To\Test\FileOrFolder'; $acl.Access
# Inspect the results. You should see something like:
# IdentityReference : NT AUTHORITY\SYSTEM
# The part after the colon (NT AUTHORITY\SYSTEM) is the SYSTEM account name according
# to Get-Acl.
#
# .PARAMETER NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls
# Optionally, specifies the name of an additional account or group to be granted full
# control. This parameter is optional; if not specified, the default value of $null
# will be used and the script will not attempt to grant additional full control
# permissions.
#
# This parameter is used when getting the ACL of the file or folder in PowerShell via
# Get-Acl or setting it with Set-Acl or SetAccessControl().
#
# To determine the value that should be supplied for this parameter, apply the
# additional administrator account or group to a test file or folder. Then, at the
# command prompt, type:
# icacls "C:\Path\To\Test\FileOrFolder"
# Inspect the results. You should see something like:
# DOMAIN\AccountName:(OI)(CI)(F)
# The part before the colon (DOMAIN\AccountName) is the account or group name according
# to icacls.exe.
#
# .PARAMETER NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl
# Optionally, specifies the name of an additional account or group to be granted full
# control. This parameter is optional; if not specified, the default value of $null
# will be used and the script will not attempt to grant additional full control
# permissions.
#
# This parameter is used when getting the ACL of the file or folder in PowerShell via
# Get-Acl or setting it with Set-Acl or SetAccessControl().
#
# To determine the value that should be supplied for this parameter, apply the
# additional administrator account or group to a test file or folder. Then, at the
# PowerShell prompt, type:
# $acl = Get-Acl 'C:\Path\To\Test\FileOrFolder'; $acl.Access
# Inspect the results. You should see something like:
# IdentityReference : DOMAIN\AccountName
# The part after the colon (DOMAIN\AccountName) is the account or group name according
# to Get-Acl.
#
# .PARAMETER NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls
# Optionally, specifies the name of an additional account or group to be granted read-
# only access. This parameter is optional; if not specified, the default value of $null
# will be used and the script will not attempt to grant additional read-only permissions.
#
# This parameter is used when applying permissions using icacls.exe.
#
# To determine the value that should be supplied for this parameter, apply the
# additional read-only account or group to a test file or folder. Then, at the
# command prompt, type:
# icacls "C:\Path\To\Test\FileOrFolder"
# Inspect the results. You should see something like:
# DOMAIN\AccountName:(OI)(CI)(RX)
# The part before the colon (DOMAIN\AccountName) is the account or group name according
# to icacls.exe.
#
# .PARAMETER NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl
# Optionally, specifies the name of an additional account or group to be granted read-
# only access. This parameter is optional; if not specified, the default value of $null
# will be used and the script will not attempt to grant additional read-only permissions.
#
# This parameter is used when getting the ACL of the file or folder in PowerShell via
# Get-Acl or setting it with Set-Acl or SetAccessControl().
#
# To determine the value that should be supplied for this parameter, apply the
# additional read-only account or group to a test file or folder. Then, at the
# PowerShell prompt, type:
# $acl = Get-Acl 'C:\Path\To\Test\FileOrFolder'; $acl.Access
# Inspect the results. You should see something like:
# IdentityReference : DOMAIN\AccountName
# The part after the colon (DOMAIN\AccountName) is the account or group name according
# to Get-Acl.
#
# .PARAMETER RemoveUnresolvedSIDs
# Optionally, specifies that unresolved SIDs should be removed from the ACL. This
# parameter is optional; if not specified,  the script will not attempt to remove
# unresolved SIDs.
#
# .PARAMETER PathToCSVContainingKnownSIDs
# Optionally, specifies the path to a CSV file containing a list of known SIDs. This
# parameter is optional in general. However, if the RemoveUnresolvedSIDs switch
# parameter is specified, then this parameter must also be specified. If specified,
# this parameter must be a string containing a valid path to a CSV file. The CSV file
# must contain a column named 'SID' that contains the SIDs to be considered "known,",
# i.e., SIDs that should not be removed from the ACL. The CSV file may contain
# additional columns, but they will be ignored.
#
# If unresolved SIDs are to be removed, this CSV is required because it provides
# protection from the scenario where, for example, connectivity between a member server
# and Active Directory Domain Services is lost and the member server is unable to
# resolve SIDs to names. In this scenario, if this protection were not in place, then
# the script would remove all unresolved SIDs from the ACL, including SIDs that are not
# resolved because of the lost connectivity. This could result in the loss of access to
# the file or folder.
#
# Therefore, in the specified CSV, it is highly recommended to provide a list of *all
# SIDs* in the environment. This should include SIDs for all user accounts, groups, and
# computer accounts.
#
# .PARAMETER DoNotPerformFinalCleanupOfRedundantACEs
# This parameter is optional; if supplied, it prevents the script from performing a
# final cleanup of redundant ACEs. This is useful when the script is being used in an
# emergency situation and the extra time cannot be spared to perform the cleanup. The
# cleanup can be done later with a separate call to the script.
#
# .EXAMPLE
# PS C:\> .\Repair-NTFSPermissions.ps1 -PathToFix 'D:\Shares\Public'
#
# This example will scan the permissions at D:\Shares\Public and ensure that local
# administrators and the SYSTEM account have full control to the folder and all files
# and subfolders. No additional accounts or groups will be granted permissions, and
# existing permissions will not be removed.
#
# .EXAMPLE
# PS C:\> .\Repair-NTFSPermissions.ps1 -PathToFix 'D:\Shares\Public' -RemoveUnresolvedSIDs -PathToCSVContainingKnownSIDs 'C:\Scripts\KnownSIDs.csv'
#
# This example will scan the permissions at D:\Shares\Public and ensure that local
# administrators and the SYSTEM account have full control to the folder and all files
# and subfolders. Additionally, it will remove any unresolved SIDs from the ACL, except
# for those SIDs that are listed in the CSV file at C:\Scripts\KnownSIDs.csv.
#
# .OUTPUTS
# None
#
# .NOTES
# This script is useful because taking ownership of a file or folder through the
# Windows graphical interface can replace existing permissions, which can be
# problematic if the existing permissions are not known or documented (and even if they
# are known or documented, it can be time-consuming and disruptive to business to re-
# apply them).
#
# Version 2.1.20250208.0

#region License ####################################################################
# Copyright (c) 2025 Frank Lesniak
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

[CmdletBinding()]
# TODO: [CmdletBinding()] is not supported by PowerShell 1.0.

param (
    [string]$PathToFix,
    [string]$NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls = 'Administrators',
    [string]$NameOfBuiltInAdministratorsGroupAccordingToGetAcl = 'BUILTIN\Administrators',
    [string]$NameOfSYSTEMAccountAccordingToTakeOwnAndICacls = 'SYSTEM',
    [string]$NameOfSYSTEMAccountAccordingToGetAcl = 'NT AUTHORITY\SYSTEM',
    [string]$NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls = '',
    [string]$NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl = '',
    [string]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls = '',
    [string]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = '',
    [switch]$RemoveUnresolvedSIDs,
    [string]$PathToCSVContainingKnownSIDs = $null,
    [switch]$DoNotPerformFinalCleanupOfRedundantACEs
)

function Repair-NTFSPermissionsRecursively {
    # .SYNOPSIS
    # Performs the recursive work to repair NTFS permissions
    #
    # .DESCRIPTION
    # This internal function calls itself over and over (i.e., uses recursion) to
    # apply various permission fixes to a folder structure. It first processes the
    # current item, then moves onto child items (starting with child files, then child
    # folders). The function automatically takes action to mitigate path length issues
    # and it will do everything possible to ensure that BUILTIN\Administrators and
    # NT AUTHORITY\SYSTEM have the expected full control permissions to an object.
    #
    # .PARAMETER WorkingPath
    # This parameter is required; it is a string that contains the path to the object
    # that we are working on. The path could be a shortened one through the the use of
    # path shortening techniques (e.g., drive substitution, symbolic links, etc.).
    #
    # .PARAMETER IterativeRepairState
    # This parameter is optional; if supplied, it is an integer that indicates an
    # alternative permission-repairing mode in which the function should run. If not
    # supplied, the parameter defaults to 0.
    #
    # 0 = Allow recursion; work normally (default)
    # 1 = Do not allow recursion, but allow ownership to be taken via Set-Acl
    # 2 = Do not allow recursion, and do not allow ownership to be taken via Set-Acl
    #
    # .PARAMETER ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful
    # This parameter is optional; if supplied, it is a reference to a boolean value
    # that indicates whether it's known that Get-PSDrive is necessary to refresh
    # PowerShell's "understanding" of drive letters. If not supplied, the function
    # defaults to assuming that Get-PSDrive is not known to be useful. Initializing
    # a boolean variable to $false and then passing it by reference using this
    # parameter can speed up the function.
    #
    # .PARAMETER LastShortenedPath
    # This parameter is optional; if supplied, it is a string that contains the path
    # to the drive subsitution, symbolic link, etc., that was last used in an attempt
    # to shorten the path. This parameter is used internally by the function to track
    # the last shortened path that was used to avoid unnecessary re-attempts to shorten
    # paths and to control other bits of function logic.
    #
    # .PARAMETER ReferenceToHashtableOfKnownSIDs
    # This parameter is optional; if supplied, it is a reference to a hashtable that
    # contains known SIDs. This hashtable is used to determine if an unresolved SID
    # should be removed from the ACL. If not supplied, the function will not attempt to
    # remove unresolved SIDs.
    #
    # .PARAMETER RealPath
    # This parameter is optional; if supplied, it is the real (i.e., non-shortened)
    # path to an object (string). Tracking this path is helpful because it allows the
    # function to output errors/warnings about paths that allow the user to
    # troubleshoot or fix issues much more easily (vs. having to try to guess what a
    # substituted drive or symbolic link points to).
    #
    # .PARAMETER ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls
    # This parameter is optional; if supplied, it is a memory reference (pointer) to a
    # string containing the name of the local administrators group. Supplying this
    # parameter may be necessary on non-English systems, where the name of the local
    # administrators group may be different. This parameter is used when taking
    # ownership of the file or folder and when applying permissions using icacls.exe.
    # If a reference is not specified, the default value of 'Administrators' will be
    # used.
    #
    # .PARAMETER ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl
    # This parameter is optional; if supplied, it is a memory reference (pointer) to a
    # string containing the name of the local administrators group. Supplying this
    # parameter may be necessary on non-English systems, where the name of the local
    # administrators group may be different. This parameter is used when getting the
    # ACL of the file or folder in PowerShell via Get-Acl. If a reference is not
    # specified, the script will use 'BUILTIN\Administrators'.
    #
    # .PARAMETER ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls
    # This parameter is optional; if supplied, it is a memory reference (pointer) to a
    # string containing the name of the SYSTEM account. Supplying this parameter may be
    # necessary on non-English systems, where the name of the SYSTEM account may be
    # different. This parameter is used when taking ownership of the file or folder and
    # when applying permissions using icacls.exe. If a reference is not specified, the
    # script will use 'SYSTEM'.
    #
    # .PARAMETER ReferenceToNameOfSYSTEMAccountAccordingToGetAcl
    # This parameter is optional; if supplied, it is a memory reference (pointer) to a
    # string containing the name of the SYSTEM account. Supplying this parameter may be
    # necessary on non-English systems, where the name of the SYSTEM account may be
    # different. This parameter is used when getting the ACL of the file or folder in
    # PowerShell via Get-Acl. If a reference is not specified, the script will use
    # 'NT AUTHORITY\SYSTEM'.
    #
    # .PARAMETER ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls
    # This parameter is optional; if supplied, it is a memory reference (pointer) to a
    # string containing the name of an additional account or group to be granted full
    # control. This parameter is used when applying permissions using icacls.exe. If a
    # reference is not specified, the script will not attempt to add full control
    # permissions for an additional account or group.
    #
    # .PARAMETER ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl
    # This parameter is optional; if supplied, it is a memory reference (pointer) to a
    # string containing the name of an additional account or group to be granted full
    # control. This parameter is used when getting the ACL of the file or folder in
    # PowerShell via Get-Acl. If a reference is not specified, the script will not
    # attempt to add full control permissions for an additional account or group.
    #
    # .PARAMETER ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls
    # This parameter is optional; if supplied, it is a memory reference (pointer) to a
    # string containing the name of an additional account or group to be granted read-
    # only access. This parameter is used when applying permissions using icacls.exe.
    # If a reference is not specified, the script will not attempt to add read-only
    # permissions for an additional account or group.
    #
    # .PARAMETER ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl
    # This parameter is optional; if supplied, it is a memory reference (pointer) to a
    # string containing the name of an additional account or group to be granted read-
    # only access. This parameter is used when getting the ACL of the file or folder in
    # PowerShell via Get-Acl. If a reference is not specified, the script will not
    # attempt to add read-only permissions for an additional account or group.
    #
    # .PARAMETER RecursionDepth
    # This parameter is optional; if supplied, it is an integer that indicates the
    # current recursion depth. If not supplied, the parameter defaults to 0.
    #
    # .PARAMETER RunWithoutRecursion
    # This parameter is optional; if supplied, it is a switch parameter that indicates
    # that the function should not run with recursion on the specified item. This is
    # useful if it's known that the item is a file, or if the function is being used to
    # repair permissions on just one item.
    #
    # .PARAMETER IgnorePathLengthLimits
    # This parameter is optional; if supplied, it is a switch parameter that indicates
    # that the function should ignore path length limits. This is useful in certain
    # types of repair operations (e.g., as a last ditch effort when attempts to
    # mitigate a long path have failed).
    #
    # .PARAMETER DOS8dot3PathBeingUsed
    # This parameter is optional; if supplied, it is a switch parameter that indicates
    # that the function is using a DOS 8.3 path. This is useful because it is the last
    # thing that the function does to mitigate a path length issue, so if we're working
    # with a DOS 8.3 path already and there are issues, then there may be nothing else
    # we can do.
    #
    # .PARAMETER DoNotPerformFinalCleanupOfRedundantACEs
    # This parameter is optional; if supplied, it prevents the script from performing a
    # final cleanup of redundant ACEs. This is useful when the function is being used
    # in an emergency situation and the extra time cannot be spared to perform the
    # cleanup. The cleanup can be done later with a separate call to the function.
    #
    # .PARAMETER FinalCleanupOfRedundantACEs
    # This parameter is optional; if supplied, it is a switch parameter that indicates
    # that the function should perform a final cleanup of redundant ACEs. This is the
    # last step of the recursive process and is used, for example, when the function
    # had previously created a non-inhertiable ACE for the BUILTIN\Administrators
    # group on every single item in a folder structure, but now the script has created
    # an inheritable ACE for the BUILTIN\Administrators group at the root of the
    # structure and any place where inheritance is blocked. In this case, the
    # individual non-inheritable ACEs are redundant and can and should be cleaned up.
    #
    # .EXAMPLE
    # $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath 'D:\Shares\Corporate' -ReferenceToHashtableOfKnownSIDs ([ref]$hashtableKnownSIDs)
    #
    # .EXAMPLE
    # $boolGetPSDriveWorkaroundKnownToBeUseful = $false
    # $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath 'D:\Shares\Corporate' -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful ([ref]$boolGetPSDriveWorkaroundKnownToBeUseful) -ReferenceToHashtableOfKnownSIDs ([ref]$hashtableKnownSIDs)
    #
    # .INPUTS
    # None. You can't pipe objects to Repair-NTFSPermissionsRecursively.
    #
    # .OUTPUTS
    # System.Int32. Repair-NTFSPermissionsRecursively returns an integer value that
    # indicates whether the process completed successfully - and if not, a return code
    # that gives a hint as to what the issue might be. 0 indicates success.
    #
    # .NOTES
    # This function also supports the use of positional parameters instead of named
    # parameters. If positional parameters are used intead of named parameters,
    # then one to fifteen positional parameters are required:
    #
    # The first positional parameter is a string that contains the path to the object
    # that we are working on. The path could be a shortened one through the the use of
    # path shortening techniques (e.g., drive substitution, symbolic links, etc.).
    #
    # The second positional parameter is optional; if supplied, it is an integer that
    # indicates an alternative permission-repairing mode in which the function should
    # run. If not supplied, the parameter defaults to 0.
    #
    # 0 = Allow recursion; work normally (default)
    # 1 = Do not allow recursion, but allow ownership to be taken via Set-Acl
    # 2 = Do not allow recursion, and do not allow ownership to be taken via Set-Acl
    #
    # The third positional parameter is optional; if supplied, it is a reference to a
    # boolean value that indicates whether it's known that Get-PSDrive is necessary to
    # refresh PowerShell's "understanding" of drive letters. If not supplied, the
    # function defaults to assuming that Get-PSDrive is not known to be useful.
    # Initializing a boolean variable to $false and then passing it by reference using
    # this parameter can speed up the function.
    #
    # The fourth positional parameter is optional; if supplied, it is a string that
    # contains the path to the drive subsitution, symbolic link, etc., that was last
    # used in an attempt to shorten the path. This parameter is used internally by the
    # function to track the last shortened path that was used to avoid unnecessary
    # re-attempts to shorten paths and to control other bits of function logic.
    #
    # The fifth positional parameter is optional; if supplied, it is a reference to a
    # hashtable that contains known SIDs. This hashtable is used to determine if an
    # unresolved SID should be removed from the ACL. If not supplied, the function will
    # not attempt to remove unresolved SIDs.
    #
    # The sixth positional parameter is optional; if supplied, it is the real (i.e.,
    # non-shortened) path to an object (string). Tracking this path is helpful because
    # it allows the function to output errors/warnings about paths that allow the user
    # to troubleshoot or fix issues much more easily (vs. having to try to guess what a
    # substituted drive or symbolic link points to).
    #
    # The seventh positional parameter is optional; if supplied, it is a memory
    # reference (pointer) to a string containing the name of the local administrators
    # group. Supplying this parameter may be necessary on non-English systems, where
    # the name of the local administrators group may be different. This parameter is
    # used when taking ownership of the file or folder and when applying permissions
    # using icacls.exe. If a reference is not specified, the default value of
    # 'Administrators' will be used.
    #
    # The eighth positional parameter is optional; if supplied, it is a memory
    # reference (pointer) to a string containing the name of the local administrators
    # group. Supplying this parameter may be necessary on non-English systems, where
    # the name of the local administrators group may be different. This parameter is
    # used when getting the ACL of the file or folder in PowerShell via Get-Acl. If a
    # reference is not specified, the script will use 'BUILTIN\Administrators'.
    #
    # The ninth positional parameter is optional; if supplied, it is a memory reference
    # (pointer) to a string containing the name of the SYSTEM account. Supplying this
    # parameter may be necessary on non-English systems, where the name of the SYSTEM
    # account may be different. This parameter is used when taking ownership of the
    # file or folder and when applying permissions using icacls.exe. If a reference is
    # not specified, the script will use 'SYSTEM'.
    #
    # The tenth positional parameter is optional; if supplied, it is a memory reference
    # (pointer) to a string containing the name of the SYSTEM account. Supplying this
    # parameter may be necessary on non-English systems, where the name of the SYSTEM
    # account may be different. This parameter is used when getting the ACL of the file
    # or folder in PowerShell via Get-Acl. If a reference is not specified, the script
    # will use 'NT AUTHORITY\SYSTEM'.
    #
    # The eleventh positional parameter is optional; if supplied, it is a memory
    # reference (pointer) to a string containing the name of an additional account or
    # group to be granted full control. This parameter is used when applying
    # permissions using icacls.exe. If a reference is not specified, the script will
    # not attempt to add full control permissions for an additional account or group.
    #
    # The twelfth positional parameter is optional; if supplied, it is a memory
    # reference (pointer) to a string containing the name of an additional account or
    # group to be granted full control. This parameter is used when getting the ACL of
    # the file or folder in PowerShell via Get-Acl. If a reference is not specified,
    # the script will not attempt to add full control permissions for an additional
    # account or group.
    #
    # The thirteenth positional parameter is optional; if supplied, it is a memory
    # reference (pointer) to a string containing the name of an additional account or
    # group to be granted read-only access. This parameter is used when applying
    # permissions using icacls.exe. If a reference is not specified, the script will
    # not attempt to add read-only permissions for an additional account or group.
    #
    # The fourteenth positional parameter is optional; if supplied, it is a memory
    # reference (pointer) to a string containing the name of an additional account or
    # group to be granted read-only access. This parameter is used when getting the ACL
    # of the file or folder in PowerShell via Get-Acl. If a reference is not specified,
    # the script will not attempt to add read-only permissions for an additional
    # account or group.
    #
    # The fifteenth positional parameter is optional; if supplied, it is an integer
    # that indicates the current recursion depth. If not supplied, the parameter
    # defaults to 0.
    #
    # Version: 3.1.20250118.0

    #region License ############################################################
    # Copyright (c) 2025 Frank Lesniak
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
        [string]$WorkingPath = '',
        [int]$IterativeRepairState = 0,
        [ref]$ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful = [ref]$null,
        [string]$LastShortenedPath = '',
        [ref]$ReferenceToHashtableOfKnownSIDs = [ref]$null,
        [string]$RealPath = '',
        [ref]$ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls = [ref]$null,
        [ref]$ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl = [ref]$null,
        [ref]$ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls = [ref]$null,
        [ref]$ReferenceToNameOfSYSTEMAccountAccordingToGetAcl = [ref]$null,
        [ref]$ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls = [ref]$null,
        [ref]$ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl = [ref]$null,
        [ref]$ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls = [ref]$null,
        [ref]$ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = [ref]$null,
        [int]$RecursionDepth = 0,
        [switch]$RunWithoutRecursion,
        [switch]$IgnorePathLengthLimits,
        [switch]$DOS8dot3PathBeingUsed,
        [switch]$DoNotPerformFinalCleanupOfRedundantACEs,
        [switch]$FinalCleanupOfRedundantACEs
    )

    function Get-PSVersion {
        # .SYNOPSIS
        # Returns the version of PowerShell that is running.
        #
        # .DESCRIPTION
        # The function outputs a [version] object representing the version of
        # PowerShell that is running.
        #
        # On versions of PowerShell greater than or equal to version 2.0, this
        # function returns the equivalent of $PSVersionTable.PSVersion
        #
        # PowerShell 1.0 does not have a $PSVersionTable variable, so this
        # function returns [version]('1.0') on PowerShell 1.0.
        #
        # .EXAMPLE
        # $versionPS = Get-PSVersion
        # # $versionPS now contains the version of PowerShell that is running.
        # # On versions of PowerShell greater than or equal to version 2.0,
        # # this function returns the equivalent of $PSVersionTable.PSVersion.
        #
        # .INPUTS
        # None. You can't pipe objects to Get-PSVersion.
        #
        # .OUTPUTS
        # System.Version. Get-PSVersion returns a [version] value indiciating
        # the version of PowerShell that is running.
        #
        # .NOTES
        # Version: 1.0.20250106.0

        #region License ####################################################
        # Copyright (c) 2025 Frank Lesniak
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

        if (Test-Path variable:\PSVersionTable) {
            return ($PSVersionTable.PSVersion)
        } else {
            return ([version]('1.0'))
        }
    }

    function Get-AvailableDriveLetter {
        # .SYNOPSIS
        # Gets a list of available drive letters on the local system.
        #
        # .DESCRIPTION
        # This function evaluates the list of drive letters that are in use on the
        # local system and returns an array of those that are available. The list of
        # available drive letters is returned as an array of uppercase letters
        #
        # .PARAMETER PSVersion
        # This parameter is optional; if supplied, it must be the version number of the
        # running version of PowerShell. If the version of PowerShell is already known,
        # it can be passed in to this function to avoid the overhead of unnecessarily
        # determining the version of PowerShell. If this parameter is not supplied, the
        # function will determine the version of PowerShell that is running as part of
        # its processing.
        #
        # .PARAMETER AssumeWindows
        # By default, this function will determine if the running system is Windows or
        # not. If this switch parameter is supplied, then the function will assume that
        # the running system is Windows. This can be useful if you have already
        # determined that the system is Windows and you want to avoid the overhead of
        # determining the system type again.
        #
        # .PARAMETER DoNotConsiderMappedDriveLettersAsInUse
        # By default, if this function encounters a drive letter that is mapped to a
        # network share, it will consider that drive letter to be in use. However, if
        # this switch parameter is supplied, then mapped drives will be ignored and
        # their drive letters will be considered available.
        #
        # .PARAMETER DoNotConsiderPSDriveLettersAsInUse
        # By default, if this function encounters a drive letter that is mapped to a
        # PowerShell drive, it will consider that drive letter to be in use. However,
        # if this switch parameter is supplied, then PowerShell drives will be ignored
        # and their drive letters will be considered available.
        #
        # .PARAMETER ConsiderFloppyDriveLettersAsEligible
        # By default, this function will not consider A: or B: drive letters as
        # available. If this switch parameter is supplied, then A: and B: drive letters
        # will be considered available if they are not in use.
        #
        # .EXAMPLE
        # $arrAvailableDriveLetters = Get-AvailableDriveLetter
        #
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
        # .INPUTS
        # None. You can't pipe objects to Get-AvailableDriveLetter.
        #
        # .OUTPUTS
        # System.Char[]. Get-AvailableDriveLetter returns an array of uppercase letters
        # (System.Char) representing available drive letters.
        #
        # Note that on non-Windows systems, this function will return an empty array
        # because drive letters are a Windows-specific concept. It will also issue a
        # warning to alert the user that the function is only supported on Windows.
        #
        # .NOTES
        # It is conventional that A: and B: drives be reserved for floppy drives,
        # and that C: be reserved for the system drive.
        #
        # This function also supports the use of one positional parameter instead of
        # named parameters. If the positional parameter is used intead of named
        # parameters, then one positional parameters is required: it must be the
        # version number of the running version of PowerShell. If the version of
        # PowerShell is already known, it can be passed in to this function to avoid
        # the overhead of unnecessarily determining the version of PowerShell. If this
        # parameter is not supplied, the function will determine the version of
        # PowerShell that is running as part of its processing.
        #
        # Version: 1.1.20250106.0

        #region License ############################################################
        # Copyright (c) 2025 Frank Lesniak
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
            [version]$PSVersion = ([version]'0.0'),
            [switch]$AssumeWindows,
            [switch]$DoNotConsiderMappedDriveLettersAsInUse,
            [switch]$DoNotConsiderPSDriveLettersAsInUse,
            [switch]$ConsiderFloppyDriveLettersAsEligible
        )

        function Get-PSVersion {
            # .SYNOPSIS
            # Returns the version of PowerShell that is running.
            #
            # .DESCRIPTION
            # The function outputs a [version] object representing the version of
            # PowerShell that is running.
            #
            # On versions of PowerShell greater than or equal to version 2.0, this
            # function returns the equivalent of $PSVersionTable.PSVersion
            #
            # PowerShell 1.0 does not have a $PSVersionTable variable, so this
            # function returns [version]('1.0') on PowerShell 1.0.
            #
            # .EXAMPLE
            # $versionPS = Get-PSVersion
            # # $versionPS now contains the version of PowerShell that is running.
            # # On versions of PowerShell greater than or equal to version 2.0,
            # # this function returns the equivalent of $PSVersionTable.PSVersion.
            #
            # .INPUTS
            # None. You can't pipe objects to Get-PSVersion.
            #
            # .OUTPUTS
            # System.Version. Get-PSVersion returns a [version] value indiciating
            # the version of PowerShell that is running.
            #
            # .NOTES
            # Version: 1.0.20250106.0

            #region License ####################################################
            # Copyright (c) 2025 Frank Lesniak
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

            if (Test-Path variable:\PSVersionTable) {
                return ($PSVersionTable.PSVersion)
            } else {
                return ([version]('1.0'))
            }
        }

        function Test-Windows {
            # .SYNOPSIS
            # Returns $true if PowerShell is running on Windows; otherwise, returns
            # $false.
            #
            # .DESCRIPTION
            # Returns a boolean ($true or $false) indicating whether the current
            # PowerShell session is running on Windows. This function is useful for
            # writing scripts that need to behave differently on Windows and non-
            # Windows platforms (Linux, macOS, etc.). Additionally, this function is
            # useful because it works on Windows PowerShell 1.0 through 5.1, which do
            # not have the $IsWindows global variable.
            #
            # .PARAMETER PSVersion
            # This parameter is optional; if supplied, it must be the version number of
            # the running version of PowerShell. If the version of PowerShell is
            # already known, it can be passed in to this function to avoid the overhead
            # of unnecessarily determining the version of PowerShell. If this parameter
            # is not supplied, the function will determine the version of PowerShell
            # that is running as part of its processing.
            #
            # .EXAMPLE
            # $boolIsWindows = Test-Windows
            #
            # .EXAMPLE
            # # The version of PowerShell is known to be 2.0 or above:
            # $boolIsWindows = Test-Windows -PSVersion $PSVersionTable.PSVersion
            #
            # .INPUTS
            # None. You can't pipe objects to Test-Windows.
            #
            # .OUTPUTS
            # System.Boolean. Test-Windows returns a boolean value indiciating whether
            # PowerShell is running on Windows. $true means that PowerShell is running
            # on Windows; $false means that PowerShell is not running on Windows.
            #
            # .NOTES
            # This function also supports the use of a positional parameter instead of
            # a named parameter. If a positional parameter is used intead of a named
            # parameter, then one positional parameters is required: it must be the
            # version number of the running version of PowerShell. If the version of
            # PowerShell is already known, it can be passed in to this function to
            # avoid the overhead of unnecessarily determining the version of
            # PowerShell. If this parameter is not supplied, the function will
            # determine the version of PowerShell that is running as part of its
            # processing.
            #
            # Version: 1.1.20250106.0

            #region License ########################################################
            # Copyright (c) 2025 Frank Lesniak
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
                [version]$PSVersion = ([version]'0.0')
            )

            function Get-PSVersion {
                # .SYNOPSIS
                # Returns the version of PowerShell that is running.
                #
                # .DESCRIPTION
                # The function outputs a [version] object representing the version of
                # PowerShell that is running.
                #
                # On versions of PowerShell greater than or equal to version 2.0, this
                # function returns the equivalent of $PSVersionTable.PSVersion
                #
                # PowerShell 1.0 does not have a $PSVersionTable variable, so this
                # function returns [version]('1.0') on PowerShell 1.0.
                #
                # .EXAMPLE
                # $versionPS = Get-PSVersion
                # # $versionPS now contains the version of PowerShell that is running.
                # # On versions of PowerShell greater than or equal to version 2.0,
                # # this function returns the equivalent of $PSVersionTable.PSVersion.
                #
                # .INPUTS
                # None. You can't pipe objects to Get-PSVersion.
                #
                # .OUTPUTS
                # System.Version. Get-PSVersion returns a [version] value indiciating
                # the version of PowerShell that is running.
                #
                # .NOTES
                # Version: 1.0.20250106.0

                #region License ####################################################
                # Copyright (c) 2025 Frank Lesniak
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

                if (Test-Path variable:\PSVersionTable) {
                    return ($PSVersionTable.PSVersion)
                } else {
                    return ([version]('1.0'))
                }
            }

            if ($PSVersion -ne ([version]'0.0')) {
                if ($PSVersion.Major -ge 6) {
                    return $IsWindows
                } else {
                    return $true
                }
            } else {
                $versionPS = Get-PSVersion
                if ($versionPS.Major -ge 6) {
                    return $IsWindows
                } else {
                    return $true
                }
            }
        }

        #region Process Input ######################################################
        if ($null -ne $PSVersion) {
            if ($PSVersion -eq ([version]'0.0')) {
                $versionPS = Get-PSVersion
            } else {
                $versionPS = $PSVersion
            }
        } else {
            $versionPS = Get-PSVersion
        }

        $boolIsWindows = $null
        if ($null -ne $AssumeWindows) {
            if ($AssumeWindows.IsPresent -eq $true) {
                $boolIsWindows = $true
            }
        }
        if ($null -eq $boolIsWindows) {
            $boolIsWindows = Test-Windows -PSVersion $versionPS
        }

        $boolExcludeMappedDriveLetters = $true
        if ($null -ne $DoNotConsiderMappedDriveLettersAsInUse) {
            if ($DoNotConsiderMappedDriveLettersAsInUse.IsPresent -eq $true) {
                $boolExcludeMappedDriveLetters = $false
            }
        }

        $boolExcludePSDriveLetters = $true
        if ($null -ne $DoNotConsiderPSDriveLettersAsInUse) {
            if ($DoNotConsiderPSDriveLettersAsInUse.IsPresent -eq $true) {
                $boolExcludePSDriveLetters = $false
            }
        }

        $boolExcludeFloppyDriveLetters = $true
        if ($null -ne $ConsiderFloppyDriveLettersAsEligible) {
            if ($ConsiderFloppyDriveLettersAsEligible.IsPresent -eq $true) {
                $boolExcludeFloppyDriveLetters = $false
            }
        }
        #endregion Process Input ######################################################

        $VerbosePreferenceAtStartOfFunction = $VerbosePreference

        if (-not $boolIsWindows) {
            Write-Warning "Get-AvailableDriveLetter is only supported on Windows."
            return , @()
        } else {
            # System is Windows
            $arrAllPossibleLetters = @(65..90 | ForEach-Object { [char]$_ })

            if ($versionPS.Major -ge 3) {
                # Use Get-CimInstance
                $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $arrUsedLogicalDriveLetters = @(Get-CimInstance -ClassName 'Win32_LogicalDisk' |
                        ForEach-Object { $_.DeviceID } |
                        Where-Object { $_.Length -eq 2 } |
                        Where-Object { $_[1] -eq ':' } |
                        ForEach-Object { $_.ToUpper() } |
                        ForEach-Object { $_[0] } |
                        Where-Object { $arrAllPossibleLetters -contains $_ })
                # fifth-, fourth-, and third-to-last bits of pipeline ensures that we
                # have a device ID like "C:"; second-to-last bit of pipeline strips off
                # the ':', leaving just the capital drive letter; last bit of pipeline
                # ensure that the drive letter is actually a letter; addresses legacy
                # Netware edge cases.
                $VerbosePreference = $VerbosePreferenceAtStartOfFunction

                if ($boolExcludeMappedDriveLetters -eq $true) {
                    $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                    $arrUsedMappedDriveLetters = @(Get-CimInstance -ClassName 'Win32_NetworkConnection' |
                            ForEach-Object { $_.LocalName } |
                            Where-Object { $_.Length -eq 2 } |
                            Where-Object { $_[1] -eq ':' } |
                            ForEach-Object { $_.ToUpper() } |
                            ForEach-Object { $_[0] } |
                            Where-Object { $arrAllPossibleLetters -contains $_ })
                    # fifth-, fourth-, and third-to-last bits of pipeline ensures that
                    # we have a LocalName like "C:"; second-to-last bit of pipeline
                    # strips off the ':', leaving just the capital drive letter; last
                    # bit of pipeline ensure that the drive letter is actually a
                    # letter; addresses legacy Netware edge cases.
                    $VerbosePreference = $VerbosePreferenceAtStartOfFunction
                } else {
                    $arrUsedMappedDriveLetters = $null
                }
            } else {
                # Use Get-WmiObject
                $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $arrUsedLogicalDriveLetters = @(Get-WmiObject -Class 'Win32_LogicalDisk' |
                        ForEach-Object { $_.DeviceID } |
                        Where-Object { $_.Length -eq 2 } |
                        Where-Object { $_[1] -eq ':' } |
                        ForEach-Object { $_.ToUpper() } |
                        ForEach-Object { $_[0] } |
                        Where-Object { $arrAllPossibleLetters -contains $_ })
                # fifth-, fourth-, and third-to-last bits of pipeline ensures that we
                # have a device ID like "C:"; second-to-last bit of pipeline strips off
                # the ':', leaving just the capital drive letter; last bit of pipeline
                # ensure that the drive letter is actually a letter; addresses legacy
                # Netware edge cases.
                $VerbosePreference = $VerbosePreferenceAtStartOfFunction

                if ($boolExcludeMappedDriveLetters -eq $true) {
                    $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                    $arrUsedMappedDriveLetters = @(Get-WmiObject -Class 'Win32_NetworkConnection' |
                            ForEach-Object { $_.LocalName } |
                            Where-Object { $_.Length -eq 2 } |
                            Where-Object { $_[1] -eq ':' } |
                            ForEach-Object { $_.ToUpper() } |
                            ForEach-Object { $_[0] } |
                            Where-Object { $arrAllPossibleLetters -contains $_ })
                    # fifth-, fourth-, and third-to-last bits of pipeline ensures that
                    # we have a LocalName like "C:"; second-to-last bit of pipeline
                    # strips off the ':', leaving just the capital drive letter; last
                    # bit of pipeline ensure that the drive letter is actually a
                    # letter; addresses legacy Netware edge cases.
                    $VerbosePreference = $VerbosePreferenceAtStartOfFunction
                } else {
                    $arrUsedMappedDriveLetters = $null
                }
            }

            if ($boolExcludePSDriveLetters -eq $true) {
                $arrUsedPSDriveLetters = @(Get-PSDrive | ForEach-Object { $_.Name } |
                        Where-Object { $_.Length -eq 1 } |
                        ForEach-Object { $_.ToUpper() } |
                        Where-Object { $arrAllPossibleLetters -contains $_ })
                # Checking for a length of 1 strips out most PSDrives that are not
                # drive letters; making sure that each item in the resultant set
                # matches something in $arrAllPossibleLetters filters out edge cases,
                # like a PSDrive named '1'.
            } else {
                $arrUsedPSDriveLetters = $null
            }

            if ($boolExcludeFloppyDriveLetters -eq $true) {
                $arrFloppyDriveLetters = @('A', 'B')
            } else {
                $arrFloppyDriveLetters = $null
            }

            $arrResult = @($arrAllPossibleLetters |
                    Where-Object { $arrUsedLogicalDriveLetters -notcontains $_ } |
                    Where-Object { $arrUsedMappedDriveLetters -notcontains $_ } |
                    Where-Object { $arrUsedPSDriveLetters -notcontains $_ } |
                    Where-Object { $arrFloppyDriveLetters -notcontains $_ } |
                    Where-Object { $arrBlacklistedDriveLetters -notcontains $_ })

            # The following code forces the function to return an array, always, even
            # when there are zero or one elements in the array.
            $intElementCount = 1
            if ($null -ne $arrResult) {
                if ($arrResult.GetType().FullName.Contains('[]')) {
                    if (($arrResult.Count -ge 2) -or ($arrResult.Count -eq 0)) {
                        $intElementCount = $arrResult.Count
                    }
                }
            }
            $strLowercaseFunctionName = $MyInvocation.InvocationName.ToLower()
            $boolArrayEncapsulation = $MyInvocation.Line.ToLower().Contains('@(' + $strLowercaseFunctionName + ')') -or $MyInvocation.Line.ToLower().Contains('@(' + $strLowercaseFunctionName + ' ')
            if ($boolArrayEncapsulation) {
                return $arrResult
            } elseif ($intElementCount -eq 0) {
                return , @()
            } elseif ($intElementCount -eq 1) {
                return , (, ($arrResult[0]))
            } else {
                return $arrResult
            }
        }
    }

    function Get-AclSafely {
        # .SYNOPSIS
        # Gets the access control list (ACL) in a way that suppresses errors, should an
        # error occur.
        #
        # .DESCRIPTION
        # Gets and returns the access control list (ACL) from a path or object. This
        # function is intended to be used in situations where the Get-Acl cmdlet may
        # fail due to a variety of reasons. This function is designed to suppress
        # errors and return a boolean value indicating whether the operation was
        # successful.
        #
        # .PARAMETER ReferenceToACL
        # This parameter is required; it is a reference to an object (the specific
        # object type will vary depending on the type of object/path supplied in the
        # PathToObject parameter; for example, a directory/folder will be a
        # System.Security.AccessControl.DirectorySecurity object, a registry key will
        # be a System.Security.AccessControl.RegistrySecurity, etc.). If the operation
        # was successful, the referenced object will be populated with the object
        # resulting from Get-Acl. If the operation was unsuccessful, the referenced
        # object is undefined.
        #
        # .PARAMETER ReferenceToInfoObject
        # This parameter is required; it is a reference to an object (the specific
        # object type will vary depending on the type of object/path supplied in the
        # PathToObject parameter; for example, a directory/folder will be a
        # System.IO.DirectoryInfo object, a registry key will be a
        # Microsoft.Win32.RegistryKey object, etc.). In cases where this function needs
        # to retrieve the object (using Get-Item) to retrieve the access control entry
        # (ACL), the referenced object will be populated with the object resulting from
        # Get-Item. If the function did not need to use Get-Item, the referenced object
        # is undefined.
        #
        # .PARAMETER PathToObject
        # This parameter is required; it is a string representing the path to the
        # object for which the ACL is to be retrieved. This path can be a file or
        # folder path, or it can be a registry path (for example).
        #
        # .PARAMETER PSVersion
        # This parameter is optional; if supplied, it must be the version number of the
        # running version of PowerShell. If the version of PowerShell is already known,
        # it can be passed in to this function to avoid the overhead of unnecessarily
        # determining the version of PowerShell. If this parameter is not supplied, the
        # function will determine the version of PowerShell that is running as part of
        # its processing.
        #
        # .EXAMPLE
        # $objThisFolderPermission = $null
        # $objThis = $null
        # $strThisObjectPath = 'D:\Shares\Share\Accounting'
        # $boolSuccess = Get-AclSafely -ReferenceToACL ([ref]$objThisFolderPermission) -ReferenceToInfoObject ([ref]$objThis) -PathToObject $strThisObjectPath
        #
        # .EXAMPLE
        # $objThisFolderPermission = $null
        # $objThis = $null
        # $strThisObjectPath = 'D:\Shares\Share\Accounting'
        # $boolSuccess = Get-AclSafely ([ref]$objThisFolderPermission) ([ref]$objThis) $strThisObjectPath
        #
        # .INPUTS
        # None. You can't pipe objects to Get-AclSafely.
        #
        # .OUTPUTS
        # System.Boolean. Get-AclSafely returns a boolean value indiciating whether the
        # process completed successfully. $true means the process completed
        # successfully; $false means there was an error.
        #
        # .NOTES
        # This function also supports the use of positional parameters instead of named
        # parameters. If positional parameters are used intead of named parameters,
        # then three or four positional parameters are required:
        #
        # The first positional parameter is a reference to an object (the specific
        # object type will vary depending on the type of object/path supplied in the
        # PathToObject parameter; for example, a directory/folder will be a
        # System.Security.AccessControl.DirectorySecurity object, a registry key will
        # be a System.Security.AccessControl.RegistrySecurity, etc.). If the operation
        # was successful, the referenced object will be populated with the object
        # resulting from Get-Acl. If the operation was unsuccessful, the referenced
        # object is undefined.
        #
        # The second positional parameter is a reference to an object (the specific
        # object type will vary depending on the type of object/path supplied in the
        # PathToObject parameter; for example, a directory/folder will be a
        # System.IO.DirectoryInfo object, a registry key will be a
        # Microsoft.Win32.RegistryKey object, etc.). In cases where this function needs
        # to retrieve the object (using Get-Item) to retrieve the access control entry
        # (ACL), the referenced object will be populated with the object resulting from
        # Get-Item. If the function did not need to use Get-Item, the referenced object
        # is undefined.
        #
        # The third positional parameter is a string representing the path to the
        # object for which the ACL is to be retrieved. This path can be a file or
        # folder path, or it can be a registry path (for example).
        #
        # The fourth positional parameter is optional; if supplied, it must be the
        # version number of the running version of PowerShell. If the version of
        # PowerShell is already known, it can be passed in to this function to avoid
        # the overhead of unnecessarily determining the version of PowerShell. If this
        # parameter is not supplied, the function will determine the version of
        # PowerShell that is running as part of its processing.
        #
        # Version: 2.1.20250208.0

        #region License ############################################################
        # Copyright (c) 2025 Frank Lesniak
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
            [ref]$ReferenceToACL = ([ref]$null),
            [ref]$ReferenceToInfoObject = ([ref]$null),
            [string]$PathToObject = '',
            [version]$PSVersion = ([version]'0.0')
        )

        #region FunctionsToSupportErrorHandling ####################################
        function Get-ReferenceToLastError {
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on on the $error stack; otherwise, returns a reference to the
            # last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     # So:
            #     # If both are null, no error
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error
            #     # If $refLastKnownError is non-null and $refNewestCurrentError is
            #     # null, no error
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to the
            # last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on on the $error stack.
            #
            # .NOTES
            # Version: 2.0.20241223.0

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

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e., during
            # the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between the
            # two errors.
            #
            # To use this function, you must first retrieve a reference to the last
            # error that occurred prior to the command you are about to run. Then,
            # run the command. After the command completes, retrieve a reference to
            # the last error that occurred. Pass these two references to this
            # function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToEarlierError
            # must be a reference to $null ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
            # whether an error occurred during the time period in question. $true
            # indicates an error occurred; $false indicates no error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters instead
            # of named parameters. If positional parameters are used intead of
            # named parameters, then two positional parameters are required:
            #
            # The first positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred. If
            # no error was on the stack at this time, the first positional
            # parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred. If no
            # error was on the stack at this time, ReferenceToLaterError must be
            # a reference to $null ([ref]$null).
            #
            # Version: 2.0.20241223.0

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
            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            # TODO: Validate input

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared; this
                # does not indicate an error.
                # So:
                # - If both are null, no error
                # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                #   is non-null, error
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            }

            return $boolErrorOccurred
        }
        #endregion FunctionsToSupportErrorHandling ####################################

        function Get-PSVersion {
            # .SYNOPSIS
            # Returns the version of PowerShell that is running.
            #
            # .DESCRIPTION
            # The function outputs a [version] object representing the version of
            # PowerShell that is running.
            #
            # On versions of PowerShell greater than or equal to version 2.0, this
            # function returns the equivalent of $PSVersionTable.PSVersion
            #
            # PowerShell 1.0 does not have a $PSVersionTable variable, so this
            # function returns [version]('1.0') on PowerShell 1.0.
            #
            # .EXAMPLE
            # $versionPS = Get-PSVersion
            # # $versionPS now contains the version of PowerShell that is running.
            # # On versions of PowerShell greater than or equal to version 2.0,
            # # this function returns the equivalent of $PSVersionTable.PSVersion.
            #
            # .INPUTS
            # None. You can't pipe objects to Get-PSVersion.
            #
            # .OUTPUTS
            # System.Version. Get-PSVersion returns a [version] value indiciating
            # the version of PowerShell that is running.
            #
            # .NOTES
            # Version: 1.0.20250106.0

            #region License ####################################################
            # Copyright (c) 2025 Frank Lesniak
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

        #region Process Input ######################################################
        if ($null -ne $PSVersion) {
            if ($PSVersion -eq ([version]'0.0')) {
                $versionPS = Get-PSVersion
            } else {
                $versionPS = $PSVersion
            }
        } else {
            $versionPS = Get-PSVersion
        }

        if ($versionPS.Major -ge 3) {
            # PowerShell 3.0 runs on .NET Framework 4.0, which supports the
            # IsNullOrWhitespace method
            if ([string]::IsNullOrWhiteSpace($PathToObject)) {
                Write-Warning 'For the Get-AclSafely function, the PathToObject parameter is required and cannot be null, empty, or solely containing whitespace.'
                return $false
            }
        } else {
            # PowerShell 1.0 and 2.0 run on .NET Framework 2.0, which does not support
            # the IsNullOrWhitespace method; fall back to IsNullOrEmpty and check for a
            # string that contains only whitespace
            if ([string]::IsNullOrEmpty($PathToObject)) {
                Write-Warning 'For the Get-AclSafely function, the PathToObject parameter is required and cannot be null or empty.'
                return $false
            } else {
                # Not null or empty; check for whitespace
                if ($PathToObject -match '^\s*$') {
                    Write-Warning 'For the Get-AclSafely function, the PathToObject parameter is required and cannot solely contain whitespace.'
                    return $false
                }
            }
        }
        #endregion Process Input ######################################################

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

        # This needs to be a one-liner for error handling to work!:
        if ($PathToObject.Contains('[') -or $PathToObject.Contains(']') -or $PathToObject.Contains('`')) { if ($versionPS.Major -ge 3) { ($ReferenceToInfoObject.Value) = Get-Item -LiteralPath $PathToObject -Force; if ($versionPS -ge ([version]'7.3')) { if (@(Get-Module Microsoft.PowerShell.Security).Count -eq 0) { Import-Module Microsoft.PowerShell.Security }; ($ReferenceToACL.Value) = [System.IO.FileSystemAclExtensions]::GetAccessControl($ReferenceToInfoObject.Value) } else { ($ReferenceToACL.Value) = ($ReferenceToInfoObject.Value).GetAccessControl() } } elseif ($versionPS.Major -eq 2) { ($ReferenceToInfoObject.Value) = Get-Item -Path ((($PathToObject.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force; ($ReferenceToACL.Value) = ($ReferenceToInfoObject.Value).GetAccessControl() } else { ($ReferenceToACL.Value) = Get-Acl -Path ($PathToObject.Replace('`', '``')) } } else { ($ReferenceToACL.Value) = Get-Acl -Path $PathToObject }
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
        # if ($PathToObject.Contains('[') -or $PathToObject.Contains(']') -or $PathToObject.Contains('`')) {
        #     # Can't use Get-Acl because Get-Acl doesn't support paths with brackets
        #     # or grave accent marks (backticks). So, we need to use Get-Item and then
        #     # GetAccessControl() or [System.IO.FileSystemAclExtensions]::GetAccessControl()
        #     if ($versionPS.Major -ge 3) {
        #         # PowerShell v3 and newer supports -LiteralPath
        #         ($ReferenceToInfoObject.Value) = Get-Item -LiteralPath $PathToObject -Force # -Force parameter is required to get hidden items
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
        #             ($ReferenceToACL.Value) = [System.IO.FileSystemAclExtensions]::GetAccessControl($ReferenceToInfoObject.Value)
        #         } else {
        #             # PowerShell v3 through v7.2
        #             ($ReferenceToACL.Value) = ($ReferenceToInfoObject.Value).GetAccessControl()
        #         }
        #     } elseif ($versionPS.Major -eq 2) {
        #         # We don't need to escape the right square bracket based on testing,
        #         # but we do need to escape the left square bracket. Nevertheless,
        #         # escaping both brackets does work and seems like the safest option.
        #         # Additionally, escape the grave accent mark (backtick).
        #         ($ReferenceToInfoObject.Value) = Get-Item -Path ((($PathToObject.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force # -Force parameter is required to get hidden items
        #         ($ReferenceToACL.Value) = ($ReferenceToInfoObject.Value).GetAccessControl()
        #     } else {
        #         # PowerShell v1
        #         # Get-Item -> GetAccessControl() does not work and returns $null on
        #         # PowerShell v1 for some reason.
        #         # And, unfortunately, there is no apparent way to escape left square
        #         # brackets with Get-Acl. However, we can escape the grave accent mark
        #         # (backtick).
        #         ($ReferenceToACL.Value) = Get-Acl -Path ($PathToObject.Replace('`', '``'))
        #     }
        # } else {
        #     # No square brackets or grave accent marks (backticks); use Get-Acl
        #     ($ReferenceToACL.Value) = Get-Acl -Path $PathToObject
        # }
        ###############################################################################

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            # Error occurred; return failure indicator:
            return $false
        } else {
            # No error occurred; return success indicator:
            return $true
        }
    }

    function Get-ChildItemUsingObjectSafely {
        # .SYNOPSIS
        # Gets the child item(s) of an object, suppressing any errors.
        #
        # .DESCRIPTION
        # Gets the child item(s) of an object in a way that suppresses errors. This
        # function replaces: $obj | Get-ChildItem (see examples)
        #
        # .PARAMETER ReferenceToChildItems
        # This parameter is required; it is a reference to an array of child objects.
        # If the operation was successful, the referenced array will be populated with
        # the child objects returned from Get-ChildItem. If the operation was
        # unsuccessful, the referenced array may be modified, but its contents would be
        # undefined.
        #
        # .PARAMETER ReferenceToParentObject
        # This parameter is required; it is a reference to the parent object. The
        # parent object will be passed to Get-ChildItem.
        #
        # .EXAMPLE
        # $objThisFolderItem = Get-Item 'D:\Shares\Share\Data'
        # $arrChildObjects = @()
        # $boolSuccess = Get-ChildItemUsingObjectSafely -ReferenceToChildItems ([ref]$arrChildObjects) -ReferenceToParentObject ([ref]$objThisFolderItem)
        #
        # .EXAMPLE
        # $objThisFolderItem = Get-Item 'D:\Shares\Share\Data'
        # $arrChildObjects = @()
        # $boolSuccess = Get-ChildItemUsingObjectSafely ([ref]$arrChildObjects) ([ref]$objThisFolderItem)
        #
        # .INPUTS
        # None. You can't pipe objects to Get-ChildItemUsingObjectSafely.
        #
        # .OUTPUTS
        # System.Boolean. Get-ChildItemUsingObjectSafely returns a boolean value
        # indiciating whether the process completed successfully. $true means the
        # process completed successfully; $false means there was an error.
        #
        # .NOTES
        # This function also supports the use of positional parameters instead of named
        # parameters. If positional parameters are used intead of named parameters,
        # then two positional parameters are required:
        #
        # The first positional parameter is a reference to an array of child objects.
        # If the operation was successful, the referenced array will be populated with
        # the child objects returned from Get-ChildItem. If the operation was
        # unsuccessful, the referenced array may be modified, but its contents would be
        # undefined.
        #
        # The second positional parameter is a reference to the parent object. The
        # parent object will be passed to Get-ChildItem.
        #
        # Version: 1.2.20241231.0

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
            [ref]$ReferenceToChildItems = ([ref]$null),
            [ref]$ReferenceToParentObject = ([ref]$null)
        )

        #region FunctionsToSupportErrorHandling ####################################
        function Get-ReferenceToLastError {
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on on the $error stack; otherwise, returns a reference to the
            # last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     # So:
            #     # If both are null, no error
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error
            #     # If $refLastKnownError is non-null and $refNewestCurrentError is
            #     # null, no error
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to the
            # last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on on the $error stack.
            #
            # .NOTES
            # Version: 2.0.20241223.0

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

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e., during
            # the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between the
            # two errors.
            #
            # To use this function, you must first retrieve a reference to the last
            # error that occurred prior to the command you are about to run. Then,
            # run the command. After the command completes, retrieve a reference to
            # the last error that occurred. Pass these two references to this
            # function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToEarlierError
            # must be a reference to $null ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
            # whether an error occurred during the time period in question. $true
            # indicates an error occurred; $false indicates no error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters instead
            # of named parameters. If positional parameters are used intead of
            # named parameters, then two positional parameters are required:
            #
            # The first positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred. If
            # no error was on the stack at this time, the first positional
            # parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred. If no
            # error was on the stack at this time, ReferenceToLaterError must be
            # a reference to $null ([ref]$null).
            #
            # Version: 2.0.20241223.0

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
            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            # TODO: Validate input

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared; this
                # does not indicate an error.
                # So:
                # - If both are null, no error
                # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                #   is non-null, error
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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

        # Get the child item(s) of the parent object:
        $ReferenceToChildItems.Value = @(($ReferenceToParentObject.Value) | Get-ChildItem -Force)

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            # Error occurred; return failure indicator:
            return $false
        } else {
            # No error occurred; return success indicator:
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
        # ReferenceToJoinedPath.
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
        #
        # .NOTES
        # This function also supports the use of positional parameters instead of named
        # parameters. If positional parameters are used intead of named parameters,
        # then three to five positional parameters are required:
        #
        # The first positional parameter is a memory reference to a string variable
        # that will be populated with the joined path (parent path + child path). If no
        # child path was specified, then the parent path will be populated in the
        # referenced variable.
        #
        # The second positional parameter is a memory reference to a boolean variable
        # that indicates whether or not the Get-PSDrive workaround should be used. If
        # the Get-PSDrive workaround is used, then the function will use the
        # Get-PSDrive cmdlet to refresh PowerShell's "understanding" of the available
        # drive letters. This variable is passed by reference to ensure that this
        # function can set the variable to $true if the Get-PSDrive workaround is
        # successful - which improves performance of subsequent runs.
        #
        # The third positional parameter is a string containing the path to be tested
        # for availability, and the parent path to be used in the Join-Path operation.
        # If no child path is specified in the fourth positional parameter, then the
        # contents of the Path parameter will populated into the variable referenced in
        # the first positional parameter.
        #
        # The fourth positional parameter is optional; if supplied, it is a string
        # containing the child path to be used in the Join-Path operation. If it is not
        # specified, or if it contains $null or a blank string, then the path specified
        # by the third positional parameter will be populated into the variable
        # referenced in the first positional parameter. However, if this fourth
        # positional parameter contains a string containing data, then the path
        # specified by the third positional parameter will be used as the parent path
        # in the Join-Path operation, and this fourth positional parameter will be used
        # as the child path in the Join-Path operation. The joined path will be
        # populated into the variable referenced in the first positional parameter.
        #
        # The fifth positional parameter is optional; if supplied, it is the maximum
        # amount of seconds to wait for the path to be ready. If the path is not ready
        # within this time, then the function will return $false. By default, this
        # parameter is set to 10 seconds.
        #
        # Version: 1.0.20241231.0

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
            # .SYNOPSIS
            # Joins two path parts together and suppresses any errors that may occur.
            #
            # .DESCRIPTION
            # Combines two paths parts (parent and child) into a single path. This
            # function is intended to be used in situations where the Join-Path cmdlet
            # may fail due to a variety of reasons. This function is designed to
            # suppress errors and return a boolean value indicating whether the
            # operation was successful.
            #
            # .PARAMETER ReferenceToJoinedPath
            # This parameter is required; it is a reference to a string object that
            # will be populated with the joined path (parent path + child path). If the
            # operation was successful, the referenced string object will be populated
            # with the joined path. If the operation was unsuccessful, the referenced
            # string is undefined.
            #
            # .PARAMETER ParentPath
            # This parameter is required; it is a string representing the parent part
            # of the path.
            #
            # .PARAMETER ChildPath
            # This parameter is required; it is the child part of the path.
            #
            # .EXAMPLE
            # $strParentPartOfPath = 'Z:'
            # $strChildPartOfPath = '####FAKE####'
            # $strJoinedPath = $null
            # $boolSuccess = Join-PathSafely -ReferenceToJoinedPath ([ref]$strJoinedPath) -ParentPath $strParentPartOfPath -ChildPath $strChildPartOfPath
            #
            # .EXAMPLE
            # $strParentPartOfPath = 'Z:'
            # $strChildPartOfPath = '####FAKE####'
            # $strJoinedPath = $null
            # $boolSuccess = Join-PathSafely ([ref]$strJoinedPath) $strParentPartOfPath $strChildPartOfPath
            #
            # .INPUTS
            # None. You can't pipe objects to Join-PathSafely.
            #
            # .OUTPUTS
            # System.Boolean. Join-PathSafely returns a boolean value indiciating
            # whether the process completed successfully. $true means the process
            # completed successfully; $false means there was an error.
            #
            # .NOTES
            # This function also supports the use of positional parameters instead of
            # named parameters. If positional parameters are used intead of named
            # parameters, then three positional parameters are required:
            #
            # The first positional parameter is a reference to a string object that
            # will be populated with the joined path (parent path + child path). If the
            # operation was successful, the referenced string object will be populated
            # with the joined path. If the operation was unsuccessful, the referenced
            # string is undefined.
            #
            # The second positional parameter is a string representing the parent part
            # of the path.
            #
            # The third positional parameter is the child part of the path.
            #
            # Version: 2.0.20241231.0

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
                [ref]$ReferenceToJoinedPath = ([ref]$null),
                [string]$ParentPath = '',
                [string]$ChildPath = ''
            )

            #region FunctionsToSupportErrorHandling ################################
            function Get-ReferenceToLastError {
                # .SYNOPSIS
                # Gets a reference (memory pointer) to the last error that occurred.
                #
                # .DESCRIPTION
                # Returns a reference (memory pointer) to $null ([ref]$null) if no
                # errors on on the $error stack; otherwise, returns a reference to the
                # last error that occurred.
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work:
                # $refLastKnownError = Get-ReferenceToLastError
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # $refNewestCurrentError = Get-ReferenceToLastError
                #
                # $boolErrorOccurred = $false
                # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #     # Both not $null
                #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # } else {
                #     # One is $null, or both are $null
                #     # NOTE: $refLastKnownError could be non-null, while
                #     # $refNewestCurrentError could be null if $error was cleared;
                #     # this does not indicate an error.
                #     # So:
                #     # If both are null, no error
                #     # If $refLastKnownError is null and $refNewestCurrentError is
                #     # non-null, error
                #     # If $refLastKnownError is non-null and $refNewestCurrentError is
                #     # null, no error
                #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Get-ReferenceToLastError.
                #
                # .OUTPUTS
                # System.Management.Automation.PSReference ([ref]).
                # Get-ReferenceToLastError returns a reference (memory pointer) to the
                # last error that occurred. It returns a reference to $null
                # ([ref]$null) if there are no errors on on the $error stack.
                #
                # .NOTES
                # Version: 2.0.20241223.0

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

                if ($Error.Count -gt 0) {
                    return ([ref]($Error[0]))
                } else {
                    return ([ref]$null)
                }
            }

            function Test-ErrorOccurred {
                # .SYNOPSIS
                # Checks to see if an error occurred during a time period, i.e., during
                # the execution of a command.
                #
                # .DESCRIPTION
                # Using two references (memory pointers) to errors, this function
                # checks to see if an error occurred based on differences between the
                # two errors.
                #
                # To use this function, you must first retrieve a reference to the last
                # error that occurred prior to the command you are about to run. Then,
                # run the command. After the command completes, retrieve a reference to
                # the last error that occurred. Pass these two references to this
                # function to determine if an error occurred.
                #
                # .PARAMETER ReferenceToEarlierError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToEarlierError
                # must be a reference to $null ([ref]$null).
                #
                # .PARAMETER ReferenceToLaterError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToLaterError
                # must be a reference to $null ([ref]$null).
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work
                # if ($Error.Count -gt 0) {
                #     $refLastKnownError = ([ref]($Error[0]))
                # } else {
                #     $refLastKnownError = ([ref]$null)
                # }
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # if ($Error.Count -gt 0) {
                #     $refNewestCurrentError = ([ref]($Error[0]))
                # } else {
                #     $refNewestCurrentError = ([ref]$null)
                # }
                #
                # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                #     # Error occurred
                # } else {
                #     # No error occurred
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Test-ErrorOccurred.
                #
                # .OUTPUTS
                # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
                # whether an error occurred during the time period in question. $true
                # indicates an error occurred; $false indicates no error occurred.
                #
                # .NOTES
                # This function also supports the use of positional parameters instead
                # of named parameters. If positional parameters are used intead of
                # named parameters, then two positional parameters are required:
                #
                # The first positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred. If
                # no error was on the stack at this time, the first positional
                # parameter must be a reference to $null ([ref]$null).
                #
                # The second positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred. If no
                # error was on the stack at this time, ReferenceToLaterError must be
                # a reference to $null ([ref]$null).
                #
                # Version: 2.0.20241223.0

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
                param (
                    [ref]$ReferenceToEarlierError = ([ref]$null),
                    [ref]$ReferenceToLaterError = ([ref]$null)
                )

                # TODO: Validate input

                $boolErrorOccurred = $false
                if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    # Both not $null
                    if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                } else {
                    # One is $null, or both are $null
                    # NOTE: $ReferenceToEarlierError could be non-null, while
                    # $ReferenceToLaterError could be null if $error was cleared; this
                    # does not indicate an error.
                    # So:
                    # - If both are null, no error
                    # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                    #   is non-null, error
                    # - If $ReferenceToEarlierError is non-null and
                    #   $ReferenceToLaterError is null, no error
                    if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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

            #region Process Input ##################################################
            if ([string]::IsNullOrEmpty($ParentPath)) {
                Write-Warning "In the function Join-PathSafely(), the ParentPath parameter is required and cannot be null or empty."
                return $false
            }
            #endregion Process Input ##################################################

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

            # Attempt to join the path
            ($ReferenceToJoinedPath.Value) = Join-Path -Path $ParentPath -ChildPath $ChildPath

            # Restore the former error preference
            $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

            # Retrieve the newest error on the error stack
            $refNewestCurrentError = Get-ReferenceToLastError

            if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                # Error occurred; return failure indicator:
                return $false
            } else {
                # No error occurred; return success indicator:
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
                $boolSuccess = Join-PathSafely -ReferenceToJoinedPath ([ref]$strJoinedPath) -ParentPath $Path -ChildPath $strWorkingChildItemPath

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
                            $boolSuccess = Join-PathSafely -ReferenceToJoinedPath ([ref]$strJoinedPath) -ParentPath $Path -ChildPath $strWorkingChildItemPath

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
        # This function also supports the use of positional parameters instead of named
        # parameters. If positional parameters are used intead of named parameters,
        # then two to three positional parameters are required:
        #
        # The first positional parameter is a memory reference to a boolean variable
        # that indicates whether or not the Get-PSDrive workaround should be used. If
        # the Get-PSDrive workaround is used, then the function will use the
        # Get-PSDrive cmdlet to refresh PowerShell's "understanding" of the available
        # drive letters. This variable is passed by reference to ensure that this
        # function can set the variable to $true if the Get-PSDrive workaround is
        # successful - which improves performance of subsequent runs.
        #
        # The second positional parameter is a string containing the path to be tested
        # for availability.
        #
        # The third positional parameter is optional; if supplied, it is the maximum
        # amount of seconds to wait for the path to be ready. If the path is not ready
        # within this time, then the function will return $false. By default, this
        # parameter is set to 10 seconds.
        #
        # Version: 1.0.20241231.0

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
            [System.Management.Automation.PSReference]$ReferenceToUseGetPSDriveWorkaround = ([ref]$null),
            [string]$Path,
            [int]$MaximumWaitTimeInSeconds = 10,
            [switch]$DoNotAttemptGetPSDriveWorkaround
        )

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
        # This function also supports the use of positional parameters instead of
        # named parameters. If positional parameters are used intead of named
        # parameters, then two or three positional parameters are required:
        #
        # The first positional parameter is a reference to a string. If the process
        # was successful, the referenced string will be updated to contain the
        # short DOS 8.3 path. If the process is not successful, then the contents
        # of the string are undefined.
        #
        # The second positional parameter is a string containing the path of the
        # folder or file for which we want to retrieve its DOS 8.3 file path.
        #
        # The third positional parameter is optional. If supplied, it is a
        # reference to a Scripting.FileSystemObject object. Supplying this
        # parameter can speed up performance by avoiding to have to create the
        # Scripting.FileSystemObject every time this function is called.
        #
        # Version: 1.1.20241223.0

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
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on on the $error stack; otherwise, returns a reference to the
            # last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     # So:
            #     # If both are null, no error
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error
            #     # If $refLastKnownError is non-null and $refNewestCurrentError is
            #     # null, no error
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to the
            # last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on on the $error stack.
            #
            # .NOTES
            # Version: 2.0.20241223.0

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

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e., during
            # the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between the
            # two errors.
            #
            # To use this function, you must first retrieve a reference to the last
            # error that occurred prior to the command you are about to run. Then,
            # run the command. After the command completes, retrieve a reference to
            # the last error that occurred. Pass these two references to this
            # function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToEarlierError
            # must be a reference to $null ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
            # whether an error occurred during the time period in question. $true
            # indicates an error occurred; $false indicates no error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters instead
            # of named parameters. If positional parameters are used intead of
            # named parameters, then two positional parameters are required:
            #
            # The first positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred. If
            # no error was on the stack at this time, the first positional
            # parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred. If no
            # error was on the stack at this time, ReferenceToLaterError must be
            # a reference to $null ([ref]$null).
            #
            # Version: 2.0.20241223.0

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
            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            # TODO: Validate input

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared; this
                # does not indicate an error.
                # So:
                # - If both are null, no error
                # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                #   is non-null, error
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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
            # This function also supports the use of a positional parameter instead of a
            # named parameter. If a positional parameter is used intead of a named
            # parameter, then exactly one positional parameter is required:
            #
            # The first and only positional parameter is a reference to an object that will
            # become the FileSystemObject COM object. If the object is created
            # successfully, then the referenced object will be updated, storing the
            # FileSystemObject COM object. If the object is not created successfully, then
            # the referenced variable becomes undefined.
            #
            # Version: 1.1.20241223.0

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
                # .SYNOPSIS
                # Gets a reference (memory pointer) to the last error that occurred.
                #
                # .DESCRIPTION
                # Returns a reference (memory pointer) to $null ([ref]$null) if no
                # errors on on the $error stack; otherwise, returns a reference to the
                # last error that occurred.
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work:
                # $refLastKnownError = Get-ReferenceToLastError
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # $refNewestCurrentError = Get-ReferenceToLastError
                #
                # $boolErrorOccurred = $false
                # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #     # Both not $null
                #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # } else {
                #     # One is $null, or both are $null
                #     # NOTE: $refLastKnownError could be non-null, while
                #     # $refNewestCurrentError could be null if $error was cleared;
                #     # this does not indicate an error.
                #     # So:
                #     # If both are null, no error
                #     # If $refLastKnownError is null and $refNewestCurrentError is
                #     # non-null, error
                #     # If $refLastKnownError is non-null and $refNewestCurrentError is
                #     # null, no error
                #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Get-ReferenceToLastError.
                #
                # .OUTPUTS
                # System.Management.Automation.PSReference ([ref]).
                # Get-ReferenceToLastError returns a reference (memory pointer) to the
                # last error that occurred. It returns a reference to $null
                # ([ref]$null) if there are no errors on on the $error stack.
                #
                # .NOTES
                # Version: 2.0.20241223.0

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

                if ($Error.Count -gt 0) {
                    return ([ref]($Error[0]))
                } else {
                    return ([ref]$null)
                }
            }

            function Test-ErrorOccurred {
                # .SYNOPSIS
                # Checks to see if an error occurred during a time period, i.e., during
                # the execution of a command.
                #
                # .DESCRIPTION
                # Using two references (memory pointers) to errors, this function
                # checks to see if an error occurred based on differences between the
                # two errors.
                #
                # To use this function, you must first retrieve a reference to the last
                # error that occurred prior to the command you are about to run. Then,
                # run the command. After the command completes, retrieve a reference to
                # the last error that occurred. Pass these two references to this
                # function to determine if an error occurred.
                #
                # .PARAMETER ReferenceToEarlierError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToEarlierError
                # must be a reference to $null ([ref]$null).
                #
                # .PARAMETER ReferenceToLaterError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToLaterError
                # must be a reference to $null ([ref]$null).
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work
                # if ($Error.Count -gt 0) {
                #     $refLastKnownError = ([ref]($Error[0]))
                # } else {
                #     $refLastKnownError = ([ref]$null)
                # }
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # if ($Error.Count -gt 0) {
                #     $refNewestCurrentError = ([ref]($Error[0]))
                # } else {
                #     $refNewestCurrentError = ([ref]$null)
                # }
                #
                # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                #     # Error occurred
                # } else {
                #     # No error occurred
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Test-ErrorOccurred.
                #
                # .OUTPUTS
                # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
                # whether an error occurred during the time period in question. $true
                # indicates an error occurred; $false indicates no error occurred.
                #
                # .NOTES
                # This function also supports the use of positional parameters instead
                # of named parameters. If positional parameters are used intead of
                # named parameters, then two positional parameters are required:
                #
                # The first positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred. If
                # no error was on the stack at this time, the first positional
                # parameter must be a reference to $null ([ref]$null).
                #
                # The second positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred. If no
                # error was on the stack at this time, ReferenceToLaterError must be
                # a reference to $null ([ref]$null).
                #
                # Version: 2.0.20241223.0

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
                param (
                    [ref]$ReferenceToEarlierError = ([ref]$null),
                    [ref]$ReferenceToLaterError = ([ref]$null)
                )

                # TODO: Validate input

                $boolErrorOccurred = $false
                if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    # Both not $null
                    if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                } else {
                    # One is $null, or both are $null
                    # NOTE: $ReferenceToEarlierError could be non-null, while
                    # $ReferenceToLaterError could be null if $error was cleared; this
                    # does not indicate an error.
                    # So:
                    # - If both are null, no error
                    # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                    #   is non-null, error
                    # - If $ReferenceToEarlierError is non-null and
                    #   $ReferenceToLaterError is null, no error
                    if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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
            $ReferenceToStoreObject.Value = New-Object -ComObject Scripting.FileSystemObject

            # Restore the former error preference
            $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

            # Retrieve the newest error on the error stack
            $refNewestCurrentError = Get-ReferenceToLastError

            if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
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
            # This function also supports the use of positional parameters instead of
            # named parameters. If positional parameters are used intead of named
            # parameters, then three positional parameters are required:
            #
            # The first positional parameter is a reference to an object that will
            # become the Folder COM object created using Scripting.FileSystemObject. If
            # the object is created successfully, then the referenced object will be
            # updated, storing the Folder COM object. If the object is not created
            # successfully, then the referenced variable becomes undefined.
            #
            # The second positional parameter is a reference to a
            # Scripting.FileSystemObject COM object, which has already been
            # initialized.
            #
            # The third positional parameter is a string containing the path to the
            # folder for which this function will obtain the Folder COM object.
            #
            # Version: 1.1.20241223.0

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
                # .SYNOPSIS
                # Gets a reference (memory pointer) to the last error that occurred.
                #
                # .DESCRIPTION
                # Returns a reference (memory pointer) to $null ([ref]$null) if no
                # errors on on the $error stack; otherwise, returns a reference to the
                # last error that occurred.
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work:
                # $refLastKnownError = Get-ReferenceToLastError
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # $refNewestCurrentError = Get-ReferenceToLastError
                #
                # $boolErrorOccurred = $false
                # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #     # Both not $null
                #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # } else {
                #     # One is $null, or both are $null
                #     # NOTE: $refLastKnownError could be non-null, while
                #     # $refNewestCurrentError could be null if $error was cleared;
                #     # this does not indicate an error.
                #     # So:
                #     # If both are null, no error
                #     # If $refLastKnownError is null and $refNewestCurrentError is
                #     # non-null, error
                #     # If $refLastKnownError is non-null and $refNewestCurrentError is
                #     # null, no error
                #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Get-ReferenceToLastError.
                #
                # .OUTPUTS
                # System.Management.Automation.PSReference ([ref]).
                # Get-ReferenceToLastError returns a reference (memory pointer) to the
                # last error that occurred. It returns a reference to $null
                # ([ref]$null) if there are no errors on on the $error stack.
                #
                # .NOTES
                # Version: 2.0.20241223.0

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

                if ($Error.Count -gt 0) {
                    return ([ref]($Error[0]))
                } else {
                    return ([ref]$null)
                }
            }

            function Test-ErrorOccurred {
                # .SYNOPSIS
                # Checks to see if an error occurred during a time period, i.e., during
                # the execution of a command.
                #
                # .DESCRIPTION
                # Using two references (memory pointers) to errors, this function
                # checks to see if an error occurred based on differences between the
                # two errors.
                #
                # To use this function, you must first retrieve a reference to the last
                # error that occurred prior to the command you are about to run. Then,
                # run the command. After the command completes, retrieve a reference to
                # the last error that occurred. Pass these two references to this
                # function to determine if an error occurred.
                #
                # .PARAMETER ReferenceToEarlierError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToEarlierError
                # must be a reference to $null ([ref]$null).
                #
                # .PARAMETER ReferenceToLaterError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToLaterError
                # must be a reference to $null ([ref]$null).
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work
                # if ($Error.Count -gt 0) {
                #     $refLastKnownError = ([ref]($Error[0]))
                # } else {
                #     $refLastKnownError = ([ref]$null)
                # }
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # if ($Error.Count -gt 0) {
                #     $refNewestCurrentError = ([ref]($Error[0]))
                # } else {
                #     $refNewestCurrentError = ([ref]$null)
                # }
                #
                # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                #     # Error occurred
                # } else {
                #     # No error occurred
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Test-ErrorOccurred.
                #
                # .OUTPUTS
                # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
                # whether an error occurred during the time period in question. $true
                # indicates an error occurred; $false indicates no error occurred.
                #
                # .NOTES
                # This function also supports the use of positional parameters instead
                # of named parameters. If positional parameters are used intead of
                # named parameters, then two positional parameters are required:
                #
                # The first positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred. If
                # no error was on the stack at this time, the first positional
                # parameter must be a reference to $null ([ref]$null).
                #
                # The second positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred. If no
                # error was on the stack at this time, ReferenceToLaterError must be
                # a reference to $null ([ref]$null).
                #
                # Version: 2.0.20241223.0

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
                param (
                    [ref]$ReferenceToEarlierError = ([ref]$null),
                    [ref]$ReferenceToLaterError = ([ref]$null)
                )

                # TODO: Validate input

                $boolErrorOccurred = $false
                if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    # Both not $null
                    if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                } else {
                    # One is $null, or both are $null
                    # NOTE: $ReferenceToEarlierError could be non-null, while
                    # $ReferenceToLaterError could be null if $error was cleared; this
                    # does not indicate an error.
                    # So:
                    # - If both are null, no error
                    # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                    #   is non-null, error
                    # - If $ReferenceToEarlierError is non-null and
                    #   $ReferenceToLaterError is null, no error
                    if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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
            $ReferenceToFolderObject.Value = ($ReferenceToScriptingFileSystemObject.Value).GetFolder($Path)

            # Restore the former error preference
            $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

            # Retrieve the newest error on the error stack
            $refNewestCurrentError = Get-ReferenceToLastError

            if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
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
            # This function also supports the use of positional parameters instead of
            # named parameters. If positional parameters are used intead of named
            # parameters, then three positional parameters are required:
            #
            # The first positional parameter is a reference to an object that will
            # become the File COM object created using Scripting.FileSystemObject. If
            # the object is created successfully, then the referenced object will be
            # updated, storing the File COM object. If the object is not created
            # successfully, then the referenced variable becomes undefined.
            #
            # The second positional parameter is a reference to a
            # Scripting.FileSystemObject COM object, which has already been
            # initialized.
            #
            # The third positional parameter is a string containing the path to the
            # file for which this function will obtain the File COM object.
            #
            # Version: 1.1.20241223.0

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
                # .SYNOPSIS
                # Gets a reference (memory pointer) to the last error that occurred.
                #
                # .DESCRIPTION
                # Returns a reference (memory pointer) to $null ([ref]$null) if no
                # errors on on the $error stack; otherwise, returns a reference to the
                # last error that occurred.
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work:
                # $refLastKnownError = Get-ReferenceToLastError
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # $refNewestCurrentError = Get-ReferenceToLastError
                #
                # $boolErrorOccurred = $false
                # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #     # Both not $null
                #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # } else {
                #     # One is $null, or both are $null
                #     # NOTE: $refLastKnownError could be non-null, while
                #     # $refNewestCurrentError could be null if $error was cleared;
                #     # this does not indicate an error.
                #     # So:
                #     # If both are null, no error
                #     # If $refLastKnownError is null and $refNewestCurrentError is
                #     # non-null, error
                #     # If $refLastKnownError is non-null and $refNewestCurrentError is
                #     # null, no error
                #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Get-ReferenceToLastError.
                #
                # .OUTPUTS
                # System.Management.Automation.PSReference ([ref]).
                # Get-ReferenceToLastError returns a reference (memory pointer) to the
                # last error that occurred. It returns a reference to $null
                # ([ref]$null) if there are no errors on on the $error stack.
                #
                # .NOTES
                # Version: 2.0.20241223.0

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

                if ($Error.Count -gt 0) {
                    return ([ref]($Error[0]))
                } else {
                    return ([ref]$null)
                }
            }

            function Test-ErrorOccurred {
                # .SYNOPSIS
                # Checks to see if an error occurred during a time period, i.e., during
                # the execution of a command.
                #
                # .DESCRIPTION
                # Using two references (memory pointers) to errors, this function
                # checks to see if an error occurred based on differences between the
                # two errors.
                #
                # To use this function, you must first retrieve a reference to the last
                # error that occurred prior to the command you are about to run. Then,
                # run the command. After the command completes, retrieve a reference to
                # the last error that occurred. Pass these two references to this
                # function to determine if an error occurred.
                #
                # .PARAMETER ReferenceToEarlierError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToEarlierError
                # must be a reference to $null ([ref]$null).
                #
                # .PARAMETER ReferenceToLaterError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToLaterError
                # must be a reference to $null ([ref]$null).
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work
                # if ($Error.Count -gt 0) {
                #     $refLastKnownError = ([ref]($Error[0]))
                # } else {
                #     $refLastKnownError = ([ref]$null)
                # }
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # if ($Error.Count -gt 0) {
                #     $refNewestCurrentError = ([ref]($Error[0]))
                # } else {
                #     $refNewestCurrentError = ([ref]$null)
                # }
                #
                # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                #     # Error occurred
                # } else {
                #     # No error occurred
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Test-ErrorOccurred.
                #
                # .OUTPUTS
                # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
                # whether an error occurred during the time period in question. $true
                # indicates an error occurred; $false indicates no error occurred.
                #
                # .NOTES
                # This function also supports the use of positional parameters instead
                # of named parameters. If positional parameters are used intead of
                # named parameters, then two positional parameters are required:
                #
                # The first positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred. If
                # no error was on the stack at this time, the first positional
                # parameter must be a reference to $null ([ref]$null).
                #
                # The second positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred. If no
                # error was on the stack at this time, ReferenceToLaterError must be
                # a reference to $null ([ref]$null).
                #
                # Version: 2.0.20241223.0

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
                param (
                    [ref]$ReferenceToEarlierError = ([ref]$null),
                    [ref]$ReferenceToLaterError = ([ref]$null)
                )

                # TODO: Validate input

                $boolErrorOccurred = $false
                if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    # Both not $null
                    if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                } else {
                    # One is $null, or both are $null
                    # NOTE: $ReferenceToEarlierError could be non-null, while
                    # $ReferenceToLaterError could be null if $error was cleared; this
                    # does not indicate an error.
                    # So:
                    # - If both are null, no error
                    # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                    #   is non-null, error
                    # - If $ReferenceToEarlierError is non-null and
                    #   $ReferenceToLaterError is null, no error
                    if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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
            $ReferenceToFileObject.Value = ($ReferenceToScriptingFileSystemObject.Value).GetFile($Path)

            # Restore the former error preference
            $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

            # Retrieve the newest error on the error stack
            $refNewestCurrentError = Get-ReferenceToLastError

            if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
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

        # Get the Scripting.FileSystemObject if necessary
        if ($null -eq $ReferenceToScriptingFileSystemObject.Value) {
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
            $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject -ReferenceToFolderObject ([ref]$objFSOFolderOrFileObject) -ReferenceToScriptingFileSystemObject $ReferenceToScriptingFileSystemObject -Path $Path
        } else {
            $boolSuccess = Get-FolderObjectSafelyUsingScriptingFileSystemObject -ReferenceToFolderObject ([ref]$objFSOFolderOrFileObject) -ReferenceToScriptingFileSystemObject ([ref]$objScriptingFileSystemObject) -Path $Path
        }
        if ($boolSuccess -eq $false) {
            # Failed to retrieve folder object; perhaps it's a file?
            if ($boolUseReferencedFSO) {
                $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject -ReferenceToFileObject ([ref]$objFSOFolderOrFileObject) -ReferenceToScriptingFileSystemObject $ReferenceToScriptingFileSystemObject -Path $Path
            } else {
                $boolSuccess = Get-FileObjectSafelyUsingScriptingFileSystemObject -ReferenceToFileObject ([ref]$objFSOFolderOrFileObject) -ReferenceToScriptingFileSystemObject ([ref]$objScriptingFileSystemObject) -Path $Path
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
        $ReferenceToDOS8Dot3Path.Value = $objFSOFolderOrFileObject.ShortPath

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
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
        # This function also supports the use of a positional parameter instead of a
        # named parameter. If a positional parameter is used intead of a named
        # parameter, then one positional parameters is required: it is a reference to
        # an object that will be tested to determine if it is a SID.
        #
        # Version: 3.0.20241223.0

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
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on on the $error stack; otherwise, returns a reference to the
            # last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     # So:
            #     # If both are null, no error
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error
            #     # If $refLastKnownError is non-null and $refNewestCurrentError is
            #     # null, no error
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to the
            # last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on on the $error stack.
            #
            # .NOTES
            # Version: 2.0.20241223.0

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

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e., during
            # the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between the
            # two errors.
            #
            # To use this function, you must first retrieve a reference to the last
            # error that occurred prior to the command you are about to run. Then,
            # run the command. After the command completes, retrieve a reference to
            # the last error that occurred. Pass these two references to this
            # function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToEarlierError
            # must be a reference to $null ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
            # whether an error occurred during the time period in question. $true
            # indicates an error occurred; $false indicates no error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters instead
            # of named parameters. If positional parameters are used intead of
            # named parameters, then two positional parameters are required:
            #
            # The first positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred. If
            # no error was on the stack at this time, the first positional
            # parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred. If no
            # error was on the stack at this time, ReferenceToLaterError must be
            # a reference to $null ([ref]$null).
            #
            # Version: 2.0.20241223.0

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
            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            # TODO: Validate input

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared; this
                # does not indicate an error.
                # So:
                # - If both are null, no error
                # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                #   is non-null, error
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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
        $objSID = ($ReferenceToObject.Value) -as [System.Security.Principal.SecurityIdentifier]

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            # Error occurred; return indicator that object is not a SID:
            return $false
        } else {
            # No error occurred
            # If $objSID is not $null, then the referenced object was a SID
            # If $objSID is $null, then the referenced object was not a SID
            return ($null -ne $objSID)
        }
    }

    function Add-AccessRuleRobust {
        # .SYNOPSIS
        # Adds an access rule to an object.
        #
        # .DESCRIPTION
        # This function adds an access rule to a
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
        # System.Security.AccessControl.DirectorySecurity or similar object to which
        # the access control entry will be added.
        #
        # .PARAMETER ReferenceToAccessRuleObject
        # This parameter is required; it is a reference to a
        # System.Security.AccessControl.FileSystemAccessRule or similar object that
        # will be added to the access control list.
        #
        # .EXAMPLE
        # $boolCheckForType = $true
        # $boolRunGetAcl = $true
        # $strPath = 'D:\Shared\Human_Resources'
        # if ($strPath.Length -gt 248) {
        #     if ($strPath.Substring(0, 2) -eq '\\') {
        #         $strPath = '\\?\UNC\' + $strPath.Substring(2)
        #     } else {
        #         $strPath = '\\?\' + $strPath
        #     }
        # }
        # $objDirectoryInfo = Get-Item -Path $strPath
        # if (@(@($objDirectoryInfo.PSObject.Methods) | Where-Object { $_.Name -eq 'GetAccessControl' }).Count -ge 1) {
        #     # The GetAccessControl() method is available on .NET Framework 2.x - 4.x
        #     $objDirectorySecurity = $objDirectoryInfo.GetAccessControl()
        # } else {
        #     # The GetAccessControl() method is not available - this is expected on
        #     # PowerShell Core 6.x and later
        #     if ($boolCheckForType) {
        #         $boolTypeNameAvailable = @([System.AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType('System.IO.FileSystemAclExtensions') } | Where-Object { $_ }).Count -ge 1
        #         if (-not $boolTypeNameAvailable) {
        #             Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        #             $boolCheckForType = $false
        #         }
        #     }
        #     $objDirectorySecurity = [System.IO.FileSystemAclExtensions]::GetAccessControl($objDirectoryInfo)
        #     # $objDirectorySecurity is created but may appear empty/uninitialized.
        #     # This is because the object is missing additional properties that
        #     # correspond to the way that PowerShell displays this object. You can fix
        #     # this by running Get-Acl on any other object that has an ACL; once you
        #     # do that, the $objDirectorySecurity object will have the "missing"
        #     # properties and will display correctly in the console.
        #     if ($boolRunGetAcl) {
        #         $arrCommands = @(Get-Command -Name 'Get-Acl' -ErrorAction SilentlyContinue)
        #         if ($arrCommands.Count -gt 0) {
        #             [void](Get-Acl -Path $HOME)
        #         }
        #         $boolRunGetAcl = $false
        #     }
        # }
        #
        # # Add the access rule
        # $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
        # $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        # $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        # $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
        # $objAccessRuleToAdd = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList 'BUILTIN\Administrators', $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
        # $boolSuccess = Add-AccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 8 -ReferenceToAccessControlListObject ([ref]$objDirectorySecurity) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToAdd)
        #
        # .INPUTS
        # None. You can't pipe objects to Add-AccessRuleRobust.
        #
        # .OUTPUTS
        # System.Boolean. Add-AccessRuleRobust returns a boolean value indicating
        # whether the process completed successfully. $true means the process completed
        # successfully; $false means there was an error.
        #
        # .NOTES
        # This function also supports the use of positional parameters instead of named
        # parameters. If positional parameters are used intead of named parameters,
        # then four positional parameters are required:
        #
        # The first positional parameter is an integer indicating the current attempt
        # number. When calling this function for the first time, it should be 1.
        #
        # The second positional parameter is an integer representing the maximum number
        # of attempts that the function will observe before giving up.
        #
        # The third positional parameter is a reference to a
        # System.Security.AccessControl.DirectorySecurity or similar object to which
        # the access control entry will be added.
        #
        # The fourth positional parameter is a reference to a
        # System.Security.AccessControl.FileSystemAccessRule or similar object that
        # will be added to the access control list.
        #
        # Version: 1.1.20250108.0

        #region License ############################################################
        # Copyright (c) 2025 Frank Lesniak
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
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on on the $error stack; otherwise, returns a reference to the
            # last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     # So:
            #     # If both are null, no error
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error
            #     # If $refLastKnownError is non-null and $refNewestCurrentError is
            #     # null, no error
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to the
            # last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on on the $error stack.
            #
            # .NOTES
            # Version: 2.0.20241223.0

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

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e., during
            # the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between the
            # two errors.
            #
            # To use this function, you must first retrieve a reference to the last
            # error that occurred prior to the command you are about to run. Then,
            # run the command. After the command completes, retrieve a reference to
            # the last error that occurred. Pass these two references to this
            # function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToEarlierError
            # must be a reference to $null ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
            # whether an error occurred during the time period in question. $true
            # indicates an error occurred; $false indicates no error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters instead
            # of named parameters. If positional parameters are used intead of
            # named parameters, then two positional parameters are required:
            #
            # The first positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred. If
            # no error was on the stack at this time, the first positional
            # parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred. If no
            # error was on the stack at this time, ReferenceToLaterError must be
            # a reference to $null ([ref]$null).
            #
            # Version: 2.0.20241223.0

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
            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            # TODO: Validate input

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared; this
                # does not indicate an error.
                # So:
                # - If both are null, no error
                # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                #   is non-null, error
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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

        # Add the access rule/access control entry to the list
        ($ReferenceToAccessControlListObject.Value).AddAccessRule($ReferenceToAccessRuleObject.Value)

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            # Error occurred
            if ($CurrentAttemptNumber -lt $MaxAttempts) {
                Start-Sleep -Seconds ([math]::Pow(2, $CurrentAttemptNumber))

                $objResultIndicator = Add-AccessRuleRobust -CurrentAttemptNumber ($CurrentAttemptNumber + 1) -MaxAttempts $MaxAttempts -ReferenceToAccessControlListObject $ReferenceToAccessControlListObject -ReferenceToAccessRuleObject $ReferenceToAccessRuleObject
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
        # The specified access rule being removed must not be inherited. If the access
        # rule is inherited, the function will attempt to remove the access rule but
        # will not succeed in doing so; yet will not throw an error. See the example
        # for a demonstration of how to handle inherited access rules.
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
        # $boolCheckForType = $true
        # $boolRunGetAcl = $true
        # $strPath = 'D:\Shared\Human_Resources'
        # if ($strPath.Length -gt 248) {
        #     if ($strPath.Substring(0, 2) -eq '\\') {
        #         $strPath = '\\?\UNC\' + $strPath.Substring(2)
        #     } else {
        #         $strPath = '\\?\' + $strPath
        #     }
        # }
        # $objDirectoryInfo = Get-Item -Path $strPath
        # if (@(@($objDirectoryInfo.PSObject.Methods) | Where-Object { $_.Name -eq 'GetAccessControl' }).Count -ge 1) {
        #     # The GetAccessControl() method is available on .NET Framework 2.x - 4.x
        #     $objDirectorySecurity = $objDirectoryInfo.GetAccessControl()
        # } else {
        #     # The GetAccessControl() method is not available - this is expected on
        #     # PowerShell Core 6.x and later
        #     if ($boolCheckForType) {
        #         $boolTypeNameAvailable = @([System.AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType('System.IO.FileSystemAclExtensions') } | Where-Object { $_ }).Count -ge 1
        #         if (-not $boolTypeNameAvailable) {
        #             Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        #             $boolCheckForType = $false
        #         }
        #     }
        #     $objDirectorySecurity = [System.IO.FileSystemAclExtensions]::GetAccessControl($objDirectoryInfo)
        #     # $objDirectorySecurity is created but may appear empty/uninitialized.
        #     # This is because the object is missing additional properties that
        #     # correspond to the way that PowerShell displays this object. You can fix
        #     # this by running Get-Acl on any other object that has an ACL; once you
        #     # do that, the $objDirectorySecurity object will have the "missing"
        #     # properties and will display correctly in the console.
        #     if ($boolRunGetAcl) {
        #         $arrCommands = @(Get-Command -Name 'Get-Acl' -ErrorAction SilentlyContinue)
        #         if ($arrCommands.Count -gt 0) {
        #             [void](Get-Acl -Path $HOME)
        #         }
        #         $boolRunGetAcl = $false
        #     }
        # }
        # $arrFileSystemAccessRules = @($objDirectorySecurity.Access)
        #
        # # Pick a random access control entry to remove:
        # $objAccessRuleToRemove = $arrFileSystemAccessRules[0]
        #
        # if ($objAccessRuleToRemove.IsInherited) {
        #     # If the access rule is inherited, we need to disable inheritance in the
        #     # access control list first
        #     $objDirectorySecurity.SetAccessRuleProtection($true, $true)
        #     if (@(@($objDirectoryInfo.PSObject.Methods) | Where-Object { $_.Name -eq 'SetAccessControl' }).Count -ge 1) {
        #         # The SetAccessControl() method is available on .NET Framework 2.x - 4.x
        #         # Disable inheritance
        #         $objDirectoryInfo.SetAccessControl($objDirectorySecurity)
        #         # Re-fetch the access control list
        #         $objDirectorySecurity = $objDirectoryInfo.GetAccessControl()
        #         # Re-choose the access control entry to remove
        #         $arrFileSystemAccessRules = @($objDirectorySecurity.Access)
        #         $objAccessRuleToRemove = $arrFileSystemAccessRules[0]
        #     } else {
        #         # The SetAccessControl() method is not available - this is expected on
        #         # PowerShell Core 6.x and later
        #         if ($boolCheckForType) {
        #             $boolTypeNameAvailable = @([System.AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType('System.IO.FileSystemAclExtensions') } | Where-Object { $_ }).Count -ge 1
        #             if (-not $boolTypeNameAvailable) {
        #                 Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        #             }
        #         }
        #         # Disable inheritance
        #         [System.IO.FileSystemAclExtensions]::SetAccessControl($objDirectoryInfo, $objDirectorySecurity)
        #         # Re-fetch the access control list
        #         $objDirectorySecurity = [System.IO.FileSystemAclExtensions]::GetAccessControl($objDirectoryInfo)
        #         # $objDirectorySecurity is created but may appear empty/uninitialized.
        #         # This is because the object is missing additional properties that
        #         # correspond to the way that PowerShell displays this object. You can fix
        #         # this by running Get-Acl on any other object that has an ACL; once you
        #         # do that, the $objDirectorySecurity object will have the "missing"
        #         # properties and will display correctly in the console.
        #         if ($boolRunGetAcl) {
        #             $arrCommands = @(Get-Command -Name 'Get-Acl' -ErrorAction SilentlyContinue)
        #             if ($arrCommands.Count -gt 0) {
        #                 [void](Get-Acl -Path $HOME)
        #             }
        #             $boolRunGetAcl = $false
        #         }
        #         # Re-choose the access control entry to remove
        #         $arrFileSystemAccessRules = @($objDirectorySecurity.Access)
        #         $objAccessRuleToRemove = $arrFileSystemAccessRules[0]
        #     }
        # }
        #
        # # Remove the access rule
        # $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 8 -ReferenceToAccessControlListObject ([ref]$objDirectorySecurity) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToRemove)
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
        # This function also supports the use of positional parameters instead of named
        # parameters. If positional parameters are used intead of named parameters,
        # then four positional parameters are required:
        #
        # The first positional parameter is an integer indicating the current attempt
        # number. When calling this function for the first time, it should be 1.
        #
        # The second positional parameter is an integer representing the maximum number
        # of attempts that the function will observe before giving up.
        #
        # The third positional parameter is a reference to a
        # System.Security.AccessControl.DirectorySecurity or similar object from which
        # the access control entry will be removed.
        #
        # The fourth positional parameter is a reference to a
        # System.Security.AccessControl.FileSystemAccessRule or similar object that
        # will be removed from the access control list.
        #
        # Version: 1.1.20241223.2

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
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on on the $error stack; otherwise, returns a reference to the
            # last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     # So:
            #     # If both are null, no error
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error
            #     # If $refLastKnownError is non-null and $refNewestCurrentError is
            #     # null, no error
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to the
            # last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on on the $error stack.
            #
            # .NOTES
            # Version: 2.0.20241223.0

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

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e., during
            # the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between the
            # two errors.
            #
            # To use this function, you must first retrieve a reference to the last
            # error that occurred prior to the command you are about to run. Then,
            # run the command. After the command completes, retrieve a reference to
            # the last error that occurred. Pass these two references to this
            # function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToEarlierError
            # must be a reference to $null ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
            # whether an error occurred during the time period in question. $true
            # indicates an error occurred; $false indicates no error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters instead
            # of named parameters. If positional parameters are used intead of
            # named parameters, then two positional parameters are required:
            #
            # The first positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred. If
            # no error was on the stack at this time, the first positional
            # parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred. If no
            # error was on the stack at this time, ReferenceToLaterError must be
            # a reference to $null ([ref]$null).
            #
            # Version: 2.0.20241223.0

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
            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            # TODO: Validate input

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared; this
                # does not indicate an error.
                # So:
                # - If both are null, no error
                # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                #   is non-null, error
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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
        ($ReferenceToAccessControlListObject.Value).RemoveAccessRuleSpecific($ReferenceToAccessRuleObject.Value)

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            # Error occurred
            if ($CurrentAttemptNumber -lt $MaxAttempts) {
                Start-Sleep -Seconds ([math]::Pow(2, $CurrentAttemptNumber))

                $objResultIndicator = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber ($CurrentAttemptNumber + 1) -MaxAttempts $MaxAttempts -ReferenceToAccessControlListObject $ReferenceToAccessControlListObject -ReferenceToAccessRuleObject $ReferenceToAccessRuleObject
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

    function Write-ACLToObject {
        # .SYNOPSIS
        # Writes an access control list to an object
        #
        # .DESCRIPTION
        # After making changes to an access control list (ACL), it must be written back
        # to its source object for it to take effect. This function calls the
        # .SetAccessControl() method of an object to set the ACL. If the process fails,
        # this script supresses the error from being displayed on screen and, instead,
        # returns a failure result code.
        #
        # .PARAMETER CurrentAttemptNumber
        # This parameter is required; it is an integer indicating the current attempt
        # number. When calling this function for the first time, it should be 1.
        #
        # .PARAMETER MaxAttempts
        # This parameter is required; it is an integer representing the maximum number
        # of attempts that the function will observe before giving up.
        #
        # .PARAMETER ReferenceToTargetObject
        # This parameter is required; it is a reference to a System.IO.DirectoryInfo,
        # System.IO.FileInfo, or similar object where the access control list (ACL)
        # will be written.
        #
        # .PARAMETER ReferenceToACL
        # This parameter is required; it is a reference to a
        # System.Security.AccessControl.DirectorySecurity,
        # System.Security.AccessControl.FileSecurity, or similar object that will be
        # written to the target object.
        #
        # .PARAMETER DoNotCheckForType
        # This parameter is an optional switch statement. If supplied, it prevents this
        # function for checking for the availability of the
        # System.IO.FileSystemAclExtensions type, which can improve performance when it
        # is known to be available
        #
        # .EXAMPLE
        # $strPath = 'C:\Users\Public\Documents'
        # $objDirectoryInfo = Get-Item -Path $strPath
        # $objDirectorySecurity = Get-Acl -Path $strPath
        # # Do something to change the ACL here...
        # $boolSuccess = Write-ACLToObject -CurrentAttemptNumber 1 -MaxAttempts 4 -ReferenceToTargetObject ([ref]$objDirectoryInfo) -ReferenceToACL ([ref]$objDirectorySecurity)
        #
        # .EXAMPLE
        # $boolCheckForType = $true
        # $boolRunGetAcl = $true
        # $strPath = 'C:\Users\Public\Documents'
        # if ($strPath.Length -gt 248) {
        #     if ($strPath.Substring(0, 2) -eq '\\') {
        #         $strPath = '\\?\UNC\' + $strPath.Substring(2)
        #     } else {
        #         $strPath = '\\?\' + $strPath
        #     }
        # }
        # $objDirectoryInfo = Get-Item -Path $strPath
        # if (@(@($objDirectoryInfo.PSObject.Methods) | Where-Object { $_.Name -eq 'GetAccessControl' }).Count -ge 1) {
        #     # The GetAccessControl() method is available on .NET Framework 2.x - 4.x
        #     $objDirectorySecurity = $objDirectoryInfo.GetAccessControl()
        # } else {
        #     # The GetAccessControl() method is not available - this is expected on
        #     # PowerShell Core 6.x and later
        #     if ($boolCheckForType) {
        #         $boolTypeNameAvailable = @([System.AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType('System.IO.FileSystemAclExtensions') } | Where-Object { $_ }).Count -ge 1
        #         if (-not $boolTypeNameAvailable) {
        #             Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        #         }
        #     }
        #     $objDirectorySecurity = [System.IO.FileSystemAclExtensions]::GetAccessControl($objDirectoryInfo)
        #     # $objDirectorySecurity is created but may appear empty/uninitialized.
        #     # This is because the object is missing additional properties that
        #     # correspond to the way that PowerShell displays this object. You can fix
        #     # this by running Get-Acl on any other object that has an ACL; once you
        #     # do that, the $objDirectorySecurity object will have the "missing"
        #     # properties and will display correctly in the console.
        #     if ($boolRunGetAcl) {
        #         $arrCommands = @(Get-Command -Name 'Get-Acl' -ErrorAction SilentlyContinue)
        #         if ($arrCommands.Count -gt 0) {
        #             [void](Get-Acl -Path $HOME)
        #         }
        #         $boolRunGetAcl = $false
        #     }
        # }
        # # <Do something to change the ACL here...>
        # $boolSuccess = Write-ACLToObject -CurrentAttemptNumber 1 -MaxAttempts 4 -ReferenceToTargetObject ([ref]$objDirectoryInfo) -ReferenceToACL ([ref]$objDirectorySecurity)
        #
        # .EXAMPLE
        # $hashtableConfigIni = $null
        # $intReturnCode = Write-ACLToObject ([ref]$hashtableConfigIni) 1 4 '.\config.ini' @(';') $true $true 'NoSection' $true
        #
        # .INPUTS
        # None. You can't pipe objects to Write-ACLToObject.
        #
        # .OUTPUTS
        # System.Boolean. Write-ACLToObject returns a boolean value indiciating whether
        # the process completed successfully. $true means the process completed
        # successfully; $false means there was an error.
        #
        # .NOTES
        # This function also supports the use of positional parameters instead of named
        # parameters. If positional parameters are used intead of named parameters,
        # then four positional parameters are required:
        #
        # The first positional parameter is an integer indicating the current attempt
        # number. When calling this function for the first time, it should be 1.
        #
        # The second positional parameter is an integer representing the maximum number
        # of attempts that the function will observe before giving up.
        #
        # The third positional parameter is a reference to a System.IO.DirectoryInfo,
        # System.IO.FileInfo, or similar object where the access control list (ACL)
        # will be written.
        #
        # The fourth positional parameter is a reference to a
        # System.Security.AccessControl.DirectorySecurity,
        # System.Security.AccessControl.FileSecurity, or similar object that will be
        # written to the target object.
        #
        # Version: 2.0.20250106.2

        #region License ############################################################
        # Copyright (c) 2025 Frank Lesniak
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
        # One of the examples in the function header is derived from several chats with
        # OpenAI's ChatGPT. Link 1:
        # https://chatgpt.com/share/67688673-1e5c-8006-b5a3-f931e0b0e19f. Link 2:
        # https://chatgpt.com/share/676886a1-0514-8006-abb0-71e0194ce39f.
        # Both links accessed on 2024-12-22.
        #endregion Acknowledgements ###################################################

        param (
            [int]$CurrentAttemptNumber = 1,
            [int]$MaxAttempts = 1,
            [ref]$ReferenceToTargetObject = [ref]$null,
            [ref]$ReferenceToACL = [ref]$null,
            [switch]$DoNotCheckForType
        )

        #region FunctionsToSupportErrorHandling ####################################
        function Get-ReferenceToLastError {
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on on the $error stack; otherwise, returns a reference to the
            # last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     # So:
            #     # If both are null, no error
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error
            #     # If $refLastKnownError is non-null and $refNewestCurrentError is
            #     # null, no error
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to the
            # last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on on the $error stack.
            #
            # .NOTES
            # Version: 2.0.20241223.0

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

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e., during
            # the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between the
            # two errors.
            #
            # To use this function, you must first retrieve a reference to the last
            # error that occurred prior to the command you are about to run. Then,
            # run the command. After the command completes, retrieve a reference to
            # the last error that occurred. Pass these two references to this
            # function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToEarlierError
            # must be a reference to $null ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating errors
            # # from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do some
            # # work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will suppress
            # # error output. Terminating errors will not output anything, kick to
            # # the empty trap statement and then continue on. Likewise, non-
            # # terminating errors will also not output anything, but they do not
            # # kick to the trap statement; they simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
            # whether an error occurred during the time period in question. $true
            # indicates an error occurred; $false indicates no error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters instead
            # of named parameters. If positional parameters are used intead of
            # named parameters, then two positional parameters are required:
            #
            # The first positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack earlier in time, i.e., prior to running the
            # command for which you wish to determine whether an error occurred. If
            # no error was on the stack at this time, the first positional
            # parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer) to a
            # System.Management.Automation.ErrorRecord that represents the newest
            # error on the stack later in time, i.e., after to running the command
            # for which you wish to determine whether an error occurred. If no
            # error was on the stack at this time, ReferenceToLaterError must be
            # a reference to $null ([ref]$null).
            #
            # Version: 2.0.20241223.0

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
            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            # TODO: Validate input

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared; this
                # does not indicate an error.
                # So:
                # - If both are null, no error
                # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                #   is non-null, error
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            }

            return $boolErrorOccurred
        }
        #endregion FunctionsToSupportErrorHandling ####################################

        function Test-TypeNameAvailability {
            # .SYNOPSIS
            # Tests to see if a type is available.
            #
            # .DESCRIPTION
            # Determines if a type name is available for use. Returns $true if the type
            # name is available in the current context; returns $false if it is not
            # available.
            #
            # .PARAMETER TypeName
            # This parameter is required; it is a string that contains the name of the
            # type for which the function will determine availability.
            #
            # .EXAMPLE
            # $boolTypeAvailable = Test-TypeNameAvailability -TypeName 'Microsoft.Exchange.Data.RecipientAccessRight'
            #
            # .EXAMPLE
            # $boolTypeAvailable = Test-TypeNameAvailability 'Microsoft.Exchange.Data.RecipientAccessRight'
            #
            # .INPUTS
            # None. You can't pipe objects to Test-TypeNameAvailability.
            #
            # .OUTPUTS
            # System.Boolean. Test-TypeNameAvailability returns a boolean value
            # indicating whether the type is available in the current context. The
            # function returns $true if the type name is available in the current
            # context; $false otherwise.
            #
            # .NOTES
            # This function also supports the use of a positional parameter instead of
            # a named parameter. If a positional parameter is used intead of a named
            # parameter, then exactly one positional parameters is required: it is a
            # string that contains the name of the type for which the function will
            # determine availability.
            #
            # Version: 2.0.20250106.0

            #region License ########################################################
            # Copyright (c) 2025 Frank Lesniak
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

            #region Acknowledgements ###############################################
            # This function is derived from a chat with OpenAI's ChatGPT:
            # https://chatgpt.com/share/67659f90-1d90-8006-a127-8d2d0b897054
            # retrieved on 2024-12-20
            #endregion Acknowledgements ###############################################

            param (
                [string]$TypeName = ''
            )

            #region FunctionsToSupportErrorHandling ################################
            function Get-ReferenceToLastError {
                # .SYNOPSIS
                # Gets a reference (memory pointer) to the last error that occurred.
                #
                # .DESCRIPTION
                # Returns a reference (memory pointer) to $null ([ref]$null) if no
                # errors on on the $error stack; otherwise, returns a reference to the
                # last error that occurred.
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work:
                # $refLastKnownError = Get-ReferenceToLastError
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # $refNewestCurrentError = Get-ReferenceToLastError
                #
                # $boolErrorOccurred = $false
                # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #     # Both not $null
                #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # } else {
                #     # One is $null, or both are $null
                #     # NOTE: $refLastKnownError could be non-null, while
                #     # $refNewestCurrentError could be null if $error was cleared;
                #     # this does not indicate an error.
                #     # So:
                #     # If both are null, no error
                #     # If $refLastKnownError is null and $refNewestCurrentError is
                #     # non-null, error
                #     # If $refLastKnownError is non-null and $refNewestCurrentError is
                #     # null, no error
                #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Get-ReferenceToLastError.
                #
                # .OUTPUTS
                # System.Management.Automation.PSReference ([ref]).
                # Get-ReferenceToLastError returns a reference (memory pointer) to the
                # last error that occurred. It returns a reference to $null
                # ([ref]$null) if there are no errors on on the $error stack.
                #
                # .NOTES
                # Version: 2.0.20241223.0

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

                if ($Error.Count -gt 0) {
                    return ([ref]($Error[0]))
                } else {
                    return ([ref]$null)
                }
            }

            function Test-ErrorOccurred {
                # .SYNOPSIS
                # Checks to see if an error occurred during a time period, i.e., during
                # the execution of a command.
                #
                # .DESCRIPTION
                # Using two references (memory pointers) to errors, this function
                # checks to see if an error occurred based on differences between the
                # two errors.
                #
                # To use this function, you must first retrieve a reference to the last
                # error that occurred prior to the command you are about to run. Then,
                # run the command. After the command completes, retrieve a reference to
                # the last error that occurred. Pass these two references to this
                # function to determine if an error occurred.
                #
                # .PARAMETER ReferenceToEarlierError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToEarlierError
                # must be a reference to $null ([ref]$null).
                #
                # .PARAMETER ReferenceToLaterError
                # This parameter is required; it is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred.
                #
                # If no error was on the stack at this time, ReferenceToLaterError
                # must be a reference to $null ([ref]$null).
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating errors
                # # from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work
                # if ($Error.Count -gt 0) {
                #     $refLastKnownError = ([ref]($Error[0]))
                # } else {
                #     $refLastKnownError = ([ref]$null)
                # }
                #
                # # Store current error preference; we will restore it after we do some
                # # work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will suppress
                # # error output. Terminating errors will not output anything, kick to
                # # the empty trap statement and then continue on. Likewise, non-
                # # terminating errors will also not output anything, but they do not
                # # kick to the trap statement; they simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # if ($Error.Count -gt 0) {
                #     $refNewestCurrentError = ([ref]($Error[0]))
                # } else {
                #     $refNewestCurrentError = ([ref]$null)
                # }
                #
                # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                #     # Error occurred
                # } else {
                #     # No error occurred
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Test-ErrorOccurred.
                #
                # .OUTPUTS
                # System.Boolean. Test-ErrorOccurred returns a boolean value indicating
                # whether an error occurred during the time period in question. $true
                # indicates an error occurred; $false indicates no error occurred.
                #
                # .NOTES
                # This function also supports the use of positional parameters instead
                # of named parameters. If positional parameters are used intead of
                # named parameters, then two positional parameters are required:
                #
                # The first positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack earlier in time, i.e., prior to running the
                # command for which you wish to determine whether an error occurred. If
                # no error was on the stack at this time, the first positional
                # parameter must be a reference to $null ([ref]$null).
                #
                # The second positional parameter is a reference (memory pointer) to a
                # System.Management.Automation.ErrorRecord that represents the newest
                # error on the stack later in time, i.e., after to running the command
                # for which you wish to determine whether an error occurred. If no
                # error was on the stack at this time, ReferenceToLaterError must be
                # a reference to $null ([ref]$null).
                #
                # Version: 2.0.20241223.0

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
                param (
                    [ref]$ReferenceToEarlierError = ([ref]$null),
                    [ref]$ReferenceToLaterError = ([ref]$null)
                )

                # TODO: Validate input

                $boolErrorOccurred = $false
                if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    # Both not $null
                    if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                } else {
                    # One is $null, or both are $null
                    # NOTE: $ReferenceToEarlierError could be non-null, while
                    # $ReferenceToLaterError could be null if $error was cleared; this
                    # does not indicate an error.
                    # So:
                    # - If both are null, no error
                    # - If $ReferenceToEarlierError is null and $ReferenceToLaterError
                    #   is non-null, error
                    # - If $ReferenceToEarlierError is non-null and
                    #   $ReferenceToLaterError is null, no error
                    if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
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

            # TODO: Perform additional input validation
            if ([string]::IsNullOrEmpty($TypeName)) {
                return $false
            }

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

            # Test to see if the type name is available
            $boolTypeNameAvailable = @([System.AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType($TypeName) } | Where-Object { $_ }).Count -ge 1

            # Restore the former error preference
            $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

            # Retrieve the newest error on the error stack
            $refNewestCurrentError = Get-ReferenceToLastError

            if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                # Error occurred; we're not returning a failure indicator, though.

                return $boolTypeNameAvailable
            } else {
                # No error occurred; but, again, we're not returning a success code.

                return $boolTypeNameAvailable
            }
        }

        trap {
            # Intentionally left empty to prevent terminating errors from halting
            # processing
        }

        # TODO: Validate input

        $boolCheckForType = $true
        if ($null -ne $DoNotCheckForType) {
            if ($DoNotCheckForType.IsPresent) {
                $boolCheckForType = $false
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

        # The following code is representative of what we are trying to do, but it's
        # commented-out because PowerShell v1-style error handling requires that all
        # code you want to error-handle be on one line
        ###############################################################################
        # # Set the ACL on the target object
        # if (@(@(($ReferenceToTargetObject.Value).PSObject.Methods) | Where-Object { $_.Name -eq 'SetAccessControl' }).Count -ge 1) {
        #     # The SetAccessControl() method is available on .NET Framework 2.x - 4.x
        #     ($ReferenceToTargetObject.Value).SetAccessControl($ReferenceToACL.Value)
        # } else {
        #     # The SetAccessControl() method is not available - this is expected on
        #     # PowerShell Core 6.x and later
        #     if ($boolCheckForType) {
        #         $boolTypeNameAvailable = Test-TypeNameAvailability -TypeName 'System.IO.FileSystemAclExtensions'
        #         if (-not $boolTypeNameAvailable) {
        #             Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        #         }
        #     }
        #     [System.IO.FileSystemAclExtensions]::SetAccessControl($ReferenceToTargetObject.Value, $ReferenceToACL.Value)
        # }
        ###############################################################################
        # Here is the above code translated to a represenative one-liner:
        if (@(@(($ReferenceToTargetObject.Value).PSObject.Methods) | Where-Object { $_.Name -eq 'SetAccessControl' }).Count -ge 1) { ($ReferenceToTargetObject.Value).SetAccessControl($ReferenceToACL.Value) } else { if ($boolCheckForType) { $boolTypeNameAvailable = Test-TypeNameAvailability -TypeName 'System.IO.FileSystemAclExtensions'; if (-not $boolTypeNameAvailable) { Add-Type -AssemblyName System.IO.FileSystem.AccessControl } }; [System.IO.FileSystemAclExtensions]::SetAccessControl($ReferenceToTargetObject.Value, $ReferenceToACL.Value) }

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            # Error occurred
            if ($CurrentAttemptNumber -lt $MaxAttempts) {
                Start-Sleep -Seconds ([math]::Pow(2, $CurrentAttemptNumber))

                $objResultIndicator = Write-ACLToObject -CurrentAttemptNumber ($CurrentAttemptNumber + 1) -MaxAttempts $MaxAttempts -ReferenceToTargetObject $ReferenceToTargetObject -ReferenceToACL $ReferenceToACL
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

    #region Process Input ##########################################################
    if ([string]::IsNullOrEmpty($WorkingPath)) {
        Write-Error -Message 'An empty working path was passed to Repair-NTFSPermissionsRecursively; this parameter is required, so the function is terminating.'
        return -100
    }

    if ($null -eq $ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value) {
        $boolLocalPSDriveWorkaroundIsKnownToBeUseful = $false
        $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful = [ref]$boolLocalPSDriveWorkaroundIsKnownToBeUseful
    } else {
        $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful = $ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful
    }

    if ([string]::IsNullOrEmpty($RealPath)) {
        $refToRealPath = [ref]$WorkingPath
    } else {
        $refToRealPath = [ref]$RealPath
    }

    if ($null -eq $ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls.Value) {
        $NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls = 'Administrators'
        $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls = [ref]$NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls
    } else {
        $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls = $ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls
    }

    if ($null -eq $ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value) {
        $NameOfBuiltInAdministratorsGroupAccordingToGetAcl = 'BUILTIN\Administrators'
        $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl = [ref]$NameOfBuiltInAdministratorsGroupAccordingToGetAcl
    } else {
        $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl = $ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl
    }

    if ($null -eq $ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls.Value) {
        $NameOfSYSTEMAccountAccordingToTakeOwnAndICacls = 'SYSTEM'
        $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls = [ref]$NameOfSYSTEMAccountAccordingToTakeOwnAndICacls
    } else {
        $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls = $ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls
    }

    if ($null -eq $ReferenceToNameOfSYSTEMAccountAccordingToGetAcl.Value) {
        $NameOfSYSTEMAccountAccordingToGetAcl = 'NT AUTHORITY\SYSTEM'
        $refNameOfSYSTEMAccountAccordingToGetAcl = [ref]$NameOfSYSTEMAccountAccordingToGetAcl
    } else {
        $refNameOfSYSTEMAccountAccordingToGetAcl = $ReferenceToNameOfSYSTEMAccountAccordingToGetAcl
    }

    if ($null -eq $ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls.Value) {
        $NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls = ''
        $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls = [ref]$NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls
    } else {
        $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls = $ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls
    }

    if ($null -eq $ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value) {
        $NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl = ''
        $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl = [ref]$NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl
    } else {
        $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl = $ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl
    }

    if ($null -eq $ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls.Value) {
        $NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls = ''
        $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls = [ref]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls
    } else {
        $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls = $ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls
    }

    if ($null -eq $ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value) {
        $NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = ''
        $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = [ref]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl
    } else {
        $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl = $ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl
    }

    #region Process Switch Parameters ##############################################
    $boolAllowRecursion = $true
    if ($null -ne $RunWithoutRecursion) {
        if ($RunWithoutRecursion.IsPresent) {
            $boolAllowRecursion = $false
        }
    }

    $boolIgnorePathLengthLimits = $false
    if ($null -ne $IgnorePathLengthLimits) {
        if ($IgnorePathLengthLimits.IsPresent) {
            $boolIgnorePathLengthLimits = $true
        }
    }

    $boolDOS8dot3PathBeingUsed = $false
    if ($null -ne $DOS8dot3PathBeingUsed) {
        if ($DOS8dot3PathBeingUsed.IsPresent) {
            $boolDOS8dot3PathBeingUsed = $true
        }
    }

    $boolDoNotPerformFinalCleanupOfRedundantACEs = $false
    if ($null -ne $DoNotPerformFinalCleanupOfRedundantACEs) {
        if ($DoNotPerformFinalCleanupOfRedundantACEs.IsPresent) {
            $boolDoNotPerformFinalCleanupOfRedundantACEs = $true
        }
    }

    $boolFinalCleanupOfRedundantACEs = $false
    if ($null -ne $FinalCleanupOfRedundantACEs) {
        if ($FinalCleanupOfRedundantACEs.IsPresent) {
            $boolFinalCleanupOfRedundantACEs = $true
        }
    }
    #endregion Process Switch Parameters ##############################################
    #endregion Process Input ##########################################################

    #region Display starting message ###############################################
    if ($null -eq $ReferenceToHashtableOfKnownSIDs) {
        if ($WorkingPath -ne $refToRealPath.Value) {
            $strMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Real path: "' + $refToRealPath.Value + '"; Working path: "' + $WorkingPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $IterativeRepairState + '; In final ACE cleanup: ' + $boolFinalCleanupOfRedundantACEs + '; Use Get-Path workaround: ' + $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value + '; Last shortened working path: "' + $LastShortenedPath + '"; Ignore path length limits: ' + $boolIgnorePathLengthLimits + '; Relaunch attempted with DOS 8.3 path: ' + $boolDOS8dot3PathBeingUsed + '; Known SIDs: not specified (unresolved SIDs will not be removed); Recursion depth :' + [string]$RecursionDepth
        } else {
            $strMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Path: "' + $WorkingPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $IterativeRepairState + '; In final ACE cleanup: ' + $boolFinalCleanupOfRedundantACEs + '; Use Get-Path workaround: ' + $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value + '; Last shortened working path: "' + $LastShortenedPath + '"; Ignore path length limits: ' + $boolIgnorePathLengthLimits + '; Relaunch attempted with DOS 8.3 path: ' + $boolDOS8dot3PathBeingUsed + '; Known SIDs: not specified (unresolved SIDs will not be removed); Recursion depth :' + [string]$RecursionDepth
        }
    } else {
        if ($null -eq $ReferenceToHashtableOfKnownSIDs.Value) {
            if ($WorkingPath -ne $refToRealPath.Value) {
                $strMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Real path: "' + $refToRealPath.Value + '"; Working path: "' + $WorkingPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $IterativeRepairState + '; In final ACE cleanup: ' + $boolFinalCleanupOfRedundantACEs + '; Use Get-Path workaround: ' + $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value + '; Last shortened working path: "' + $LastShortenedPath + '"; Ignore path length limits: ' + $boolIgnorePathLengthLimits + '; Relaunch attempted with DOS 8.3 path: ' + $boolDOS8dot3PathBeingUsed + '; Known SIDs: not specified (unresolved SIDs will not be removed); Recursion depth :' + [string]$RecursionDepth
            } else {
                $strMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Path: "' + $WorkingPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $IterativeRepairState + '; In final ACE cleanup: ' + $boolFinalCleanupOfRedundantACEs + '; Use Get-Path workaround: ' + $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value + '; Last shortened working path: "' + $LastShortenedPath + '"; Ignore path length limits: ' + $boolIgnorePathLengthLimits + '; Relaunch attempted with DOS 8.3 path: ' + $boolDOS8dot3PathBeingUsed + '; Known SIDs: not specified (unresolved SIDs will not be removed); Recursion depth :' + [string]$RecursionDepth
            }
        } else {
            if ($WorkingPath -ne $refToRealPath.Value) {
                $strMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Real path: "' + $refToRealPath.Value + '"; Working path: "' + $WorkingPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $IterativeRepairState + '; In final ACE cleanup: ' + $boolFinalCleanupOfRedundantACEs + '; Use Get-Path workaround: ' + $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value + '; Last shortened working path: "' + $LastShortenedPath + '"; Ignore path length limits: ' + $boolIgnorePathLengthLimits + '; Relaunch attempted with DOS 8.3 path: ' + $boolDOS8dot3PathBeingUsed + '; Known SIDs: yes (unresolved SIDs unmatched to SIDs in the hashtable will be removed); Recursion depth :' + [string]$RecursionDepth
            } else {
                $strMessage = 'Now starting Repair-NTFSPermissionsRecursively with the following parameters: Path: "' + $WorkingPath + '"; Allow recursion: ' + $boolAllowRecursion + '; Iterative repair state: ' + $IterativeRepairState + '; In final ACE cleanup: ' + $boolFinalCleanupOfRedundantACEs + '; Use Get-Path workaround: ' + $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value + '; Last shortened working path: "' + $LastShortenedPath + '"; Ignore path length limits: ' + $boolIgnorePathLengthLimits + '; Relaunch attempted with DOS 8.3 path: ' + $boolDOS8dot3PathBeingUsed + '; Known SIDs: yes (unresolved SIDs unmatched to SIDs in the hashtable will be removed); Recursion depth :' + [string]$RecursionDepth
            }
        }
    }
    Write-Verbose -Message $strMessage
    #endregion Display starting message ###############################################

    # $IterativeRepairState:
    # 0 = Allow recursion (default)
    # 1 = Do not allow recursion, but allow ownership to be taken via Set-Acl
    # 2 = Do not allow recursion, and do not allow ownership to be taken via Set-Acl

    $FILEPATHLIMIT = 260
    $FOLDERPATHLIMIT = 248

    $intFunctionReturn = 0

    $objThis = $null
    $objThisObjectPermission = $null
    $versionPS = Get-PSVersion

    # We don't know if $WorkingPath is pointing to a folder or a file, so use the folder
    # (shorter) length limit
    if ($WorkingPath.Length -ge $FOLDERPATHLIMIT -and $boolIgnorePathLengthLimits -ne $true) {
        #region Path length exceeds limit; mitigate and restart the process ########
        if ($WorkingPath -ne $refToRealPath.Value) {
            $strMessage = $WorkingPath + ' (real path: "' + $refToRealPath.Value + '") is too long.'
        } else {
            $strMessage = $WorkingPath + ' is too long.'
        }
        Write-Debug -Message $strMessage
        if ($IterativeRepairState -ge 1) {
            #region In Iterative Repair State; No Recursion Allowed ################
            if ($WorkingPath -ne $refToRealPath.Value) {
                $strMessage = 'Despite attempts to mitigate, the path length of ' + $WorkingPath + ' (real path "' + $refToRealPath.Value + '") exceeds the maximum length of ' + $FOLDERPATHLIMIT + ' characters.'
            } else {
                $strMessage = 'Despite attempts to mitigate, the path length of ' + $WorkingPath + ' exceeds the maximum length of ' + $FOLDERPATHLIMIT + ' characters.'
            }
            Write-Error -Message $strMessage
            $intFunctionReturn = -1
            return $intFunctionReturn
            #endregion In Iterative Repair State; No Recursion Allowed ################
        } else {
            #region Running Normally (Not In Iterative Repair State); Recursion Allowed
            $intAttemptNumber = 0
            $boolPossibleAttemptsExceeded = $false
            $boolTenablePathFound = $false

            # Get path separator
            # $strTempPathToAdd = '###FAKE###'
            # $strTempPath = Join-Path $WorkingPath $strTempPathToAdd
            # $strPathSeparator = $strTempPath.Substring($strTempPath.Length - $strTempPathToAdd.Length - ($strTempPath.Length - $strTempPathToAdd.Length - $WorkingPath.Length), $strTempPath.Length - $strTempPathToAdd.Length - $WorkingPath.Length)

            $arrPathElements = @(Split-Path -Path $WorkingPath)
            # $arrPathElements = Split-StringOnLiteralString $WorkingPath $strPathSeparator

            while (($boolPossibleAttemptsExceeded -eq $false) -and ($boolTenablePathFound -eq $false)) {
                $strParentFolder = $arrPathElements[0]
                for ($intCounter = 1; $intCounter -le ($arrPathElements.Count - 2 - $intAttemptNumber); $intCounter++) {
                    $strParentFolder = Join-Path -Path $strParentFolder -ChildPath $arrPathElements[$intCounter]
                    # $strParentFolder += $strPathSeparator + $arrPathElements[$intCounter]
                }
                if ($strParentFolder -eq $arrPathElements[0]) {
                    $boolPossibleAttemptsExceeded = $true
                }
                if ($strParentFolder -eq $WorkingPath) {
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
                #region We found a parent folder that is within the path length limit
                if ($strParentFolder -eq $LastShortenedPath) {
                    #region The parent folder that is under the length limit is the same as the last shortened path
                    # Don't attempt another substitution since we already did that
                    #
                    # We are not in temporary path length ignoring mode yet, so try
                    # again with temporary path length ignoring mode enabled and
                    # recursion turned off
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'The path length of item "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") exceeds the maximum number of characters. A drive substitution or synbolic link should be used to mitigate this, however this mitigation has already been performed, so trying again with temporary path length ignoring mode enabled.'
                    } else {
                        $strMessage = 'The path length of item "' + $WorkingPath + '" exceeds the maximum number of characters. A drive substitution or synbolic link should be used to mitigate this, however this mitigation has already been performed, so trying again with temporary path length ignoring mode enabled.'
                    }
                    Write-Debug -Message $strMessage
                    # Rerun without recursion and with path length ignoring mode enabled
                    if ($boolFinalCleanupOfRedundantACEs) {
                        $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -RunWithoutRecursion -IgnorePathLengthLimits -FinalCleanupOfRedundantACEs
                    } else {
                        $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -RunWithoutRecursion -IgnorePathLengthLimits
                    }
                    $intFunctionReturn = $intReturnCode
                    return $intFunctionReturn
                    #endregion The parent folder that is under the length limit is the same as the last shortened path
                } else {
                    #region The parent folder that is under the length limit is different than the last shortened path (this is good)
                    if ($strParentFolder.Length -le 3) {
                        #region The parent folder is a root folder (this is bad, it doesn't get any shorter than this)
                        # We are already working with the shortest possible path; no
                        # need to try a substitution
                        #
                        # We are not in temporary path length ignoring mode yet, so try
                        # again with temporary path length ignoring mode enabled and
                        # recursion turned off
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'The path length of item "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") exceeds the maximum number of characters. A drive substitution or synbolic link cannot be used to mitigate this because this item''s parent folder is already the root of a drive, so trying again with temporary path length ignoring mode enabled.'
                        } else {
                            $strMessage = 'The path length of item "' + $WorkingPath + '" exceeds the maximum number of characters. A drive substitution or synbolic link cannot be used to mitigate this because this item''s parent folder is already the root of a drive, so trying again with temporary path length ignoring mode enabled.'
                        }
                        Write-Debug -Message $strMessage
                        # Rerun without recursion and with path length ignoring mode enabled
                        if ($boolFinalCleanupOfRedundantACEs) {
                            $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -RunWithoutRecursion -IgnorePathLengthLimits -FinalCleanupOfRedundantACEs
                        } else {
                            $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -RunWithoutRecursion -IgnorePathLengthLimits
                        }
                        $intFunctionReturn = $intReturnCode
                        return $intFunctionReturn
                        #endregion The parent folder is a root folder (this is bad, it doesn't get any shorter than this)
                    } else {
                        #region The parent folder is not a root folder (this is good)
                        $strRemainderOfPath = $WorkingPath.Substring($strParentFolder.Length + 1, $WorkingPath.Length - $strParentFolder.Length - 1)

                        $strFolderTarget = $strParentFolder
                        $strChildFolderOfTarget = $strRemainderOfPath

                        #region Mitigate Path Length with Drive Substitution ###############
                        # Inputs:
                        # $strFolderTarget
                        # $strChildFolderOfTarget

                        $boolSubstWorked = $false
                        # TODO: Rework to pass along whether the OS is Windows
                        $arrAvailableDriveLetters = @(Get-AvailableDriveLetter -PSVersion $versionPS)
                        if ($arrAvailableDriveLetters.Count -gt 0) {
                            #region Drive Letters Available ########################
                            $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                            $strEscapedPathForInvokeExpression = (((($strFolderTarget.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                            $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strEscapedPathForInvokeExpression + '"'
                            Write-Verbose -Message ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand

                            # Confirm the path is ready
                            $strJoinedPath = ''
                            $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                            if ($boolPathAvailable -eq $false) {
                                #region The drive substitution seems to have failed
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...'
                                } else {
                                    $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...'
                                }
                                Write-Debug -Message $strMessage
                                $intReturnCode = -1
                                #endregion The drive substitution seems to have failed
                            } else {
                                #region The drive substitution was successful ######
                                if ($boolFinalCleanupOfRedundantACEs) {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path ($strDriveLetterToUse + ':') '') -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -FinalCleanupOfRedundantACEs
                                } else {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path ($strDriveLetterToUse + ':') '') -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth
                                }
                                #endregion The drive substitution was successful ######
                            }

                            $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                            Write-Verbose -Message ('About to run command: ' + $strCommand)
                            $null = Invoke-Expression $strCommand

                            # TODO: This is not necessary, right? Because Wait-PathToBeNotReady will run Get-PSDrive
                            if ($refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value -eq $true) {
                                # Use workaround for drives not refreshing in current PowerShell session
                                Get-PSDrive | Out-Null
                            }

                            $boolPathUnavailable = Wait-PathToBeNotReady -Path ($strDriveLetterToUse + ':') -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                            if ($boolPathUnavailable -eq $false) {
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand
                                } else {
                                    $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand
                                }
                                Write-Debug -Message $strMessage
                            }

                            if ($intReturnCode -eq 0) {
                                $boolSubstWorked = $true
                            }
                            #endregion Drive Letters Available ########################
                        }
                        #endregion Mitigate Path Length with Drive Substitution ###############

                        #region Mitigate Path Length with Symbolic Link ####################
                        # Inputs:
                        # $strFolderTarget
                        # $strChildFolderOfTarget

                        # If a substituted drive failed, try a symbolic link instead
                        $boolSymbolicLinkWorked = $false
                        if ($boolSubstWorked -eq $false) {
                            #region The earlier attempt at a drive substitution was not successful
                            $boolSymbolicLinkTargetFound = $false
                            $strSymbolicLinkFolderName = ''
                            if ($strFolderTarget.Length -gt 35) {
                                #region We can use a GUID for the symbolic link folder name
                                # Use a GUID to avoid name collisions
                                $strSymbolicLinkFolderName = [System.Guid]::NewGuid().ToString()
                                $strSymbolicLinkFolderName = $strSymbolicLinkFolderName.Replace('-', '')
                                $boolSymbolicLinkTargetFound = $true
                                #endregion We can use a GUID for the symbolic link folder name
                            } elseif ($strFolderTarget.Length -gt 5) {
                                #region We cannot use a GUID for the symbolic link folder name, so we'll use a single character instead
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
                                #endregion We cannot use a GUID for the symbolic link folder name, so we'll use a single character instead
                            } else {
                                #region We cannot create a symbolic link because it won't help; the parent folder path is too short for it to be effective
                                # The path is already short enough; cannot create a symbolic link
                                # $boolSymbolicLinkTargetFound = $false
                                #endregion We cannot create a symbolic link because it won't help; the parent folder path is too short for it to be effective
                            }

                            if ($boolSymbolicLinkTargetFound -eq $true) {
                                #region We found a suitable symbolic link target ###
                                # Create the symbolic link
                                $versionPS = Get-PSVersion
                                if ($versionPS -ge ([version]'5.0')) {
                                    #region PowerShell 5.0 or newer: make the symbolic link using native PowerShell
                                    # PowerShell 5.0 and newer can make symbolic links in PowerShell
                                    Write-Verbose -Message ('An error occurred when mitigating path length using drive substitution (real path: "' + $refToRealPath.Value + '"). Trying to create a symbolic link instead via PowerShell:' + " `n" + 'Symbolic link path: ' + 'C:\' + $strSymbolicLinkFolderName + " `n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$'))
                                    # TODO: Test this with a path containing a dollar sign ($)
                                    New-Item -ItemType SymbolicLink -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                                    #endregion PowerShell 5.0 or newer: make the symbolic link using native PowerShell
                                } else {
                                    #region PowerShell 4.0 or older: make the symbolic link using mklink command
                                    # Need to use mklink command in command prompt instead
                                    # TODO: Test this with a path containing a dollar sign ($)
                                    $strEscapedPathForInvokeExpression = (((($strFolderTarget.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                    $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "' + (Join-Path 'C:' $strSymbolicLinkFolderName) + '" "' + $strEscapedPathForInvokeExpression + '"'
                                    Write-Verbose -Message ('An error occurred when mitigating path length using drive substitution (real path: "' + $refToRealPath.Value + '"). Trying to create a symbolic link instead via command: ' + $strCommand)
                                    $null = Invoke-Expression $strCommand
                                    #endregion PowerShell 4.0 or older: make the symbolic link using mklink command
                                }

                                # Confirm the path is ready
                                $strJoinedPath = ''
                                $boolPathAvailable = Wait-PathToBeReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                if ($boolPathAvailable -eq $false) {
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" (real path: "' + $refToRealPath.Value + '") because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.'
                                    } else {
                                        $strMessage = 'Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.'
                                    }
                                    Write-Error -Message $strMessage
                                    $intReturnCode = -2
                                } else {
                                    if ($boolFinalCleanupOfRedundantACEs) {
                                        $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path 'C:' $strSymbolicLinkFolderName) -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -FinalCleanupOfRedundantACEs
                                    } else {
                                        $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path 'C:' $strSymbolicLinkFolderName) -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth
                                    }
                                }

                                if ($intReturnCode -lt 0) {
                                    # -2 if drive substitution and symbolic link failed
                                    $intFunctionReturn = $intReturnCode
                                    return $intFunctionReturn
                                } elseif ($intReturnCode -eq 0) {
                                    $boolSymbolicLinkWorked = $true
                                }

                                # Remove Symbolic Link
                                Write-Verbose -Message ('Removing symbolic link: ' + (Join-Path 'C:' $strSymbolicLinkFolderName))
                                # TODO: Build error handling for this deletion:
                                (Get-Item (Join-Path 'C:' $strSymbolicLinkFolderName)).Delete()

                                # TODO: This is not necessary, right? Because Wait-PathToBeNotReady will run Get-PSDrive
                                if ($refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value -eq $true) {
                                    # Use workaround for drives not refreshing in current PowerShell session
                                    Get-PSDrive | Out-Null
                                }

                                $boolPathUnavailable = Wait-PathToBeNotReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                if ($boolPathUnavailable -eq $false) {
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.'
                                    } else {
                                        $strMessage = 'There was an issue processing the path "' + $WorkingPath + '". A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.'
                                    }
                                    Write-Warning -Message $strMessage
                                }
                                #endregion We found a suitable symbolic link target ###
                            }
                            #endregion The earlier attempt at a drive substitution was not successful
                        }
                        #endregion Mitigate Path Length with Symbolic Link ####################

                        if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                            #region Both drive substitution and symbolic link failed
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $WorkingPath + ' (real path: "' + $refToRealPath.Value + '")'
                            } else {
                                $strMessage = 'Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $WorkingPath
                            }
                            Write-Error -Message $strMessage
                            $intFunctionReturn = -3
                            return $intFunctionReturn
                            #endregion Both drive substitution and symbolic link failed
                        }
                        #endregion The parent folder is not a root folder (this is good)
                    }
                    #endregion The parent folder that is under the length limit is different than the last shortened path (this is good)
                }
                #endregion We found a parent folder that is within the path length limit
            } elseif ($boolPossibleAttemptsExceeded -eq $true) {
                #region No parent folder that is within the path length limit was found
                if ($WorkingPath -ne $refToRealPath.Value) {
                    $strMessage = 'Cannot process the following path because it contains no parent folder element that is of an acceptable length with which to perform drive substitution or creation of a symbolic link: ' + $WorkingPath + ' (real path: "' + $refToRealPath.Value + '")'
                } else {
                    $strMessage = 'Cannot process the following path because it contains no parent folder element that is of an acceptable length with which to perform drive substitution or creation of a symbolic link: ' + $WorkingPath
                }
                Write-Error -Message $strMessage
                $intFunctionReturn = -4
                return $intFunctionReturn
                #endregion No parent folder that is within the path length limit was found
            } else {
                #region Unexpected Error ###########################################
                if ($WorkingPath -ne $refToRealPath.Value) {
                    $strMessage = 'While working on the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"), the path was too long, and an acceptable parent folder element with which path substitution should be performed could not be found. This is unexpected.'
                } else {
                    $strMessage = 'While working on the path "' + $WorkingPath + '", the path was too long, and an acceptable parent folder element with which path substitution should be performed could not be found. This is unexpected.'
                }
                Write-Error -Message $strMessage
                $intFunctionReturn = -10
                return $intFunctionReturn
                #endregion Unexpected Error ###########################################
            }
            #endregion Running Normally (Not In Iterative Repair State); Recursion Allowed
        }
        #endregion Path length exceeds limit; mitigate and restart the process ########
    } else {
        #region Path is not too long, or the function was called with "IgnorePathLengthLimits"
        $boolCriticalErrorOccurred = $false

        $boolSuccess = Get-AclSafely -ReferenceToACL ([ref]$objThisObjectPermission) -ReferenceToInfoObject ([ref]$objThis) -PathToObject $WorkingPath -PSVersion $versionPS

        if ($boolSuccess -eq $false) {
            #region An error occurred reading the ACL; mitigate and restart the process if possible

            #region Take ownership #################################################
            $strEscapedPathForInvokeExpression = (((($WorkingPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
            $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strEscapedPathForInvokeExpression + '" /A'
            Write-Verbose -Message ('About to run command: ' + $strCommand)
            $null = Invoke-Expression $strCommand
            #endregion Take ownership #################################################

            # Should now be able to read permissions

            $boolSuccess = Get-AclSafely -ReferenceToACL ([ref]$objThisObjectPermission) -ReferenceToInfoObject ([ref]$objThis) -PathToObject $WorkingPath -PSVersion $versionPS

            if ($boolSuccess -eq $false) {
                #region Still unable to read permissions after running takeown.exe #
                if ($boolDOS8dot3PathBeingUsed -eq $true) {
                    #region We're already running using a DOS 8.3 path, and it didn't work
                    # We already tried a DOS 8.3 path, and it didn't work; nothing else
                    # we can do
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Despite attempting to take ownership of the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'This may occur if subst.exe was used to mitigate path length issues; if so, the function should retry...'
                    } else {
                        $strMessage = 'Despite attempting to take ownership of the folder/file "' + $WorkingPath + '" on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'This may occur if subst.exe was used to mitigate path length issues; if so, the function should retry...'
                    }
                    Write-Debug -Message $strMessage
                    $intFunctionReturn = -5
                    return $intFunctionReturn
                    #endregion We're already running using a DOS 8.3 path, and it didn't work
                } else {
                    #region We're not already running using a DOS 8.3 path, so try that
                    # Get the DOS 8.3 path and try again
                    $strDOS83Path = ''
                    # TODO: Get Scripting.FileSystemObject and pass it to Get-DOS83Path to improve efficiency
                    $boolSuccess = Get-DOS83Path -ReferenceToDOS8Dot3Path ([ref]$strDOS83Path) -Path $WorkingPath
                    if ($boolSuccess -eq $false) {
                        #region Unable to get DOS 8.3 path #########################
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Despite attempting to take ownership of the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'As a potential workaround, the script was going to try again with using the DOS 8.3 path. However, the script was unable to get the DOS 8.3 folder/file name.'
                        } else {
                            $strMessage = 'Despite attempting to take ownership of the folder/file "' + $WorkingPath + '" on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'As a potential workaround, the script was going to try again with using the DOS 8.3 path. However, the script was unable to get the DOS 8.3 folder/file name.'
                        }
                        Write-Error -Message $strMessage
                        $intFunctionReturn = -13
                        return $intFunctionReturn
                        #endregion Unable to get DOS 8.3 path #########################
                    } else {
                        #region We got the DOS 8.3 path ############################
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Despite attempting to take ownership of the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'As a potential workaround, the script is going to try again with using the DOS 8.3 path: ' + $strDOS83Path
                        } else {
                            $strMessage = 'Despite attempting to take ownership of the folder/file "' + $WorkingPath + '" on behalf of administrators, its permissions still cannot be read. The command used to take ownership was:' + "`n`n" + $strCommand + "`n`n" + 'As a potential workaround, the script is going to try again with using the DOS 8.3 path: ' + $strDOS83Path
                        }
                        Write-Debug -Message $strMessage
                        if ($boolIgnorePathLengthLimits) {
                            # Run in DOS 8.3 path mode and ignore path length limits
                            if ($boolFinalCleanupOfRedundantACEs) {
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strDOS83Path -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -DOS8dot3PathBeingUsed -IgnorePathLengthLimits -FinalCleanupOfRedundantACEs
                            } else {
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strDOS83Path -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -DOS8dot3PathBeingUsed -IgnorePathLengthLimits
                            }
                        } else {
                            # Run in DOS 8.3 path mode
                            if ($boolFinalCleanupOfRedundantACEs) {
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strDOS83Path -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -DOS8dot3PathBeingUsed -FinalCleanupOfRedundantACEs
                            } else {
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strDOS83Path -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -DOS8dot3PathBeingUsed
                            }
                        }
                        return $intReturnCode
                        #endregion We got the DOS 8.3 path ############################
                    }
                    #endregion We're not already running using a DOS 8.3 path, so try that
                }
                #endregion Still unable to read permissions after running takeown.exe #
            }
            #endregion An error occurred reading the ACL; mitigate and restart the process if possible
        } else {
            #region Able to read the ACL (permissions) of the item #################
            if ($null -eq $objThisObjectPermission) {
                #region An error did not occur retrieving permissions; however no permissions were retrieved - Get-Acl did not work as expected. Mitigate and restart the process if possible

                #region Take ownership #############################################
                $strEscapedPathForInvokeExpression = (((($WorkingPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strEscapedPathForInvokeExpression + '" /A'
                Write-Verbose -Message ('About to run command: ' + $strCommand)
                $null = Invoke-Expression $strCommand
                #endregion Take ownership #############################################

                # Should now be able to read permissions

                $boolSuccess = Get-AclSafely -ReferenceToACL ([ref]$objThisObjectPermission) -ReferenceToInfoObject ([ref]$objThis) -PathToObject $WorkingPath -PSVersion $versionPS

                if ($boolSuccess -eq $false) {
                    #region We had success reading permissions before, but now that we took ownership, we suddenly cannot read them
                    # This is a critical error.
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'After taking ownership of the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") on behalf of administrators, the script is unable to read permissions from the folder/file using Get-Acl. The command used to take ownership was:' + "`n`n" + $strCommand
                    } else {
                        $strMessage = 'After taking ownership of the folder/file "' + $WorkingPath + '" on behalf of administrators, the script is unable to read permissions from the folder/file using Get-Acl. The command used to take ownership was:' + "`n`n" + $strCommand
                    }
                    Write-Error -Message $strMessage
                    $intFunctionReturn = -6
                    $boolCriticalErrorOccurred = $true
                    return $intFunctionReturn
                    #endregion We had success reading permissions before, but now that we took ownership, we suddenly cannot read them
                } else {
                    #region The script was able to read permissions after taking ownership
                    if ($null -eq $objThisObjectPermission) {
                        #region An error did not occur retrieving permissions the second time; however no permissions were retrieved
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'The script was able read permissions from the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") using Get-Acl, even after taking ownership. It''s possibe this is because the ACL is blank/empty on the object, but that is unusual.'
                        } else {
                            $strMessage = 'The script was able read permissions from the folder/file "' + $WorkingPath + '" using Get-Acl, even after taking ownership. It''s possibe this is because the ACL is blank/empty on the object, but that is unusual.'
                        }
                        Write-Warning -Message $strMessage
                        #endregion An error did not occur retrieving permissions the second time; however no permissions were retrieved
                    }
                    #endregion The script was able to read permissions after taking ownership
                }
                #endregion An error did not occur retrieving permissions; however no permissions were retrieved - Get-Acl did not work as expected. Mitigate and restart the process if possible
            }
            #endregion Able to read the ACL (permissions) of the item #################
        }

        if ($boolCriticalErrorOccurred -eq $false) {
            #region We were able to read the permissions on the object - or, potentially, the object has an empty ACL

            #region Complete initialization of variables for processing ############
            if ($null -eq $objThis) {
                #region The System.IO.DirectoryInfo or System.IO.FileInfo object was null after retrieving the ACL
                if ($WorkingPath.Contains('[') -or $WorkingPath.Contains(']') -or $WorkingPath.Contains('`')) {
                    #region Working path contains characters that potentially need to be escaped
                    if ($versionPS.Major -ge 3) {
                        #region PowerShell v3 and newer supports -LiteralPath
                        # -Force parameter is required to get hidden items
                        $objThis = Get-Item -LiteralPath $WorkingPath -Force
                        #endregion PowerShell v3 and newer supports -LiteralPath
                    } else {
                        #region PowerShell v1 and v2 does not support -LiteralPath; escape the characters
                        # -Force parameter is required to get hidden items
                        $objThis = Get-Item -Path ((($WorkingPath.Replace('[', '`[')).Replace(']', '`]')).Replace('`', '``')) -Force
                        #endregion PowerShell v1 and v2 does not support -LiteralPath; escape the characters
                    }
                    #endregion Working path contains characters that potentially need to be escaped
                } else {
                    #region Working path does not contain characters that need to be escaped
                    # -Force parameter is required to get hidden items
                    $objThis = Get-Item $WorkingPath -Force
                    #endregion Working path does not contain characters that need to be escaped
                }
                #endregion The System.IO.DirectoryInfo or System.IO.FileInfo object was null after retrieving the ACL
            }

            if ($null -eq $objThisObjectPermission) {
                #region The permissions object was null, indicating that the ACL was blank/empty
                $arrACEs = @()
                $boolPermissionsNotInherited = $true
                #endregion The permissions object was null, indicating that the ACL was blank/empty
            } else {
                #region The permissions object was not null
                $arrACEs = @($objThisObjectPermission.Access)
                $boolPermissionsNotInherited = $objThisObjectPermission.AreAccessRulesProtected
                if ($boolPermissionsNotInherited -ne $true -and $boolPermissionsNotInherited -ne $false) {
                    #region The permissions inheritance status was not a boolean value
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'The script was able to read permissions from the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") using Get-Acl, but the permissions inheritance status was not a boolean value. This is unexpected.'
                    } else {
                        $strMessage = 'The script was able to read permissions from the folder/file "' + $WorkingPath + '" using Get-Acl, but the permissions inheritance status was not a boolean value. This is unexpected.'
                    }
                    Write-Warning -Message $strMessage
                    $boolPermissionsNotInherited = $true
                    #endregion The permissions inheritance status was not a boolean value
                }
                #endregion The permissions object was not null
            }
            #endregion Complete initialization of variables for processing ############

            if (-not $boolFinalCleanupOfRedundantACEs) {
                #region Not in final cleanup of redundant SIDs mode; check if Built-In Administrators group and SYSTEM account have sufficient access
                $boolBuiltInAdministratorsHaveSufficientAccess = $false
                $boolSYSTEMAccountHasSufficientAccess = $false

                $arrACEs | ForEach-Object {
                    #region Looping through each access control entry (ACE) in the ACL
                    $objThisACE = $_
                    if ($objThisACE.IdentityReference.Value -eq $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value) {
                        #region Found an ACE for the Built-In Administrators group #####
                        if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
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
                        #endregion Found an ACE for the Built-In Administrators group #####
                    } elseif ($objThisACE.IdentityReference.Value -eq $refNameOfSYSTEMAccountAccordingToGetAcl.Value) {
                        #region Found an ACE for the SYSTEM account ####################
                        if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
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
                        #endregion Found an ACE for the SYSTEM account ####################
                    }
                    #endregion Looping through each access control entry (ACE) in the ACL
                }
                #endregion Not in final cleanup of redundant SIDs mode; check if Built-In Administrators group and SYSTEM account have sufficient access

                #region Not in final cleanup of redundant SIDs mode; grant permission to built-in Administrators group and SYSTEM account if necessary
                if ($boolBuiltInAdministratorsHaveSufficientAccess -eq $false -or $boolSYSTEMAccountHasSufficientAccess -eq $false) {
                    $boolPermissionAdjustmentNecessary = $true
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Permission adjustment necessary for "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Permission adjustment necessary for "' + $WorkingPath + '".'
                    }
                    Write-Debug -Message $strMessage
                } else {
                    $boolPermissionAdjustmentNecessary = $false
                }

                $strAllCommandsInThisSection = ''

                if ($boolBuiltInAdministratorsHaveSufficientAccess -eq $false) {
                    #region Built-In Administrators group does not have sufficient access
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'The built-in Administrators group ("' + $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value + '") does not have sufficient access to the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'The built-in Administrators group ("' + $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value + '") does not have sufficient access to the folder/file "' + $WorkingPath + '".'
                    }
                    Write-Debug -Message $strMessage
                    # Add ACE for administrators
                    $strEscapedPathForInvokeExpression = (((($WorkingPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                    if ($objThis.PSIsContainer) {
                        # Is a folder
                        $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls.Value + ':(NP)(F)"'
                    } else {
                        # Is not a folder
                        $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls.Value + ':(F)"'
                    }
                    if ($IterativeRepairState -le 1) {
                        # For iterative repair state 1 or 2, we do not suppress errors
                        $strCommand += ' 2>&1'
                    }
                    $strAllCommandsInThisSection += "`n" + $strCommand
                    Write-Verbose -Message ('About to run command: ' + $strCommand)
                    $null = Invoke-Expression $strCommand
                    #endregion Built-In Administrators group does not have sufficient access
                }

                if ($boolSYSTEMAccountHasSufficientAccess -eq $false) {
                    #region SYSTEM account does not have sufficient access #############
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'The SYSTEM account ("' + $refNameOfSYSTEMAccountAccordingToGetAcl.Value + '") does not have sufficient access to the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'The SYSTEM account ("' + $refNameOfSYSTEMAccountAccordingToGetAcl.Value + '") does not have sufficient access to the folder/file "' + $WorkingPath + '".'
                    }
                    Write-Debug -Message $strMessage
                    # Add ACE for SYSTEM
                    $strEscapedPathForInvokeExpression = (((($WorkingPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                    if ($objThis.PSIsContainer) {
                        # Is a folder
                        $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls.Value + ':(NP)(F)"'
                    } else {
                        # Is not a folder
                        $strCommand = 'C:\Windows\System32\icacls.exe "' + $strEscapedPathForInvokeExpression + '" /grant "' + $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls.Value + ':(F)"'
                    }
                    if ($IterativeRepairState -le 1) {
                        # For iterative repair state 1 or 2, we do not suppress errors
                        $strCommand += ' 2>&1'
                    }
                    $strAllCommandsInThisSection += "`n" + $strCommand
                    Write-Verbose -Message ('About to run command: ' + $strCommand)
                    $null = Invoke-Expression $strCommand
                    #endregion SYSTEM account does not have sufficient access #############
                }

                if ($boolPermissionAdjustmentNecessary) {
                    #region Permissions adjustments were attempted; re-read permissions to verify they are now correct

                    $boolSuccess = Get-AclSafely -ReferenceToACL ([ref]$objThisObjectPermission) -ReferenceToInfoObject ([ref]$objThis) -PathToObject $WorkingPath -PSVersion $versionPS
                    if ($boolSuccess -eq $false) {
                        #region An error occurred reading permissions with Get-Acl after attempts were made to fix permissions
                        #
                        # We had success reading permissions before, but now that we
                        # granted accounts permission, we suddenly cannot read them. This
                        # is a critical error.
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'After granting permissions to the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"), the script is unable to read permissions from the folder/file using Get-Acl. The command(s) used to grant permissions were:' + "`n`n" + $strAllCommandsInThisSection
                        } else {
                            $strMessage = 'After granting permissions to the folder/file "' + $WorkingPath + '", the script is unable to read permissions from the folder/file using Get-Acl. The command(s) used to grant permissions were:' + "`n`n" + $strAllCommandsInThisSection
                        }
                        Write-Error -Message $strMessage
                        $intFunctionReturn = -7
                        $boolCriticalErrorOccurred = $true
                        return $intFunctionReturn
                        #endregion An error occurred reading permissions with Get-Acl after attempts were made to fix permissions
                    } else {
                        #region The script was able to read permissions after it attempted permission fixes
                        # TODO: Review this more closely; I don't believe this is
                        # necessary anymore because Get-AclSafely now returns the
                        # permission object without needing to copy it
                        # if ($versionPS -eq ([version]'1.0')) {
                        #     # The object returned from Get-Acl is not copy-able on
                        #     # PowerShell 1.0
                        #     # Not sure why...
                        #     # So, we need to get the ACL directly and hope that we don't
                        #     # have an error this time
                        #     $objThisObjectPermission = Get-Acl
                        # }

                        $arrACEs = @($objThisObjectPermission.Access)

                        $boolPermissionsNotInherited = $objThisObjectPermission.AreAccessRulesProtected
                        if ($boolPermissionsNotInherited -ne $true -and $boolPermissionsNotInherited -ne $false) {
                            #region The permissions inheritance status was not a boolean value
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'The script was able to read permissions from the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") using Get-Acl, but the permissions inheritance status was not a boolean value. This is unexpected.'
                            } else {
                                $strMessage = 'The script was able to read permissions from the folder/file "' + $WorkingPath + '" using Get-Acl, but the permissions inheritance status was not a boolean value. This is unexpected.'
                            }
                            Write-Warning -Message $strMessage
                            $boolPermissionsNotInherited = $true
                            #endregion The permissions inheritance status was not a boolean value
                        }

                        $boolBuiltInAdministratorsHaveSufficientAccess = $false
                        $boolSYSTEMAccountHasSufficientAccess = $false

                        $arrACEs | ForEach-Object {
                            #region Looping through each access control entry (ACE) in the ACL
                            $objThisACE = $_
                            if ($objThisACE.IdentityReference.Value -eq $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value) {
                                #region Found an ACE for the Built-In Administrators group
                                if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
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
                                #endregion Found an ACE for the Built-In Administrators group
                            } elseif ($objThisACE.IdentityReference.Value -eq $refNameOfSYSTEMAccountAccordingToGetAcl.Value) {
                                #region Found an ACE for the SYSTEM account ############
                                if ($objThisACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
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
                                #endregion Found an ACE for the SYSTEM account ############
                            }
                            #endregion Looping through each access control entry (ACE) in the ACL
                        }

                        if ($boolBuiltInAdministratorsHaveSufficientAccess -eq $false -or $boolSYSTEMAccountHasSufficientAccess -eq $false) {
                            #region Permissions adjustments were attempted; however, they are still not correct
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Despite attempting to apply permissions to the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"), the permissions are not present as expected. This can occur because of a lack of ownership over the folder/file.'
                            } else {
                                $strMessage = 'Despite attempting to apply permissions to the folder/file "' + $WorkingPath + '", the permissions are not present as expected. This can occur because of a lack of ownership over the folder/file.'
                            }
                            Write-Debug -Message $strMessage
                            if ($IterativeRepairState -eq 0) {
                                #region We are running normally (not in an iterative repair state), so we can try taking ownership of the folder/file

                                #region Take ownership using takeown.exe ###############
                                $strEscapedPathForInvokeExpression = (((($WorkingPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                $strCommand = 'C:\Windows\System32\takeown.exe /F "' + $strEscapedPathForInvokeExpression + '" /A'
                                $strCommand += ' 2>&1'
                                Write-Verbose -Message ('About to run command: ' + $strCommand)
                                $null = Invoke-Expression $strCommand
                                #endregion Take ownership using takeown.exe ###############

                                # Restart process without recursion flag, repair phase 1
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -RunWithoutRecursion -IterativeRepairState 1

                                if ($intReturnCode -ne 0) {
                                    $intFunctionReturn = $intReturnCode
                                    return $intFunctionReturn
                                }

                                # If we are still here, the repair was successful after
                                # taking ownership. Carry on with child objects

                                #endregion We are running normally (not in an iterative repair state), so we can try taking ownership of the folder/file
                            } elseif ($IterativeRepairState -eq 1) {
                                #region We are in repair phase 1, so we can try taking ownership of the folder/file with Set-Acl instead of takeown.exe
                                # Try taking ownership of the folder/file with Set-Acl

                                #region Take ownership using Set-Acl ###################
                                $objThisObjectPermission.SetOwner([System.Security.Principal.NTAccount]($NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls))
                                # TODO: Create Set-ACLSafely function to suppress errors
                                Set-Acl -Path $WorkingPath -AclObject $objThisObjectPermission
                                # Restart process without recursion flag, phase 2
                                #endregion Take ownership using Set-Acl ###################

                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -RunWithoutRecursion -IterativeRepairState 2

                                if ($intReturnCode -ne 0) {
                                    $intFunctionReturn = $intReturnCode
                                    return $intFunctionReturn
                                }

                                # If we are still here, the repair was successful after
                                # taking ownership. Carry on with child objects

                                #endregion We are in repair phase 1, so we can try taking ownership of the folder/file with Set-Acl instead of takeown.exe
                            } else {
                                #region We are in repair phase 2, so we have already tried taking ownership using takeown.exe and Set-Acl; however, we still cannot add the required permissions to the object
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'The permissions on the folder/file "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") could not be repaired. Please repair them manually.'
                                } else {
                                    $strMessage = 'The permissions on the folder/file "' + $WorkingPath + '" could not be repaired. Please repair them manually.'
                                }
                                Write-Warning -Message $strMessage
                                #endregion We are in repair phase 2, so we have already tried taking ownership using takeown.exe and Set-Acl; however, we still cannot add the required permissions to the object
                            }
                            #endregion Permissions adjustments were attempted; however, they are still not correct
                        }
                        #endregion The script was able to read permissions after it attempted permission fixes
                    }
                    #endregion Permissions adjustments were attempted; re-read permissions to verify they are now correct
                }
                #endregion Not in final cleanup of redundant SIDs mode; grant permission to built-in Administrators group and SYSTEM account if necessary
            } else {
                #region We're in final cleanup of redundant SIDs mode; perform final cleanup of redundant SIDs

                #region Make a copy of $arrACEs and store it in $arrWorkingACEs ####
                $arrWorkingACEs = @($arrACEs |
                        ForEach-Object {
                            $strIdentityReference = $_.IdentityReference.Value
                            $identityReference = [System.Security.Principal.NTAccount]$strIdentityReference
                            $intFileSystemRights = [int]($_.FileSystemRights)
                            $boolACEInherited = $_.IsInherited
                            $intInheritanceFlags = [int]($_.InheritanceFlags)
                            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]$intInheritanceFlags
                            $intPropagationFlags = [int]($_.PropagationFlags)
                            $propagationFlags = [System.Security.AccessControl.PropagationFlags]$intPropagationFlags
                            $intAccessControlType = [int]($_.AccessControlType)
                            $accessControlType = [System.Security.AccessControl.AccessControlType]$intAccessControlType

                            $objThisObjectPermission.AccessRuleFactory($identityReference, $intFileSystemRights, $boolACEInherited, $inheritanceFlags, $propagationFlags, $accessControlType)
                        })
                #endregion Make a copy of $arrACEs and store it in $arrWorkingACEs ####

                # Initialize variables used to confirm ACE count changes after a change
                # is made.
                $intNumberOfItems = $arrWorkingACEs.Count
                $intLastNumberOfItems = $arrACEs.Count

                # Initialize ACE tracker, which will be used to prevent duplicate
                # operations on ACEs (this is more-relevant as we move beyond SID
                # cleanup and other basic operations).
                $arrACETracking = New-Object bool[] $intNumberOfItems
                for ($intCounterA = 0; $intCounterA -lt $intNumberOfItems; $intCounterA++) {
                    $arrACETracking[$intCounterA] = $false
                }

                # Track at an overall level whether an ACL change was made; if so, we need to
                # write the ACL back later.
                $boolACLChangeMade = $false

                #region Initialize action tags for each type of ACE ################
                $boolBuiltInAdministratorsInheritedACEFound = $false
                $boolBuiltInAdministratorsNonInheritedNonInheritableACEFound = $false
                $intBuiltInAdministratorsNonInheritedNonInheritableACEPermissions = 0
                $boolSYSTEMAccountInheritedACEFound = $false
                $boolSYSTEMAccountNonInheritedNonInheritableACEFound = $false
                $intSYSTEMAccountNonInheritedNonInheritableACEPermissions = 0
                #endregion Initialize action tags for each type of ACE ################

                #region Look for redundant ACEs that need to be removed ############
                for ($intCounterA = 0; $intCounterA -lt $intNumberOfItems; $intCounterA++) {
                    #region Looping through each ACE in the ACL ####################
                    if (($arrWorkingACEs[$intCounterA]).IsInherited -eq $false) {
                        #region Current ACE is not inherited #######################
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Found non-inherited ACE in path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".'
                        } else {
                            $strMessage = 'Found non-inherited ACE in path "' + $WorkingPath + '". AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".'
                        }
                        Write-Debug -Message $strMessage
                        if ($null -ne ($arrWorkingACEs[$intCounterA]).IdentityReference) {
                            #region Non-inherited ACE has an IdentityReference #############
                            if (($arrWorkingACEs[$intCounterA]).IdentityReference.GetType().Name -eq 'SecurityIdentifier') {
                                #region Non-inherited ACE is a SID #########################
                                #endregion Non-inherited ACE is a SID #########################
                            } elseif (Test-ValidSID ([ref](($arrWorkingACEs[$intCounterA]).IdentityReference))) {
                                #region Non-inherited ACE is a SID (string) ################
                                #endregion Non-inherited ACE is a SID (string) ################
                            } else {
                                #region Non-inherited ACE is presumably an NTAccount #######
                                # See:
                                # https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.identityreference?view=net-7.0

                                if (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value) {
                                    #region Found a non-inherited ACE for the Built-In Administrators group
                                    if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                                        #region Found a non-inherited allow ACE for the built-in Administrators group
                                        $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                        if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                        } else {
                                            # See if the FileSystemRights is an integer value that
                                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                            $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                            }
                                        }

                                        if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                            #region Found a non-inherited allow ACE that grants full control to the built-in Administrators group
                                            # Check inheritable ACE settings
                                            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                                            $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                            if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                $boolBuiltInAdministratorsNonInheritedNonInheritableACEFound = $true
                                                $intBuiltInAdministratorsNonInheritedNonInheritableACEPermissions = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                            }
                                            #endregion Found a non-inherited allow ACE that grants full control to the built-in Administrators group
                                        }
                                        #endregion Found a non-inherited allow ACE for the built-in Administrators group
                                    }
                                    #endregion Found a non-inherited ACE for the Built-In Administrators group
                                } elseif (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfSYSTEMAccountAccordingToGetAcl.Value) {
                                    #region Found a non-inherited ACE for the SYSTEM account
                                    if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                                        #region Found a non-inherited allow ACE for the SYSTEM account
                                        $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                        if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                        } else {
                                            # See if the FileSystemRights is an integer value that
                                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                            $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                            }
                                        }

                                        if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                            #region Found a non-inherited allow ACE that grants full control to the SYSTEM account
                                            # Check inheritable ACE settings
                                            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                                            $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                            if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                $boolSYSTEMAccountNonInheritedNonInheritableACEFound = $true
                                                $intSYSTEMAccountNonInheritedNonInheritableACEPermissions = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                            }
                                            #endregion Found a non-inherited allow ACE that grants full control to the SYSTEM account
                                        }
                                        #endregion Found a non-inherited allow ACE for the SYSTEM account
                                    }
                                }
                                #endregion Non-inherited ACE is presumably an NTAccount #######
                            }
                            #endregion Non-inherited ACE has an IdentityReference #############
                        }
                        #endregion Current ACE is not inherited #######################
                    } else {
                        #region Current ACE is inherited ###################################
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Found inherited ACE in path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".'
                        } else {
                            $strMessage = 'Found inherited ACE in path "' + $WorkingPath + '". AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".'
                        }
                        Write-Debug -Message $strMessage
                        if ($null -ne ($arrWorkingACEs[$intCounterA]).IdentityReference) {
                            #region Inherited ACE has an IdentityReference #################
                            if (($arrWorkingACEs[$intCounterA]).IdentityReference.GetType().Name -eq 'SecurityIdentifier') {
                                #region Inherited ACE is a SID #############################
                                #endregion Inherited ACE is a SID #############################
                            } elseif (Test-ValidSID ([ref](($arrWorkingACEs[$intCounterA]).IdentityReference))) {
                                #region Inherited ACE is a SID (string) ####################
                                #endregion Inherited ACE is a SID (string) ####################
                            } else {
                                #region Inherited ACE is presumably an NTAccount ###########
                                # See:
                                # https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.identityreference?view=net-7.0

                                if (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value) {
                                    #region Found an inherited ACE for the built-in Administrators group
                                    if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                                        #region Found an inherited allow ACE for the built-in Administrators group
                                        $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                        if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                        } else {
                                            # See if the FileSystemRights is an integer value that
                                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                            $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                            }
                                        }

                                        if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                            #region Found an inherited allow ACE that grants full control to the built-in Administrators group
                                            if ($objThis.PSIsContainer) {
                                                # Check inheritable ACE settings
                                                $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                                $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                    $boolBuiltInAdministratorsInheritedACEFound = $true
                                                }
                                            } else {
                                                $boolBuiltInAdministratorsInheritedACEFound = $true
                                            }
                                            #endregion Found an inherited allow ACE that grants full control to the built-in Administrators group
                                        }
                                        #endregion Found an inherited allow ACE for the built-in Administrators group
                                    }
                                    #endregion Found an inherited ACE for the built-in Administrators group
                                } elseif (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfSYSTEMAccountAccordingToGetAcl.Value) {
                                    #region Found an inherited ACE for the SYSTEM account
                                    if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                                        #region Found an inherited allow ACE for the SYSTEM account
                                        $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                        if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                        } else {
                                            # See if the FileSystemRights is an integer value that
                                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                            $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                            }
                                        }

                                        if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                            #region Found an inherited allow ACE that grants full control to the SYSTEM account
                                            if ($objThis.PSIsContainer) {
                                                # Check inheritable ACE settings
                                                $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                                $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                    $boolSYSTEMAccountInheritedACEFound = $true
                                                }
                                            } else {
                                                $boolSYSTEMAccountInheritedACEFound = $true
                                            }
                                            #endregion Found an inherited allow ACE that grants full control to the SYSTEM account
                                        }
                                        #endregion Found an inherited allow ACE for the SYSTEM account
                                    }
                                    #endregion Found an inherited ACE for the SYSTEM account
                                }
                                #endregion Inherited ACE is presumably an NTAccount ###########
                            }
                            #endregion Inherited ACE has an IdentityReference #################
                        }
                        #endregion Current ACE is inherited ###################################
                    }
                    #endregion Looping through each ACE in the ACL ####################
                }
                #endregion Look for redundant ACEs that need to be removed ############

                #region Cleanup redundant ACEs if any were found ###################
                if ($boolBuiltInAdministratorsNonInheritedNonInheritableACEFound -and $boolBuiltInAdministratorsInheritedACEFound) {
                    #region A redundant ACE exists for the built-in Administrators group; need to perform cleanup
                    $strIdentityReference = $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value
                    if ($objThis.PSIsContainer) {
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Removing redundant, non-inherited, non-inheritable ACE for ' + $strIdentityReference + ' with full control from the following folder. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Removing redundant, non-inherited, non-inheritable ACE for ' + $strIdentityReference + ' with full control from the following folder. The path is "' + $WorkingPath + '".'
                        }
                    } else {
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Removing redundant, non-inherited, non-inheritable ACE for ' + $strIdentityReference + ' with full control from the following file. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Removing redundant, non-inherited, non-inheritable ACE for ' + $strIdentityReference + ' with full control from the following file. The path is "' + $WorkingPath + '".'
                        }
                    }
                    Write-Verbose -Message $strMessage
                    $identityReference = [System.Security.Principal.NTAccount]$strIdentityReference
                    $intFileSystemRights = $intBuiltInAdministratorsNonInheritedNonInheritableACEPermissions
                    $boolACEInherited = $false
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow

                    $objAccessRuleToRemove = $objThisObjectPermission.AccessRuleFactory($identityReference, $intFileSystemRights, $boolACEInherited, $inheritanceFlags, $propagationFlags, $accessControlType)

                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToRemove)
                    if ($boolSuccess -eq $false) {
                        #region Access rule removal failed #############################
                        $boolIssueWithRemovalOccurred = $true
                        if ($objThis.PSIsContainer) {
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                            }
                        } else {
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following file. Remove-SpecificAccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following file. Remove-SpecificAccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                            }
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule removal failed #############################
                    } else {
                        #region Access rule removal was successful #####################
                        # Test to see if permissions were removed by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed removed based on change in ACE count
                            Write-Debug -Message ('...the permission was removed...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed removed based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not removed
                            $boolIssueWithRemovalOccurred = $true
                            if ($objThis.PSIsContainer) {
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                } else {
                                    $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '".'
                                }
                            } else {
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following file. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                } else {
                                    $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following file. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '".'
                                }
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not removed
                        }
                        #endregion Access rule removal was successful #####################
                    }
                    #endregion A redundant ACE exists for the built-in Administrators group; need to perform cleanup
                }

                if ($boolSYSTEMAccountNonInheritedNonInheritableACEFound -and $boolSYSTEMAccountInheritedACEFound) {
                    #region A redundant ACE exists for the SYSTEM account; need to perform cleanup
                    $strIdentityReference = $refNameOfSYSTEMAccountAccordingToGetAcl.Value
                    if ($objThis.PSIsContainer) {
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Removing redundant, non-inherited, non-inheritable ACE for ' + $strIdentityReference + ' with full control from the following folder. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Removing redundant, non-inherited, non-inheritable ACE for ' + $strIdentityReference + ' with full control from the following folder. The path is "' + $WorkingPath + '".'
                        }
                    } else {
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Removing redundant, non-inherited, non-inheritable ACE for ' + $strIdentityReference + ' with full control from the following file. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Removing redundant, non-inherited, non-inheritable ACE for ' + $strIdentityReference + ' with full control from the following file. The path is "' + $WorkingPath + '".'
                        }
                    }
                    Write-Verbose -Message $strMessage
                    $identityReference = [System.Security.Principal.NTAccount]$strIdentityReference
                    $intFileSystemRights = $intSYSTEMAccountNonInheritedNonInheritableACEPermissions
                    $boolACEInherited = $false
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow

                    $objAccessRuleToRemove = $objThisObjectPermission.AccessRuleFactory($identityReference, $intFileSystemRights, $boolACEInherited, $inheritanceFlags, $propagationFlags, $accessControlType)

                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToRemove)
                    if ($boolSuccess -eq $false) {
                        #region Access rule removal failed #############################
                        $boolIssueWithRemovalOccurred = $true
                        if ($objThis.PSIsContainer) {
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                            }
                        } else {
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following file. Remove-SpecificAccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following file. Remove-SpecificAccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                            }
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule removal failed #############################
                    } else {
                        #region Access rule removal was successful #####################
                        # Test to see if permissions were removed by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed removed based on change in ACE count
                            Write-Debug -Message ('...the permission was removed...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed removed based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not removed
                            $boolIssueWithRemovalOccurred = $true
                            if ($objThis.PSIsContainer) {
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                } else {
                                    $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '".'
                                }
                            } else {
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following file. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                } else {
                                    $strMessage = 'Failed to remove ACE for ' + $strIdentityReference + ' with full control to the following file. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '".'
                                }
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not removed
                        }
                        #endregion Access rule removal was successful #####################
                    }
                    #endregion A redundant ACE exists for the SYSTEM account; need to perform cleanup
                }

                if ($boolACLChangeMade -eq $true) {
                    #region At least once change was made to the ACL; we need to write it to disk
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Writing ACL changes to disk for path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Writing ACL changes to disk for path "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $boolSuccess = Write-ACLToObject -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToTargetObject ([ref]$objThis) -ReferenceToACL ([ref]$objThisObjectPermission)
                    if ($boolSuccess -eq $false) {
                        #region Write-ACLToObject failed ###################################
                        # TODO: Capture $_.Exception.Message from failure in Write-ACLToObject
                        # Write-Warning ('Unable to write ACL changes to disk for path "' + $WorkingPath + '". Error: ' + $_.Exception.Message + '; child folders and files will not be processed!')
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Unable to write ACL changes to disk for path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). Child folders and files will not be processed!'
                        } else {
                            $strMessage = 'Unable to write ACL changes to disk for path "' + $WorkingPath + '". Child folders and files will not be processed!'
                        }
                        Write-Error -Message $strMessage
                        intFunctionReturn = -14
                        return $intFunctionReturn
                        #endregion Write-ACLToObject failed ###################################
                    }
                    #endregion At least once change was made to the ACL; we need to write it to disk
                }
                #endregion Cleanup redundant ACEs if any were found ###################

                #endregion We're in final cleanup of redundant SIDs mode; perform final cleanup of redundant SIDs
            }
            #endregion We were able to read the permissions on the object - or, potentially, the object has an empty ACL
        }

        #region We've theoretically repaired permissions on the object #############
        if ($objThis.PSIsContainer) {
            #region This object is a folder, not a file; process all files in this folder and then recursively process all subfolders

            if ($boolAllowRecursion -eq $true) {
                #region Recursion is allowed #######################################

                # Get the child objects
                $arrChildObjects = $null
                $boolSuccess = Get-ChildItemUsingObjectSafely -ReferenceToChildItems ([ref]$arrChildObjects) -ReferenceToParentObject ([ref]$objThis)

                if ($boolSuccess -eq $false) {
                    #region An error occurred getting child objects, probably because the path length is too long

                    if ($WorkingPath -eq $LastShortenedPath) {
                        #region The path is already as short as it can be, so there is nothing further for this script to try
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Unable to enumerate child objects in path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). This can occur if path length is too long. However, its path length has already been shortened, so there is nothing further for this script to try. Please repair the permissions on this folder manually.'
                        } else {
                            $strMessage = 'Unable to enumerate child objects in path "' + $WorkingPath + '". This can occur if path length is too long. However, its path length has already been shortened, so there is nothing further for this script to try. Please repair the permissions on this folder manually.'
                        }
                        Write-Error -Message $strMessage
                        $intFunctionReturn = -8
                        return $intFunctionReturn
                        #endregion The path is already as short as it can be, so there is nothing further for this script to try
                    } else {
                        #region The path is not as short as it can be, so try again with a shorter path
                        if ($WorkingPath.Length -le 3) {
                            # The path is already as short as it can be, so there is
                            # nothing further for this script to try
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Unable to enumerate child objects in path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). This can occur if path length is too long. However, in this case, its path length is already as short as possible, so there is nothing further for this script to try. Please investigate and then repair the permissions on this folder manually.'
                            } else {
                                $strMessage = 'Unable to enumerate child objects in path "' + $WorkingPath + '". This can occur if path length is too long. However, in this case, its path length is already as short as possible, so there is nothing further for this script to try. Please investigate and then repair the permissions on this folder manually.'
                            }
                            Write-Error -Message $strMessage
                            $intFunctionReturn = -12
                            return $intFunctionReturn
                        } else {
                            # Try again with a shorter path
                            $strFolderTarget = $WorkingPath
                            $strChildFolderOfTarget = ''

                            #region Mitigate Path Length with Drive Substitution
                            # Inputs:
                            # $strFolderTarget
                            # $strChildFolderOfTarget

                            $boolSubstWorked = $false
                            # TODO: Rework to pass along whether the OS is Windows
                            $arrAvailableDriveLetters = @(Get-AvailableDriveLetter -PSVersion $versionPS)
                            if ($arrAvailableDriveLetters.Count -gt 0) {
                                #region Drive Letters Available ################
                                $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                                $strEscapedPathForInvokeExpression = (((($strFolderTarget.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strEscapedPathForInvokeExpression + '"'
                                Write-Verbose -Message ('About to run command: ' + $strCommand)
                                $null = Invoke-Expression $strCommand

                                # Confirm the path is ready
                                $strJoinedPath = ''
                                $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                if ($boolPathAvailable -eq $false) {
                                    #region The drive substitution seems to have failed
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...'
                                    } else {
                                        $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...'
                                    }
                                    Write-Debug -Message $strMessage
                                    $intReturnCode = -1
                                    #endregion The drive substitution seems to have failed
                                } else {
                                    #region The drive substitution was successful
                                    if ($boolFinalCleanupOfRedundantACEs) {
                                        $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path ($strDriveLetterToUse + ':') '') -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -FinalCleanupOfRedundantACEs
                                    } else {
                                        $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path ($strDriveLetterToUse + ':') '') -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth
                                    }
                                    #endregion The drive substitution was successful
                                }

                                $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                                Write-Verbose -Message ('About to run command: ' + $strCommand)
                                $null = Invoke-Expression $strCommand

                                # TODO: This is not necessary, right? Because Wait-PathToBeNotReady will run Get-PSDrive
                                if ($refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value -eq $true) {
                                    # Use workaround for drives not refreshing in current PowerShell session
                                    Get-PSDrive | Out-Null
                                }

                                $boolPathUnavailable = Wait-PathToBeNotReady -Path ($strDriveLetterToUse + ':') -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                if ($boolPathUnavailable -eq $false) {
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand
                                    } else {
                                        $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand
                                    }
                                    Write-Warning -Message $strMessage
                                }

                                if ($intReturnCode -eq 0) {
                                    $boolSubstWorked = $true
                                }
                                #endregion Drive Letters Available ################
                            }
                            #endregion Mitigate Path Length with Drive Substitution

                            #region Mitigate Path Length with Symbolic Link ####
                            # Inputs:
                            # $strFolderTarget
                            # $strChildFolderOfTarget

                            # If a substituted drive failed, try a symbolic link instead
                            $boolSymbolicLinkWorked = $false
                            if ($boolSubstWorked -eq $false) {
                                #region The earlier attempt at a drive substitution was not successful
                                $boolSymbolicLinkTargetFound = $false
                                $strSymbolicLinkFolderName = ''
                                if ($strFolderTarget.Length -gt 35) {
                                    #region We can use a GUID for the symbolic link folder name
                                    # Use a GUID to avoid name collisions
                                    $strSymbolicLinkFolderName = [System.Guid]::NewGuid().ToString()
                                    $strSymbolicLinkFolderName = $strSymbolicLinkFolderName.Replace('-', '')
                                    $boolSymbolicLinkTargetFound = $true
                                    #endregion We can use a GUID for the symbolic link folder name
                                } elseif ($strFolderTarget.Length -gt 5) {
                                    #region We cannot use a GUID for the symbolic link folder name, so we'll use a single character instead
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
                                    #endregion We cannot use a GUID for the symbolic link folder name, so we'll use a single character instead
                                } else {
                                    #region We cannot create a symbolic link because it won't help; the parent folder path is too short for it to be effective
                                    # The path is already short enough; cannot create a symbolic link
                                    # $boolSymbolicLinkTargetFound = $false
                                    #endregion We cannot create a symbolic link because it won't help; the parent folder path is too short for it to be effective
                                }

                                if ($boolSymbolicLinkTargetFound -eq $true) {
                                    #region We found a suitable symbolic link target
                                    # Create the symbolic link
                                    $versionPS = Get-PSVersion
                                    if ($versionPS -ge ([version]'5.0')) {
                                        #region PowerShell 5.0 or newer: make the symbolic link using native PowerShell
                                        # PowerShell 5.0 and newer can make symbolic links in PowerShell
                                        $strMessage = 'An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via PowerShell:' + "`n" + 'Symbolic link path: ' + 'C:\' + $strSymbolicLinkFolderName + "`n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$')
                                        Write-Verbose -Message $strMessage
                                        # TODO: Test this with a path containing a dollar sign ($)
                                        New-Item -ItemType SymbolicLink -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                                        #endregion PowerShell 5.0 or newer: make the symbolic link using native PowerShell
                                    } else {
                                        #region PowerShell 4.0 or older: make the symbolic link using mklink command
                                        # Need to use mklink command in command prompt instead
                                        # TODO: Test this with a path containing a dollar sign ($)
                                        $strEscapedPathForInvokeExpression = (((($WorkingPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                        $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "' + (Join-Path 'C:' $strSymbolicLinkFolderName) + '" "' + $strEscapedPathForInvokeExpression + '"'
                                        $strMessage = 'An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via command: ' + $strCommand
                                        Write-Verbose -Message $strMessage
                                        $null = Invoke-Expression $strCommand
                                        #endregion PowerShell 4.0 or older: make the symbolic link using mklink command
                                    }

                                    # Confirm the path is ready
                                    $strJoinedPath = ''
                                    $boolPathAvailable = Wait-PathToBeReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                    if ($boolErrorOccurredUsingNewPath -eq $true) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" (real path: "' + $refToRealPath.Value + '") because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.'
                                        } else {
                                            $strMessage = 'Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.'
                                        }
                                        Write-Error -Message $strMessage
                                        $intReturnCode = -2
                                    } else {
                                        if ($boolFinalCleanupOfRedundantACEs) {
                                            $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path 'C:' $strSymbolicLinkFolderName) -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -FinalCleanupOfRedundantACEs
                                        } else {
                                            $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path 'C:' $strSymbolicLinkFolderName) -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth
                                        }
                                    }

                                    if ($intReturnCode -lt 0) {
                                        # -2 if drive substitution and symbolic link failed
                                        $intFunctionReturn = $intReturnCode
                                        return $intFunctionReturn
                                    } elseif ($intReturnCode -eq 0) {
                                        $boolSymbolicLinkWorked = $true
                                    }

                                    # Remove Symbolic Link
                                    Write-Verbose -Message ('Removing symbolic link: ' + (Join-Path 'C:' $strSymbolicLinkFolderName))
                                    # TODO: Build error handling for this deletion:
                                    (Get-Item (Join-Path 'C:' $strSymbolicLinkFolderName)).Delete()

                                    # TODO: This is not necessary, right? Because Wait-PathToBeNotReady will run Get-PSDrive
                                    if ($refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value -eq $true) {
                                        # Use workaround for drives not refreshing in current PowerShell session
                                        Get-PSDrive | Out-Null
                                    }

                                    $boolPathUnavailable = Wait-PathToBeNotReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                    if ($boolPathUnavailable -eq $false) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.'
                                        } else {
                                            $strMessage = 'There was an issue processing the path "' + $WorkingPath + '". A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.'
                                        }
                                        Write-Warning -Message $strMessage
                                    }
                                    #endregion We found a suitable symbolic link target
                                }
                                #endregion The earlier attempt at a drive substitution was not successful
                            }
                            #endregion Mitigate Path Length with Symbolic Link ####

                            if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                                #region Both drive substitution and symbolic link failed
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $WorkingPath + ' (real path: "' + $refToRealPath.Value + '")'
                                } else {
                                    $strMessage = 'Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $WorkingPath
                                }
                                Write-Error -Message $strMessage
                                $intFunctionReturn = -9
                                return $intFunctionReturn
                                #endregion Both drive substitution and symbolic link failed
                            }
                        }
                        #endregion The path is not as short as it can be, so try again with a shorter path
                    }
                    #endregion An error occurred getting child objects, probably because the path length is too long
                } else {
                    #region No error occurred getting child items ##################
                    $boolLengthOfChildrenOK = $true

                    #region Check the length of all child objects first ############
                    $arrChildObjects | ForEach-Object {
                        $objDirectoryOrFileInfoChild = $_

                        # We don't know if $WorkingPath is pointing to a folder or a file, so use the folder
                        # (shorter) length limit
                        if (($objDirectoryOrFileInfoChild.FullName).Length -ge $FOLDERPATHLIMIT) {
                            $boolLengthOfChildrenOK = $false
                        }
                    }
                    #endregion Check the length of all child objects first ############

                    if ($boolLengthOfChildrenOK -eq $false -and $boolIgnorePathLengthLimits -ne $true) {
                        #region One or more child objects are too long and we are not ignoring path length limits

                        if ($WorkingPath -eq $LastShortenedPath) {
                            #region Try again with IgnorePathLengthLimits enabled ##
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'The path length on one or more child objects in folder "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") exceeds the maximum number of characters. A drive substitution or synbolic link should be used to mitigate this, however this mitigation has already been performed, so trying again with temporary path length ignoring mode enabled.'
                            } else {
                                $strMessage = 'The path length on one or more child objects in folder "' + $WorkingPath + '" exceeds the maximum number of characters. A drive substitution or synbolic link should be used to mitigate this, however this mitigation has already been performed, so trying again with temporary path length ignoring mode enabled.'
                            }
                            Write-Debug -Message $strMessage
                            if ($boolFinalCleanupOfRedundantACEs) {
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -IgnorePathLengthLimits -FinalCleanupOfRedundantACEs
                            } else {
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -IgnorePathLengthLimits
                            }
                            $intFunctionReturn = $intReturnCode
                            return $intFunctionReturn
                            #endregion Try again with IgnorePathLengthLimits enabled ##
                        } else {
                            #region The parent folder that is under the length limit is different than the last shortened path (this is good)
                            if ($WorkingPath.Length -le 3) {
                                #region The parent folder is a root folder (this is bad, it doesn't get any shorter than this)
                                # The path is already as short as it can be, so there
                                # is nothing further to do to mitigate path length
                                #
                                # We are not in temporary path length ignoring mode
                                # yet, so try again with temporary path length
                                # ignoring mode enabled
                                if ($WorkingPath -ne $refToRealPath.Value) {
                                    $strMessage = 'The path length on one or more child objects in folder "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") exceeds the maximum number of characters. Normally, a drive substitution or symbolic link should be used to mitigate this, however the path is already as short as possible. Therefore, there is nothing further to do to mitigate path length. Trying again with temporary path length ignoring mode enabled.'
                                } else {
                                    $strMessage = 'The path length on one or more child objects in folder "' + $WorkingPath + '" exceeds the maximum number of characters. Normally, a drive substitution or symbolic link should be used to mitigate this, however the path is already as short as possible. Therefore, there is nothing further to do to mitigate path length. Trying again with temporary path length ignoring mode enabled.'
                                }
                                Write-Debug -Message $strMessage
                                if ($boolFinalCleanupOfRedundantACEs) {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -IgnorePathLengthLimits -FinalCleanupOfRedundantACEs
                                } else {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -IgnorePathLengthLimits
                                }
                                $intFunctionReturn = $intReturnCode
                                return $intFunctionReturn
                                #endregion The parent folder is a root folder (this is bad, it doesn't get any shorter than this)
                            } else {
                                #region The parent folder is not a root folder (this is good)
                                # Try again with a shorter path
                                $strFolderTarget = $WorkingPath
                                $strChildFolderOfTarget = ''

                                #region Mitigate Path Length with Drive Substitution
                                # Inputs:
                                # $strFolderTarget
                                # $strChildFolderOfTarget

                                $boolSubstWorked = $false
                                # TODO: Rework to pass along whether the OS is Windows
                                $arrAvailableDriveLetters = @(Get-AvailableDriveLetter -PSVersion $versionPS)
                                if ($arrAvailableDriveLetters.Count -gt 0) {
                                    #region Drive Letters Available ############
                                    $strDriveLetterToUse = $arrAvailableDriveLetters[$arrAvailableDriveLetters.Count - 1]
                                    $strEscapedPathForInvokeExpression = (((($strFolderTarget.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                    $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': "' + $strEscapedPathForInvokeExpression + '"'
                                    Write-Verbose -Message ('About to run command: ' + $strCommand)
                                    $null = Invoke-Expression $strCommand

                                    # Confirm the path is ready
                                    $strJoinedPath = ''
                                    $boolPathAvailable = Wait-PathToBeReady -Path ($strDriveLetterToUse + ':') -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                    if ($boolPathAvailable -eq $false) {
                                        #region The drive substitution seems to have failed
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...'
                                        } else {
                                            $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" because running the following command to mitigate path length failed to create an accessible drive letter (' + $strDriveLetterToUse + ':): ' + $strCommand + "`n`n" + 'Will try a symbolic link instead...'
                                        }
                                        # TODO: Should this be an error?
                                        Write-Debug -Message $strMessage
                                        $intReturnCode = -1
                                        #endregion The drive substitution seems to have failed
                                    } else {
                                        #region The drive substitution was successful
                                        if ($boolIgnorePathLengthLimits) {
                                            # Run with ignoring path length limits
                                            if ($boolFinalCleanupOfRedundantACEs) {
                                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path ($strDriveLetterToUse + ':') '') -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -IgnorePathLengthLimits -FinalCleanupOfRedundantACEs
                                            } else {
                                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path ($strDriveLetterToUse + ':') '') -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -IgnorePathLengthLimits
                                            }
                                        } else {
                                            if ($boolFinalCleanupOfRedundantACEs) {
                                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path ($strDriveLetterToUse + ':') '') -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -FinalCleanupOfRedundantACEs
                                            } else {
                                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path ($strDriveLetterToUse + ':') '') -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth
                                            }
                                        }
                                        #endregion The drive substitution was successful
                                    }

                                    $strCommand = 'C:\Windows\System32\subst.exe ' + $strDriveLetterToUse + ': /D'
                                    Write-Verbose -Message ('About to run command: ' + $strCommand)
                                    $null = Invoke-Expression $strCommand

                                    # TODO: This is not necessary, right? Because Wait-PathToBeNotReady will run Get-PSDrive
                                    if ($refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value -eq $true) {
                                        # Use workaround for drives not refreshing in current PowerShell session
                                        Get-PSDrive | Out-Null
                                    }

                                    $boolPathUnavailable = Wait-PathToBeNotReady -Path ($strDriveLetterToUse + ':') -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                    if ($boolPathUnavailable -eq $false) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand
                                        } else {
                                            $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" because running the following command to remove the drive letter (' + $strDriveLetterToUse + ':) failed (please remove the drive manually!): ' + $strCommand
                                        }
                                        Write-Warning -Message $strMessage
                                    }

                                    if ($intReturnCode -eq 0) {
                                        $boolSubstWorked = $true
                                    }
                                    #endregion Drive Letters Available ############
                                }
                                #endregion Mitigate Path Length with Drive Substitution

                                #region Mitigate Path Length with Symbolic Link
                                # Inputs:
                                # $strFolderTarget
                                # $strChildFolderOfTarget

                                # If a substituted drive failed, try a symbolic link instead
                                $boolSymbolicLinkWorked = $false
                                if ($boolSubstWorked -eq $false) {
                                    #region The earlier attempt at a drive substitution was not successful
                                    $boolSymbolicLinkTargetFound = $false
                                    $strSymbolicLinkFolderName = ''
                                    if ($strFolderTarget.Length -gt 35) {
                                        #region We can use a GUID for the symbolic link folder name
                                        # Use a GUID to avoid name collisions
                                        $strSymbolicLinkFolderName = [System.Guid]::NewGuid().ToString()
                                        $strSymbolicLinkFolderName = $strSymbolicLinkFolderName.Replace('-', '')
                                        $boolSymbolicLinkTargetFound = $true
                                        #endregion We can use a GUID for the symbolic link folder name
                                    } elseif ($strFolderTarget.Length -gt 5) {
                                        #region We cannot use a GUID for the symbolic link folder name, so we'll use a single character instead
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
                                        #endregion We cannot use a GUID for the symbolic link folder name, so we'll use a single character instead
                                    } else {
                                        #region We cannot create a symbolic link because it won't help; the parent folder path is too short for it to be effective
                                        # The path is already short enough; cannot create a symbolic link
                                        # $boolSymbolicLinkTargetFound = $false
                                        #endregion We cannot create a symbolic link because it won't help; the parent folder path is too short for it to be effective
                                    }

                                    if ($boolSymbolicLinkTargetFound -eq $true) {
                                        #region We found a suitable symbolic link target
                                        # Create the symbolic link
                                        $versionPS = Get-PSVersion
                                        if ($versionPS -ge ([version]'5.0')) {
                                            #region PowerShell 5.0 or newer: make the symbolic link using native PowerShell
                                            # PowerShell 5.0 and newer can make symbolic links in PowerShell
                                            $strMessage = 'An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via PowerShell:' + "`n" + 'Symbolic link path: ' + 'C:\' + $strSymbolicLinkFolderName + "`n" + 'Target path: ' + $strFolderTarget.Replace('$', '`$')
                                            Write-Verbose -Message $strMessage
                                            # TODO: Test this with a path containing a dollar sign ($)
                                            New-Item -ItemType SymbolicLink -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -Target $strFolderTarget.Replace('$', '`$') | Out-Null
                                            #endregion PowerShell 5.0 or newer: make the symbolic link using native PowerShell
                                        } else {
                                            #region PowerShell 4.0 or older: make the symbolic link using mklink command
                                            # Need to use mklink command in command prompt instead
                                            # TODO: Test this with a path containing a dollar sign ($)
                                            $strEscapedPathForInvokeExpression = (((($WorkingPath.Replace('`', '``')).Replace('$', '`$')).Replace([string]([char]8220), '`' + [string]([char]8220))).Replace([string]([char]8221), '`' + [string]([char]8221))).Replace([string]([char]8222), '`' + [string]([char]8222))
                                            $strCommand = 'C:\Windows\System32\cmd.exe /c mklink /D "' + (Join-Path 'C:' $strSymbolicLinkFolderName) + '" "' + $strEscapedPathForInvokeExpression + '"'
                                            Write-Verbose -Message ('An error occurred when mitigating path length using drive substitution. Trying to create a symbolic link instead via command: ' + $strCommand)
                                            $null = Invoke-Expression $strCommand
                                            #endregion PowerShell 4.0 or older: make the symbolic link using mklink command
                                        }

                                        # Confirm the path is ready
                                        $strJoinedPath = ''
                                        $boolPathAvailable = Wait-PathToBeReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ChildItemPath $strChildFolderOfTarget -ReferenceToJoinedPath ([ref]$strJoinedPath) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                        if ($boolErrorOccurredUsingNewPath -eq $true) {
                                            if ($WorkingPath -ne $refToRealPath.Value) {
                                                $strMessage = 'Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" (real path: "' + $refToRealPath.Value + '") because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.'
                                            } else {
                                                $strMessage = 'Unable to process the path "' + $strFolderTarget.Replace('$', '`$') + '" because the attempt to mitigate path length using drive substitution failed and the attempt to create a symbolic link also failed.'
                                            }
                                            Write-Error -Message $strMessage
                                            $intReturnCode = -2
                                        } else {
                                            if ($boolFinalCleanupOfRedundantACEs) {
                                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path 'C:' $strSymbolicLinkFolderName) -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth -FinalCleanupOfRedundantACEs
                                            } else {
                                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $strJoinedPath -LastShortenedPath (Join-Path 'C:' $strSymbolicLinkFolderName) -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth $RecursionDepth
                                            }
                                        }

                                        if ($intReturnCode -lt 0) {
                                            # -2 if drive substitution and symbolic link failed
                                            $intFunctionReturn = $intReturnCode
                                            return $intFunctionReturn
                                        } elseif ($intReturnCode -eq 0) {
                                            $boolSymbolicLinkWorked = $true
                                        }

                                        # Remove Symbolic Link
                                        Write-Verbose -Message ('Removing symbolic link: ' + (Join-Path 'C:' $strSymbolicLinkFolderName))
                                        # TODO: Build error handling for this deletion:
                                        (Get-Item (Join-Path 'C:' $strSymbolicLinkFolderName)).Delete()

                                        # TODO: This is not necessary, right? Because Wait-PathToBeNotReady will run Get-PSDrive
                                        if ($refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful.Value -eq $true) {
                                            # Use workaround for drives not refreshing in current PowerShell session
                                            Get-PSDrive | Out-Null
                                        }

                                        $boolPathUnavailable = Wait-PathToBeNotReady -Path (Join-Path 'C:' $strSymbolicLinkFolderName) -ReferenceToUseGetPSDriveWorkaround $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful

                                        if ($boolPathUnavailable -eq $false) {
                                            if ($WorkingPath -ne $refToRealPath.Value) {
                                                $strMessage = 'There was an issue processing the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.'
                                            } else {
                                                $strMessage = 'There was an issue processing the path "' + $WorkingPath + '". A symbolic link (' + (Join-Path 'C:' $strSymbolicLinkFolderName) + ') was used to work-around a long path issue. When the processing was completed, the symbolic link was attempted to be removed. However, its removal failed. Please remove the symbolic link manually.'
                                            }
                                            Write-Warning -Message $strMessage
                                        }
                                        #endregion We found a suitable symbolic link target
                                    }
                                    #endregion The earlier attempt at a drive substitution was not successful
                                }
                                #endregion Mitigate Path Length with Symbolic Link

                                if ($boolSubstWorked -eq $false -and $boolSymbolicLinkWorked -eq $false) {
                                    #region Both drive substitution and symbolic link failed
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $WorkingPath + ' (real path: "' + $refToRealPath.Value + '")'
                                    } else {
                                        $strMessage = 'Cannot process the following path because it is too long and attempted mitigations using drive substitution and a symbolic link failed: ' + $WorkingPath
                                    }
                                    Write-Error -Message $strMessage
                                    $intFunctionReturn = -11
                                    return $intFunctionReturn
                                    #endregion Both drive substitution and symbolic link failed
                                }
                                #endregion The parent folder is not a root folder (this is good)
                            }
                            #endregion The parent folder that is under the length limit is different than the last shortened path (this is good)
                        }
                        #endregion One or more child objects are too long and we are not ignoring path length limits
                    } else {
                        #region The length of all child objects was OK, or IgnorePathLengthLimits was specified

                        #region Process all child files ############################
                        $arrChildObjects | Where-Object { $_.PSIsContainer -eq $false } | ForEach-Object {
                            $objDirectoryOrFileInfoChild = $_
                            # Process the file

                            # Generate a new real path for the item and pass it to the
                            # recursive function
                            $strNewRealPath = Join-Path -Path ($refToRealPath.Value) -ChildPath $objDirectoryOrFileInfoChild.Name

                            if ($boolFinalCleanupOfRedundantACEs) {
                                # Pass-through temporary path length ignoring mode
                                if ($boolIgnorePathLengthLimits) {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath ($objDirectoryOrFileInfoChild.FullName) -LastShortenedPath $LastShortenedPath -RealPath $strNewRealPath -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth ($RecursionDepth + 1) -RunWithoutRecursion -IgnorePathLengthLimits -FinalCleanupOfRedundantACEs
                                } else {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath ($objDirectoryOrFileInfoChild.FullName) -LastShortenedPath $LastShortenedPath -RealPath $strNewRealPath -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth ($RecursionDepth + 1) -RunWithoutRecursion -FinalCleanupOfRedundantACEs
                                }
                            } else {
                                # Pass-through temporary path length ignoring mode
                                if ($boolIgnorePathLengthLimits) {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath ($objDirectoryOrFileInfoChild.FullName) -LastShortenedPath $LastShortenedPath -RealPath $strNewRealPath -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth ($RecursionDepth + 1) -RunWithoutRecursion -IgnorePathLengthLimits
                                } else {
                                    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath ($objDirectoryOrFileInfoChild.FullName) -LastShortenedPath $LastShortenedPath -RealPath $strNewRealPath -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth ($RecursionDepth + 1) -RunWithoutRecursion
                                }
                            }
                            if ($intReturnCode -ne 0) {
                                if ($objDirectoryOrFileInfoChild.FullName -ne $strNewRealPath) {
                                    $strMessage = 'There was an issue processing the path "' + $objDirectoryOrFileInfoChild.FullName + '" (real path: "' + $strNewRealPath + '") The error code returned was: ' + $intReturnCode
                                } else {
                                    $strMessage = 'There was an issue processing the path "' + $objDirectoryOrFileInfoChild.FullName + '" The error code returned was: ' + $intReturnCode
                                }
                                Write-Warning -Message $strMessage
                                $intFunctionReturn = $intReturnCode
                            }
                        }
                        #endregion Process all child files ############################

                        #region Process all child folders recursively ##############
                        $arrChildObjects | Where-Object { $_.PSIsContainer -eq $true } | ForEach-Object {
                            $objDirectoryOrFileInfoChild = $_
                            # Recursively process the child directory

                            # Generate a new real path for the item and pass it to the
                            # recursive function
                            $strNewRealPath = Join-Path -Path ($refToRealPath.Value) -ChildPath $objDirectoryOrFileInfoChild.Name

                            if ($boolFinalCleanupOfRedundantACEs) {
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath ($objDirectoryOrFileInfoChild.FullName) -LastShortenedPath $LastShortenedPath -RealPath $strNewRealPath -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth ($RecursionDepth + 1) -FinalCleanupOfRedundantACEs
                            } else {
                                $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath ($objDirectoryOrFileInfoChild.FullName) -LastShortenedPath $LastShortenedPath -RealPath $strNewRealPath -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToHashtableOfKnownSIDs $ReferenceToHashtableOfKnownSIDs -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl -RecursionDepth ($RecursionDepth + 1)
                            }
                            if ($intReturnCode -ne 0) {
                                if ($objDirectoryOrFileInfoChild.FullName -ne $strNewRealPath) {
                                    $strMessage = 'There was an issue processing the path "' + $objDirectoryOrFileInfoChild.FullName + '" (real path: "' + $strNewRealPath + '") The error code returned was: ' + $intReturnCode
                                } else {
                                    $strMessage = 'There was an issue processing the path "' + $objDirectoryOrFileInfoChild.FullName + '" The error code returned was: ' + $intReturnCode
                                }
                                Write-Warning -Message $strMessage
                                $intFunctionReturn = $intReturnCode
                            }
                        }
                        #endregion Process all child folders recursively ##############
                        #endregion The length of all child objects was OK, or IgnorePathLengthLimits was specified
                    }
                    #endregion No error occurred getting child items ##################
                }
                #endregion Recursion is allowed #######################################
            }
            #endregion This object is a folder, not a file; process all files in this folder and then recursively process all subfolders
        }

        if (-not $boolFinalCleanupOfRedundantACEs) {
            #region Not in final cleanup of redundance ACEs mode; programmatically change permissions via .NET
            # $arrACEs is already initialized (and refreshed if permission changes were
            # made above)

            #region Check to see if unresolved SIDs should be removed ##################
            if ($null -eq $ReferenceToHashtableOfKnownSIDs) {
                $boolRemoveUnresolvedSIDs = $false
            } else {
                $boolRemoveUnresolvedSIDs = ($null -ne ($ReferenceToHashtableOfKnownSIDs.Value))
            }
            #endregion Check to see if unresolved SIDs should be removed ##################

            #region Make a copy of $arrACEs and store it in $arrWorkingACEs ############
            $arrWorkingACEs = @($arrACEs |
                    ForEach-Object {
                        $strIdentityReference = $_.IdentityReference.Value
                        $identityReference = [System.Security.Principal.NTAccount]$strIdentityReference
                        $intFileSystemRights = [int]($_.FileSystemRights)
                        $boolACEInherited = $_.IsInherited
                        $intInheritanceFlags = [int]($_.InheritanceFlags)
                        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]$intInheritanceFlags
                        $intPropagationFlags = [int]($_.PropagationFlags)
                        $propagationFlags = [System.Security.AccessControl.PropagationFlags]$intPropagationFlags
                        $intAccessControlType = [int]($_.AccessControlType)
                        $accessControlType = [System.Security.AccessControl.AccessControlType]$intAccessControlType

                        $objThisObjectPermission.AccessRuleFactory($identityReference, $intFileSystemRights, $boolACEInherited, $inheritanceFlags, $propagationFlags, $accessControlType)
                    })
            #endregion Make a copy of $arrACEs and store it in $arrWorkingACEs ############

            # Initialize variables used to confirm ACE count changes after a change is
            # made.
            $intNumberOfItems = $arrWorkingACEs.Count
            $intLastNumberOfItems = $arrACEs.Count

            # Initialize ACE tracker, which will be used to prevent duplicate operations
            # on ACEs (this is more-relevant as we move beyond SID cleanup and other basic
            # operations).
            $arrACETracking = New-Object bool[] $intNumberOfItems
            for ($intCounterA = 0; $intCounterA -lt $intNumberOfItems; $intCounterA++) {
                $arrACETracking[$intCounterA] = $false
            }

            # Track at an overall level whether an ACL change was made; if so, we need to
            # write the ACL back later.
            $boolACLChangeMade = $false

            #region Initialize action tags for each type of ACE ########################
            if ($objThis.PSIsContainer) {
                if ($boolPermissionsNotInherited -or ($RecursionDepth -eq 0)) {
                    #region This object is a folder and either it is not inheriting any permissions, or we are at the root of the process
                    $boolBuiltInAdministratorsInheritableACENeedsToBeApplied = $true
                    $boolSYSTEMInheritableACENeedsToBeApplied = $true

                    if ([string]::IsNullOrEmpty($refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value) -eq $false) {
                        # An additional administrator account/group is specified
                        $boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied = $true
                    } else {
                        # An additional administrator account/group is not specified
                        $boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied = $false
                    }
                    $boolAdditionalAdministratorAccountNonInheritableACENeedsToBeApplied = $false

                    if ([string]::IsNullOrEmpty($refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value) -eq $false) {
                        # An additional read-only account/group is specified
                        $boolAdditionalReadOnlyAccountInheritableACENeedsToBeApplied = $true
                    } else {
                        # An additional read-only account/group is not specified
                        $boolAdditionalReadOnlyAccountInheritableACENeedsToBeApplied = $false
                    }
                    $boolAdditionalReadOnlyAccountNonInheritableACENeedsToBeApplied = $false
                    #endregion This object is a folder and either it is not inheriting any permissions, or we are at the root of the process
                } else {
                    #region This object is a folder that is inheriting permissions and we are not at the root of the process
                    $boolBuiltInAdministratorsInheritableACENeedsToBeApplied = $false
                    $boolSYSTEMInheritableACENeedsToBeApplied = $false
                    $boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied = $false
                    $boolAdditionalAdministratorAccountNonInheritableACENeedsToBeApplied = $false
                    $boolAdditionalReadOnlyAccountInheritableACENeedsToBeApplied = $false
                    $boolAdditionalReadOnlyAccountNonInheritableACENeedsToBeApplied = $false
                    #endregion This object is a folder that is inheriting permissions and we are not at the root of the process
                }
            } else {
                #region This object is a file
                $boolBuiltInAdministratorsInheritableACENeedsToBeApplied = $false
                $boolSYSTEMInheritableACENeedsToBeApplied = $false
                $boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied = $false

                $boolAdditionalAdministratorAccountNonInheritableACENeedsToBeApplied = $false
                if ([string]::IsNullOrEmpty($refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value) -eq $false) {
                    if ($boolPermissionsNotInherited -or ($RecursionDepth -eq 0)) {
                        # This object is a file and either it is not inheriting any permissions, or we are at the root of the process
                        $boolAdditionalAdministratorAccountNonInheritableACENeedsToBeApplied = $true
                    }
                }

                $boolAdditionalReadOnlyAccountInheritableACENeedsToBeApplied = $false

                $boolAdditionalReadOnlyAccountNonInheritableACENeedsToBeApplied = $false
                if ([string]::IsNullOrEmpty($refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value) -eq $false) {
                    if ($boolPermissionsNotInherited -or ($RecursionDepth -eq 0)) {
                        # This object is a file and either it is not inheriting any permissions, or we are at the root of the process
                        $boolAdditionalReadOnlyAccountNonInheritableACENeedsToBeApplied = $true
                    }
                }
                #endregion This object is a file
            }
            $boolBuiltInAdministratorsNonInheritedNonInheritableACEFound = $false
            $boolSYSTEMNonInheritedNonInheritableACEFound = $false
            $boolAdditionalAdministratorAccountNonInheritedNonInheritableACEFound = $false
            $boolAdditionalReadOnlyAccountNonInheritedNonInheritableACEFound = $false
            $intExistingReadOnlyAccountNonInheritedNonInheritableFileSystemRights = 0
            #endregion Initialize action tags for each type of ACE ########################

            #region Look for ACEs that need to be removed, or that already exist (and don't need to be added)
            for ($intCounterA = 0; $intCounterA -lt $intNumberOfItems; $intCounterA++) {
                #region Looping through each ACE in the ACL ############################
                if (($arrWorkingACEs[$intCounterA]).IsInherited -eq $false) {
                    #region Current ACE is not inherited ###############################
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Found non-inherited ACE in path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".'
                    } else {
                        $strMessage = 'Found non-inherited ACE in path "' + $WorkingPath + '". AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".'
                    }
                    Write-Debug -Message $strMessage
                    if ($null -ne ($arrWorkingACEs[$intCounterA]).IdentityReference) {
                        #region Non-inherited ACE has an IdentityReference #############
                        if (($arrWorkingACEs[$intCounterA]).IdentityReference.GetType().Name -eq 'SecurityIdentifier') {
                            #region Non-inherited ACE is a SID #########################
                            if ($boolRemoveUnresolvedSIDs -eq $true) {
                                #region Non-inherited ACE is a SID and the function is set to remove unresolved SIDs
                                if (($ReferenceToHashtableOfKnownSIDs.Value).ContainsKey(($arrWorkingACEs[$intCounterA]).IdentityReference.Value) -eq $true) {
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = '...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because it is associated with a known SID. Is the connection to the domain down?'
                                    } else {
                                        $strMessage = '...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" because it is associated with a known SID. Is the connection to the domain down?'
                                    }
                                    Write-Warning -Message $strMessage
                                } else {
                                    #region Non-inherited ACE is a SID, the function is configured to remove unresolved SIDs, and we confirmed that this SID is not on the protected list - so we will remove it
                                    if ($arrACETracking[$intCounterA] -eq $true) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") that was already been used in an operation.'
                                        } else {
                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" that was already been used in an operation.'
                                        }
                                        Write-Warning -Message $strMessage
                                    }
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'Removing unresolved SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                    } else {
                                        $strMessage = 'Removing unresolved SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '".'
                                    }
                                    Write-Verbose -Message $strMessage
                                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]($arrWorkingACEs[$intCounterA]))
                                    if ($boolSuccess -eq $false) {
                                        #region Access rule removal failed #############
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'The unresolved SID (' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ') was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (.NET call failed).'
                                        } else {
                                            $strMessage = 'The unresolved SID (' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ') was not removed from path "' + $WorkingPath + '" (.NET call failed).'
                                        }
                                        Write-Warning -Message $strMessage
                                        #endregion Access rule removal failed #############
                                    } else {
                                        #region Access rule removal was successful #####
                                        $arrACETracking[$intCounterA] = $true
                                        # Test to see if permissions were removed by comparing the ACE count
                                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                                            #region Permissions confirmed removed based on change in ACE count
                                            Write-Debug -Message ('...the unresolved SID was removed...')
                                            $intLastNumberOfItems = $intCurrentNumberOfItems
                                            $boolACLChangeMade = $true
                                            #endregion Permissions confirmed removed based on change in ACE count
                                        } else {
                                            #region Based on no change in ACE count, permissions were not removed
                                            if ($WorkingPath -ne $refToRealPath.Value) {
                                                $strMessage = 'The unresolved SID (' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ') was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (ACE count did not change as expected after removal).'
                                            } else {
                                                $strMessage = 'The unresolved SID (' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ') was not removed from path "' + $WorkingPath + '" (ACE count did not change as expected after removal).'
                                            }
                                            Write-Warning -Message $strMessage
                                            #endregion Based on no change in ACE count, permissions were not removed
                                        }
                                        #endregion Access rule removal was successful #####
                                    }
                                    #endregion Non-inherited ACE is a SID, the function is configured to remove unresolved SIDs, and we confirmed that this SID is not on the protected list - so we will remove it
                                }
                                #endregion Non-inherited ACE is a SID and the function is set to remove unresolved SIDs
                            }
                            #endregion Non-inherited ACE is a SID #########################
                        } elseif (Test-ValidSID ([ref](($arrWorkingACEs[$intCounterA]).IdentityReference))) {
                            #region Non-inherited ACE is a SID (string) ################
                            if ($boolRemoveUnresolvedSIDs -eq $true) {
                                #region Non-inherited ACE is a SID and the function is set to remove unresolved SIDs
                                if (($ReferenceToHashtableOfKnownSIDs.Value).ContainsKey(($arrWorkingACEs[$intCounterA]).IdentityReference.Value) -eq $true) {
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = '...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because it is associated with a known SID. Is the connection to the domain down?'
                                    } else {
                                        $strMessage = '...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" because it is associated with a known SID. Is the connection to the domain down?'
                                    }
                                    Write-Warning -Message $strMessage
                                } else {
                                    #region Non-inherited ACE Is a SID, the function is set to remove unresolved SIDs, and the SID is not on the protected SID list - so we will remove it
                                    if ($arrACETracking[$intCounterA] -eq $true) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") that was already been used in an operation.'
                                        } else {
                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" that was already been used in an operation.'
                                        }
                                        Write-Warning -Message $strMessage
                                    }
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'Removing unresolved SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                    } else {
                                        $strMessage = 'Removing unresolved SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '".'
                                    }
                                    Write-Verbose -Message $strMessage
                                    $SID = New-Object System.Security.Principal.SecurityIdentifier(($arrWorkingACEs[$intCounterA]).IdentityReference.Value)
                                    $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                    $inheritanceFlags = ($arrWorkingACEs[$intCounterA]).InheritanceFlags
                                    $propagationFlags = ($arrWorkingACEs[$intCounterA]).PropagationFlags
                                    $accessControlType = ($arrWorkingACEs[$intCounterA]).AccessControlType
                                    $fileSystemAccessRuleOld = $objThisObjectPermission.AccessRuleFactory($SID, $intFileSystemRights, $false, $inheritanceFlags, $propagationFlags, $accessControlType)
                                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]($fileSystemAccessRuleOld))
                                    if ($boolSuccess -eq $false) {
                                        #region Access rule removal failed #########
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'The unresolved SID (' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ') was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (.NET call failed).'
                                        } else {
                                            $strMessage = 'The unresolved SID (' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ') was not removed from path "' + $WorkingPath + '" (.NET call failed).'
                                        }
                                        Write-Warning -Message $strMessage
                                        #endregion Access rule removal failed #########
                                    } else {
                                        #region Access rule removal was successful #
                                        $arrACETracking[$intCounterA] = $true
                                        # Test to see if permissions were removed by comparing the ACE count
                                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                                            #region Permissions confirmed removed based on change in ACE count
                                            Write-Debug -Message ('...the unresolved SID was removed...')
                                            $intLastNumberOfItems = $intCurrentNumberOfItems
                                            $boolACLChangeMade = $true
                                            #endregion Permissions confirmed removed based on change in ACE count
                                        } else {
                                            #region Based on no change in ACE count, permissions were not removed
                                            if ($WorkingPath -ne $refToRealPath.Value) {
                                                $strMessage = 'The unresolved SID (' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ') was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (ACE count did not change as expected after removal).'
                                            } else {
                                                $strMessage = 'The unresolved SID (' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ') was not removed from path "' + $WorkingPath + '" (ACE count did not change as expected after removal).'
                                            }
                                            Write-Warning -Message $strMessage
                                            #endregion Based on no change in ACE count, permissions were not removed
                                        }
                                        #endregion Access rule removal was successful #
                                    }
                                    #endregion Non-inherited ACE Is a SID, the function is set to remove unresolved SIDs, and the SID is not on the protected SID list - so we will remove it
                                }
                                #endregion Non-inherited ACE is a SID and the function is set to remove unresolved SIDs
                            }
                            #endregion Non-inherited ACE is a SID (string) ################
                        } else {
                            #region Non-inherited ACE is presumably an NTAccount #######
                            # See:
                            # https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.identityreference?view=net-7.0

                            if (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value) {
                                #region Found a non-inherited ACE for the Built-In Administrators group
                                if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                    #region Found a non-inherited deny ACE for the built-in Administrators group
                                    if ($arrACETracking[$intCounterA] -eq $true) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") that was already been used in an operation.'
                                        } else {
                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" that was already been used in an operation.'
                                        }
                                        Write-Warning -Message $strMessage
                                    }
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'Removing deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                    } else {
                                        $strMessage = 'Removing deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '".'
                                    }
                                    Write-Verbose -Message $strMessage
                                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]($arrWorkingACEs[$intCounterA]))
                                    if ($boolSuccess -eq $false) {
                                        #region Access rule removal failed #############
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (.NET call failed).'
                                        } else {
                                            $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (.NET call failed).'
                                        }
                                        Write-Warning -Message $strMessage
                                        #endregion Access rule removal failed #############
                                    } else {
                                        #region Access rule removal was successful #####
                                        $arrACETracking[$intCounterA] = $true
                                        # Test to see if permissions were removed by comparing the ACE count
                                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                                            #region Permissions confirmed removed based on change in ACE count
                                            Write-Debug -Message ('...the deny permission was removed...')
                                            $intLastNumberOfItems = $intCurrentNumberOfItems
                                            $boolACLChangeMade = $true
                                            #endregion Permissions confirmed removed based on change in ACE count
                                        } else {
                                            #region Based on no change in ACE count, permissions were not removed
                                            if ($WorkingPath -ne $refToRealPath.Value) {
                                                $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (ACE count did not change as expected after removal).'
                                            } else {
                                                $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (ACE count did not change as expected after removal).'
                                            }
                                            Write-Warning -Message $strMessage
                                            #endregion Based on no change in ACE count, permissions were not removed
                                        }
                                        #endregion Access rule removal was successful #####
                                    }
                                    #endregion Found a non-inherited deny ACE for the built-in Administrators group
                                } else {
                                    #region Found a non-inherited allow ACE for the built-in Administrators group

                                    # We are not worried about built-in Administrators
                                    # group permissions on individual files because we've
                                    # already gone through and fixed them
                                    if ($objThis.PSIsContainer) {
                                        #region Found a non-inherited allow ACE for the built-in Administrators group on a folder object

                                        # For built-in administrators/SYSTEM, we only need
                                        # to examine ACEs again when no permissions are
                                        # inherited on this object, or when we are at the
                                        # root of the process. This is because our only
                                        # interest at the moment is determining if we need
                                        # to apply an inheritable ACE to this object, and
                                        # it's because we've already reviewed permissions
                                        # on a per-item basis
                                        if ($boolPermissionsNotInherited -or ($RecursionDepth -eq 0)) {
                                            #region Found a non-inherited allow ACE for the built-in Administrators group on a folder object and either no permissions on this folder are inherited, or we're at the root of the process
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                            if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                            } else {
                                                # See if the FileSystemRights is an integer value that
                                                # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                                $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                                if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                    $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                }
                                            }

                                            if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                #region Found a non-inherited allow ACE on a folder object that grants full control to the built-in Administrators group, and either no permissions on this object are inherited, or we're at the root of the process
                                                # Check inheritable ACE settings
                                                $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                                $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                    $boolBuiltInAdministratorsInheritableACENeedsToBeApplied = $false
                                                } else {
                                                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                                                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                    if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                        $boolBuiltInAdministratorsNonInheritedNonInheritableACEFound = $true
                                                    }
                                                }
                                                #endregion Found a non-inherited allow ACE on a folder object that grants full control to the built-in Administrators group, and either no permissions on this object are inherited, or we're at the root of the process
                                            }
                                            #endregion Found a non-inherited allow ACE for the built-in Administrators group on a folder object and either no permissions on this folder are inherited, or we're at the root of the process
                                        }
                                        # We don't care about file objects because they
                                        # have already been addressed; see comment above
                                        # the region start
                                        #endregion Found a non-inherited allow ACE for the built-in Administrators group on a folder object
                                    }
                                    #endregion Found a non-inherited allow ACE for the built-in Administrators group
                                }
                                #endregion Found a non-inherited ACE for the Built-In Administrators group
                            } elseif (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfSYSTEMAccountAccordingToGetAcl.Value) {
                                #region Found a non-inherited ACE for the SYSTEM account
                                if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                    #region Found a non-inherited deny ACE for the SYSTEM account
                                    if ($arrACETracking[$intCounterA] -eq $true) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") that was already been used in an operation.'
                                        } else {
                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" that was already been used in an operation.'
                                        }
                                        Write-Warning -Message $strMessage
                                    }
                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                        $strMessage = 'Removing deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                    } else {
                                        $strMessage = 'Removing deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '".'
                                    }
                                    Write-Verbose -Message $strMessage
                                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]($arrWorkingACEs[$intCounterA]))
                                    if ($boolSuccess -eq $false) {
                                        #region Access rule removal failed #############
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (.NET call failed).'
                                        } else {
                                            $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (.NET call failed).'
                                        }
                                        Write-Warning -Message $strMessage
                                        #endregion Access rule removal failed #############
                                    } else {
                                        #region Access rule removal was successful #####
                                        $arrACETracking[$intCounterA] = $true
                                        # Test to see if permissions were removed by comparing the ACE count
                                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                                            #region Permissions confirmed removed based on change in ACE count
                                            Write-Debug -Message ('...the deny permission was removed...')
                                            $intLastNumberOfItems = $intCurrentNumberOfItems
                                            $boolACLChangeMade = $true
                                            #endregion Permissions confirmed removed based on change in ACE count
                                        } else {
                                            #region Based on no change in ACE count, permissions were not removed
                                            if ($WorkingPath -ne $refToRealPath.Value) {
                                                $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (ACE count did not change as expected after removal).'
                                            } else {
                                                $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (ACE count did not change as expected after removal).'
                                            }
                                            Write-Warning -Message $strMessage
                                            #endregion Based on no change in ACE count, permissions were not removed
                                        }
                                        #endregion Access rule removal was successful #####
                                    }
                                    #endregion Found a non-inherited deny ACE for the SYSTEM account
                                } else {
                                    #region Found a non-inherited allow ACE for the SYSTEM account

                                    # We are not worried about the SYSTEM account
                                    # permissions on individual files because we've already
                                    # gone through and fixed them
                                    if ($objThis.PSIsContainer) {
                                        #region Found a non-inherited allow ACE for the SYSTEM account on a folder object

                                        # For built-in administrators/SYSTEM, we only need
                                        # to examine ACEs again when no permissions are
                                        # inherited on this object, or when we are at the
                                        # root of the process. This is because our only
                                        # interest at the moment is determining if we need
                                        # to apply an inheritable ACE to this object, and
                                        # it's because we've already reviewed permissions
                                        # on a per-item basis
                                        if ($boolPermissionsNotInherited -or ($RecursionDepth -eq 0)) {
                                            #region Found a non-inherited allow ACE for the SYSTEM account on a folder object and either no permissions on this folder are inherited, or we're at the root of the process
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                            if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                            } else {
                                                # See if the FileSystemRights is an integer value that
                                                # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                                $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                                if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                    $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                }
                                            }

                                            if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                #region Found a non-inherited allow ACE on a folder object that grants full control to the SYSTEM account, and either no permissions on this object are inherited, or we're at the root of the process
                                                # Check inheritable ACE settings
                                                $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                                $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                    $boolSYSTEMInheritableACENeedsToBeApplied = $false
                                                } else {
                                                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                                                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                    if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                        $boolSYSTEMNonInheritedNonInheritableACEFound = $true
                                                    }
                                                }
                                                #endregion Found a non-inherited allow ACE on a folder object that grants full control to the SYSTEM account, and either no permissions on this object are inherited, or we're at the root of the process
                                            }
                                            #endregion Found a non-inherited allow ACE for the SYSTEM account on a folder object and either no permissions on this folder are inherited, or we're at the root of the process
                                        }
                                        # We don't care about file objects because they
                                        # have already been addressed; see comment above
                                        # the region start
                                        #endregion Found a non-inherited allow ACE for the SYSTEM account on a folder object
                                    }
                                    #endregion Found a non-inherited allow ACE for the SYSTEM account
                                }
                                #endregion Found a non-inherited ACE for the SYSTEM account
                            } else {
                                # check additional accounts
                                $boolFoundGroup = $false

                                if ($boolFoundGroup -eq $false) {
                                    if ([string]::IsNullOrEmpty($refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value) -eq $false) {
                                        #region We're working on a non-inherited ACE and an additional administrator account/group is specified
                                        if (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value) {
                                            #region Found a non-inherited ACE for the additional administrator account/group
                                            $boolFoundGroup = $true
                                            if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                                #region Found a non-inherited deny ACE for the additional administrator account/group
                                                if ($arrACETracking[$intCounterA] -eq $true) {
                                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                                        $strMessage = 'Removing ACE from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") that was already been used in an operation.'
                                                    } else {
                                                        $strMessage = 'Removing ACE from path "' + $WorkingPath + '" that was already been used in an operation.'
                                                    }
                                                    Write-Warning -Message $strMessage
                                                }
                                                if ($WorkingPath -ne $refToRealPath.Value) {
                                                    $strMessage = 'Removing deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                                } else {
                                                    $strMessage = 'Removing deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '".'
                                                }
                                                Write-Verbose -Message $strMessage
                                                $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]($arrWorkingACEs[$intCounterA]))
                                                if ($boolSuccess -eq $false) {
                                                    #region Access rule removal failed #############
                                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                                        $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (.NET call failed).'
                                                    } else {
                                                        $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (.NET call failed).'
                                                    }
                                                    Write-Warning -Message $strMessage
                                                    #endregion Access rule removal failed #############
                                                } else {
                                                    #region Access rule removal was successful #####
                                                    $arrACETracking[$intCounterA] = $true
                                                    # Test to see if permissions were removed by comparing the ACE count
                                                    $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                                                    if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                                                        #region Permissions confirmed removed based on change in ACE count
                                                        Write-Debug -Message ('...the deny permission was removed...')
                                                        $intLastNumberOfItems = $intCurrentNumberOfItems
                                                        $boolACLChangeMade = $true
                                                        #endregion Permissions confirmed removed based on change in ACE count
                                                    } else {
                                                        #region Based on no change in ACE count, permissions were not removed
                                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                                            $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (ACE count did not change as expected after removal).'
                                                        } else {
                                                            $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (ACE count did not change as expected after removal).'
                                                        }
                                                        Write-Warning -Message $strMessage
                                                        #endregion Based on no change in ACE count, permissions were not removed
                                                    }
                                                    #endregion Access rule removal was successful #####
                                                }
                                                #endregion Found a non-inherited deny ACE for the additional administrator account/group
                                            } else {
                                                #region Found a non-inherited allow ACE for the additional administrator account/group
                                                if ($objThis.PSIsContainer) {
                                                    #region Found a non-inherited allow ACE for the additional administrator account/group on a folder object
                                                    if ($boolPermissionsNotInherited -or ($RecursionDepth -eq 0)) {
                                                        #region Found a non-inherited allow ACE for the additional administrator account/group on a folder object and either no permissions on this folder are inherited, or we're at the root of the process
                                                        $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                                        if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                                            $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                        } else {
                                                            # See if the FileSystemRights is an integer value that
                                                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                                            $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                            }
                                                        }

                                                        if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                            #region Found a non-inherited allow ACE on a folder object that grants full control to the additional administrator account/group, and either no permissions on this object are inherited, or we're at the root of the process
                                                            # Check inheritable ACE settings
                                                            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                                            $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                            if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                                $boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied = $false
                                                            } else {
                                                                $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                                                                $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                                if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                                    $boolAdditionalAdministratorAccountNonInheritedNonInheritableACEFound = $true
                                                                }
                                                            }
                                                            #endregion Found a non-inherited allow ACE on a folder object that grants full control to the additional administrator account/group, and either no permissions on this object are inherited, or we're at the root of the process
                                                        }
                                                        #endregion Found a non-inherited allow ACE for the additional administrator account/group on a folder object and either no permissions on this folder are inherited, or we're at the root of the process
                                                    } else {
                                                        #region Found a non-inherited allow ACE for the additional administrator account/group on a folder object with inherited permissions that is not at the root of the process
                                                        # We don't care about folder
                                                        # objects where the permissions on
                                                        # the folder are inherited and
                                                        # we're not at the root of the
                                                        # process; as we continue to work
                                                        # upstream (through parent
                                                        # folders), this object will get
                                                        # the required account permission
                                                        # assigned
                                                        #
                                                        # In this case, we do not want to
                                                        # create an ACE. But this is
                                                        # already set above
                                                        #endregion Found a non-inherited allow ACE for the additional administrator account/group on a folder object with inherited permissions that is not at the root of the process
                                                    }

                                                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                                                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                    if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                        $boolAdditionalAdministratorAccountNonInheritedNonInheritableACEFound = $true
                                                    }
                                                    #endregion Found a non-inherited allow ACE for the additional administrator account/group on a folder object
                                                } else {
                                                    #region Found a non-inherited allow ACE for the additional administrator account/group on a file object
                                                    $boolThisACEHasTheRequiredAmountOfPermissions = $false
                                                    if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                                        $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                    } else {
                                                        # See if the FileSystemRights is an integer value that
                                                        # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                                        $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                                        if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                            $boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied = $false
                                                        }
                                                    }
                                                    if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                        #region Found a non-inherited allow ACE on a file object that grants full control to the additional administrator account/group
                                                        $boolAdditionalAdministratorAccountNonInheritableACENeedsToBeApplied = $false
                                                        #endregion Found a non-inherited allow ACE on a folder object that grants full control to the additional administrator account/group
                                                    }
                                                    #endregion Found a non-inherited allow ACE for the additional administrator account/group on a file object
                                                }
                                                #endregion Found a non-inherited allow ACE for the additional administrator account/group
                                            }
                                            #endregion Found a non-inherited ACE for the additional administrator account/group
                                        }
                                        #endregion We're working on a non-inherited ACE and an additional administrator account/group is specified
                                    }
                                }

                                if ($boolFoundGroup -eq $false) {
                                    if ([string]::IsNullOrEmpty($refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value) -eq $false) {
                                        #region We're working on a non-inherited ACE and an additional read-only account/group is specified
                                        if (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value) {
                                            #region Found a non-inherited ACE for the additional read-only account/group
                                            $boolFoundGroup = $true

                                            #region Check for minimum-required level of permissions
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $false
                                            $intPermissionsThatExceedRequiredAmountOfPermissions = 0
                                            # Check for read & execute permissions:

                                            # There are three ways to have this. The
                                            # first is
                                            # [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                                            #
                                            # The second is
                                            # [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                                            # +
                                            # [System.Security.AccessControl.FileSystemRights]::Synchronize)
                                            #
                                            # The third is to have
                                            # GENERIC_EXECUTE (536870912 or
                                            # 0x20000000) + GENERIC_READ
                                            # (-2147483648 or 0x80000000)
                                            #
                                            # First, check for GENERIC_ALL
                                            # (268435456 or 0x1000000), which is
                                            # not part of
                                            # [System.Security.AccessControl.FileSystemRights]
                                            $intFileSystemRights = 268435456
                                            if ((($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights) -eq $intFileSystemRights) {
                                                #region GENERIC_ALL permission found
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                # In this case, the permissions that
                                                # exceed (GENERIC_EXECUTE +
                                                # GENERIC_READ) are GENERIC_WRITE
                                                # (1073741824 or 0x40000000)
                                                #
                                                # But we should check for any other
                                                # permissions first:
                                                $intFileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
                                                # First calculate any permissions in
                                                # excess of ReadAndExecute +
                                                # Synchronize:
                                                $intPermissionsThatExceedRequiredAmountOfPermissions = ($arrWorkingACEs[$intCounterA]).FileSystemRights - (($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights)
                                                # Add GENERIC_WRITE:
                                                $intPermissionsThatExceedRequiredAmountOfPermissions += 1073741824
                                                #endregion GENERIC_ALL permission found
                                            } else {
                                                #region No GENERIC_ALL permission found
                                                # Try plain ol' ReadAndExecute
                                                # first
                                                $intFileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                                                if ((($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights) -eq $intFileSystemRights) {
                                                    $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                }

                                                # Try ReadAndExecute + Synchronize
                                                # next
                                                if (-not $boolThisACEHasTheRequiredAmountOfPermissions) {
                                                    $intFileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
                                                    if ((($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights) -eq $intFileSystemRights) {
                                                        $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                    }
                                                }

                                                # Try GENERIC_EXECUTE (536870912 or
                                                # 0x20000000) and GENERIC_READ
                                                # (-2147483648 or 0x80000000) next
                                                if (-not $boolThisACEHasTheRequiredAmountOfPermissions) {
                                                    $intFileSystemRights = 536870912 + -2147483648
                                                    if ((($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights) -eq $intFileSystemRights) {
                                                        $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                    }
                                                }

                                                # Next, regardless of how read &
                                                # execute permissions were applied, we
                                                # need to calculate whether any
                                                # permissions are in excess of read &
                                                # execute:
                                                if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                    # Calculate permissions that are in excess of read and execute:
                                                    $intFileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize -bor 536870912 -bor -2147483648
                                                    $intPermissionsThatExceedRequiredAmountOfPermissions = ($arrWorkingACEs[$intCounterA]).FileSystemRights - (($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights)
                                                }
                                                #endregion No GENERIC_ALL permission found
                                            }
                                            #endregion Check for minimum-required level of permissions

                                            if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                #region Found a non-inherited ACE with at least read & execute permissions for the additional read-only account/group
                                                if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                                    #region Found a non-inherited deny ACE with at least read & execute permissions for the additional read-only account/group
                                                    if ($arrACETracking[$intCounterA] -eq $true) {
                                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") that was already been used in an operation.'
                                                        } else {
                                                            $strMessage = 'Removing ACE from path "' + $WorkingPath + '" that was already been used in an operation.'
                                                        }
                                                        Write-Warning -Message $strMessage
                                                    }
                                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                                        $strMessage = 'Removing deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                                    } else {
                                                        $strMessage = 'Removing deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '".'
                                                    }
                                                    Write-Verbose -Message $strMessage
                                                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]($arrWorkingACEs[$intCounterA]))
                                                    if ($boolSuccess -eq $false) {
                                                        #region Access rule removal failed #############
                                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                                            $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (.NET call failed).'
                                                        } else {
                                                            $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (.NET call failed).'
                                                        }
                                                        Write-Warning -Message $strMessage
                                                        #endregion Access rule removal failed #############
                                                    } else {
                                                        #region Access rule removal was successful #####
                                                        $arrACETracking[$intCounterA] = $true
                                                        # Test to see if permissions were removed by comparing the ACE count
                                                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                                                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                                                            #region Permissions confirmed removed based on change in ACE count
                                                            Write-Debug -Message ('...the deny permission was removed...')
                                                            $intLastNumberOfItems = $intCurrentNumberOfItems
                                                            $boolACLChangeMade = $true
                                                            #endregion Permissions confirmed removed based on change in ACE count
                                                        } else {
                                                            #region Based on no change in ACE count, permissions were not removed
                                                            if ($WorkingPath -ne $refToRealPath.Value) {
                                                                $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") (ACE count did not change as expected after removal).'
                                                            } else {
                                                                $strMessage = 'The deny ACE for ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' was not removed from path "' + $WorkingPath + '" (ACE count did not change as expected after removal).'
                                                            }
                                                            Write-Warning -Message $strMessage
                                                            #endregion Based on no change in ACE count, permissions were not removed
                                                        }
                                                        #endregion Access rule removal was successful #####
                                                    }
                                                    #endregion Found a non-inherited deny ACE with at least read & execute permissions for the additional read-only account/group
                                                } else {
                                                    #region Found a non-inherited allow ACE with at least read & execute permissions for the additional read-only account/group
                                                    # Does it have excess permissions?
                                                    # If so, write a warning.
                                                    if ($intPermissionsThatExceedRequiredAmountOfPermissions -ne 0) {
                                                        #region Found a non-inherited allow ACE with permissions that exceed read & execute for the additional read-only account/group
                                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                                            $strMessage = 'An ACE was found at the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") that grants more permissions than necessary to the account "' + $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value + '". The permissions that exceed Read & Execute are: ' + $intPermissionsThatExceedRequiredAmountOfPermissions
                                                        } else {
                                                            $strMessage = 'An ACE was found at the path "' + $WorkingPath + '" that grants more permissions than necessary to the account "' + $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value + '". The permissions that exceed Read & Execute are: ' + $intPermissionsThatExceedRequiredAmountOfPermissions
                                                        }
                                                        Write-Warning -Message $strMessage
                                                        #endregion Found a non-inherited allow ACE with permissions that exceed read & execute for the additional read-only account/group
                                                    }

                                                    # Check to see if the folder/file
                                                    # has inheritance broken (across
                                                    # all ACEs, not just this one) - or
                                                    # check to see if we are at the
                                                    # root of the process
                                                    if ($boolPermissionsNotInherited -or ($RecursionDepth -eq 0)) {
                                                        #region Found a non-inherited allow ACE with at least read & execute permissions for the additional read-only account/group and either no permissions on this folder are inherited, or we're at the root of the process
                                                        if ($objThis.PSIsContainer) {
                                                            #region Found a non-inherited allow ACE on a folder with at least read & execute permissions for the additional read-only account/group and either no permissions on this folder are inherited, or we're at the root of the process
                                                            # Check inheritable ACE
                                                            # settings
                                                            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                                            $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                            if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                                $boolAdditionalReadOnlyAccountInheritableACENeedsToBeApplied = $false
                                                            }
                                                            #endregion Found a non-inherited allow ACE on a folder with at least read & execute permissions for the additional read-only account/group and either no permissions on this folder are inherited, or we're at the root of the process
                                                        } else {
                                                            #region Found a non-inherited allow ACE on a file with at least read & execute permissions for the additional read-only account/group and either no permissions on this folder are inherited, or we're at the root of the process
                                                            $boolAdditionalReadOnlyAccountNonInheritableACENeedsToBeApplied = $false
                                                            #endregion Found a non-inherited allow ACE on a file with at least read & execute permissions for the additional read-only account/group and either no permissions on this folder are inherited, or we're at the root of the process
                                                        }
                                                        #endregion Found a non-inherited allow ACE with at least read & execute permissions for the additional read-only account/group and either no permissions on this folder are inherited, or we're at the root of the process
                                                    } else {
                                                        #region Found a non-inherited allow ACE with at least read & execute permissions for the additional read-only account/group, permissions on this folder are inherited, and we're not at the root of the process
                                                        # In this case, we do not want to
                                                        # create an ACE. But this is
                                                        # already set above
                                                        #endregion Found a non-inherited allow ACE with at least read & execute permissions for the additional read-only account/group, permissions on this folder are inherited, and we're not at the root of the process
                                                    }

                                                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                                                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                    if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                        $intExistingReadOnlyAccountNonInheritedNonInheritableFileSystemRights = ($arrWorkingACEs[$intCounterA]).FileSystemRights
                                                        $boolAdditionalReadOnlyAccountNonInheritedNonInheritableACEFound = $true
                                                    }
                                                    #endregion Found a non-inherited allow ACE with at least read & execute permissions for the additional read-only account/group
                                                }
                                                #endregion Found a non-inherited ACE with at least read & execute permissions for the additional read-only account/group
                                            }
                                            #endregion Found a non-inherited ACE for the additional read-only account/group
                                        }
                                        #endregion We're working on a non-inherited ACE and an additional read-only account/group is specified
                                    }
                                }
                            }
                            #endregion Non-inherited ACE is presumably an NTAccount #######
                        }
                        #endregion Non-inherited ACE has an IdentityReference #############
                    }
                    #endregion Current ACE is not inherited ###############################
                } else {
                    #region Current ACE is inherited ###################################
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Found inherited ACE in path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".'
                    } else {
                        $strMessage = 'Found inherited ACE in path "' + $WorkingPath + '". AccessControlType="' + ($arrWorkingACEs[$intCounterA]).AccessControlType + '"; IdentityReference="' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '"; FileSystemRights="' + ($arrWorkingACEs[$intCounterA]).FileSystemRights + '"; InheritanceFlags="' + ($arrWorkingACEs[$intCounterA]).InheritanceFlags + '"; PropagationFlags="' + ($arrWorkingACEs[$intCounterA]).PropagationFlags + '".'
                    }
                    Write-Debug -Message $strMessage
                    if ($null -ne ($arrWorkingACEs[$intCounterA]).IdentityReference) {
                        #region Inherited ACE has an IdentityReference #################
                        if (($arrWorkingACEs[$intCounterA]).IdentityReference.GetType().Name -eq 'SecurityIdentifier') {
                            #region Inherited ACE is a SID #############################
                            if ($RecursionDepth -eq 0) {
                                #region At the root of the process; inherited ACE is a SID
                                if ($boolRemoveUnresolvedSIDs -eq $true) {
                                    #region At the root of the process; inherited ACE is a SID and the function is set to remove unresolved SIDs
                                    if (($ReferenceToHashtableOfKnownSIDs.Value).ContainsKey(($arrWorkingACEs[$intCounterA]).IdentityReference.Value) -eq $true) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = '...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because it is associated with a known SID. Is the connection to the domain down?'
                                        } else {
                                            $strMessage = '...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" because it is associated with a known SID. Is the connection to the domain down?'
                                        }
                                        Write-Warning -Message $strMessage
                                    } else {
                                        #region At the root of the process; inherited ACE is a SID, the function is configured to remove unresolved SIDs, and we confirmed that this SID is not on the protected list - so we would theoretically want to remove it
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Unresolved SID ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' found at the root path of the permission repair process cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the unresolved SID. Root path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                        } else {
                                            $strMessage = 'Unresolved SID ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' found at the root path of the permission repair process cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the unresolved SID. Root path is "' + $WorkingPath + '".'
                                        }
                                        Write-Warning -Message $strMessage
                                        #endregion At the root of the process; inherited ACE is a SID, the function is configured to remove unresolved SIDs, and we confirmed that this SID is not on the protected list - so we would theoretically want to remove it
                                    }
                                    #endregion At the root of the process; inherited ACE is a SID and the function is set to remove unresolved SIDs
                                }
                                #endregion At the root of the process; inherited ACE is a SID
                            }
                            #endregion Inherited ACE is a SID #############################
                        } elseif (Test-ValidSID ([ref](($arrWorkingACEs[$intCounterA]).IdentityReference))) {
                            #region Inherited ACE is a SID (string) ####################
                            if ($RecursionDepth -eq 0) {
                                #region At the root of the process; inherited ACE is a SID (string)
                                if ($boolRemoveUnresolvedSIDs -eq $true) {
                                    #region At the root of the process; inherited ACE is a SID and the function is set to remove unresolved SIDs
                                    if (($ReferenceToHashtableOfKnownSIDs.Value).ContainsKey(($arrWorkingACEs[$intCounterA]).IdentityReference.Value) -eq $true) {
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = '...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") because it is associated with a known SID. Is the connection to the domain down?'
                                        } else {
                                            $strMessage = '...not removing SID "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" from path "' + $WorkingPath + '" because it is associated with a known SID. Is the connection to the domain down?'
                                        }
                                        Write-Warning -Message $strMessage
                                    } else {
                                        #region At the root of the process; inherited ACE Is a SID, the function is set to remove unresolved SIDs, and the SID is not on the protected SID list - so we would theoretically want to remove it
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Unresolved SID ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' found at the root path of the permission repair process cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the unresolved SID. Root path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                        } else {
                                            $strMessage = 'Unresolved SID ' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + ' found at the root path of the permission repair process cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the unresolved SID. Root path is "' + $WorkingPath + '".'
                                        }
                                        Write-Warning -Message $strMessage
                                        #endregion At the root of the process; inherited ACE Is a SID, the function is set to remove unresolved SIDs, and the SID is not on the protected SID list - so we would theoretically want to remove it
                                    }
                                    #endregion At the root of the process; inherited ACE is a SID and the function is set to remove unresolved SIDs
                                }
                                #endregion At the root of the process; inherited ACE is a SID (string)
                            }
                            #endregion Inherited ACE is a SID (string) ####################
                        } else {
                            #region Inherited ACE is presumably an NTAccount ###########
                            # See:
                            # https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.identityreference?view=net-7.0

                            if (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value) {
                                #region Found an inherited ACE for the built-in Administrators group
                                if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                    #region Found an inherited deny ACE for the built-in Administrators group
                                    if ($RecursionDepth -eq 0) {
                                        #region At the root of the process, found an inherited deny ACE for the built-in Administrators group
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Found a deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" at the root of the permissions repair process that cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the deny permission. Root path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                        } else {
                                            $strMessage = 'Found a deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" at the root of the permissions repair process that cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the deny permission. Root path is "' + $WorkingPath + '".'
                                        }
                                        Write-Warning -Message $strMessage
                                        #endregion At the root of the process, found an inherited deny ACE for the built-in Administrators group
                                    }
                                    #endregion Found an inherited deny ACE for the built-in Administrators group
                                } else {
                                    #region Found an inherited allow ACE for the built-in Administrators group

                                    # We are not worried about built-in Administrators
                                    # group "allow" permissions on individual files because
                                    # we've already gone through and fixed them
                                    if ($objThis.PSIsContainer) {
                                        #region Found an inherited allow ACE for the built-in Administrators group on a folder object
                                        $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                        if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                        } else {
                                            # See if the FileSystemRights is an integer value that
                                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                            $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                            }
                                        }

                                        if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                            #region Found an inherited allow ACE on a folder object that grants full control to the built-in Administrators group
                                            # Check inheritable ACE settings
                                            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                            $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                            if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                $boolBuiltInAdministratorsInheritableACENeedsToBeApplied = $false
                                            }
                                            #endregion Found an inherited allow ACE on a folder object that grants full control to the built-in Administrators group
                                        }
                                        # We don't care about file objects because they
                                        # have already been addressed; see comment above
                                        # the region start
                                        #endregion Found an inherited allow ACE for the built-in Administrators group on a folder object
                                    }
                                    #endregion Found an inherited allow ACE for the built-in Administrators group
                                }
                                #endregion Found an inherited ACE for the built-in Administrators group
                            } elseif (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfSYSTEMAccountAccordingToGetAcl.Value) {
                                #region Found an inherited ACE for the SYSTEM account ##
                                if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                    #region Found an inherited deny ACE for the SYSTEM account
                                    if ($RecursionDepth -eq 0) {
                                        #region At the root of the process, found an inherited deny ACE for the SYSTEM account
                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                            $strMessage = 'Found a deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" at the root of the permissions repair process that cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the deny permission. Root path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                        } else {
                                            $strMessage = 'Found a deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" at the root of the permissions repair process that cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the deny permission. Root path is "' + $WorkingPath + '".'
                                        }
                                        Write-Warning -Message $strMessage
                                        #endregion At the root of the process, found an inherited deny ACE for the SYSTEM account
                                    }
                                    #endregion Found an inherited deny ACE for the SYSTEM account
                                } else {
                                    #region Found an inherited allow ACE for the SYSTEM account

                                    # We are not worried about the SYSTEM account
                                    # permissions on individual files because we've
                                    # already gone through and fixed them
                                    if ($objThis.PSIsContainer) {
                                        #region Found an inherited allow ACE for the SYSTEM account on a folder object
                                        $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                        if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                        } else {
                                            # See if the FileSystemRights is an integer value that
                                            # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                            $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                            if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                            }
                                        }

                                        if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                            #region Found an inherited allow ACE on a folder object that grants full control to the SYSTEM account
                                            # Check inheritable ACE settings
                                            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                            $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                            if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                $boolSYSTEMInheritableACENeedsToBeApplied = $false
                                            }
                                            #endregion Found an inherited allow ACE on a folder object that grants full control to the SYSTEM account
                                        }
                                        # We don't care about file objects because they
                                        # have already been addressed; see comment above
                                        # the region start
                                        #endregion Found an inherited allow ACE for the SYSTEM account on a folder object
                                    }
                                    #endregion Found an inherited allow ACE for the SYSTEM account
                                }
                                #endregion Found an inherited ACE for the SYSTEM account ##
                            } else {
                                # check additional accounts
                                $boolFoundGroup = $false

                                if ($boolFoundGroup -eq $false) {
                                    if ([string]::IsNullOrEmpty($refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value) -eq $false) {
                                        #region We're working on an inherited ACE and an additional administrator account/group is specified
                                        if (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value) {
                                            #region We found an inherited ACE for the additional administrator account/group
                                            $boolFoundGroup = $true
                                            if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                                #region Found an inherited deny ACE for the additional administrator account/group
                                                if ($RecursionDepth -eq 0) {
                                                    #region At the root of the process, found an inherited deny ACE for the additional administrator account/group
                                                    if ($WorkingPath -ne $refToRealPath.Value) {
                                                        $strMessage = 'Found a deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" at the root of the permissions repair process that cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the deny permission. Root path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                                    } else {
                                                        $strMessage = 'Found a deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" at the root of the permissions repair process that cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the deny permission. Root path is "' + $WorkingPath + '".'
                                                    }
                                                    Write-Warning -Message $strMessage
                                                    #endregion At the root of the process, found an inherited deny ACE for the additional administrator account/group
                                                }
                                                #endregion Found an inherited deny ACE for the additional administrator account/group
                                            } else {
                                                #region Found an inherited allow ACE for the additional administrator account/group
                                                if ($objThis.PSIsContainer) {
                                                    #region Found an inherited allow ACE for the additional administrator account/group on a folder object
                                                    $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                                    if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                                        $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                    } else {
                                                        # See if the FileSystemRights is an integer value that
                                                        # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                                        $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                                        if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                            $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                        }
                                                    }

                                                    if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                        #region Found an inherited allow ACE on a folder object that grants full control to the additional administrator account/group
                                                        # Check inheritable ACE settings
                                                        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                                        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                        if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                            $boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied = $false
                                                        }
                                                        #endregion Found an inherited allow ACE on a folder object that grants full control to the additional administrator account/group
                                                    }
                                                    #endregion Found an inherited allow ACE for the additional administrator account/group on a folder object
                                                } else {
                                                    #region Found an inherited allow ACE for the additional administrator account/group on a file object
                                                    $boolThisACEHasTheRequiredAmountOfPermissions = $false

                                                    if (($arrWorkingACEs[$intCounterA]).FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                                        $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                    } else {
                                                        # See if the FileSystemRights is an integer value that
                                                        # includes FullControl (2032127) or GENERIC_ALL (268435456)
                                                        $intFileSystemRights = [int](($arrWorkingACEs[$intCounterA]).FileSystemRights)
                                                        if (($intFileSystemRights -band 2032127) -eq 2032127 -or ($intFileSystemRights -band 268435456) -eq 268435456) {
                                                            $boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied = $false
                                                        }
                                                    }

                                                    if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                        #region Found an inherited allow ACE on a file object that grants full control to the additional administrator account/group
                                                        $boolAdditionalAdministratorAccountNonInheritableACENeedsToBeApplied = $false
                                                        #endregion Found an inherited allow ACE on a file object that grants full control to the additional administrator account/group
                                                    }
                                                    #endregion Found an inherited allow ACE for the additional administrator account/group on a file object
                                                }
                                                #endregion Found an inherited allow ACE for the additional administrator account/group
                                            }
                                            #endregion We found an inherited ACE for the additional administrator account/group
                                        }
                                        #endregion We're working on an inherited ACE and an additional administrator account/group is specified
                                    }
                                }

                                if ($boolFoundGroup -eq $false) {
                                    if ([string]::IsNullOrEmpty($refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value) -eq $false) {
                                        #region We're working on an inherited ACE and an additional read-only account/group is specified
                                        if (($arrWorkingACEs[$intCounterA]).IdentityReference.Value -eq $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value) {
                                            #region Found an inherited ACE for the additional read-only account/group
                                            $boolFoundGroup = $true

                                            #region Check for minimum-required level of permissions
                                            $boolThisACEHasTheRequiredAmountOfPermissions = $false
                                            $intPermissionsThatExceedRequiredAmountOfPermissions = 0
                                            # Check for read & execute permissions:

                                            # There are three ways to have this. The
                                            # first is
                                            # [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                                            #
                                            # The second is
                                            # [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                                            # +
                                            # [System.Security.AccessControl.FileSystemRights]::Synchronize)
                                            #
                                            # The third is to have
                                            # GENERIC_EXECUTE (536870912 or
                                            # 0x20000000) + GENERIC_READ
                                            # (-2147483648 or 0x80000000)
                                            #
                                            # First, check for GENERIC_ALL
                                            # (268435456 or 0x1000000), which is
                                            # not part of
                                            # [System.Security.AccessControl.FileSystemRights]
                                            $intFileSystemRights = 268435456
                                            if ((($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights) -eq $intFileSystemRights) {
                                                #region GENERIC_ALL permission found
                                                $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                # In this case, the permissions that
                                                # exceed (GENERIC_EXECUTE +
                                                # GENERIC_READ) are GENERIC_WRITE
                                                # (1073741824 or 0x40000000)
                                                #
                                                # But we should check for any other
                                                # permissions first:
                                                $intFileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
                                                # First calculate any permissions in
                                                # excess of ReadAndExecute +
                                                # Synchronize:
                                                $intPermissionsThatExceedRequiredAmountOfPermissions = ($arrWorkingACEs[$intCounterA]).FileSystemRights - (($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights)
                                                # Add GENERIC_WRITE:
                                                $intPermissionsThatExceedRequiredAmountOfPermissions += 1073741824
                                                #endregion GENERIC_ALL permission found
                                            } else {
                                                #region No GENERIC_ALL permission found
                                                # Try plain ol' ReadAndExecute
                                                # first
                                                $intFileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                                                if ((($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights) -eq $intFileSystemRights) {
                                                    $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                }

                                                # Try ReadAndExecute + Synchronize
                                                # next
                                                if (-not $boolThisACEHasTheRequiredAmountOfPermissions) {
                                                    $intFileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
                                                    if ((($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights) -eq $intFileSystemRights) {
                                                        $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                    }
                                                }

                                                # Try GENERIC_EXECUTE (536870912 or
                                                # 0x20000000) and GENERIC_READ
                                                # (-2147483648 or 0x80000000) next
                                                if (-not $boolThisACEHasTheRequiredAmountOfPermissions) {
                                                    $intFileSystemRights = 536870912 + -2147483648
                                                    if ((($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights) -eq $intFileSystemRights) {
                                                        $boolThisACEHasTheRequiredAmountOfPermissions = $true
                                                    }
                                                }

                                                # Next, regardless of how read &
                                                # execute permissions were applied, we
                                                # need to calculate whether any
                                                # permissions are in excess of read &
                                                # execute:
                                                if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                    # Calculate permissions that are in excess of read and execute:
                                                    $intFileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize -bor 536870912 -bor -2147483648
                                                    $intPermissionsThatExceedRequiredAmountOfPermissions = ($arrWorkingACEs[$intCounterA]).FileSystemRights - (($arrWorkingACEs[$intCounterA]).FileSystemRights -band $intFileSystemRights)
                                                }
                                                #endregion No GENERIC_ALL permission found
                                            }
                                            #endregion Check for minimum-required level of permissions

                                            if ($boolThisACEHasTheRequiredAmountOfPermissions) {
                                                #region Found an inherited ACE with at least read & execute permissions for the additional read-only account/group
                                                if (($arrWorkingACEs[$intCounterA]).AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                                    #region Found an inherited deny ACE with at least read & execute permissions for the additional read-only account/group
                                                    if ($RecursionDepth -eq 0) {
                                                        #region At the root of the process, found an inherited deny ACE with at least read & execute permissions for the additional read-only account/group
                                                        if ($WorkingPath -ne $refToRealPath.Value) {
                                                            $strMessage = 'Found a deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" at the root of the permissions repair process that cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the deny permission. Root path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                                                        } else {
                                                            $strMessage = 'Found a deny permission for "' + ($arrWorkingACEs[$intCounterA]).IdentityReference.Value + '" at the root of the permissions repair process that cannot be removed because it''s inherited; please re-run the process on a parent folder, or manually remove the deny permission. Root path is "' + $WorkingPath + '".'
                                                        }
                                                        Write-Warning -Message $strMessage
                                                        #endregion At the root of the process, found an inherited deny ACE with at least read & execute permissions for the additional read-only account/group
                                                    }
                                                    #endregion Found an inherited deny ACE with at least read & execute permissions for the additional read-only account/group
                                                } else {
                                                    #region Found an inherited allow ACE with at least read & execute permissions for the additional read-only account/group
                                                    # Does it have excess permissions?
                                                    if ($intPermissionsThatExceedRequiredAmountOfPermissions -ne 0) {
                                                        #region Found an inherited allow ACE with permissions that exceed read & execute for the additional read-only account/group
                                                        if ($RecursionDepth -eq 0) {
                                                            #region At the root of the process, found an inherited allow ACE with permissions that exceed read & execute for the additional read-only account/group
                                                            if ($WorkingPath -ne $refToRealPath.Value) {
                                                                $strMessage = 'An ACE was found at the path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '") that grants more permissions than necessary to the account "' + $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value + '". The permissions that exceed Read & Execute are: ' + $intPermissionsThatExceedRequiredAmountOfPermissions
                                                            } else {
                                                                $strMessage = 'An ACE was found at the path "' + $WorkingPath + '" that grants more permissions than necessary to the account "' + $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value + '". The permissions that exceed Read & Execute are: ' + $intPermissionsThatExceedRequiredAmountOfPermissions
                                                            }
                                                            Write-Warning -Message $strMessage
                                                            #endregion At the root of the process, found an inherited allow ACE with permissions that exceed read & execute for the additional read-only account/group
                                                        }
                                                        #endregion Found an inherited allow ACE with permissions that exceed read & execute for the additional read-only account/group
                                                    }

                                                    if ($objThis.PSIsContainer) {
                                                        #region Found an inherited allow ACE on a folder with at least read & execute permissions for the additional read-only account/group
                                                        # Check inheritable ACE settings
                                                        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                                                        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                                                        if (($arrWorkingACEs[$intCounterA]).InheritanceFlags -eq $inheritanceFlags -and ($arrWorkingACEs[$intCounterA]).PropagationFlags -eq $propagationFlags) {
                                                            $boolAdditionalReadOnlyAccountInheritableACENeedsToBeApplied = $false
                                                        }
                                                        #endregion Found an inherited allow ACE on a folder with at least read & execute permissions for the additional read-only account/group
                                                    } else {
                                                        #region Found an inherited allow ACE on a file with at least read & execute permissions for the additional read-only account/group
                                                        $boolAdditionalReadOnlyAccountNonInheritableACENeedsToBeApplied = $false
                                                        #endregion Found an inherited allow ACE on a file with at least read & execute permissions for the additional read-only account/group
                                                    }
                                                    #endregion Found an inherited allow ACE with at least read & execute permissions for the additional read-only account/group
                                                }
                                                #endregion Found an inherited ACE with at least read & execute permissions for the additional read-only account/group
                                            }
                                            #endregion Found an inherited ACE for the additional read-only account/group
                                        }
                                        #endregion We're working on an inherited ACE and an additional read-only account/group is specified
                                    }
                                }
                            }
                            #endregion Inherited ACE is presumably an NTAccount ###########
                        }
                        #endregion Inherited ACE has an IdentityReference #################
                    }
                    #endregion Current ACE is inherited ###################################
                }
                #endregion Looping through each ACE in the ACL ############################
            }
            #endregion Look for ACEs that need to be removed, or that already exist (and don't need to be added)

            if ($boolBuiltInAdministratorsInheritableACENeedsToBeApplied) {
                #region An inheritable ACE needs to be applied here for the built-in Administrators group
                $strPrincipal = $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl.Value

                $boolIssueWithRemovalOccurred = $false
                if ($boolBuiltInAdministratorsNonInheritedNonInheritableACEFound) {
                    # Need to remove the non-inherited, non-inheritable ACE first
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Removing non-inherited, non-inheritable ACE for ' + $strPrincipal + ' with full control from the following folder. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Removing non-inherited, non-inheritable ACE for ' + $strPrincipal + ' with full control from the following folder. The path is "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                    $objAccessRuleToRemove = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToRemove)
                    if ($boolSuccess -eq $false) {
                        #region Access rule removal failed #############################
                        $boolIssueWithRemovalOccurred = $true
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule removal failed #############################
                    } else {
                        #region Access rule removal was successful #####################
                        # Test to see if permissions were removed by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed removed based on change in ACE count
                            Write-Debug -Message ('...the permission was removed...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed removed based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not removed
                            $boolIssueWithRemovalOccurred = $true
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '".'
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not removed
                        }
                        #endregion Access rule removal was successful #####################
                    }
                }

                if (-not $boolIssueWithRemovalOccurred) {
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Adding ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Adding ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The path is "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                    $objAccessRuleToAdd = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                    $boolSuccess = Add-AccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToAdd)
                    if ($boolSuccess -eq $false) {
                        #region Access rule addition failed ################################
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. Add-AccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. Add-AccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule addition failed ################################
                    } else {
                        #region Access rule addition was successful #####
                        # Test to see if permissions were added by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed added based on change in ACE count
                            Write-Debug -Message ('...the permission was added...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed added based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not added
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '".'
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not added
                        }
                        #endregion Access rule addition was successful #####
                    }
                }
                #endregion An inheritable ACE needs to be applied here for the built-in Administrators group
            }

            if ($boolSYSTEMInheritableACENeedsToBeApplied) {
                #region An inheritable ACE needs to be applied here for the SYSTEM account
                $strPrincipal = $refNameOfSYSTEMAccountAccordingToGetAcl.Value

                $boolIssueWithRemovalOccurred = $false
                if ($boolSYSTEMNonInheritedNonInheritableACEFound) {
                    # Need to remove the non-inherited, non-inheritable ACE first
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Removing non-inherited, non-inheritable ACE for ' + $strPrincipal + ' with full control from the following folder. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Removing non-inherited, non-inheritable ACE for ' + $strPrincipal + ' with full control from the following folder. The path is "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                    $objAccessRuleToRemove = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToRemove)
                    if ($boolSuccess -eq $false) {
                        #region Access rule removal failed #############################
                        $boolIssueWithRemovalOccurred = $true
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule removal failed #############################
                    } else {
                        #region Access rule removal was successful #####################
                        # Test to see if permissions were removed by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed removed based on change in ACE count
                            Write-Debug -Message ('...the permission was removed...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed removed based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not removed
                            $boolIssueWithRemovalOccurred = $true
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '".'
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not removed
                        }
                        #endregion Access rule removal was successful #####################
                    }
                }

                if (-not $boolIssueWithRemovalOccurred) {
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Adding ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Adding ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The path is "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                    $objAccessRuleToAdd = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                    $boolSuccess = Add-AccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToAdd)
                    if ($boolSuccess -eq $false) {
                        #region Access rule addition failed ################################
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. Add-AccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. Add-AccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule addition failed ################################
                    } else {
                        #region Access rule addition was successful #####
                        # Test to see if permissions were added by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed added based on change in ACE count
                            Write-Debug -Message ('...the permission was added...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed added based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not added
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '".'
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not added
                        }
                        #endregion Access rule addition was successful #####
                    }
                }
                #endregion An inheritable ACE needs to be applied here for the SYSTEM account
            }

            if ($boolAdditionalAdministratorAccountInheritableACENeedsToBeApplied) {
                #region An inheritable ACE needs to be applied here for the additional administrator account/group
                $strPrincipal = $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value

                $boolIssueWithRemovalOccurred = $false
                if ($boolAdditionalAdministratorAccountNonInheritedNonInheritableACEFound) {
                    # Need to remove the non-inherited, non-inheritable ACE first
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Removing non-inherited, non-inheritable ACE for ' + $strPrincipal + ' with full control from the following folder. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Removing non-inherited, non-inheritable ACE for ' + $strPrincipal + ' with full control from the following folder. The path is "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                    $objAccessRuleToRemove = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToRemove)
                    if ($boolSuccess -eq $false) {
                        #region Access rule removal failed #############################
                        $boolIssueWithRemovalOccurred = $true
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule removal failed #############################
                    } else {
                        #region Access rule removal was successful #####################
                        # Test to see if permissions were removed by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed removed based on change in ACE count
                            Write-Debug -Message ('...the permission was removed...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed removed based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not removed
                            $boolIssueWithRemovalOccurred = $true
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with full control to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '".'
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not removed
                        }
                        #endregion Access rule removal was successful #####################
                    }
                }

                if (-not $boolIssueWithRemovalOccurred) {
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Adding ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Adding ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The path is "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                    $objAccessRuleToAdd = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                    $boolSuccess = Add-AccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToAdd)
                    if ($boolSuccess -eq $false) {
                        #region Access rule addition failed ################################
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. Add-AccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. Add-AccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule addition failed ################################
                    } else {
                        #region Access rule addition was successful #####
                        # Test to see if permissions were added by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed added based on change in ACE count
                            Write-Debug -Message ('...the permission was added...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed added based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not added
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following folder, and all subfolders and files. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '".'
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not added
                        }
                        #endregion Access rule addition was successful #####
                    }
                }
                #endregion An inheritable ACE needs to be applied here for the additional administrator account/group
            }

            if ($boolAdditionalAdministratorAccountNonInheritableACENeedsToBeApplied) {
                #region A non-inheritable ACE needs to be applied here for the additional administrator account/group
                $strPrincipal = $refNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl.Value

                if ($WorkingPath -ne $refToRealPath.Value) {
                    $strMessage = 'Adding ACE for ' + $strPrincipal + ' with full control to the following file. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                } else {
                    $strMessage = 'Adding ACE for ' + $strPrincipal + ' with full control to the following file. The path is "' + $WorkingPath + '".'
                }
                Write-Verbose -Message $strMessage
                $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                $objAccessRuleToAdd = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                $boolSuccess = Add-AccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToAdd)
                if ($boolSuccess -eq $false) {
                    #region Access rule addition failed ################################
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following file. Add-AccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following file. Add-AccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                    }
                    Write-Warning -Message $strMessage
                    #endregion Access rule addition failed ################################
                } else {
                    #region Access rule addition was successful #####
                    # Test to see if permissions were added by comparing the ACE count
                    $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                    if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                        #region Permissions confirmed added based on change in ACE count
                        Write-Debug -Message ('...the permission was added...')
                        $intLastNumberOfItems = $intCurrentNumberOfItems
                        $boolACLChangeMade = $true
                        #endregion Permissions confirmed added based on change in ACE count
                    } else {
                        #region Based on no change in ACE count, permissions were not added
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following file. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following file. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Based on no change in ACE count, permissions were not added
                    }
                    #endregion Access rule addition was successful #####
                }
                #endregion A non-inheritable ACE needs to be applied here for the additional administrator account/group
            }

            if ($boolAdditionalReadOnlyAccountInheritableACENeedsToBeApplied) {
                #region An inheritable ACE needs to be applied here for the additional read-only account/group
                $strPrincipal = $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value

                $boolIssueWithRemovalOccurred = $false
                if ($boolAdditionalReadOnlyAccountNonInheritedNonInheritableACEFound) {
                    # Need to remove the non-inherited, non-inheritable ACE first
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Removing non-inherited, non-inheritable ACE for ' + $strPrincipal + ' with read and execute permissions from the following folder. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Removing non-inherited, non-inheritable ACE for ' + $strPrincipal + ' with read and execute permissions from the following folder. The path is "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $fileSystemRights = $intExistingReadOnlyAccountNonInheritedNonInheritableFileSystemRights
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                    $objAccessRuleToRemove = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                    $boolSuccess = Remove-SpecificAccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToRemove)
                    if ($boolSuccess -eq $false) {
                        #region Access rule removal failed #############################
                        $boolIssueWithRemovalOccurred = $true
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder. Remove-SpecificAccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule removal failed #############################
                    } else {
                        #region Access rule removal was successful #####################
                        # Test to see if permissions were removed by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed removed based on change in ACE count
                            Write-Debug -Message ('...the permission was removed...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed removed based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not removed
                            $boolIssueWithRemovalOccurred = $true
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to remove ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder. The ACE count indicates that it was not removed successfully. The path is "' + $WorkingPath + '".'
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not removed
                        }
                        #endregion Access rule removal was successful #####################
                    }
                }

                if (-not $boolIssueWithRemovalOccurred) {
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Adding ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder, and all subfolders and files. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Adding ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder, and all subfolders and files. The path is "' + $WorkingPath + '".'
                    }
                    Write-Verbose -Message $strMessage
                    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                    $objAccessRuleToAdd = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                    $boolSuccess = Add-AccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToAdd)
                    if ($boolSuccess -eq $false) {
                        #region Access rule addition failed ################################
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder, and all subfolders and files. Add-AccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder, and all subfolders and files. Add-AccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Access rule addition failed ################################
                    } else {
                        #region Access rule addition was successful #####
                        # Test to see if permissions were added by comparing the ACE count
                        $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                        if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                            #region Permissions confirmed added based on change in ACE count
                            Write-Debug -Message ('...the permission was added...')
                            $intLastNumberOfItems = $intCurrentNumberOfItems
                            $boolACLChangeMade = $true
                            #endregion Permissions confirmed added based on change in ACE count
                        } else {
                            #region Based on no change in ACE count, permissions were not added
                            if ($WorkingPath -ne $refToRealPath.Value) {
                                $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder, and all subfolders and files. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                            } else {
                                $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with read and execute permissions to the following folder, and all subfolders and files. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '".'
                            }
                            Write-Warning -Message $strMessage
                            #endregion Based on no change in ACE count, permissions were not added
                        }
                        #endregion Access rule addition was successful #####
                    }
                }
                #endregion An inheritable ACE needs to be applied here for the additional read-only account/group
            }

            if ($boolAdditionalReadOnlyAccountNonInheritableACENeedsToBeApplied) {
                #region A non-inheritable ACE needs to be applied here for the additional read-only account/group
                $strPrincipal = $refNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl.Value
                if ($WorkingPath -ne $refToRealPath.Value) {
                    $strMessage = 'Adding ACE for ' + $strPrincipal + ' with read and execute permissions to the following file. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                } else {
                    $strMessage = 'Adding ACE for ' + $strPrincipal + ' with read and execute permissions to the following file. The path is "' + $WorkingPath + '".'
                }
                Write-Verbose -Message $strMessage
                $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
                $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                $objAccessRuleToAdd = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $strPrincipal, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType
                $boolSuccess = Add-AccessRuleRobust -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToAccessControlListObject ([ref]$objThisObjectPermission) -ReferenceToAccessRuleObject ([ref]$objAccessRuleToAdd)
                if ($boolSuccess -eq $false) {
                    #region Access rule addition failed ################################
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with read and execute permissions to the following file. Add-AccessRuleRobust returned an error indicator. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                    } else {
                        $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with read and execute permissions to the following file. Add-AccessRuleRobust returned an error indicator. successfully The path is "' + $WorkingPath + '".'
                    }
                    Write-Warning -Message $strMessage
                    #endregion Access rule addition failed ################################
                } else {
                    #region Access rule addition was successful #####
                    # Test to see if permissions were added by comparing the ACE count
                    $intCurrentNumberOfItems = $objThisObjectPermission.Access.Count
                    if ($intCurrentNumberOfItems -ne $intLastNumberOfItems) {
                        #region Permissions confirmed added based on change in ACE count
                        Write-Debug -Message ('...the permission was added...')
                        $intLastNumberOfItems = $intCurrentNumberOfItems
                        $boolACLChangeMade = $true
                        #endregion Permissions confirmed added based on change in ACE count
                    } else {
                        #region Based on no change in ACE count, permissions were not added
                        if ($WorkingPath -ne $refToRealPath.Value) {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following file. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                        } else {
                            $strMessage = 'Failed to add ACE for ' + $strPrincipal + ' with full control to the following file. The ACE count indicates that it was not added successfully. The path is "' + $WorkingPath + '".'
                        }
                        Write-Warning -Message $strMessage
                        #endregion Based on no change in ACE count, permissions were not added
                    }
                    #endregion Access rule addition was successful #####
                }
                #endregion A non-inheritable ACE needs to be applied here for the additional read-only account/group
            }

            if ($boolACLChangeMade -eq $true) {
                #region At least once change was made to the ACL; we need to write it to disk
                if ($WorkingPath -ne $refToRealPath.Value) {
                    $strMessage = 'Writing ACL changes to disk for path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '").'
                } else {
                    $strMessage = 'Writing ACL changes to disk for path "' + $WorkingPath + '".'
                }
                Write-Verbose -Message $strMessage
                $boolSuccess = Write-ACLToObject -CurrentAttemptNumber 1 -MaxAttempts 2 -ReferenceToTargetObject ([ref]$objThis) -ReferenceToACL ([ref]$objThisObjectPermission)
                if ($boolSuccess -eq $false) {
                    #region Write-ACLToObject failed ###################################
                    # TODO: Capture $_.Exception.Message from failure in Write-ACLToObject
                    # Write-Warning ('Unable to write ACL changes to disk for path "' + $WorkingPath + '". Error: ' + $_.Exception.Message + '; child folders and files will not be processed!')
                    if ($WorkingPath -ne $refToRealPath.Value) {
                        $strMessage = 'Unable to write ACL changes to disk for path "' + $WorkingPath + '" (real path: "' + $refToRealPath.Value + '"). Child folders and files will not be processed!'
                    } else {
                        $strMessage = 'Unable to write ACL changes to disk for path "' + $WorkingPath + '". Child folders and files will not be processed!'
                    }
                    Write-Warning -Message $strMessage
                    intFunctionReturn = -14
                    return $intFunctionReturn
                    #endregion Write-ACLToObject failed ###################################
                }
                #endregion At least once change was made to the ACL; we need to write it to disk
            }
            #endregion Not in final cleanup of redundance ACEs mode; programmatically change permissions via .NET
        }
        #endregion We've theoretically repaired permissions on the object #############
        #endregion Path is not too long, or the function was called with "IgnorePathLengthLimits"
    }
    if (($RecursionDepth -eq 0) -and ($intFunctionReturn -eq 0) -and (-not $boolFinalCleanupOfRedundantACEs)) {
        # We just finished with initial processing of everything, no errors occurred, and are not yet in final cleanup of redundant SIDs
        if (-not $boolDoNotPerformFinalCleanupOfRedundantACEs) {
            $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $WorkingPath -LastShortenedPath $LastShortenedPath -RealPath $refToRealPath.Value -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful $refWorkingVersionOfWhetherGetPSDriveWorkaroundIsKnownToBeUseful -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls $refNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl $refNameOfBuiltInAdministratorsGroupAccordingToGetAcl -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls $refNameOfSYSTEMAccountAccordingToTakeOwnAndICacls -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl $refNameOfSYSTEMAccountAccordingToGetAcl -RecursionDepth $RecursionDepth -FinalCleanupOfRedundantACEs
            if ($intReturnCode -ne 0) {
                $intFunctionReturn = $intReturnCode
            }
        }
    }
    return $intFunctionReturn
}

#region Process Input ##############################################################
if ([string]::IsNullOrEmpty($PathToFix)) {
    Write-Error -Message 'The PathToFix parameter is required.'
    return
}

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

if ($null -eq $DoNotPerformFinalCleanupOfRedundantACEs) {
    $boolDoNotPerformFinalCleanupOfRedundantACEs = $false
} else {
    if ($DoNotPerformFinalCleanupOfRedundantACEs.IsPresent -eq $false) {
        $boolDoNotPerformFinalCleanupOfRedundantACEs = $false
    } else {
        $boolDoNotPerformFinalCleanupOfRedundantACEs = $true
    }
}
#endregion Process Input ##############################################################

# TODO: additional code/logic is necessary for adding a read-only account, see TODO
# markers in Repair-NTFSPermissionsRecursively

$hashtableKnownSIDs = $null
if ($boolRemoveUnresolvedSIDs -eq $true) {
    # If the user requested that we remove unresolved SIDs, make sure they've specified
    # a CSV file containing all known SIDs in the environment. This protects against
    # situation where an AD outage or domain connectivity disruption causes the script
    # to remove all permissions from a folder/file because it cannot resolve the SIDs
    # in the ACLs.

    if ([string]::IsNullOrEmpty($strPathToCSVContainingKnownSIDs) -eq $true) {
        Write-Error -Message 'The -RemoveUnresolvedSIDs parameter was specified, but no path to a CSV file containing all known SIDs in the environment was specified. Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
        return
    } else {
        if ((Test-Path $strPathToCSVContainingKnownSIDs) -eq $false) {
            Write-Error -Message 'The -RemoveUnresolvedSIDs parameter was specified, but the path specified for the CSV file containing all known SIDs in the environment does not exist. Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
            return
        } else {
            $arrSIDsFromCSV = @()
            $arrSIDsFromCSV = @(Import-Csv $strPathToCSVContainingKnownSIDs)
            if ($arrSIDsFromCSV.Count -eq 0) {
                Write-Error -Message 'The -RemoveUnresolvedSIDs parameter was specified, but the CSV file specified for the CSV file containing all known SIDs in the environment is empty. Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
                return
            } else {
                $strKnownSID = ($arrSIDsFromCSV[0]).SID
                if ([string]::IsNullOrEmpty($strKnownSID) -eq $true) {
                    Write-Error -Message 'The -RemoveUnresolvedSIDs parameter was specified, but the CSV file specified for the CSV file containing all known SIDs in the environment contains an empty value for the "SID" column (or does not contain the SID column at all). Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
                    return
                } else {
                    # The CSV file specified for the CSV file containing all known SIDs in the environment appears to be valid
                    # Build these into a $hashtable for fast lookup later
                    Write-Debug -Message 'Loading known SIDs from the specified CSV file into memory...'
                    $hashtableKnownSIDs = @{}
                    $arrSIDsFromCSV | ForEach-Object {
                        $strSID = $_.SID
                        if ([string]::IsNullOrEmpty($strSID) -eq $false) {
                            if ($hashtableKnownSIDs.ContainsKey($strSID) -eq $false) {
                                $hashtableKnownSIDs.Add($strSID, $null)
                            }
                        }
                    }
                    Write-Debug -Message 'Finished loading known SIDs from the specified CSV file into memory'

                    # Make sure the count of SIDs is not zero in the hashtable
                    if ($hashtableKnownSIDs.Count -eq 0) {
                        Write-Error -Message 'The -RemoveUnresolvedSIDs parameter was specified, but the CSV file specified for the CSV file containing all known SIDs in the environment contains an empty value for the "SID" column (or does not contain the SID column at all). Please create a CSV containing all known SIDs in the environment and then specify the path to that CSV using the -PathToCSVContainingKnownSIDs parameter. The CSV should contain a column header "SID" and then list all of the SIDs beneath it in string format'
                        return
                    }
                }
            }
        }
    }
}

function Get-PSVersion {
    # .SYNOPSIS
    # Returns the version of PowerShell that is running.
    #
    # .DESCRIPTION
    # The function outputs a [version] object representing the version of
    # PowerShell that is running.
    #
    # On versions of PowerShell greater than or equal to version 2.0, this
    # function returns the equivalent of $PSVersionTable.PSVersion
    #
    # PowerShell 1.0 does not have a $PSVersionTable variable, so this
    # function returns [version]('1.0') on PowerShell 1.0.
    #
    # .EXAMPLE
    # $versionPS = Get-PSVersion
    # # $versionPS now contains the version of PowerShell that is running.
    # # On versions of PowerShell greater than or equal to version 2.0,
    # # this function returns the equivalent of $PSVersionTable.PSVersion.
    #
    # .INPUTS
    # None. You can't pipe objects to Get-PSVersion.
    #
    # .OUTPUTS
    # System.Version. Get-PSVersion returns a [version] value indiciating
    # the version of PowerShell that is running.
    #
    # .NOTES
    # Version: 1.0.20250106.0

    #region License ####################################################
    # Copyright (c) 2025 Frank Lesniak
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

    if (Test-Path variable:\PSVersionTable) {
        return ($PSVersionTable.PSVersion)
    } else {
        return ([version]('1.0'))
    }
}

$versionPS = Get-PSVersion

if ($versionPS.Major -ge 5) {
    Write-Information -MessageData ('Beginning to process path: ' + $PathToFix)
} else {
    Write-Host -Object ('Beginning to process path: ' + $PathToFix)
}
$boolGetPSDriveWorkaroundIsKnownToBeUseful = $false
if ($boolDoNotPerformFinalCleanupOfRedundantACEs) {
    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $PathToFix -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful ([ref]$boolGetPSDriveWorkaroundIsKnownToBeUseful) -ReferenceToHashtableOfKnownSIDs ([ref]$hashtableKnownSIDs) -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls ([ref]$NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls) -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl ([ref]$NameOfBuiltInAdministratorsGroupAccordingToGetAcl) -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls ([ref]$NameOfSYSTEMAccountAccordingToTakeOwnAndICacls) -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl ([ref]$NameOfSYSTEMAccountAccordingToGetAcl) -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls ([ref]$NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls) -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl ([ref]$NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls ([ref]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls) -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl ([ref]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl) -DoNotPerformFinalCleanupOfRedundantACEs
} else {
    $intReturnCode = Repair-NTFSPermissionsRecursively -WorkingPath $PathToFix -ReferenceToWhetherGetPSDriveWorkaroundIsKnownToBeUseful ([ref]$boolGetPSDriveWorkaroundIsKnownToBeUseful) -ReferenceToHashtableOfKnownSIDs ([ref]$hashtableKnownSIDs) -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls ([ref]$NameOfBuiltInAdministratorsGroupAccordingToTakeOwnAndICacls) -ReferenceToNameOfBuiltInAdministratorsGroupAccordingToGetAcl ([ref]$NameOfBuiltInAdministratorsGroupAccordingToGetAcl) -ReferenceToNameOfSYSTEMAccountAccordingToTakeOwnAndICacls ([ref]$NameOfSYSTEMAccountAccordingToTakeOwnAndICacls) -ReferenceToNameOfSYSTEMAccountAccordingToGetAcl ([ref]$NameOfSYSTEMAccountAccordingToGetAcl) -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls ([ref]$NameOfAdditionalAdministratorAccountOrGroupAccordingToTakeOwnAndICacls) -ReferenceToNameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl ([ref]$NameOfAdditionalAdministratorAccountOrGroupAccordingToGetAcl) -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls ([ref]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToTakeOwnAndICacls) -ReferenceToNameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl ([ref]$NameOfAdditionalReadOnlyAccountOrGroupAccordingToGetAcl)
}
if ($intReturnCode -eq 0) {
    if ($versionPS.Major -ge 5) {
        Write-Information -MessageData ('Successfully processed path: ' + $PathToFix)
    } else {
        Write-Host -Object ('Successfully processed path: ' + $PathToFix)
    }
} else {
    Write-Error -Message ('There were one or more issues processing the path "' + $PathToFix + '" One error code returned was: ' + $intReturnCode)
}
