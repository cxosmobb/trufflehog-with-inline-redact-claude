# Fails unless lowpriv runs commands the way a standard Windows user runs
# them: no privilege but SeChangeNotifyPrivilege, the Administrators group
# deny-only, medium integrity.
#
# Usage: check-token.ps1 <path to lowpriv.exe>
param([Parameter(Mandatory)][string]$Lowpriv)
$ErrorActionPreference = 'Stop'

$privileges = & $Lowpriv whoami /priv /fo csv | ConvertFrom-Csv
$groups = & $Lowpriv whoami /groups /fo csv | ConvertFrom-Csv
$privileges | Format-Table -AutoSize | Out-String | Write-Host

$names = @($privileges | ForEach-Object { $_.'Privilege Name' })
if ($names.Count -ne 1 -or $names[0] -ne 'SeChangeNotifyPrivilege') {
    throw "restricted token holds privileges: $($names -join ', ')"
}
$admins = $groups | Where-Object { $_.'Group Name' -eq 'BUILTIN\Administrators' }
if ($admins -and $admins.Attributes -notmatch 'deny only') {
    throw 'restricted token is a member of Administrators'
}
if (-not ($groups | Where-Object { $_.'Group Name' -eq 'Mandatory Label\Medium Mandatory Level' })) {
    throw 'restricted token is not at medium integrity'
}
Write-Host 'Restricted token: standard user (SeChangeNotifyPrivilege only, Administrators deny-only, medium integrity).'
