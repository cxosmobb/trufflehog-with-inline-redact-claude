# Fails unless lowpriv runs commands the way a standard Windows user runs
# them: no privilege but SeChangeNotifyPrivilege, not an effective member of
# Administrators, medium integrity. The facts come from lowpriv -describe run
# under the restricted token, i.e. from the token itself; whoami's group list
# is not used because it fails to resolve some groups on GitHub's runners.
#
# Usage: check-token.ps1 <path to lowpriv.exe>
param([Parameter(Mandatory)][string]$Lowpriv)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$Lowpriv = (Resolve-Path $Lowpriv).Path

& $Lowpriv whoami /priv | Write-Host
$facts = (& $Lowpriv $Lowpriv -describe) -join "`n" | ConvertFrom-StringData
$facts | Format-Table -AutoSize | Out-String | Write-Host

if ($facts.privileges_besides_change_notify -ne '0') {
    throw "restricted token holds $($facts.privileges_besides_change_notify) privileges besides SeChangeNotifyPrivilege"
}
if ($facts.administrator -ne 'false') {
    throw 'restricted token is an effective member of Administrators'
}
if ($facts.integrity -ne '0x2000') {
    throw "restricted token has integrity $($facts.integrity), not medium (0x2000)"
}
Write-Host 'Restricted token: standard user (SeChangeNotifyPrivilege only, not an administrator, medium integrity).'
