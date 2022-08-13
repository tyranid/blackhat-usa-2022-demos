# S4U2Self (needs to run with SeImpersonatePrivilege)
param(
    [Parameter(Mandatory)]
    [string]$Username,
    [switch]$Format
)

. "$PSScriptRoot\common.ps1"

try {
    Remove-KerberosTicket -All
    $tgt = Get-UserTgt
    Remove-KerberosTicket -All
    Add-KerberosTicket -Credential $tgt
    $cache = New-KerberosTicketCache -Credential $tgt
    $client = New-LsaClientContext -Cache $cache -Target $Username -SessionKeyTicket $tgt.Tickets[0] -S4U2Self
    if ($Format) {
        Format-LsaAuthToken $client | Out-Host
    }
    Use-NtObject($cred_handle = New-LsaCredentialHandle -Package 'Kerberos' -UseFlag Inbound) {
        Use-NtObject($server = New-LsaServerContext -CredHandle $cred_handle) {
            Update-LsaServerContext $server $client
            Get-LsaAccessToken $server
        }
    }
} catch {
    Write-Error $_
}