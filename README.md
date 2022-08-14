# blackhat-usa-2022-demos
Demos for the Blackhat USA 2022 talk "Taking Kerberos to the Next Level".

This is the slides and demos for James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo)) and Nick Landers ([@monoxgas](https://twitter.com/monoxgas)) presentation. The demos are as follows:

* demo1.ps1 - Silver ticket with password.
* demo2.ps1 - Silver ticket U2U.
* demo3.ps1 - Silver ticket with buffer type confusion.
* demo4.ps1 - KDC pinning and BYOKDC
* demo5.ps1 - S4U2Self
* demo6.ps1 - UAC bypass

Note that demo 1 is expected to fail, and demos 2-4 will only work if the system hasn't been updated to August 2022 patch for [CVE-2022-35756](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-35756).

The demos require an updated version of the NtObjectManager PowerShell module built from source. They do not work on the version in the PowerShell gallery. Get the source code for the module from [Github](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)
