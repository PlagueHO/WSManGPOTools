WSManGPOTools
==========

## Install-WSManHttpsListener
This PowerShell script can be used to install an HTTPS WSMan Listener on a computer with a valid certificate.

### Overview
This script is designed to be called from a Startup/Logon PowerShell GPO. The Distinguished Name of the certificate issuer must be passed to the script.

**The computer MUST have a valid certificate with an Extended Key Usage or Server Authentication and issued by the CA specified in the Issuer parameter passed to the script. The certificate DNS name must contain a name that matches either the FQDN name of the computer or the flat computer name.**

If a certificate can't be found that matches the above properties then the WSMan HTTPS listener will not be installed. If a WSMan HTTPS listener already exists on this computer then the script will not execute which allows the script to be set to always run at computer start up.

The WSMan HTTPS Listener is installed to port 5986 by default, but this can be changed by specifying the port parameter.

Normally, the script will first look for a Server Authentication certificate that has a DNS name matching the FQDN of the computer, and if one can't be found it will look for one using only the computer name. The script can be restricted so that it will only look for FQDN or Computer name rather than both by passing the 

####Examples
Install a WSMan HTTPS listener from an appropriate machine certificate issued by 'CN=LABBUILDER.COM Issuing CA, DC=LABBUILDER, DC=COM':
```powershell
Install-WSManHttpsListener -Issuer 'CN=CONTOSO.COM Issuing CA, DC=CONTOSO, DC=COM'
```

Install a WSMan HTTPS listener from an appropriate machine certificate issued by 'CN=LABBUILDER.COM Issuing CA, DC=LABBUILDER, DC=COM' on port 7000:
```powershell
Install-WSManHttpsListener -Issuer 'CN=CONTOSO.COM Issuing CA, DC=CONTOSO, DC=COM' -Port 7000
```

See:
```powershell
Get-Help .\Install-WSManHttpsListener.ps1 -Full
```
For more information.


### Minimum requirements

- PowerShell 4.0


### License and Copyright

Copyright 2014 Daniel Scott-Raynsford

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
