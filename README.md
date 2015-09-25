WSManGPOTools
==========

## Install-WSManHttpsListener
This PowerShell script can be used to install an HTTPS WSMan Listener on a computer with a valid certificate.

### Changelog
2015-09-25: Initial Version.

### Overview
This script is designed to be called from a Startup/Logon PowerShell GPO. The Distinguished Name of the certificate issuer must be passed to the script. The script can be run outside of a GPO if required.

**The computer MUST have a valid certificate with the following properties:**

- An Extended Key Usage of **Server Authentication**.
- Issued by the CA specified in the Issuer parameter passed to the script.
- The **Subject** must contain a **Common Name** that contains either the FQDN computer name or the flat computer name (e.g. CN=SERVER1.CONTOSO.COM or CN=SERVER1)
- An option can also be set to require that the **Subject Alternamte Name** must contain a **DNS Name** that matches either the FQDN computer name or the flat computer name (e.g. DNS Name=SA_DHCP1.LABBUILDER.COM or DNS Name=SERVER1)

If a certificate can't be found that matches the above properties then the WSMan HTTPS listener will not be installed. Please ensure that at least one computer certificate on each computer matches these properties - it is recommended that you configure a custom autoentrollment computer certificate to ensure the Subject Name and Alternate Subject names are automatically populated.

If a WSMan HTTPS listener already exists on this computer then the script will not execute which allows the script to be set to always run at computer start up.

The WSMan HTTPS Listener is installed to port 5986 by default, but this can be changed by specifying the port parameter.

Normally, the script will first look for a Server Authentication certificate that has a DNS name matching the FQDN of the computer, and if one can't be found it will look for one using only the computer name. The script can be restricted so that it will only look for FQDN or Computer name rather than both by passing the 

### Autoenrollment Certificate Template
Normally this script will be used in conjunction with a Computer Certificate Autoenrollment GPO. If this is the case you should ensure that the Autoenrollment Computer Certificate Template that is being used to issue server certificates should generate a valid Subject containing the computer DNS name (and optionally Alternate Subject as well).

### Parameters
#### Issuer
The full Distinguished Name of the Issing CA that will have issued the certificate to be used
for this HTTPS WSMan Listener. It is a required parameter.

#### DNSNameType
The allowed DNS Name types that will be used to find a matching certificate.
Default: Both

##### MatchAlternate
The certificate used must also have an alternate subject name containing the DNS name found in
the subject as well.
Default:False

#### Port
This is the port the HTTPS WSMan Listener will be installed onto.
Default:5986

### Examples
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

- PowerShell 2.0


### License and Copyright

Copyright 2015 Daniel Scott-Raynsford

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
