<#
.Synopsis
    Is used to install an HTTPS WSMan Listener on a computer with a valid certificate.
.DESCRIPTION
    This script is designed to be called from a Startup/Logon PowerShell GPO.
    The Distinguished Name of the certificate issuer must be passed to the script.
.PARAMETER Issuer
The full Distinguished Name of the Issing CA that will have issued the certificate to be used
for this HTTPS WSMan Listener.
.PARAMETER DNSNameType
The allowed DNS Name types that will be used to find a matching certificate. Defaults to Both.
.PARAMETER Port
This is the port the HTTPS WSMan Listener will be installed onto. Defaults to 5986.
.EXAMPLE
 Install-WSManHttpsListener -Issuer 'CN=CONTOSO.COM Issuing CA, DC=CONTOSO, DC=COM'
Install a WSMan HTTPS listener from an appropriate machine certificate issued by 'CN=LABBUILDER.COM Issuing CA, DC=LABBUILDER, DC=COM'.

.EXAMPLE
 Install-WSManHttpsListener -Issuer 'CN=CONTOSO.COM Issuing CA, DC=CONTOSO, DC=COM' -Port 7000
Install a WSMan HTTPS listener from an appropriate machine certificate issued by 'CN=LABBUILDER.COM Issuing CA, DC=LABBUILDER, DC=COM' on port 7000.

#>
[CmdLetBinding()]
Param (
    [Parameter(Mandatory=$true)]
    [String] $Issuer,

    [ValidateSet('Both', 'FQDN', 'ComputerName')]
    [String] $DNSNameType = 'Both',

    [Int] $Port = 5986
)
Try {
    Get-WSManInstance `
        -ResourceURI winrm/config/Listener `
        -SelectorSet @{Address='*';Transport='HTTPS'}
    Write-Verbose 'An HTTPS WinRM Listener already exists for this computer.'
    Return
} Catch {
# A listener doesn't exist so can now install one.
}
$Issuer = 'CN=LABBUILDER.COM Issuing CA, DC=LABBUILDER, DC=COM'
[String] $Thumbprint = ''
# First try and find a certificate that is used to the FQDN of the machine
if ($DNSNameType -in 'Both','FQDN') {
    [String] $HostName = 'DA_IT01.LABBUILDER.COM'
    $Thumbprint = (get-childitem -Path Cert:\localmachine\my | Where-Object { 
		    ($_.Extensions.EnhancedKeyUsages.FriendlyName -contains 'Server Authentication') -and
		    ($_.IssuerName.Name -eq $Issuer) -and
		    ($HostName -in $_.DNSNameList.Unicode) }
        ).Thumbprint
}
if (($DNSNameType -in 'Both','ComputerName') -and -not $Thumbprint) {
    # If could not find an FQDN cert, try for one issued to the computer name
    [String] $HostName = $ENV:ComputerName
    $Thumbprint = (get-childitem -Path Cert:\localmachine\my | Where-Object { 
		    ($_.Extensions.EnhancedKeyUsages.FriendlyName -contains 'Server Authentication') -and
		    ($_.IssuerName.Name -eq $Issuer) -and
		    ($HostName -in $_.DNSNameList.Unicode) }
        ).Thumbprint
} # if
if ($Thumbprint) {
    # A certificate was found, so use it to enable the HTTPS WinRM listener
    Write-Verbose -Message `
        "Creating new HTTPS WinRM Listener for '$Hostname' with certificate '$Thumbprint' ..."
    Try {
        New-WSManInstance `
            -ResourceURI winrm/config/Listener `
            -SelectorSet @{Address='*';Transport='HTTPS'} `
            -ValueSet @{Hostname=$HostName;CertificateThumbprint=$Thumbprint} `
            -Port $Port `
            -ErrorAction Stop
    } Catch {
        Write-Verbose -Message `
            "Creating new HTTPS WinRM Listener for '$Hostname' with certificate '$Thumbprint'..."
    }
    Write-Verbose "The new HTTPS WinRM Listener for '$Hostname' with certificate '$Thumbprint' has been created."
} else {
    Write-Verbose -Message ( @(
        'A computer certificate issued by $Issued to this computer with '
        'an enhanced key usage of Server Authentication could not be found.'
        ) -join '' )
} # if