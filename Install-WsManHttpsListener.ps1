<#
.SYNOPSIS
    Is used to install an HTTPS WSMan Listener on a computer with a valid certificate.

.DESCRIPTION
    This script is designed to be called from a Startup/Logon PowerShell GPO.
    The Distinguished Name of the certificate issuer must be passed to the script.

.PARAMETER Issuer
The full Distinguished Name of the Issing CA that will have issued the certificate to be used
for this HTTPS WSMan Listener.

.PARAMETER DNSNameType
The allowed DNS Name types that will be used to find a matching certificate. Defaults to Both.

.PARAMETER MatchAlternate
The certificate used must also have an alternate subject name containing the DNS name found in
the subject as well. Defaults to false.

.PARAMETER Port
This is the port the HTTPS WSMan Listener will be installed onto. Defaults to 5986.

.PARAMETER LogFilename
This optional parameter contains a full path and file name to the log file to create.
If this parameter is not set then a log file will not be created.

.EXAMPLE
 Install-WSManHttpsListener -Issuer 'CN=CONTOSO.COM Issuing CA, DC=CONTOSO, DC=COM'
Install a WSMan HTTPS listener from an appropriate machine certificate issued by
'CN=LABBUILDER.COM Issuing CA, DC=LABBUILDER, DC=COM'.

.EXAMPLE
 Install-WSManHttpsListener -Issuer 'CN=CONTOSO.COM Issuing CA, DC=CONTOSO, DC=COM' -Port 7000
Install a WSMan HTTPS listener from an appropriate machine certificate issued by
'CN=LABBUILDER.COM Issuing CA, DC=LABBUILDER, DC=COM' on port 7000.

#>
[CmdLetBinding()]
param
(
    [Parameter(Mandatory=$true)]
    [String] $Issuer,

    [ValidateSet('Both', 'FQDN', 'ComputerName')]
    [String] $DNSNameType = 'Both',

    [Switch] $MatchAlternate = $false,

    [Int] $Port = 5986,
    
    [ValidateNotNullOrEmpty()]
    [String] $LogFilename
) # param
try
{
    Get-WSManInstance `
        -ResourceURI winrm/config/Listener `
        -SelectorSet @{Address='*';Transport='HTTPS'}
    $Message = 'An HTTPS WinRM Listener already exists for this computer.'
    Write-Verbose -Message $Message
    return
}
catch
{
# An error incidcates a listener doesn't exist so we can install one.
}
[String] $Thumbprint = ''
# First try and find a certificate that is used to the FQDN of the machine
if ($DNSNameType -in 'Both','FQDN')
{
    [String] $HostName = [System.Net.Dns]::GetHostByName($ENV:computerName).Hostname
    if ($MatchAlternate)
    {
        $Thumbprint = (get-childitem -Path Cert:\localmachine\my | Where-Object { 
		        ($_.Extensions.EnhancedKeyUsages.FriendlyName -contains 'Server Authentication') -and
		        ($_.IssuerName.Name -eq $Issuer) -and
		        ($HostName -in $_.DNSNameList.Unicode) -and
                ($_.Subject -eq "CN=$HostName") } | Select-Object -First 1
            ).Thumbprint
    }
    else
    {
        $Thumbprint = (get-childitem -Path Cert:\localmachine\my | Where-Object { 
		        ($_.Extensions.EnhancedKeyUsages.FriendlyName -contains 'Server Authentication') -and
		        ($_.IssuerName.Name -eq $Issuer) -and
                ($_.Subject -eq "CN=$HostName") } | Select-Object -First 1
            ).Thumbprint    
    } # if
}
if (($DNSNameType -in 'Both','ComputerName') -and -not $Thumbprint)
{
    # If could not find an FQDN cert, try for one issued to the computer name
    [String] $HostName = $ENV:ComputerName
    if ($MatchAlternate) {
        $Thumbprint = (get-childitem -Path Cert:\localmachine\my | Where-Object { 
		        ($_.Extensions.EnhancedKeyUsages.FriendlyName -contains 'Server Authentication') -and
		        ($_.IssuerName.Name -eq $Issuer) -and
		        ($HostName -in $_.DNSNameList.Unicode) -and
                ($_.Subject -eq "CN=$HostName") } | Select-Object -First 1
            ).Thumbprint
    }
    else
    {
        $Thumbprint = (get-childitem -Path Cert:\localmachine\my | Where-Object { 
		        ($_.Extensions.EnhancedKeyUsages.FriendlyName -contains 'Server Authentication') -and
		        ($_.IssuerName.Name -eq $Issuer) -and
                ($_.Subject -eq "CN=$HostName") } | Select-Object -First 1
            ).Thumbprint    
    } # if
} # if
if ($Thumbprint)
{
    # A certificate was found, so use it to enable the HTTPS WinRM listener
    $Message = "Creating new HTTPS WinRM Listener for '$Hostname' with certificate '$Thumbprint'." 
    Write-Verbose -Message $Message
    if ($LogFilename)
    {
        Add-Content -Path $LogFilename -Value "$(Get-Date) - $($ENV:ComputerName): $Message`n`r" 
    }

    try {
        New-WSManInstance `
            -ResourceURI winrm/config/Listener `
            -SelectorSet @{Address='*';Transport='HTTPS'} `
            -ValueSet @{Hostname=$HostName;CertificateThumbprint=$Thumbprint;Port=$Port} `
            -ErrorAction Stop
        Write-Verbose -Message ( @(
            "The new HTTPS WinRM Listener for '$Hostname' with certificate '$Thumbprint' "
            'has been created.'
            ) -join '')
    }
    catch
    {
        $Message = $_
        Write-Verbose -Message $Message
        if ($LogFilename)
        {
        Add-Content -Path $LogFilename -Value "$(Get-Date) - $($ENV:ComputerName): $Message`n`r" 
        }
    } # try
}
else
{
    $Message = ( @(
        "A computer certificate issued by '$Issuer' to this computer with "
        'an enhanced key usage of Server Authentication could not be found.'
        ) -join '' )
    Write-Verbose -Message $Message 
    if ($LogFilename)
    {
        Add-Content -Path $LogFilename -Value "$(Get-Date) - $($ENV:ComputerName): $Message`n`r" 
    }
} # if