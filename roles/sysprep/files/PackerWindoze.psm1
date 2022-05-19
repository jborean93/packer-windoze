# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

Function New-LegacySelfSignedCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $Subject,

        [Parameter(Mandatory)]
        [Int32]
        $ValidDays
    )
    Write-Verbose -Message "Creating self-signed certificate of CN=$Subject for $ValidDays days"
    $subjectName = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $subjectName.Encode("CN=$Subject", 0)

    $privateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
    $privateKey.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $privateKey.KeySpec = 1
    $privateKey.Length = 4096
    $privateKey.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $privateKey.MachineContext = 1
    $privateKey.Create()

    $serverAuthOid = New-Object -ComObject X509Enrollment.CObjectId
    $serverAuthOid.InitializeFromValue("1.3.6.1.5.5.7.3.1")

    $ekuoids = New-Object -ComObject X509Enrollment.CObjectIds
    $ekuoids.Add($serverAuthOid)

    $ekuExtension = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
    $ekuExtension.InitializeEncode($ekuoids)

    $names = @($env:COMPUTERNAME, ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).Hostname))
    $altNames = New-Object -ComObject X509Enrollment.CAlternativeNames
    foreach ($name in $names) {
        $altName = New-Object -ComObject X509Enrollment.CAlternativeName
        $altName.InitializeFromString(0x3, $name)
        $altNames.Add($altName)
    }
    $altNamesExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $altNamesExtension.InitializeEncode($altNames)

    $digitalSignature = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
    $keyEncipherment = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
    $keyUsage = [int]($digitalSignature -bor $keyEncipherment)
    $keyUsageExtension = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
    $keyUsageExtension.InitializeEncode($keyUsage)
    $keyUsageExtension.Critical = $true

    $signatureOID = New-Object -ComObject X509Enrollment.CObjectId
    $sha256OID = New-Object -TypeName Security.Cryptography.Oid -ArgumentList "SHA256"
    $signatureOID.InitializeFromValue($sha256OID.Value)

    $certificate = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
    $certificate.InitializeFromPrivateKey(2, $privateKey, "")
    $certificate.Subject = $subjectName
    $certificate.Issuer = $certificate.Subject
    $certificate.NotBefore = (Get-Date).AddDays(-1)
    $certificate.NotAfter = $certificate.NotBefore.AddDays($ValidDays)
    $certificate.X509Extensions.Add($keyUsageExtension)
    $certificate.X509Extensions.Add($altNamesExtension)
    $certificate.X509Extensions.Add($ekuExtension)
    $certificate.SignatureInformation.HashAlgorithm = $signatureOID
    $certificate.Encode()

    $enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
    $enrollment.InitializeFromRequest($certificate)
    $certificateData = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certificateData, 0, "")

    $parsedCertificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $parsedCertificate.Import([System.Text.Encoding]::UTF8.GetBytes($certificateData))

    $parsedCertificate
}

Function New-FirewallRule {
    param(
        [Parameter(mandatory)]
        [String]
        $Name,

        [Parameter(mandatory)]
        [String]
        $Description,

        [Parameter(mandatory)]
        [Int32]
        $Port,

        [Parameter()]
        [Switch]
        $Deny
    )
    $fw = New-Object -ComObject HNetCfg.FWPolicy2

    $rules = $fw.Rules | Where-Object { $_.Name -eq $Name }
    if (-not $rules) {
        Write-Verbose -Message "Creating new firewall rule - $Name"
        $rule = New-Object -ComObject HNetCfg.FwRule
        $rule.Name = $name
        $rule.Description = $Description
        $rule.Profiles = 0x7FFFFFFF
        $rules = @($rule)
    }

    foreach ($rule in $rules) {
        $action = 1  # Allow
        if ($Deny.IsPresent) {
            $action = 0  # Deny
        }
        $ruleDetails = @{
            LocalPorts      = $Port
            RemotePorts     = "*"
            LocalAddresses  = "*"
            Enabled         = $true
            Direction       = 1
            Action          = $action
            Grouping        = "Windows Remote Management"
            ApplicationName = "System"
        }
        $rule.Protocol = 6

        $changed = $false
        foreach ($detail in $ruleDetails.GetEnumerator()) {
            $originalValue = $rule.$($detail.Name)
            $newValue = $detail.Value
            Write-Verbose -Message "Checking FW Rule property $($detail.Name) - Actual: '$originalValue', Expected: '$newValue'"
            if ($originalValue -ne $newValue) {
                Write-Verbose -Message "FW Rule property $($detail.Name) does not match, changing rule"
                $rule.$($detail.Name) = $newValue
                $changed = $true
            }
        }

        if ($changed) {
            Write-Verbose -Message "Firewall rule $($rule.Name) needs to be (re)created as config does not match expectation"
            try {
                $fw.Rules.Add($rule)
            }
            catch [System.Runtime.InteropServices.COMException] {
                # E_UNEXPECTED 0x80000FFFF means the rule already exists
                if ($_.Exception.ErrorCode -eq 0x8000FFFF) {
                    Write-Verbose -Message "Firewall rule $($rule.Name) already exists, deleting before recreating"
                    $fw.Rules.Remove($rule.Name)
                    $fw.Rules.Add($rule)
                }
                else {
                    Write-Verbose -Message "Failed to add firewall rule $($rule.Name): $($_.Exception.Message)"
                    throw $_
                }
            }
        }
    }
}

Function Remove-FirewallRule {
    param(
        [Parameter(mandatory = $true)][String]$Name
    )
    $fw = New-Object -ComObject HNetCfg.FWPolicy2

    $rules = $fw.Rules | Where-Object { $_.Name -eq $Name }
    foreach ($rule in $rules) {
        Write-Verbose -Message "Removing firewall rule $($rule.Name)"
        $fw.Rules.Remove($rule.Name)
    }
}

Function Reset-WinRMConfig {
    <#
    .SYNOPSIS
    Resets the WinRM configuration for the current host. This cmdlet will
    always do the following;

        1. Deletes all existing WinRM listeners to start fresh
        2. Removes all certificates in LocalMachine\My so we don't have duplicates
        3. Creates a HTTP and HTTPS listener with a SHA256 self-signed certificate
        4. Enables PSRemoting
        5. Enables Basic auth
        6. Enables CredSSP auth
        7. Tests that both HTTP and HTTPS are accessible over localhost
    .PARAMETER CertificateThumbprint
        [string] - Instead of generating a self-signed certificate, use this
        thumbprint that corresponds to the certificate to use for the listener.
    .INPUTS
    None
    You cannot pipe input to this command.
    .OUTPUTS
    None
    #>
    [CmdletBinding()]
    Param(
        [string]$CertificateThumbprint
    )

    Write-Verbose "Removing all existing WinRM listeners"
    Remove-Item -Path WSMan:\localhost\Listener\* -Force -Recurse

    if (-not $CertificateThumbprint) {
        Write-Verbose "Removing all existing certificate in the personal store"
        Remove-Item -Path Cert:\LocalMachine\My\* -Force -Recurse
    }

    # add a deny Firewall Rule for port 5985 and 5986 to force Vagrant to wait
    # until all the steps are completed before returning. This deny rule is
    # removed at the end of this process
    Write-Verbose -Message "Creating deny WinRM Firewall rules during setup process"
    $httpDenyRule = "PackerWindoze temp WinRM HTTP Deny rule"
    $httpsDenyRule = "PackerWindoze temp WinRM HTTPS Deny rule"
    New-FirewallRule -Name $httpDenyRule -Description $httpDenyRule -Port 5985 -Deny
    New-FirewallRule -Name $httpsDenyRule -Description $httpsDenyRule -Port 5986 -Deny

    Write-Verbose -Message "Enabling Basic authentication"
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

    Write-Verbose -Message "Enabling CredSSP authentication"
    Enable-WSManCredSSP -role server -Force > $null

    Write-Verbose -Message "Setting AllowUnencrypted to False"
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false

    Write-Verbose -Message "Setting the LocalAccountTokenFilterPolicy registry key for remote admin access"
    $tokenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $tokenPropName = "LocalAccountTokenFilterPolicy"
    $tokenKey = Get-Item -Path $tokenPath
    try {
        $tokenValue = $tokenKey.GetValue($tokenPropName, $null)
        if ($tokenValue -ne 1) {
            Write-Verbose -Message "Setting LocalAccountTokenFilterPolicy to 1"
            if ($null -ne $tokenValue) {
                Remove-ItemProperty -Path $tokenPath -Name $tokenPropName
            }
            New-ItemProperty -Path $tokenPath -Name $tokenPropName -Value 1 -PropertyType DWORD > $null
        }
    }
    finally {
        $tokenKey.Dispose()
    }

    Write-Verbose -Message "Creating HTTP listener"
    $selectorSet = @{
        Transport = "HTTP"
        Address   = "*"
    }
    $valueSet = @{
        Enabled = $true
    }
    New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet $selectorSet -ValueSet $valueSet > $null

    Write-Verbose -Message "Creating HTTPS listener"
    if ($CertificateThumbprint) {
        $thumbprint = $CertificateThumbprint
    }
    else {
        $certificate = New-LegacySelfSignedCert -Subject $env:COMPUTERNAME -ValidDays 1095
        $thumbprint = $certificate.Thumbprint
    }
    $selectorSet = @{
        Transport = "HTTPS"
        Address   = "*"
    }
    $valueSet = @{
        CertificateThumbprint = $thumbprint
        Enabled               = $true
    }
    New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet $selectorSet -ValueSet $valueSet > $null

    Write-Verbose -Message "Setting WinRM CredSSP certificate thumbprint"
    Set-Item -Path WSMan:\localhost\Service\CertificateThumbprint -Value $thumbprint

    Write-Verbose -Message "Configuring WinRM HTTPS firewall rule"
    $firewallArgs = @{
        Name        = 'Windows Remote Management (HTTPS-In)'
        Description = 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]'
        Port        = 5986
    }
    New-FirewallRule @firewallArgs

    Write-Verbose "Enabling PowerShell Remoting"
    # Change the verbose output for this cmdlet only as the output is really verbose
    $origVerbose = $VerbosePreference
    $VerbosePreference = "SilentlyContinue"
    Enable-PSRemoting -Force > $null
    $VerbosePreference = $origVerbose

    Write-Verbose -Message "Removing WinRM deny firewall rules as config is complete"
    Remove-FirewallRule -Name $httpDenyRule
    Remove-FirewallRule -Name $httpsDenyRule

    Write-Verbose -Message "Testing out WinRM communication over localhost"
    $invokeArgs = @{
        ComputerName  = "localhost"
        ScriptBlock   = { $env:COMPUTERNAME }
        SessionOption = (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck)
    }
    Invoke-Command @invokeArgs > $null
    Invoke-Command -UseSSL @invokeArgs > $null

    Write-Verbose -Message "WinRM and PS Remoting have been set up successfully"
}

Export-ModuleMember -Function Reset-WinRMConfig
