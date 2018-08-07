Function New-LegacySelfSignedCert($subject, $valid_days) {
    Write-Verbose -Message "Creating self-signed certificate of CN=$subject for $valid_days days"
    $subject_name = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $subject_name.Encode("CN=$subject", 0)

    $private_key = New-Object -ComObject X509Enrollment.CX509PrivateKey
    $private_key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $private_key.KeySpec = 1
    $private_key.Length = 4096
    $private_key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $private_key.MachineContext = 1
    $private_key.Create()

    $server_auth_oid = New-Object -ComObject X509Enrollment.CObjectId
    $server_auth_oid.InitializeFromValue("1.3.6.1.5.5.7.3.1")

    $ekuoids = New-Object -ComObject X509Enrollment.CObjectIds
    $ekuoids.Add($server_auth_oid)

    $eku_extension = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
    $eku_extension.InitializeEncode($ekuoids)

    $name = @($env:COMPUTERNAME, ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).Hostname))
    $alt_names = New-Object -ComObject X509Enrollment.CAlternativeNames
    foreach ($name in $name) {
        $alt_name = New-Object -ComObject X509Enrollment.CAlternativeName
        $alt_name.InitializeFromString(0x3, $name)
        $alt_names.Add($alt_name)
    }
    $alt_names_extension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $alt_names_extension.InitializeEncode($alt_names)

    $digital_signature = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
    $key_encipherment = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
    $key_usage = [int]($digital_signature -bor $key_encipherment)
    $key_usage_extension = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
    $key_usage_extension.InitializeEncode($key_usage)
    $key_usage_extension.Critical = $true

    $signature_oid = New-Object -ComObject X509Enrollment.CObjectId
    $sha256_oid = New-Object -TypeName Security.Cryptography.Oid -ArgumentList "SHA256"
    $signature_oid.InitializeFromValue($sha256_oid.Value)

    $certificate = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
    $certificate.InitializeFromPrivateKey(2, $private_key, "")
    $certificate.Subject = $subject_name
    $certificate.Issuer = $certificate.Subject
    $certificate.NotBefore = (Get-Date).AddDays(-1)
    $certificate.NotAfter = $certificate.NotBefore.AddDays($valid_days)
    $certificate.X509Extensions.Add($key_usage_extension)
    $certificate.X509Extensions.Add($alt_names_extension)
    $certificate.X509Extensions.Add($eku_extension)
    $certificate.SignatureInformation.HashAlgorithm = $signature_oid
    $certificate.Encode()

    $enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
    $enrollment.InitializeFromRequest($certificate)
    $certificate_data = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certificate_data, 0, "")

    $parsed_certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $parsed_certificate.Import([System.Text.Encoding]::UTF8.GetBytes($certificate_data))

    return $parsed_certificate
}

Function New-FirewallRule {
    param(
        [Parameter(mandatory=$true)][String]$Name,
        [Parameter(mandatory=$true)][String]$Description,
        [Parameter(mandatory=$true)][int]$Port,
        [Parameter()][Switch]$Deny
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
        $rule_details = @{
            LocalPorts = $Port
            RemotePorts = "*"
            LocalAddresses = "*"
            Enabled = $true
            Direction = 1
            Action = $action
            Grouping = "Windows Remote Management"
            ApplicationName = "System"
        }
        $rule.Protocol = 6
    
        $changed = $false
        foreach ($detail in $rule_details.GetEnumerator()) {
            $original_value = $rule.$($detail.Name)
            $new_value = $detail.Value
            Write-Verbose -Message "Checking FW Rule property $($detail.Name) - Actual: '$original_value', Expected: '$new_value'"
            if ($original_value -ne $new_value) {
                Write-Verbose -Message "FW Rule property $($detail.Name) does not match, changing rule"
                $rule.$($detail.Name) = $new_value
                $changed = $true
            }
        }
    
        if ($changed) {
            Write-Verbose -Message "Firewall rule $($rule.Name) needs to be (re)created as config does not match expectation"
            try {
                $fw.Rules.Add($rule)
            } catch [System.Runtime.InteropServices.COMException] {
                # E_UNEXPECTED 0x80000FFFF means the rule already exists
                if ($_.Exception.ErrorCode -eq 0x8000FFFF) {
                    Write-Verbose -Message "Firewall rule $($rule.Name) already exists, deleting before recreating"
                    $fw.Rules.Remove($rule.Name)
                    $fw.Rules.Add($rule)
                } else {
                    Write-Verbose -Message "Failed to add firewall rule $($rule.Name): $($_.Exception.Message)"
                    throw $_
                }
            }
        }
    }
}

Function Remove-FirewallRule {
    param(
        [Parameter(mandatory=$true)][String]$Name
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
        6. Enabled CredSSP auth
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
    $http_deny_rule = "PackerWindoze temp WinRM HTTP Deny rule"
    $https_deny_rule = "PackerWindoze temp WinRM HTTPS Deny rule"
    New-FirewallRule -Name $http_deny_rule -Description $http_deny_rule -Port 5985 -Deny
    New-FirewallRule -Name $https_deny_rule -Description $https_deny_rule -Port 5986 -Deny

    Write-Verbose -Message "Enabling Basic authentication"
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
    
    Write-Verbose -Message "Enabling CredSSP authentication"
    Enable-WSManCredSSP -role server -Force > $null
    
    Write-Verbose -Message "Setting AllowUnencrypted to False"
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false

    Write-Verbose -Message "Setting the LocalAccountTokenFilterPolicy registry key for remote admin access"
    $reg_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $reg_prop_name = "LocalAccountTokenFilterPolicy"
    
    $reg_key = Get-Item -Path $reg_path
    $reg_prop = $reg_key.GetValue($reg_prop_name)
    if ($reg_prop -ne 1) {
        if ($null -eq $reg_prop) {
            Remove-ItemProperty -Path $reg_path -Name $reg_prop_name
        }
        New-ItemProperty -Path $reg_path -Name $reg_prop_name -Value 1 -PropertyType DWord > $null
    }

    Write-Verbose -Message "Creating HTTP listener"
    $selector_set = @{
        Transport = "HTTP"
        Address = "*"
    }
    $value_set = @{
        Enabled = $true
    }
    New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet $selector_set -ValueSet $value_set > $null
    
    Write-Verbose -Message "Creating HTTPS listener"
    if ($CertificateThumbprint) {
        $thumbprint = $CertificateThumbprint
    } else {
        $certificate = New-LegacySelfSignedCert -subject $env:COMPUTERNAME -valid_days 1095
        $thumbprint = $certificate.Thumbprint
    }
    $selector_set = @{
        Transport = "HTTPS"
        Address = "*"
    }
    $value_set = @{
        CertificateThumbprint = $thumbprint
        Enabled = $true
    }
    New-WSManInstance -ResourceURI "winrm/config/Listener" -SelectorSet $selector_set -ValueSet $value_set > $null

    Write-Verbose -Message "Configuring WinRM HTTPS firewall rule"
    New-FirewallRule -Name "Windows Remote Management (HTTPS-In)" `
        -Description "Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]" `
        -Port 5986

    Write-Verbose "Enabling PowerShell Remoting"
    # Change the verbose output for this cmdlet only as the output is really verbose
    $orig_verbose = $VerbosePreference
    $VerbosePreference = "SilentlyContinue"
    Enable-PSRemoting -Force > $null
    $VerbosePreference = $orig_verbose

    Write-Verbose -Message "Removing WinRM deny firewall rules as config is complete"
    Remove-FirewallRule -Name $http_deny_rule
    Remove-FirewallRule -Name $https_deny_rule
    
    Write-Verbose -Message "Testing out WinRM communication over localhost"
    $session_option = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $invoke_args = @{
        ComputerName = "localhost"
        ScriptBlock = { $env:COMPUTERNAME }
        SessionOption = $session_option
    }
    Invoke-Command @invoke_args > $null
    Invoke-Command -UseSSL @invoke_args > $null
    
    Write-Verbose -Message "WinRM and PS Remoting have been set up successfully"
}

Export-ModuleMember -Function Reset-WinRMConfig
