#Requires -Version 3.0

<#
This script is really a brute force method of setting up the WinRM listeners.
It does the following
    1. Deletes all existing WinRM listeners to start fresh
    2. Removes all certificates in LocalMachine\My so we don't have duplicates
    3. Creates a HTTP and HTTPS listener with a SHA256 self-signed certificate
    4. Enables PSRemoting
    5. Enables Basic auth
    6. Enabled CredSSP auth
    7. Tests that both HTTP and HTTPS are accessible over localhost
#>

[CmdletBinding()]
Param()
$ErrorActionPreference = "Stop"

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

Write-Verbose "Removing all existing WinRM listeners"
Remove-Item -Path WSMan:\localhost\Listener\* -Force -Recurse

Write-Verbose "Removing all existing certificate in the personal store"
Remove-Item -Path Cert:\LocalMachine\My\* -Force -Recurse

Write-Verbose -Message "Creating HTTP listener"
$selector_set = @{
    Transport = "HTTP"
    Address = "*"
}
$value_set = @{
    Enabled = $true
}
New-WSManInstance -ResourceURI "winrm/config/Listener" -SelectorSet $selector_set -ValueSet $value_set > $null

$certificate = New-LegacySelfSignedCert -subject $env:COMPUTERNAME -valid_days 1095
$selector_set = @{
    Transport = "HTTPS"
    Address = "*"
}
$value_set = @{
    Hostname = $certificate.Subject.Replace("CN=", "")
    CertificateThumbprint = $certificate.Thumbprint
    Enabled = $true
}

Write-Verbose -Message "Creating HTTPS listener"
New-WSManInstance -ResourceURI "winrm/config/Listener" -SelectorSet $selector_set -ValueSet $value_set > $null

Write-Verbose "Enabling PowerShell Remoting"
# This configured the WinRM service and other basic tasks
Enable-PSRemoting -Force > $null

Write-Verbose -Message "Enabling Basic authentication"
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

Write-Verbose -Message "Enabling CredSSP authentication"
Enable-WSManCredSSP -role server -Force > $null

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
