$ErrorActionPreference = 'Stop'

Function Test-RegistryProperty($path, $name) {
    # checks whether the registry property exists or no
    try {
        $value = (Get-Item -Path $path).GetValue($name)
        # need to do it this way return ($value -eq $null) does not work
        if ($value -eq $null) {
            return $false
        } else {
            return $true
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        # key didn't exist so the property mustn't
        return $false
    }
}

# we need to remove the auto logon value after logging on automatically
$auto_logon_path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# AutoAdminLogon normally exists and is set to 0
Set-ItemProperty -Path $auto_logon_path -Name AutoAdminLogon -Value "0"

# The rest can be removed
$auto_logon_properties = @('DefaultUserName', 'DefaultPassword', 'ForceAutoLogon')
foreach ($property in $auto_logon_properties) {
    $exists = Test-RegistryProperty -path $auto_logon_path -name $property
    if ($exists) {
        Remove-ItemProperty -Path $auto_logon_path -Name $property | Out-Null
    }
}

# run the sysprep command to shutdown and generalize
&C:\windows\system32\sysprep\sysprep.exe /generalize /oobe /quiet /reboot /unattend:C:\Windows\Panther\Unattend\unattend.xml
