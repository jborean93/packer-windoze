$ErrorActionPreference = 'Stop'

$reg_winlogon_path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $reg_winlogon_path -Name AutoAdminLogon -Value 0
Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultUserName -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultPassword -ErrorAction SilentlyContinue

PowerShell.exe -ExecutionPolicy ByPass -File C:\temp\ConfigureRemotingForAnsible.ps1 -EnableCredSSP -ForceNewSSLCert
