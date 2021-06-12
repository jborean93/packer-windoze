$ErrorActionPreference = 'Stop'

Function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $Message,

        [ValidateSet('Info', 'Error')]
        [String]
        $Level = 'Info'
    )

    $dateStr = Get-Date -Format s
    $msg = '{0} - {1} - {2}' -f $dateStr, $Level.ToUpper(), $Message

    Write-Host $msg
    $logFile = Join-Path $PSScriptRoot 'sysprep-setup.log'
    Add-Content -Path $logFile -Value $msg
}

$action = $args[0]
switch( $action) {
    "post-sysprep" {
        Write-Log -Message "Deleting packer shutdown scheduled task"
        &schtasks.exe /Delete /TN "packer-shutdown" /F

        Write-Log -Message "Removing the sysprep files as they are no longer needed"
        Remove-Item -Path C:\Windows\Panther\Unattend -Force -Recurse > $null

        Write-Log -Message "Disabling the Administrator account as it is not needed"
        &cmd.exe /c net user Administrator /active:no

        Write-Log -Message "Disabling the password expiration of the current account"
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
        $user = $adsi.Children | Where-Object {
            if ($_.SchemaClassName -ne 'User') {
                return $false
            }

            $userSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $_.objectSid[0], 0
            $userSid.Equals($sid)
        }
        $user.UserFlags = $user.UserFlags.Value -bor 65536  # ADS_UF_DONT_EXPIRE_PASSWD
        $user.SetInfo()

        Write-Log -Message "Setting sshd services to auto start"
        Set-Service -Name sshd -StartupType Automatic
        Set-Service -Name ssh-agent -StartupType Automatic

        Write-Log -Message "Rearming the host using slmgr.vbs /rearm"
        &C:\Windows\System32\cscript.exe C:\Windows\System32\slmgr.vbs /rearm

        $runonceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        $psPath = "$env:SystemDrive\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

        Write-Log -Message "Restarting the host to rerun script with action winrm-active"
        $command = "$psPath $PSCommandPath winrm-active"
        Set-ItemProperty -Path $runonceKey -Name "bootstrap" -Value $command
        Restart-Computer -Force
    }
    "winrm-active" {
        Write-Log -Message "Deleting auto logon entries from registry"
        $regWinlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Set-ItemProperty -Path $regWinlogon -Name AutoAdminLogon -Value 0
        Remove-ItemProperty -Path $regWinlogon -Name DefaultUserName -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $regWinlogon -Name DefaultPassword -ErrorAction SilentlyContinue

        Write-Log -Message "Setting the rearm key back to 0 so people in the future can rearm the OS"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name SkipRearm -Value 0

        Write-Log -Message "Recreate the WinRM listeners"
        Reset-WinRMConfig -Verbose

        # Older Windows hosts (Server 2012) uses a SHA1 cert which newer OpenSSL versions don't support.
        # We just replace on all hosts to make things simple and uniform
        Write-Log -Message "Updating RDP certificate to a SHA256 backed cert"
        $thumbprint = Get-Item WSMan:\localhost\Listener\*\* |
            Where-Object { $_.Name -eq 'CertificateThumbprint' -and $_.Value } |
            Select-Object -First 1 -ExpandProperty Value

        Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace ROOT\CIMV2\TerminalServices |
            Set-CimInstance -Property @{ SSLCertificateSHA1Hash = $thumbprint }

        Write-Log -Message "Cleaning up C:\temp and logging off"
        Remove-Item -Path C:\temp -Force -Recurse
        New-Item -Path C:\temp -ItemType Directory

        &cmd.exe /c logoff
    }
}
