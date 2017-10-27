# initial bootstrapping script, this script configures the host so that Ansible
# can talk to it, including all pre-requisites for older hosts
$ErrorActionPreference = 'Stop'
$tmp_dir = "$env:SystemDrive\temp"

Function Write-Log($message, $level="INFO") {
    # Poor man's implementation of Log4Net
    $date_stamp = Get-Date -Format s
    $log_entry = "$date_stamp - $level - $message"
    $log_file = "$tmp_dir\bootstrap.log"
    Write-Host $log_entry
    Add-Content -Path $log_file -Value $log_entry
}

Function Reboot-AndResume($action) {
    # need to reboot the server and rerun this script at the next action
    $command = "$env:SystemDrive\Windows\System32\WindowsPowerShell\v1.0\powershell.exe A:\bootstrap.ps1 $action"
    $reg_key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $reg_property_name = "bootstrap"
    Set-ItemProperty -Path $reg_key -Name $reg_property_name -Value $command
    Write-Log -message "rebooting server and continuing bootstrap.ps1 with action '$action'"
    if (Get-Command -Name Restart-Computer -ErrorAction SilentlyContinue) {
        Restart-Computer -Force
    } else {
        # PS v1 (Server 2008) doesn't have the cmdlet Restart-Computer, use el-traditional
        shutdown /r /t 0
    }
}

Function Run-Process($executable, $arguments) {
    $process = New-Object -TypeName System.Diagnostics.Process
    $psi = $process.StartInfo
    $psi.FileName = $executable
    $psi.Arguments = $arguments
    Write-Log -message "starting new process '$executable $arguments'"
    $process.Start() | Out-Null
    
    $process.WaitForExit() | Out-Null
    $exit_code = $process.ExitCode
    Write-Log -message "process completed with exit code '$exit_code'"

    return $exit_code
}

Function Download-File($url, $path) {
    Write-Log -message "downloading url '$url' to '$path'"
    $client = New-Object -TypeName System.Net.WebClient
    $client.DownloadFile($url, $path)
}

Function Extract-Zip($zip, $dest) {
    Write-Log -message "extracting '$zip' to '$dest'"
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem > $null
        $legacy = $false
    } catch {
        $legacy = $true
    }

    if ($legacy) {
        try {
            $shell = New-Object -ComObject Shell.Application
            $zip_src = $shell.NameSpace($zip)
            $zip_dest = $shell.NameSpace($dest)
            $zip_dest.CopyHere($zip_src.Items(), 1044)
        } catch {
            Write-Log -message "failed to extract zip file: $($_.Exception.Message)" -level "ERROR"
            throw $_
        }
    } else {
        try {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $dest)
        } catch {
            Write-Log -message "failed to extract zip file: $($_.Exception.Message)" -level "ERROR"
            throw $_
        }
    }
}

$action = $args[0]
if (-not (Test-Path -Path $tmp_dir)) {
    New-Item -Path $tmp_dir -ItemType Directory | Out-Null
}
Write-Log -message "starting bootstrap.ps1 with action '$action'"

# there are 4 actions the boostrap script can run, the subsequent actions are
# run based on where it is started, e.g. 2008-sp2 goes to powershell-2 which
# goes to ie9 and continues until the WinRM listener is started
#   1. 2008-sp2 - Installs SP2 on Server 2008, eval ISO do not have this pre-installed :( (Server 2008)
#   2. powershell-2 - Installs Powershell 2.0 (Server 2008)
#   3. ie9 - Installs IE9, seems to fail with win_updates (Server 2008)
#   4. dotnet - Installs .NET 4.5 required by Powershell 3.0 (Server 2008 and 2008 R2)
#   5. powershell-3 - Installs Powershell 3.0 (Server 2008 and 2008 R2)
#   6. tiworker-fix - Installs a fix for TiWorker taking up too much memory (Server 2012)
#   7. winrm-hotfix - Installs hotfix that solves OutOfMemoryIssues winrm (Server 2008, 2008 R2, 2012 and 7)
#   8. update-wua - Updates the windows update agent to the latest version (all)
#   9. winrm-listener - Configures WinRM HTTP and HTTPS listener and enables RDP with NLA (all)
#
# These are all actions that need to be run before Ansible can talk to the host
# the older the OS the more tasks that need to be run
switch($action) {
    "2008-sp2" {
        Write-Log -message "install Server 2008 SP2"
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($architecture -eq "AMD64") {
            $sp_url = "https://download.microsoft.com/download/4/7/3/473B909B-7B52-49FE-A443-2E2985D3DFC3/Windows6.0-KB948465-X64.exe"
        } else {
            $sp_url = "https://download.microsoft.com/download/E/7/7/E77CBA41-0B6B-4398-BBBF-EE121EEC0535/Windows6.0-KB948465-X86.exe"
        }
        $sp_filename = $sp_url.Split("/")[-1]
        $sp_file = "$tmp_dir\$sp_filename"
        Download-File -url $sp_url -path $sp_file
        $exit_code = Run-Process -executable $sp_file -arguments "/quiet /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to update Server 2008 to SP2: exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "powershell-2"
    }
    "powershell-2" {
        Write-Log -message "running powershell update to version 2"
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($architecture -eq "AMD64") {
            $ps_url = "https://download.microsoft.com/download/2/8/6/28686477-3242-4E96-9009-30B16BED89AF/Windows6.0-KB968930-x64.msu"
        } else {
            $ps_url = "https://download.microsoft.com/download/F/9/E/F9EF6ACB-2BA8-4845-9C10-85FC4A69B207/Windows6.0-KB968930-x86.msu"
        }
        $ps_filename = $ps_url.Split("/")[-1]
        $ps_file = "$tmp_dir\$ps_filename"
        Download-File -url $ps_url -path $ps_file
        $exit_code = Run-Process -executable $ps_file -arguments "/quiet /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to update Powershell from 1.0 to 2.0: exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "ie9"
    }
    "ie9" {
        Write-Log -message "install Internet Explorer 9"
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($architecture -eq "AMD64") {
            $url = "http://download.windowsupdate.com/msdownload/update/software/uprl/2011/03/wu-ie9-windowsvista-x64_f599c02e7e1ea8a4e1029f0e49418a8be8416367.exe"
        } else {
            $url = "http://download.windowsupdate.com/msdownload/update/software/updt/2011/03/wu-ie9-windowsvista-x86_a2b66ff9e9affda9675dd85ba2b637a882979a25.exe"
        }
        $file = "$tmp_dir\wu-ie9-windowsvista.exe"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable $file -arguments "/quiet /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to install Internet Explorer 9: exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "dotnet"
    }
    "dotnet" {
        Write-Log -message "running .NET update to 4.5"
        $url = "http://download.microsoft.com/download/B/A/4/BA4A7E71-2906-4B2D-A0E1-80CF16844F5F/dotNetFx45_Full_x86_x64.exe"
        $file = "$tmp_dir\dotNetFx45_Full_x86_x64.exe"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable $file -arguments "/q /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to update .NET to 4.5 required by Ansible and WinRM: exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "powershell-3"
    }
    "powershell-3" {
        Write-Log -message "running powershell update to version 3"
        $os_version_minor = [Environment]::OSVersion.Version.Minor
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($architecture -eq "AMD64") {
            $architecture = "x64"
        } else {
            $architecture = "x86"
        }

        if ($os_version_minor -eq 1) {
            $url = "https://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-$($architecture).msu"
        } else {
            $url = "https://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.0-KB2506146-$($architecture).msu"
        }
        $filename = $url.Split("/")[-1]
        $file = "$tmp_dir\$filename"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable $file -arguments "/quiet /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to update Powershell to version 3: exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "winrm-hotfix"
    }
    "tiworker-fix" {
        # TODO: see if killing TiWorker.exe before running speeds this up
        Write-Log -message "installing KB2771431 to fix unresponsive TiWorker"
        $url = "https://download.microsoft.com/download/D/D/C/DDC353A0-A56D-48E8-B2C0-97615C503145/Windows8-RT-KB2771431-x64.msu"
        $file = "$tmp_dir\Windows8-RT-KB2771431-x64.msu"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable $file -arguments "/quiet /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to install KB2771431 for Server 2012 to fix TiWorker issues: exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "winrm-hotfix"
    }
    "winrm-hotfix" {
        $os_version_major = [Environment]::OSVersion.Version.Major
        $os_version_minor = [Environment]::OSVersion.Version.Minor
        $architecture = $env:PROCESSOR_ARCHITECTURE
        $host_string = "$($os_version_major).$($os_version_minor)-$architecture"
        Write-Log -message "installing hotfix KB2842230 with host string $host_string"

        switch($host_string) {
            "6.0-x86" {
                $hotfix_url = "http://hotfixv4.microsoft.com/Windows%20Vista/sp3/Fix467401/6000/free/464091_intl_i386_zip.exe"
            }
            "6.0-AMD64" {
                $hotfix_url = "http://hotfixv4.microsoft.com/Windows%20Vista/sp3/Fix467401/6000/free/464090_intl_x64_zip.exe"
            }
            "6.1-x86" {
                $hotfix_url = "http://hotfixv4.microsoft.com/Windows%207/Windows%20Server2008%20R2%20SP1/sp2/Fix467402/7600/free/463983_intl_i386_zip.exe"
            }
            "6.1-AMD64" {
                $hotfix_url = "http://hotfixv4.microsoft.com/Windows%207/Windows%20Server2008%20R2%20SP1/sp2/Fix467402/7600/free/463984_intl_x64_zip.exe"
            }
            "6.2-x86" {
                $hotfix_url = "http://hotfixv4.microsoft.com/Windows%208%20RTM/nosp/Fix452763/9200/free/463940_intl_i386_zip.exe"
            }
            "6.2-AMD64" {
                $hotfix_url = "http://hotfixv4.microsoft.com/Windows%208%20RTM/nosp/Fix452763/9200/free/463941_intl_x64_zip.exe"
            }
            default {
                $error_message = "unknown host string $host_string, cannot download Hotfix"
                Write-Log -message $error_message -level "ERROR"
                throw $error_message
            }
        }
        $filename = $hotfix_url.Split("/")[-1]
        $compressed_file = "$tmp_dir\$($filename).zip"
        Download-File -url $hotfix_url -path $compressed_file
        Extract-Zip -zip $compressed_file -dest $tmp_dir
        $hotfix_file = Get-Item -Path "$tmp_dir\*KB2842230*.msu"
        if ($hotfix_file -eq $null) {
            $error_message = "unable to find extracted msu file for hotfix KB"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        
        # Now install the hotfix
        $hotfix_args = "/quiet /norestart"
        $exit_code = Run-Process -executable $hotfix_file -arguments $hotfix_args
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to install hotfix from $($hotfix_file): exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "update-wua"
    }
    "update-wua" {
        $os_version_major = [Environment]::OSVersion.Version.Major
        $os_version_minor = [Environment]::OSVersion.Version.Minor
        $architecture = $env:PROCESSOR_ARCHITECTURE
        $host_string = "$($os_version_major).$($os_version_minor)-$architecture"
        Write-Log -message "updating the Windows Update Agent to the latest version with host string '$host_string'"

        # urls are from https://support.microsoft.com/en-au/help/949104/how-to-update-the-windows-update-agent-to-the-latest-version
        switch($host_string) {
            "6.0-x86" {
                $wua_url = "http://download.windowsupdate.com/windowsupdate/redist/standalone/7.6.7600.320/windowsupdateagent-7.6-x86.exe"
            }
            "6.0-AMD64" {
                $wua_url = "http://download.windowsupdate.com/windowsupdate/redist/standalone/7.6.7600.320/windowsupdateagent-7.6-x64.exe"
            }
            "6.1-x86" {
                $wua_url = "http://download.windowsupdate.com/windowsupdate/redist/standalone/7.6.7600.320/windowsupdateagent-7.6-x86.exe"
            }
            "6.1-AMD64" {
                $wua_url = "http://download.windowsupdate.com/windowsupdate/redist/standalone/7.6.7600.320/windowsupdateagent-7.6-x64.exe"
            }
            "6.2-x86" {
                $wua_url = "http://download.windowsupdate.com/c/msdownload/update/software/crup/2014/07/windows8-rt-kb2937636-x86_9c82bea917f34d581ab164eb08f93e2141412d7d.msu"
            }
            "6.2-AMD64" {
                $wua_url = "http://download.windowsupdate.com/c/msdownload/update/software/crup/2014/07/windows8-rt-kb2937636-x64_29e0b587c8f09bcf635c1b79d09c00eef33113ec.msu"
            }
            default {
                $wua_url = $null
            }
        }

        if ($wua_url -ne $null) {
            $wua_filename = $wua_url.Split("/")[-1]
            $wua_file = "$tmp_dir\$wua_filename"
            Download-File -url $wua_url -path $wua_file
            $exit_code = Run-Process -executable $wua_file -arguments "/quiet /norestart"
            if ($exit_code -ne 0 -and $exit_code -ne 3010) {
                $error_message = "failed to install wua update: exit code $exit_code"
                Write-Log -message $error_message -level "ERROR"
                throw $error_message
            }
        } else {
            Write-Log -message "could not match host string $host_string with wua update, assuming wua update isn't needed"
        }
        Reboot-AndResume -action "winrm-listener"
    }
    "winrm-listener" {
        Write-Log -message "downloading WinRM config script and enabling the protocol"
        $url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
        $file = "$tmp_dir\ConfigureRemotingForAnsible.ps1"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable "$env:SystemDrive\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -arguments "-File $file"
        if ($exit_code -ne 0) {
            $error_message = "failed to configure WinRM endpoint required by Ansible"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }

        Write-Log -message "enabling RDP"
        $rdp_wmi = Get-CimInstance -ClassName Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices
        $rdp_enable = $rdp_wmi | Invoke-CimMethod -MethodName SetAllowTSConnections -Arguments @{ AllowTSConnections = 1; ModifyFirewallException = 1 }
        if ($rdp_enable.ReturnValue -ne 0) {
            $error_message = "failed to change RDP connection settings, error code: $($rdp_enable.ReturnValue)"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }

        Write-Log -message "enabling NLA authentication for RDP"
        $nla_wmi = Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace root\CIMV2\TerminalServices
        $nla_wmi | Invoke-CimMethod -MethodName SetUserAuthenticationRequired -Arguments @{ UserAuthenticationRequired = 1 } | Out-Null
        $nla_wmi = Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace root\CIMV2\TerminalServices
        if ($nla_wmi.UserAuthenticationRequired -ne 1) {
            $error_message = "failed to enable NLA"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
    }
    default {
        $error_message = "invalid action '$action', cannot continue"
        Write-Log -message $error_message -level "ERROR"
        throw $error_message
    }
}

Write-Log -message "bootstrap.ps1 complete"
