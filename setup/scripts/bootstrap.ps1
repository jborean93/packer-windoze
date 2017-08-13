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
    $command = "$env:SystemDrive\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy ByPass -File A:\bootstrap.ps1 $action"
    $reg_key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $reg_property_name = "bootstrap"
    Set-ItemProperty -Path $reg_key -Name $reg_property_name -Value $command
    Write-Log -message "rebooting server and continuing bootstrap.ps1 with action '$action'"
    Restart-Computer -Force
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
    $client = New-Object -Typename System.Net.WebClient
    $client.DownloadFile($url, $path)
}

$action = $args[0]
if (-not (Test-Path -Path $tmp_dir)) {
    New-Item -Path $tmp_dir -ItemType Directory | Out-Null
}
Write-Log -message "starting bootstrap.ps1 with action '$action'"

# there are 4 actions the boostrap script can run, the subsequent actions are
# run based on where it is started, e.g. 2008-sp2 goes to dotnet which goes to
# powershell and finally default.
#   1. 2008-sp2 - Installs SP2 on Server 2008, eval ISO do not have this pre-installed :( (Server 2008)
#   2. dotnet - Installs .NET 4.5 required by Powershell 4.0 (Server 2008 and 2008 R2)
#   3. powershell - Installs Powershell 4.0 (Server 2008 and 2008 R2)
#   4. winrm-hotfix - Installs hotfix that solves OutOfMemoryIssues winrm (Server 2008, 2008 R2, 2012 and 7)
#   5. default - Configures WinRM HTTP and HTTPS listener (all)
#
# These are all actions that need to be run before Ansible can talk to the host
# the older the OS the more tasks that need to be run
switch($action) {
    "2008-sp2" {
        Write-Log -message "install Server 2008 SP2"
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($architecture -eq "AMD64") {
            $architecture = "x64"
        } else {
            $architecture = "x86"
        }
        $url = "https://download.microsoft.com/download/4/7/3/473B909B-7B52-49FE-A443-2E2985D3DFC3/Windows6.0-KB948465-$($architecture).exe"
        $file = "$tmp_dir\Windows6.0-KB948465-$($architecture).exe"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable $file -arguments "/quiet /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to update Server 2008 to SP2: exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "dotnet"
        break
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
        Reboot-AndResume -action "powershell"
        break
    }
    "powershell" {
        Write-Log -message "running powershell update to version 4"
        $os_version_minor = [Environment]::OSVersion.Version.Minor
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($architecture -eq "AMD64") {
            $architecture = "x64"
        } else {
            $architecture = "x86"
        }
        
        if ($os_version_minor -eq 1) {
            $url = "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-$($architecture).msu"
        } else {
            $url = "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.0-KB2506146-$($architecture).msu"
        }
        $filename = $url.Split("/")[-1]
        $file = "$tmp_dir\$filename"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable $file -arguments "/quiet /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to update Powershell to 4: exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action "winrm-hotfix"
        break
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

        Write-Log -message "extracting hotfix from $compressed_file"
        $shell = New-Object -ComObject Shell.Application
        $zip_src = $shell.NameSpace($compressed_file)
        $zip_dest = $shell.NameSpace($tmp_dir)
        # The hotfix file is the first file in the zip, need to loop through the zip contents
        foreach ($entry in $zip_src.Items()) {
            $hotfix_filename = "$($entry.Name).msu"
            $zip_dest.CopyHere($entry, 1044)
        }
        Write-Log -message "extraction complete, hotfix extract filename is '$hotfix_filename'"
        
        # Now install the hotfix
        $hotfix_file = "$tmp_dir\$hotfix_filename"
        $hotfix_args = "/quiet /norestart"
        $exit_code = Run-Process -executable $hotfix_file -arguments $hotfix_args
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_message = "failed to install hotfix from $($hotfix_file): exit code $exit_code"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        Reboot-AndResume -action ""
        break
    }
    default {
        # This would be the final task to run which downloads the Ansible
        # WinRM configuration script and runs it
        $url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
        $file = "$tmp_dir\ConfigureRemotingForAnsible.ps1"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable "cmd.exe" -arguments "/c $env:SystemDrive\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy ByPass -File $file"
        if ($exit_code -ne 0) {
            $error_message = "failed to configure WinRM endpoint required by Ansible"
            Write-Log -message $error_message -level "ERROR"
            throw $error_message
        }
        break
    }
}

Write-Log -message "bootstrap.ps1 complete"
