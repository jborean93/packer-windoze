## Packer Windoze Image Changelog

_Note: This changelog is generated as part of the packer-setup role. Please add
changelog entries to `roles/packer-setup/vars/main.yml` to modify this file_

This is the changelog of each image version uploaded to the Vagrant Cloud. It
contains a list of changes that each incorporate.

### v0.5.0 - 2018-08-08

* Disabled automatic Windows Update to eliminate post-startup thrash on older images - https://github.com/jborean93/packer-windoze/issues/10
* Updated Win32-OpenSSH to the latest release [v7.7.2.0p1-Beta](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/v7.7.2.0p1-Beta)
* Ensure WinRM HTTPS listener and firewall is configured before allowing Vagrant to detect the host is up - https://github.com/jborean93/packer-windoze/issues/11
* Run ngen before sysprep process to try and speed up the Vagrant init time
* Clean up `C:\Windows\SoftwareDistribution\Download` and `C:\Recovery` as part of the cleanup process

### v0.4.0 - 2018-05-16

* Create a PS Module called `PackerWindoze` that stores the `Reset-WinRMConfig` cmdlet that recreates the WinRM configuration and keep that post sysprep for downstream users to call at any time
* Added support for the Server 1803 image
* Install the full sysinternals suite instead of just PsTools, ProcMon, and ProcExp
* Fixed issue where the WinRM HTTPS firewall rule was not created after sysprep
* Fixed issue where WinRM still allowed unencrypted data after sysprep

### v0.3.0 - 2018-05-10

* Updated OpenSSH version to [v7.6.1.0p1-Beta](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/v7.6.1.0p1-Beta)
* Set the builtin `vagrant` account password to never expire
* Stop using the Ansible ConfigureRemotingForAnsible.ps1 script, swap over to custom script to support SHA256 and simplify steps
* Added Hyper-V builder support by specifying `-e opt_packer_setup_builder=hyperv` - This will only run on a Windows with WSL host and doesn't work for Server 2008
* 2008-x64
    * Enabled TLSv1.2 client support, server is still disabled by default
* 2008-x86
    * Enabled TLSv1.2 client support, server is still disabled by default

### v0.2.0 - 2017-12-01

* Create a custom Vagrantfile template for the final image that includes the username and other required settings
* Moved sysprep process before the image is created
* Added `slmgr.vbs /rearm` to run just after Vagrant starts the image to get the full evaluation period possible
* Removed SSL certificates that were created during the packer build process
* Installed [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH) v0.0.23.0 on all images eacept Server 2008
* Added .travis-ci file to run [ansible-lint](https://github.com/willthames/ansible-lint) on the Ansible files for some testing sanity
* Decided to install the VirtualBox guest additions tools as part fo the build process
* Added vim to the list of chocolatey packages to help with Core OS installs or connecting via SSH
* 1709
    * Added support for Windows Server 1709
    * This won't be available in Vagrant Cloud as it is not avaible as a public evaluation ISO
* 2016
    * Will not remove Features on Demand until [this](https://social.msdn.microsoft.com/Forums/en-US/2ad1c1d9-09ba-407e-ba03-951c6f2baa34/features-on-demand-server-2016-source-not-found?forum=ws2016) is resolved
* 2008r2
    * Enabled TLSv1.2 cipher support for both the client and server components
* 2008-x64
    * Disabled screensaver to stop auto logoff by default
    * Ensure TLSv1.2 cipher support KB is installed but not enabled due to bug in the server implementation
* 2008-x86
    * Disabled screensaver to stop auto logoff by default
    * Ensure TLSv1.2 cipher support KB is installed but not enabled due to bug in the server implementation

### v0.0.1 - 2017-10-29

* First images built by this process

