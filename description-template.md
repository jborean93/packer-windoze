## Packer Windoze ### HOST TYPE HERE ###

### Info

This is an image based on the evaluation ISO supplied by Microsoft. It has all
the updates available for the host at the time applied and comes ready to be
run by Vagrant. When Vagrant starts the box, sysprep will automatically run
and create a brand new Windows instance with WinRM up and running.

Details on how to connect are;

* `username`: vagrant
* `password`: vagrant
* `connector`: winrm

Included programs (versions dependent on the Windows version);

* PowerShell v3.0 or higher
* .NET Framework 4.5 or higher
* VirtualBox Guest Additions
* [Chocolatey](https://chocolatey.org/)
* [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
* [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)
* [PsTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools)
* [Vim](https://vim.sourceforge.io/) for Windows

Other configurations from the standard image;

* WinRM HTTP and HTTPS listener with Basic and CredSSP enabled
* [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH) v0.0.23.0 - Except on Server 2008 SP2 images
* Default Administrator account disabled, password is also `vagrant`
* Hidden files and folders and file extensions are shown by default

### Changes

See [packer-windoze CHANGELOG.md](https://github.com/jborean93/packer-windoze/blob/master/CHANGELOG.md)
for more info

* Vagrantfile template is now associated with each image
* Sysprep is now run before the image is created saving time when starting up
  a box
* Evaluation is rearmed after image is started to get the full trial
* Removed the SSL HTTPS certificate created during the Packer build as it is
  redundant after that
* Install Win32-OpenSSH and set to start that when the image is created, this
  is not done with Server 2008 SP2 as it does not work on this version
* Installed the VirtualBox Guest Additions in the image
* Added Vim to the list of installed programs so the core image is more useful

Version specific changes;

