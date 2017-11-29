## Packer Windoze Image Changelog

This is the changelog of each image version uploaded to the Vagrant Cloud. It
contains a list of changes that each incorporate.

### v0.0.2 - 2017-12-01

#### All

* Create a custom Vagrantfile template for the final image that includes the
  username and other required settings
* Moved sysprep process before the image is created
* Added `slmgr.vbs /rearm` to run just after Vagrant starts the image up to get
  the full eval period possible.
* Removed SSL certificate installed during Packer build process
* Installed [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH)
  v.0.0.23.0 on all images and set to start by default for all hosts except
  Server 2008
* Added .travis-ci file to run [ansible-lint](https://github.com/willthames/ansible-lint)
  on the Ansible files for some testing sanity
* Decided to install the virtualbox guest additions tools as part of the build
  process.
* Added vim to the list of chocolatey packages to help with Core OS installs or
  connecting via SSH


#### Server 1709

* Added support for Windows Server, version 1709, under the host type value of
  `1709`
* This is the first build from the new Windows Server Semi-Annual update
  release cycle and won't be supported as often as the LTSB release of Server
  2016
* Desktop Experience is not installed with this pack so only core is available
* Note: This won't be available in Vagrant Cloud as it is currently closed off
  to the public. If you can download the ISO manually then you can build your
  own private image by setting `opt_packer_setup_iso_path`. This will be the
  case until Microsoft release an evaluation ISO on their evaluation centre.

#### Server 2016

* Will not remove the Features on Demand for Server 2016 until [this](https://social.msdn.microsoft.com/Forums/en-US/2ad1c1d9-09ba-407e-ba03-951c6f2baa34/features-on-demand-server-2016-source-not-found?forum=ws2016)
  is resolved.

#### Server 2008 R2

* Enabled TLSv1.2 cipher support for both client and server components

#### Server 2008

* Disabled screensaver to stop auto logoff by default
* Ensure the TLSv1.2 cipher support package is installed but does not enable
  them, pywinrm fails to work with this enabled and will have to figure the
  reason why before enabling this in a future version


### v0.0.1 - 2017-10-29

* First images built by this repo
