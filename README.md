# packer-windoze

_This is still a work in progress and some things are subject to change_

This repo contains code that can generate Packer templates designed to build
and package Windows templates for use with Vagrant boxes. The overall goal is
to cover all supported Windows OS' included Windows Server, Server Core,
Server Nano and the Desktop OS' but the main focus is on the Windows Server
images.

Each image is designed to be;

* Fully updated at the time of creation
* As small as can be possible for a Windows image
* Contain minimal tools useful for Windows development such as the sysinternals suite
* Enable WinRM (HTTP and HTTPS) and RDP on creation in Vagrant allowing other tools to interact with a new image without manual interaction
* Each image contain the maximum amount of time available on a Windows evaluation image (usually 180 days) without prompting for a key

## Requirements

To use the scripts in this repo you will need the following;

* [Packer](https://www.packer.io/docs/install/index.html) >= 1.0.0
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads) >= 5.1.12
* [Ansible](https://github.com/ansible/ansible) >= 2.5 or devel

_Note: as of writting this Ansible 2.5 has not been officially released, please checkout from source on the devel branch_

## How to Run

To create an image, the process is split up into 2 phases

1. Create the files required for Packer to build and provision an image
2. Run Packer based on the files created above

### Create Packer Files

For Packer to provision a Windows host it first needs an `Autounattend.xml`
file and bootstrapping script to configure the base host requirements needed by
Ansible. Instead of having them already stored in the repo, they are
dynamically created by Ansible.

To create the files for a particular host type run;

```bash
ansible-playbook packer-setup.yml -e man_packer_setup_host_type=<host type>

# see below what can be used for <host type> but to create the Packer files for a Server 2012 R2 image run
ansible-playbook packer-setup.yml -e man_packer_setup_host_type=2012r2
```

After running the playbook, a folder named based on the value set for
`man_packer_setup_host_type` will be created and it will contain the following
files;

* `Autounattend.xml`: The answer file used by Windows during the initial install
* `bootstrap.ps1`: A PowerShell script that is run after the initial install to configure the host required by Ansible
* `hosts.ini`: An Ansible inventory file containing the info required by Ansible during the provisioning phase
* `packer.json`: The Packer definition file the contains all the info that Packer needs to build the image

#### Mandatory Variables

The following parameters must be set using the `-e` arguments;

* `man_packer_setup_host_type`: The host type string that tells packer what to build, see options below

You can set the host type to the following values

* `2008`: Windows Server 2008 Standard 64-bit
* `2008r2`: Windows Server 2008 R2 Standard
* `2012`: Windows Server 2012 Standard
* `2012r2`: Windows Server 2012 R2 Standard
* `2016`: Windows Server 2016 Standard

#### Optional Variables

The following are optional parameters set using the `-e` argument and can
change the way Packer builds the images in the next step;

* `opt_packer_setup_iso_path`: The local path to the install Windows ISO, this means packer will use this instead of downloading the pre-set evaluation ISO from the internet.
* `opt_packer_setup_iso_wim_label`: The WIM image name to use when installing Windows from an ISO, the process defaults to the Standard edition if not set.
* `opt_packer_setup_username`: (Default: `vagrant`) The name of the user to create in the provisioning process, this is the only user that will available in the image created as the builtin Administrator account is disabled.
* `opt_packer_setup_password`: (Default: `vagrant`) The password for `opt_packer_setup_username`, this password is also set for the builtin Administrator account even though it is disabled in the image.

### Create Images with Packer

Once the packer files have been created under it's own folder, Packer can now
be used to create the image. Run the following to start the process

```bash
packer build -force <host_type>/packer.json

# replace <host_type> with the type to build, e.g. for Server 2012 R2
packer build -force 2012r2/packer.json
```

This process takes a looong time to finish as Packer will download the ISO,
install Windows and finally configure Windows. The best thing to do is to run
this overnight or as a background process.

Once complete a `.box` file will be created in the same folder the
`packer.json` file is located in. This file can be added to Vagrant using
`vagrant box add file.box` or can be shared with others using your own methods.

## What It Does

Here is a brief step by step overview of what actually happens with the images

1. Packer start a VM under VirtualBox and attactes the `Autounattend.xml` and `bootstrap.ps1` script to the floppy disk (`A:` drive)
2. Windows starts the install process and configures it according to the `Autounattend.xml` file
3. After the install is complete Windows will auto login to the `vagrant` user and run the `bootstrap.ps1` script
4. The bootstrap script will ensure that PowerShell v3 or greater is installed, WinRM is setup and other things
5. Packer detects that WinRM is up and running and starts the provision process which is the Ansible playbook
6. Ansible will then install all available updates and reboot accordingly (this step can take hours so be prepared to wait)
7. Some personalisation tweaks occur such as showing hidden files and folders, file extensions and installing the sysinternals tools
8. Will try to cleanup as much of the WinSXS folder as possible (older hosts are limited in how much it can do)
9. Will remove all non enabled Features if Features on Demand is supported (Server 2012 and newer)
10. Remove pagefile, temp files, log files that are not needed. Defrags the disk and 0's out empty space for the compression to work properly
11. Setup the sysprep files and add flags for Windows to automatically run sysprep on the next login
12. Remove the WinRM listeners and shutdown the host

From this point Packer will create an image of the OS which can be used by
Vagrant. Due to the actions above, when Vagrant first starts up the image it
will automatically log on and start the sysprep process. It will reboot and on
the next startup, recreate the WinRM listeners and end the startup process.

Because the sysprep happens straight after Vagrant starts the image, the launch
time is a bit longer than normal but the full 180 days will be available in the
evaluation time.

## Backlog/Future Work

* Windows Server 2008 32 bit
* Windows Server Core images
* Windows Server Nano images
* Windows Vista 32 and 64 bit
* Windows 7 32 and 64 bit
* Windows 8.1 32 and 64 bit
* Windows 10 32 and 64 bit
* Look at supporting parallel builds
* Look at downloading the evaluation ISO's and storing them locally (extract Server 2008 from exe if possible)
* Look at slipstreaming Windows updates into the evaluation ISO's instead of running the updates from scratch each time
* Look at supporting local WSUS servers during the Update phase to save time and bandwidth
