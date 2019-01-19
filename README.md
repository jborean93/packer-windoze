# packer-windoze

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
* Also include the latest [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH) in the image that starts up automatically
* Each image contain the maximum amount of time available on a Windows evaluation image (usually 180 days) without prompting for a key

The blog post [Using Packer to Create Windows Images](http://www.bloggingforlogging.com/2017/11/23/using-packer-to-create-windows-images/)
contain a more detailed guide on this process and how it all works. Feel free
to read through it if you want to understand each component and how they fit
together more.

## Requirements

To use the scripts in this repo you will need the following;

* [pywinrm](https://pypi.org/project/pywinrm)
* [Packer](https://www.packer.io/docs/install/index.html) >= 1.0.0, 1.2.4 is required for Hyper-V with Server 2008 R2 support
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads) >= 5.1.12
* [Hyper-V](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-on-windows-server) - Server 2008 is not supported with Hyper-V
* [Ansible](https://github.com/ansible/ansible) >= 2.5.1
* `mkisofs` for Windows this needs to be installed in WSL where Ansible is located

When setting `man_packer_setup_host_type: 2008-x64`, Ansible will extract the
evaluation ISO from a self extracting archive. This requires the `unrar`
package to be installed. If you don't want to install this package, manually
extract the ISO on another box and specify the path under
`opt_packer_setup_iso_path`.

To install `mkisofs` and `unrar`, you can run one of the commands below
depending on your distribution;

```bash
# for Debian/Ubuntu
sudo apt-get install mkisofs unrar

# for RHEL/CentOS
sudo yum install mkisofs

sudo yum localinstall --nogpgcheck https://download1.rpmfusion.org/free/el/rpmfusion-free-release-7.noarch.rpm https://download1.rpmfusion.org/nonfree/el/rpmfusion-nonfree-release-7.noarch.rpm
sudo yum install unrar

# for Fedora
sudo dnf install mkisofs

sudo dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
sudo dnf install unrar

# for MacOS (requires Homebrew)
brew install cdrtools unrar
```

## How to Run

To create an image, the process is split up into 2 phases

1. Create the files required for Packer to build and provision an image
2. Run Packer based on the files created above

### Create Packer Files

For Packer to provision a Windows host it first needs an `Autounattend.xml`
file and bootstrapping script to configure the base host requirements needed by
Ansible. Instead of having them already stored in the repo, they are
dynamically created by Ansible based on the configuration provided.

To create the files for a particular host type run;

```bash
ansible-playbook packer-setup.yml -e man_packer_setup_host_type=<host type>

# see below what can be used for <host type> but to create the Packer files for a Server 2012 R2 image run
ansible-playbook packer-setup.yml -e man_packer_setup_host_type=2012r2

# specify custom Chocolatey packages to install instead of vim and sysinternals on the image
ansible-playbook packer-setup.yml -e opt_packer_setup_packages='["pstools", "notepadplusplus"]'

# when running on Windows, you can run this from PowerShell like
bash.exe -ic "ansible-playbook packer-setup.yml -e man_packer_setup_host_type=2012r2 -e opt_packer_setup_builder=hyperv"
```

After running the playbook, a folder which is named after the value of
`man_packer_setup_host_type` will be created and it will contain the following
files;

* `iso/Autounattend.xml`: The answer file used by Windows during the initial install
* `iso/bootstrap.ps1`: A PowerShell script that is run after the initial install to configure the host required by Ansible
* `iso/*`: Other files used in the bootstrapping process like hotfixes and updates required to configure WinRM
* `configure-hyperv-network.ps1`: Used in the Hyper-V builder to set the correct IP for Ansible's inventory file
* `description.md`: The changelog description of that current build
* `hosts.ini`: An Ansible inventory file containing the info required by Ansible during the provisioning phase
* `packer.json`: The Packer definition file the contains all the info that Packer needs to build the image
* `secondary.iso`: The secondary ISO file used to store the `Autounattend.xml`, `bootstrap.ps1`, and other files used in that process
* `vagrantfile.template`: The templated Vagrantfile that is embedded in the Vagrant box produced

When `opt_packer_setup_builder=hyperv`, this process will also create the
Hyper-V switch defined by `opt_packer_setup_hyperv_switch` if it does not
exist. This switch is created as an External Network type with the host OS
allowed to share with the guest. This type of switch is required for 2 reasons;

1. Allows the Windows host to access the guest
2. Allows the guest to access the internet for things like updates and downloading packages

An Internal Network type covers the first point but you need an External
Network type to access the internet.

This switch is NOT cleaned up afterwards automatically.

#### Mandatory Variables

The following parameters must be set using the `-e` arguments;

* `man_packer_setup_host_type`: The host type string that tells packer what to build, see options below

You can set the host type to the following values

* `2008-x86`: Windows Server 2008 Standard 32-bit
* `2008-x64`: Windows Server 2008 Standard 64-bit
* `2008r2`: Windows Server 2008 R2 Standard
* `2012`: Windows Server 2012 Standard
* `2012r2`: Windows Server 2012 R2 Standard
* `2016`: Windows Server 2016 Standard
* `2019`: Windows Server 2019 Standard

The following host types can also be used but it requires the ISO to be
manually downloaded and set with `opt_packager_setup_iso_path`. Microsoft does
not offer evaluation ISOs for these builds so it won't be part of the public
facing images

* `1709`: Windows Server Build 1709 Standard
* `1803`: Windows Server Build 1803 Standard

#### Optional Variables

The following are optional parameters set using the `-e` argument and can
change the way Packer builds the images in the next step;

* `opt_packer_setup_builder`: The Packer builder to use, defaults to `virtualbox` but can be `hyperv` when running on Windows.
* `opt_packer_setup_iso_path`: The local path to the install Windows ISO, this means packer will use this instead of downloading the pre-set evaluation ISO from the internet.
* `opt_packer_setup_iso_wim_label`: The WIM image name to use when installing Windows from an ISO, the process defaults to the Standard edition if not set.
* `opt_packer_setup_username`: (Default: `vagrant`) The name of the user to create in the provisioning process, this is the only user that will available in the image created as the builtin Administrator account is disabled.
* `opt_packer_setup_password`: (Default: `vagrant`) The password for `opt_packer_setup_username`, this password is also set for the builtin Administrator account even though it is disabled in the image.
* `opt_packer_setup_product_key`: The product key to use when installing Windows, do not set this unless you know what you are doing.
* `opt_packer_setup_hyperv_switch`: (Default: `packer-windoze`) The name of the Hyper-V switch to create. There shouldn't be a need to change this unless you know what you're doing.
* `opt_packer_setup_packages`: (Default: `vim`, `sysinternals`) Override the default Chocolatey packages that are installed on each image. This should be a list of valid Chocolatey package names that are packes to the `win_chocolatey` module, see the examples for more details.

To add a post-processor to upload to Vagrant Cloud, add in the following 3
variables;

* `opt_packer_setup_access_token`: The acces token for the Vagrant Cloud API, this is set to the `access_token` key in the packer build file.
* `opt_packer_setup_box_tag`: The shorthand tag for the map that maps to Vagrant Cloud, this is set to the `box_tag` key in the packer build file.
* `opt_packer_setup_version`: The version number for the box which is validated based on semantic versioning, this is set to the `version` key in the packer build file and if ommitted then the latest version in the changelog is used.

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

Once complete a file with the `.box` extension will be created in the same
folder the `packer.json` file is located in. This file can be added to Vagrant
using `vagrant box add <filename>.box` or can be shared with others using your own
methods. The filename is dependent on the builder that was used. When
`opt_packer_setup_builder` is `virtualbox` then it will be `virtualbox.box`,
otherwise `hyperv` will be `hyperv.box`.

## What It Does

Here is a brief step by step overview of what actually happens with the images

1. Packer start a VM under the hypervisor and attaches the ISO that contains the `Autounattend.xml`, `bootstrap.ps1`, and other bootstrap files
2. Windows starts the install process and configures it according to the `Autounattend.xml` file
3. After the install is complete Windows will auto login to the `vagrant` user and run the `bootstrap.ps1` script
4. The bootstrap script will ensure that PowerShell v3 or greater is installed, WinRM is setup and other things
5. Packer detects that WinRM is up and running and starts the provision process which is the Ansible playbook
6. Ansible will then install all available updates and reboot accordingly (this step can take hours so be prepared to wait)
7. Some personalisation tweaks occur such as showing hidden files and folders, file extensions and installing the sysinternals tools
8. Will try to cleanup as much of the WinSXS folder as possible (older hosts are limited in how much it can do)
9. Will remove all non enabled Features if Features on Demand is supported (Server 2012 and newer)
10. Remove pagefile, temp files, log files that are not needed. Defrags the disk and 0's out empty space for the compression to work properly
11. Setup the sysprep template files
12. Remove the WinRM listeners and run the sysprep process to shutdown the host

From this point Packer will create an image of the OS which can be used by
Vagrant. When Vagrant first starts up the image, it will automatically log on
and, rearm the activation key and recreate the WinRM listeners.

## Backlog/Future Work

* Windows Server Core images
* Windows Server Nano images
* Windows 10 32 and 64 bit
* Look at supporting parallel builds
* Look at slipstreaming Windows updates into the evaluation ISO's instead of running the updates from scratch each time
* Look at supporting local WSUS servers during the Update phase to save time and bandwidth
