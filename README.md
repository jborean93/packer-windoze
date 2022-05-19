# packer-windoze

This repo contains code that can generate Vagrant boxes.
The overall goal is to cover supported Windows Server OS'.

Each image is designed to be;

* Fully updated at the time of creation
* As small as can be possible for a Windows image
* Contain minimal tools useful for Windows development such as the sysinternals suite
* Enable WinRM (HTTP and HTTPS) and RDP on creation in Vagrant allowing other tools to interact with a new image without manual interaction
* Incldues `pwsh` (formally known as PowerShell Core) on all host types except for Server 2012
* Also include the latest [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH) in the image that starts up automatically
* Each image contain the maximum amount of time available on a Windows evaluation image (usually 180 days) without prompting for a key

The blog post [Using Packer to Create Windows Images](http://www.bloggingforlogging.com/2017/11/23/using-packer-to-create-windows-images/) contain a more detailed guide on this process and how it all works.
The contents there are outdated as `Packer` is no longer used but the generic concepts still apply here.
Feel free to read through it if you want to understand each component and how they fit together more.

_Note: This repo used to use Packer to build the Vagrant images (hence the name) but no longer does._

## Requirements

To use the scripts in this repo you will need the following;

* [Ansible](https://github.com/ansible/ansible) >= 2.9.0
* `mkisofs` to build the bootstrapping iso for Windows
* `pigz` to compress the resulting Vagrant box image

The following Python libraries are also used:

* [httpx](https://pypi.org/project/httpx/)
* [psutil](https://pypi.org/project/psutil/)
* [pypsrp](https://pypi.org/project/pypsrp/)
* [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) to retrieve the latest Windows Updates for the build

One of the following hypervisers as defined by `platform`:

* [VirtualBox](https://www.virtualbox.org/wiki/Downloads) >= 5.1.12
* [Hyper-V](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-on-windows-server)
* [QEMU](https://www.qemu.org/)

To install `mkisofs` and `pigz`, you can run one of the commands below depending on your distribution;

```bash
# for Debian/Ubuntu
sudo apt-get install mkisofs pigz

# for RHEL/CentOS
sudo yum install mkisofs pigz

# for Fedora
sudo dnf install genisoimage pigz

# for MacOS (requires Homebrew)
brew install cdrtools pigz
```

The Ansible requirements can be installed with

```bash
pip install -r requirements.txt
ansible-galaxy role install -r requirements.yml -p roles
ansible-galaxy collection install -r requirements.yml -p collections
```

## How to Run

The imaging process uses Ansible from start to finish and in most cases can be rerun for it to take off where it started.
To start the process run the following script:

```bash
ansible-playbook main.yml --limit '*2022'
```

This will build the Windows Server 2022 image for QEMU.
You can change `*2022` to the Windows version as defined in inventory.yml that you wish to build (the `*` is important).
The following options can also be specified with `-e` to change the build behaviour:

* `platform`: The Hypervisor to build for - can be `qemu`, `virtualbox`, or `hyperv` (default: `qemu`).
* `headless`: Dont't display the VM console during the build process (default: `true`)
* `output_dir`: The base directory to store the output/build files (default: `{{ playbook_dir }}/output`).
* `setup_username`: The name of the user to create on the base image
* `setup_password`: The password to apply to the username that is created.
* `iso_src_<host>`: The URL or path to use for the install ISO, change `<host>` to the inventory hostname, e.g. `2022`, or `2019`.
* `iso_checksum_<host>`: The checksum for `iso_src`, change `<host>` to the inventory hostname, e.g. `2022`, or `2019`.
* `iso_wim_label_<host>`: The Windows install WIM label to install, change `<host>` to the inventory hostname, e.g. `2022`, or `2019`.

It is technically possible to build more than 1 image at a time by specifying multiple hosts with `--limit` but it is recommended to kick off the runs in parallel to keep better track.

After running the image process will have created a few files in `{{ output_dir }}/{{ host }}`:

* `description.md`: A markdown description of the box created.
* `{{ platform }}.box`: The box for the specific platform hypervisor.

### Hyper-V and WSL

Because Ansible cannot run natively on Windows the Hyper-V builder must be run on WSL.
The current process has been tested on WSL2 and will probably not work for WSL1.
Before kicking off the run on WSL you must ensure that you've started the WSL process as an administrator so it has access to manage Hyper-V VMs.
You also need to either run this repo from a Windows path or specify `-e output_dir=/mnt/c/some/path` so that Hyper-V can access the build artifacts.


## What It Does

Here is a brief step by step overview of what actually happens with the images

1. Ansible prepares the unattended install of Windows including the latest available updates and install ISOs
1. Ansible kicks off the Hypervisor to create and run the VM
1. Windows starts the install process and configures it according to the `Autounattend.xml` file generated by Ansible
1. After the install process is complete, Windows will auto login the `vagrant` user and run the `bootstrap.ps1` script
1. The bootstrap script will ensure that the base updates are applied and WinRM is set up for Ansible to talk to
1. Ansible will then run the provisioning steps against that host over the newly set up WinRM connection
1. Ansible will then install all available updates and reboot accordingly (this step can take hours so be prepared to wait)
1. Some personalisation tweaks occur such as showing hidden files and folders, file extensions and installing the sysinternals tools
1. Will try to cleanup as much of the WinSXS folder as possible (older hosts are limited in how much it can do)
1. Will remove all non enabled Features if Features on Demand is supported (Server 2012 and newer)
1. Remove pagefile, temp files, log files that are not needed. Defrags the disk and 0's out empty space for the compression to work properly
1. Setup the sysprep template files
1. Remove the WinRM listeners and run the sysprep process to shutdown the host

From this point Ansible will create an image of the OS which can be used by Vagrant.
When Vagrant first starts up the image, it will automatically log on and, rearm the activation key and recreate the WinRM listeners.
