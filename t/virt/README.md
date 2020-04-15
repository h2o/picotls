# Fast and easy Linux Kernel Dev environment

Simply build, setup and run a recent linux kernel within stable debian
on qemu-kvm.

## Some packages required

Some package needed to boot the vm and compile the linux kernel

qemu-kvm flex bison libelf-dev

This script is borrowed from https://github.com/bhesmans/mpsocks, and
slightly modified. The methodology is straightforward: source a set of
functions within your bash environment, which can be applied step by
step to obtain the environment.

$ source picotls_vm_setup.sh

### build a debian image base

$ build_image

This step will prompt you to choose a root password for the vm at the
end of it.

### build the linux kernel, v5.6

$ build_kernel v5.6 6

clone, checkout v5.6 and compile the kernel with 6 threads for kvm usage (with kvm
optimizations)

### Create tap for nw

$ configure_host_tap

Simply configure some interface to the VM (to do once)

### Nat out the tap

$ configure_host_nat

To do once.

### add picotcpls in /root and compile it
$ add_picotcpls

### boot the vm
$ boot_vm

### To shutdown the vm:

From the guest

$ shutdown -h now

From the host:

$ ssh_vm shutdown -h now

### To cleanup:

$ clean_host_tap

$ clean_host_nat

### Typical workflow

Doing once build_image, configure_host_tap, configure_host_nat then
build_kernel and boot_vm each time the kernel code is modified
