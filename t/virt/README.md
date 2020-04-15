
Simply build, setup and run a recent linux kernel within stable debian
on qemu-kvm.

This script is borrowed from https://github.com/bhesmans/mpsocks, and
slightly modified

source picotls_vm_setup.sh

# build a debian image base
build_image

# build the linux kernel, v5.6
build_kernel v5.6

# Create tap for nw
configure_host_tap

# Nat out the tap
configure_host_nat

# add picotcpls in /root and compile it
add_pictocpls

# boot the vm
boot_vm

# To shutdown the vm:

shutdown -h now

To cleanup:

clean_host_tap

clean_host_nat

# Typical workflow

Doing once build_image, configure_host_tap, configure_host_nat then
build_kernel and boot_vm each time the kernel code is modified
