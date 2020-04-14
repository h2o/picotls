
Simply build, setup and run a recent linux kernel within stable debian
on qemu-kvm.

This script is borrowed from https://github.com/bhesmans/mpsocks, and
slightly modified

source picotls_vm_setup.sh

# build a debian image base
build_image

# build mptcp kernel
build_kernel

# Create tap for nw
configure_host_tap

# Nat out the tap
configure_host_nat

# boot the vm
boot_vm


