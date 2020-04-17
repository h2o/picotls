#!/bin/bash

# This has been mostly adapted from https://github.com/bhesmans/mpsocks

IMG="debian.img"
DIR="${PWD}/mount_${IMG}"

SUBNET16=${SUBNET16:-"10.66"}
SUBNETSTART=${SUBNETSTART:-"6"}

TABLESTART=665

TAP_PREFIX=${TAP_PREFIX:-"tcpls"}

SOCK_PORT=${SOCK_PORT:-6666}

subnet24() {
	local n=${1:-0}
	echo "${SUBNET16}.$(($n + $SUBNETSTART))"
}

# $1 24's subnet idx, $2 nth subnet's ip
nth_ip() {
	echo "$(subnet24 ${1}).${2}"
}

subnet() {
	echo "$(nth_ip ${1:-0} 0)/24"
}

host_ip() {
	nth_ip ${1:-0} 1
}

host_cidr() {
	echo "$(host_ip ${1:-0})/24"
}

guest_ip() {
	nth_ip ${1:-0} 2
}

guest_cidr() {
	echo "$(guest_ip ${1:-0})/24"
}

build_image() {
	qemu-img create $IMG 4g
	mkfs.ext3 $IMG
	mkdir $DIR
	sudo mount -o loop $IMG $DIR

  sudo debootstrap --components=main,contrib,non-free
  --include=firmware-realtek,ssh,vim,git,build-essential,cmake,libssl-dev,libbrotli-dev,faketime,libscope-guard-perl,libtest-tcp-perl,libbpf-dev,libz-dev --arch amd64 buster $DIR
	
  sudo chroot $DIR passwd root

	# auto up our mgmt interface
	#TODO check EOF when rerun, due to align change
	sudo bash -c "grep -q enp0s3 $DIR/etc/network/interfaces ||
	cat >> $DIR/etc/network/interfaces <<EOF
auto enp0s3
allow-hotplug enp0s3
iface enp0s3 inet dhcp
EOF"

	# install SSH and our key.

	sudo mkdir $DIR/root/.ssh
	sudo chmod 700 $DIR/root/.ssh
	sudo bash -c "cat $HOME/.ssh/id_rsa.pub >> $DIR/root/.ssh/authorized_keys"
	sudo chmod 600 $DIR/root/.ssh/authorized_keys

	# TODO integrate this, i did this to cancel the default route learn over dhcp for mgmt
	# we won't use it.
	# cat /etc/dhcp/dhclient-exit-hooks.d/drop_default
	# if [ "${reason}" = "BOUND" -a "${interface}" = "enp0s3" ] ; then
	#         if [ "$(ip r | grep default | awk '{print $3}')" = "${new_routers}" ] ; then
	#                 ip route del default
	#         fi
	# fi
	sudo umount $DIR
	rmdir $DIR
}

build_kernel() {
  git clone https://github.com/torvalds/linux.git
	cd linux
  git checkout ${1}
  make x86_64_defconfig
  make kvmconfig
  make -j ${2}
	cd ..
}

tap_name() {
	echo "${TAP_PREFIX}${1:-0}"
}

configure_host_tap() {
	local n=${1:-0}
	local tap=$(tap_name $n)

	sudo ip tuntap add mode tap user $(whoami) name $tap
	sudo ip address add $(host_cidr $n) dev $tap
	sudo ip l set dev $tap up
}

clean_host_tap() {
	local tap=$(tap_name ${1:-0})
	sudo ip link del $tap
}

ssh_vm() {
	ssh -o "UserKnownHostsFile /dev/null" -o "StrictHostKeyChecking no" -p 6222 root@localhost $@
}

guest_itf() {
	echo "enp0s$((4 + ${1:-0}))"
}

guest_table() {
	local n=${1:-0}

	if [ "$n" = 0 ] ; then
		echo "main"
	else
		echo $(($TABLESTART + $n))
	fi
}

configure_guest_nw() {
	local n=${1:-0}
	local itf=$(guest_itf $n)
	local table=$(guest_table $n)

	ssh_vm ip addr add $(guest_cidr $n) dev $itf
	ssh_vm ip link set dev $itf up

	ssh_vm ip rule add from $(guest_ip $n) table $table
	ssh_vm ip route del default table $table
	ssh_vm ip route add default via $(host_ip $n) table $table
}

add_picotcpls() {
  ssh_vm git clone https://github.com/frochet/picotcpls.git
  ssh_vm "cd picotcpls; git submodule init; git submodule update; cmake .; make"
}

configure_host_nat() {
	local n=${1:-0}
	sudo iptables -t nat -A POSTROUTING -s $(guest_ip $n)/32 -j MASQUERADE
	sudo iptables -A FORWARD -i $(tap_name $n) -j ACCEPT
	sudo iptables -A FORWARD -o $(tap_name $n) -j ACCEPT
}

clean_host_nat() {
	local n=${1:-0}
	sudo iptables -t nat -D POSTROUTING -s $(guest_ip $n)/32 -j MASQUERADE
	sudo iptables -D FORWARD -i $(tap_name $n) -j ACCEPT
	sudo iptables -D FORWARD -o $(tap_name $n) -j ACCEPT
}

# $1 where to get out from src routing
configure_host_source_routing() {
	local itf=${1?Which itf should I use to go out ???}
	local n=${2:-1}
	local tap=$(tap_name $n)
	local table=$(guest_table $n)

	sudo ip rule add iif $tap table $table

	local gw=$(ip route | grep default | grep $itf | awk '{ print $3}')
	sudo ip route add default via $gw table $table
}

clean_host_source_routing() {
	local n=${2:-1}
	local tap=$(tap_name $n)
	local table=$(guest_table $n)

	sudo ip rule del iif $tap table $table
	sudo ip route del default table $table
}


run_ssh_socks() {
	ssh -o "UserKnownHostsFile /dev/null" -o "StrictHostKeyChecking no" -p 6222 -D $SOCK_PORT -N  root@localhost
}

run_socks() {
	echo "^C to kill it !"
	local method=${1:-ssh}
	run_${method}_socks
}

qemu_vm_netdev() {
	local n=${1:-1}
	local i

	for i in $(seq 0 $(($n - 1))); do
		echo -n "-device e1000,netdev=network${i} "
		echo -n "-netdev tap,id=network${i},ifname=$(tap_name $i),script=no,downscript=no "
	done
}

boot_vm() {
	local n=${1:-1}
	sudo qemu-system-x86_64 -m 512 -kernel ./linux/arch/x86/boot/bzImage -hda $IMG -append "root=/dev/sda rw console=ttyS0" --enable-kvm --nographic -device e1000,netdev=mgmt -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:6222-:22 $(qemu_vm_netdev $n)
}
