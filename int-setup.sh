modprobe dummy
ip link add eth1 type dummy
link show eth1
ip addr add 192.168.80.196/20 brd + dev eth1 label eth1:0
ip link set dev eth1 up
ip link set dev eth1 promisc on