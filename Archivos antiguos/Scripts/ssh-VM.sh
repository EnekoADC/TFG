machine="${1:-dpdk}"
ip=192.168.31.1

case $machine in
	"dpdk"|"DPDK")
		ip=192.168.31.1
		;;
	
	"pc1"|"PC1")
		ip=192.168.30.3
		;;

	"pc2"|"PC2")
		ip=192.168.30.4
		;;
esac

ssh ubuntu@"$ip"
