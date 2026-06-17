sudo modprobe vfio-pci

dpdk-devbind.py --status

sudo dpdk-devbind.py --bind=vfio-pci enp1s0f0 --noiommu-mode
sudo dpdk-devbind.py --bind=vfio-pci enp1s0f1 --noiommu-mode

dpdk-devbind.py --status
