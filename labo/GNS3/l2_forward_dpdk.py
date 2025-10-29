#!/usr/bin/env python3
"""
Simple L2 Forwarding using DPDK (via Python bindings or subprocess).
Requires DPDK installed and two NICs bound to DPDK-compatible drivers.
"""

import subprocess
import os

# Ajusta las interfaces según tu configuración (PCI IDs)
# Puedes verlas con: dpdk-devbind.py -s
DPDK_INTERFACES = ["0000:00:08.0", "0000:00:09.0"]

def setup_environment():
    # Hugepages mount
    if not os.path.ismount("/mnt/huge"):
        os.system("sudo mkdir -p /mnt/huge && sudo mount -t hugetlbfs nodev /mnt/huge")

def run_l2fwd():
    cmd = [
        "sudo", "dpdk-l2fwd",
        "-l", "0-1",              # usar CPU cores 0 y 1
        "-n", "4",                # número de canales de memoria
        "--", "-p", "0x3",        # habilitar dos puertos
        "-q", "1"                 # una cola por puerto
    ]
    print(f"Ejecutando: {' '.join(cmd)}")
    subprocess.run(cmd)

if __name__ == "__main__":
    setup_environment()
    run_l2fwd()

