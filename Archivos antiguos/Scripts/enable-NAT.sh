# Activamos forwarding en el PC
sudo sysctl -w net.ipv4.ip_forward=1

#Configuramos un NAT temporal con iptables
sudo iptables -t nat -A POSTROUTING -o wlp4s0 -j MASQUERADE
sudo iptables -A FORWARD -i tap-pcDPDK -j ACCEPT
sudo iptables -A FORWARD -o tap-pcDPDK -m state --state RELATED,ESTABLISHED -j ACCEPT
