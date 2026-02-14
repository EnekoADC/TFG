#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_mempool.h>

#include "modules/connectionTable.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

struct headers
{
    struct rte_ether_hdr *ethernet_header;
    struct rte_ipv4_hdr *ip_header;
    struct rte_icmp_hdr *icmp_header;
    struct rte_tcp_hdr *tcp_header;
    struct rte_udp_hdr *udp_header;
};

/* Variable global para controlar la terminación */
static volatile bool force_quit = false;

/* Manejador de señales */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSeñal %d recibida, preparando para salir...\n",
                signum);
        force_quit = true;
    }
}

/* Configuración básica de los puertos */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
    },
};

/* Inicializa un puerto ethernet */
static inline int
first_portit(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error obteniendo info del dispositivo: %s\n",
               strerror(-retval));
        return retval;
    }

    /* Configura el dispositivo ethernet */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Asigna y configura las colas RX */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    
    /* Asigna y configura las colas TX */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Arranca el dispositivo */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Muestra la dirección MAC del puerto */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    printf("Puerto %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
            port, RTE_ETHER_ADDR_BYTES(&addr));

    /* Habilita modo promiscuo */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

void icmpTranslations(uint8_t icmp_type)
{
    switch (icmp_type)
    {
        case RTE_ICMP_TYPE_ECHO_REPLY:
            printf("Recibido echo reply\n");
            break;

        case RTE_ICMP_TYPE_ECHO_REQUEST:
            printf("Recibido echo request\n");
            break;

        case RTE_ICMP_TYPE_DEST_UNREACHABLE:
            printf("Recibido destination unreachable\n");
            break;

        default:
            printf("Recibido ICMP no reconocido\n");
            break;
    }

}

void inspect_packet(struct rte_mbuf *mbuf,
                    struct headers pkt_hdrs,
                    struct conn_table *connections)
{
    pkt_hdrs.ethernet_header = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    printf("\n\n\t\t--- INICIO DEL ANÁLISIS ---\n");
    printf("\n\t--- Analizando trama ETHERNET ---\n");
    printf("MAC origen: %d:%d:%d:%d:%d:%d\n", RTE_ETHER_ADDR_BYTES(&(pkt_hdrs.ethernet_header->src_addr)));
    printf("MAC destino: %d:%d:%d:%d:%d:%d\n", RTE_ETHER_ADDR_BYTES(&(pkt_hdrs.ethernet_header->dst_addr)));

    if (pkt_hdrs.ethernet_header -> ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
    {
        pkt_hdrs.ip_header = (struct rte_ipv4_hdr *) (pkt_hdrs.ethernet_header + 1);

        char ip_src_str[INET_ADDRSTRLEN];
        char ip_dst_str[INET_ADDRSTRLEN];

        printf("\n\t--- Analizando paquete IP ---\n");

        inet_ntop(AF_INET, &pkt_hdrs.ip_header->src_addr, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &pkt_hdrs.ip_header->dst_addr, ip_dst_str, INET_ADDRSTRLEN);

        printf("IP origen: %s -> IP destino: %s\n", ip_src_str, ip_dst_str);

        //ID de la conexión:
        struct five_tuple flow_key;

        //Puertos
        uint16_t src_port;
        uint16_t dst_port;

        switch (pkt_hdrs.ip_header->next_proto_id)
        {
            case IPPROTO_ICMP:
                pkt_hdrs.icmp_header = (struct rte_icmp_hdr *) (pkt_hdrs.ip_header + 1);

                printf("\n\t--- Analizando paquete ICMP ---\n");

                flow_key = (struct five_tuple)
                {
                    .src_ip = pkt_hdrs.ip_header->src_addr,
                    .dst_ip = pkt_hdrs.ip_header->dst_addr,
                    .src_port = 0,
                    .dst_port = 0,
                    .proto = IPPROTO_ICMP
                };

                icmpTranslations(pkt_hdrs.icmp_header->icmp_type);
                updateConnections(connections, flow_key, rte_pktmbuf_pkt_len(mbuf));
                
                break;

            case IPPROTO_TCP:
                pkt_hdrs.tcp_header = (struct rte_tcp_hdr *) (pkt_hdrs.ip_header + 1);

                src_port = rte_be_to_cpu_16(pkt_hdrs.tcp_header->src_port);
                dst_port = rte_be_to_cpu_16(pkt_hdrs.tcp_header->dst_port);
                
                printf("\n\t--- Analizando paquete TCP ---\n");
                printf("Puerto TCP origen: %" PRIu16 "\n", src_port);
                printf("Puerto TCP destino: %" PRIu16 "\n", dst_port);

                flow_key = (struct five_tuple)
                {
                    .src_ip = pkt_hdrs.ip_header->src_addr,
                    .dst_ip = pkt_hdrs.ip_header->dst_addr,
                    .src_port = src_port,
                    .dst_port = dst_port,
                    .proto = IPPROTO_TCP
                };

                updateConnections(connections, flow_key, rte_pktmbuf_pkt_len(mbuf));

                break;

            case IPPROTO_UDP:
                pkt_hdrs.udp_header = (struct rte_udp_hdr *) (pkt_hdrs.ip_header + 1);

                src_port = rte_be_to_cpu_16(pkt_hdrs.tcp_header->src_port);
                dst_port = rte_be_to_cpu_16(pkt_hdrs.tcp_header->dst_port);
                
                printf("\n\t--- Analizando paquete UDP ---\n");
                printf("Puerto UDP origen: %" PRIu16 "\n", src_port);
                printf("Puerto UDP destino: %" PRIu16 "\n", dst_port);

                flow_key = (struct five_tuple)
                {
                    .src_ip = pkt_hdrs.ip_header->src_addr,
                    .dst_ip = pkt_hdrs.ip_header->dst_addr,
                    .src_port = src_port,
                    .dst_port = dst_port,
                    .proto = IPPROTO_UDP
                };

                updateConnections(connections, flow_key, rte_pktmbuf_pkt_len(mbuf));


            default:
                printf("Protocolo no reconocido (%d)\n", pkt_hdrs.ip_header->next_proto_id);
                break;
        }
    }
    else
        printf("Protocolo no reconocido (no es IPv4)\n");

    printf("\t\t--- FIN DEL ANÁLISIS ---\n");
}

static void
read_send(uint16_t first_port, uint16_t second_port, struct conn_table *connections)
{
    //Variables de lectura de paquetes
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx;
    uint16_t nb_tx;
    uint16_t i;

    //Variables de inspección de paquetes
    struct headers packet_headers;

    /* Recibe ráfaga de paquetes del puerto de entrada */
    nb_rx = rte_eth_rx_burst(first_port, 0, bufs, BURST_SIZE);

    if (nb_rx > 0)
    {
        //Analiza cada paquete antes de enviarlo
        for (i = 0; i < nb_rx; i++)
            inspect_packet(bufs[i], packet_headers, connections);

        /* Envía los paquetes por el puerto de salida */
        nb_tx = rte_eth_tx_burst(second_port, 0, bufs, nb_rx);
    }

    /* Libera los paquetes que no se pudieron enviar */
    if (unlikely(nb_tx < nb_rx))
    {
        for (i = nb_tx; i < nb_rx; i++)
            rte_pktmbuf_free(bufs[i]);
    }
}

/* Loop principal de forwarding */
static void
l2fwd_main_loop(uint16_t first_port, uint16_t second_port, struct conn_table *connections)
{
    printf("\nCore %u haciendo L2 forwarding entre puertos %u y %u\n",
            rte_lcore_id(), first_port, second_port);
    printf("Presiona Ctrl+C para terminar limpiamente\n\n");

    /* Loop de RX/TX con condición de salida */
    while (!force_quit)
    {
        //Reenvío de if0 a if1
        read_send(first_port, second_port, connections);

        //Reenvío de if1 a if0
        read_send(second_port, first_port, connections);
    }

    printf("\nSaliendo del loop de forwarding...\n");

    showConnections(connections);
}

int
main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;
    struct conn_table *connections;

    /* Inicializa el Environment Abstraction Layer (EAL) */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error con rte_eal_init()\n");

    argc -= ret;
    argv += ret;

    /* Registrar manejadores de señales */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Verifica que tengamos al menos 2 puertos */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2)
        rte_exit(EXIT_FAILURE, "Error: se necesitan al menos 2 puertos\n");

    printf("Puertos disponibles: %u\n", nb_ports);

    /* Crea el memory pool para los mbufs */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear mbuf pool\n");
    
    connections = initConnectionTable("flow_hash_table", "flow_pool");

    /* Inicializa los primeros 2 puertos */
    if (first_portit(0, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "No se puede inicializar el puerto 0\n");

    if (first_portit(1, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "No se puede inicializar el puerto 1\n");

    /* Verifica que tengamos al menos un lcore disponible */
    if (rte_lcore_count() > 1)
        printf("\nWARNING: Demasiados lcores habilitados. Solo se usa 1.\n");

    /* Llama al loop principal en el lcore principal */
    l2fwd_main_loop(0, 1, connections);

    printf("\n==== Iniciando limpieza ====\n");

    /* Limpia y termina */
    RTE_ETH_FOREACH_DEV(portid) {
        printf("Cerrando puerto %d...", portid);
        ret = rte_eth_dev_stop(portid);
        if (ret != 0)
            printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
        rte_eth_dev_close(portid);
        printf(" Hecho\n");
    }

    /* Limpia el EAL */
    rte_eal_cleanup();
    printf("Bye...\n");

    return 0;
}
