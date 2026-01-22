#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

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
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
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

/* Opción 1: No modificar MACs (MITM transparente)
 * Para un verdadero man-in-the-middle, simplemente reenviamos
 * los paquetes sin tocar las direcciones MAC.
 */

/* Opción 2: Intercambiar MACs (modo reflector/echo)
 * Solo útil para testing o responder al origen.
 * Descomenta esta función si quieres modo echo.
 */
/*
static void
swap_mac_addresses(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ether_addr tmp_addr;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    
    rte_ether_addr_copy(&eth_hdr->dst_addr, &tmp_addr);
    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&tmp_addr, &eth_hdr->src_addr);
}
*/

/* Opción 3: Reescribir MACs para forzar routing
 * Útil si necesitas que TODO el tráfico pase por ti.
 */
static void
rewrite_mac_addresses(struct rte_mbuf *m, uint16_t out_port)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ether_addr port_mac;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    
    /* Cambiar src_addr a la MAC del puerto de salida */
    rte_eth_macaddr_get(out_port, &port_mac);
    rte_ether_addr_copy(&port_mac, &eth_hdr->src_addr);
    
    /* dst_addr lo dejamos como está (o podrías cambiarlo al gateway) */
}

/* Verifica si es un paquete broadcast */
static inline int
is_broadcast(struct rte_ether_addr *addr)
{
    return (addr->addr_bytes[0] == 0xff &&
            addr->addr_bytes[1] == 0xff &&
            addr->addr_bytes[2] == 0xff &&
            addr->addr_bytes[3] == 0xff &&
            addr->addr_bytes[4] == 0xff &&
            addr->addr_bytes[5] == 0xff);
}

/* Loop principal de forwarding */
static void
l2fwd_main_loop(uint16_t port_in, uint16_t port_out)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx;
    uint16_t nb_tx;
    uint16_t i;

    printf("\nCore %u haciendo L2 forwarding. Puerto %u -> Puerto %u\n",
            rte_lcore_id(), port_in, port_out);
    printf("Presiona Ctrl+C para terminar limpiamente\n\n");

    /* Loop de RX/TX con condición de salida */
    while (!force_quit) {
        /* Recibe ráfaga de paquetes del puerto de entrada */
        nb_rx = rte_eth_rx_burst(port_in, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        /* MODO BRIDGE TRANSPARENTE: No modificamos NADA */
        /* Los paquetes se reenvían tal cual (broadcast, unicast, multicast) */
        /* Esto permite que ARP funcione correctamente */

        /* Envía los paquetes por el puerto de salida */
        nb_tx = rte_eth_tx_burst(port_out, 0, bufs, nb_rx);

        /* Libera los paquetes que no se pudieron enviar */
        if (unlikely(nb_tx < nb_rx)) {
            for (i = nb_tx; i < nb_rx; i++) {
                rte_pktmbuf_free(bufs[i]);
            }
        }
    }
    
    printf("\nSaliendo del loop de forwarding...\n");
}

int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;

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

    /* Inicializa los primeros 2 puertos */
    if (port_init(0, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "No se puede inicializar el puerto 0\n");

    if (port_init(1, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "No se puede inicializar el puerto 1\n");

    /* Verifica que tengamos al menos un lcore disponible */
    if (rte_lcore_count() > 1)
        printf("\nWARNING: Demasiados lcores habilitados. Solo se usa 1.\n");

    /* Llama al loop principal en el lcore principal */
    l2fwd_main_loop(0, 1);

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
