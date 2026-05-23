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
#include <rte_jhash.h>
#include <rte_flow.h>

#include "modules/ipBlocker.h"

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 256
#define MAX_QUEUE_SIZE 256

/* rte_flow_flush: para limpiar las reglas instaladas
    configure_port_template para integrar la configuración rte_flow
     */

/* Variable global para controlar la terminación */
static volatile bool force_quit = false;

/* Manejador de señales */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSeñal %d recibida, preparando para salir...\n", signum);
        force_quit = true;
    }
}


//Configura el puerto para usar rte_flow
static void
configure_port_template(uint16_t port_id, uint32_t counters)
{
	int ret;
	uint16_t std_queue;
	struct rte_flow_error error;
	struct rte_flow_queue_attr queue_attr[RTE_MAX_LCORE];
	const struct rte_flow_queue_attr *attr_list[RTE_MAX_LCORE];
	struct rte_flow_port_attr port_attr = { .nb_counters = counters };

	for (std_queue = 0; std_queue < RTE_MAX_LCORE; std_queue++) {
		queue_attr[std_queue].size = MAX_QUEUE_SIZE;
		attr_list[std_queue] = &queue_attr[std_queue];
	}

	ret = rte_flow_configure(port_id, &port_attr,
				 1, attr_list, &error);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			 "rte_flow_configure:err=%d, port=%u\n",
			 ret, port_id);
	printf(":: Configuring template port [%d] Done ..\n", port_id);
}

/* Configuración básica de los puertos */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
    },
};

/* Inicializa un puerto ethernet */
static inline int
init_port(uint16_t port, struct rte_mempool *mbuf_pool, uint32_t *hw_list_size_out)
{
    int retval;
    uint16_t q;

    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;

    /* Ethernet port configured with default settings. */
	struct rte_eth_conf port_conf = {
		.txmode = {
			.offloads =
				RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
				RTE_ETH_TX_OFFLOAD_IPV4_CKSUM  |
				RTE_ETH_TX_OFFLOAD_UDP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_TCP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_SCTP_CKSUM  |
				RTE_ETH_TX_OFFLOAD_TCP_TSO,
		}
	};

    struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxq_conf;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        rte_exit(EXIT_FAILURE, "Invalid port!!!\n");

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
        rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port, strerror(-retval));

    port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	printf("\n:: initializing port: %d\n", port);

    /* Configura el dispositivo ethernet */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			retval, port);

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        rte_exit(EXIT_FAILURE,
			"Error adjusting descriptors in port %u. Error = %s\n",
			port, strerror(-retval));

    rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;

    /* Asigna y configura las colas RX */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), &rxq_conf, mbuf_pool);
        if (retval < 0)
            rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				retval, port);
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    
    /* Asigna y configura las colas TX */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				retval, port);
    }

    /* Habilita el modo promiscuo */
    retval = rte_eth_promiscuous_enable(port);
    printf(":: promiscuous mode enabled\n");
    if (retval != 0)
        rte_exit(EXIT_FAILURE,
            ":: promiscuous mode enable failed: err=%s, port=%u\n",
            rte_strerror(-retval), port);

    /* Arranca el dispositivo */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			retval, port);

    printf(":: initializing port: %d done\n", port);

    /* Configuro el máximo número de IPs bloqueables por hardware */
    struct rte_flow_port_info port_info = {0};
    struct rte_flow_error error = {0};
    
    retval = rte_flow_info_get(port, &port_info, NULL, &error);

    if (retval != 0)
    {
        printf(":: Port %d: rte_flow no soportado por NIC :(\n", port);
        if (hw_list_size_out != NULL)
            *hw_list_size_out = 0;

        return 0;
    }


    printf("Realmente soporta bloqueo hardware. Bypasseado para las pruebas.\n");
return 0;


    uint32_t hw_list_max_size = 0.8 * port_info.max_nb_counters;

    if (hw_list_size_out != NULL)
            *hw_list_size_out = hw_list_max_size;
    
    /* Adds rules engine configuration.  */
	retval = rte_eth_dev_stop(port);
	if (retval < 0)
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_stop:err=%d, port=%u\n",
			retval, port);


	configure_port_template(port, hw_list_max_size);

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			retval, port);
  

	/*  End of adding rules engine configuration. */

    // /* Muestra la dirección MAC del puerto */
    // struct rte_ether_addr addr;
    // retval = rte_eth_macaddr_get(port, &addr);
    // if (retval != 0)
    //     return retval;

    // printf("Puerto %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
    //        ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
    //         port, RTE_ETHER_ADDR_BYTES(&addr));


    return 1;
}

static void
read_send(uint16_t rx_port, uint16_t tx_port, struct banned_ips *banned_ips)
{
    //Variables de lectura de paquetes
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_mbuf *approved[BURST_SIZE];
    uint16_t nb_rx, nb_tx, i, clean_pkts;

    /* Recibe ráfaga de paquetes del puerto de entrada */
    nb_rx = rte_eth_rx_burst(rx_port, 0, bufs, BURST_SIZE);
    
    if (nb_rx > 0)
    {        
        clean_pkts = blacklist(banned_ips, bufs, approved, nb_rx);
        
        /* Envía los paquetes por el puerto de salida */
        nb_tx = rte_eth_tx_burst(tx_port, 0, approved, clean_pkts);

        /* Libera los paquetes que no se pudieron enviar */
        if (unlikely(nb_tx < clean_pkts))
        {
            for (i = nb_tx; i < clean_pkts; i++)
                rte_pktmbuf_free(approved[i]);
        }

        
        /* Envía los paquetes por el puerto de salida */
        // nb_tx = rte_eth_tx_burst(tx_port, 0, bufs, nb_rx);

        // printf("ENVIADOS %d PAQUETES\n", nb_tx);

        // /* Libera los paquetes que no se pudieron enviar */
        // if (unlikely(nb_tx < nb_rx))
        // {
        //     for (i = nb_tx; i < nb_rx; i++)
        //         rte_pktmbuf_free(bufs[i]);      //BUFS[I] ANTES ERA APPROVED[I]
        // }
    }

    for (i = 0; i < nb_rx; i++)
    {
        if (bufs[i] != NULL)
            rte_pktmbuf_free(bufs[i]);
    }
    
}



/* Loop principal de forwarding */
static void
l2fwd_main_loop(uint16_t *ports, struct banned_ips *banned_ips)
{
    printf("\nCore %u haciendo L2 forwarding entre puertos %u y %u\n",
            rte_lcore_id(), ports[0], ports[1]);
    printf("Presiona Ctrl+C para terminar limpiamente\n\n");

    /* Loop de RX/TX con condición de salida */
    while (!force_quit)
    {
        //Reenvío de if0 a if1
        read_send(ports[0], ports[1], banned_ips);

        //Reenvío de if1 a if0
        read_send(ports[1], ports[0], banned_ips);
    }

    printf("\nSaliendo del loop de forwarding...\n");

    dumpStats(banned_ips);
}

int
main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;
    struct banned_ips *blocker;
    uint16_t ports [] = {0, 1};
    uint8_t hw_filter_supported = 1;    //Máscara de filtrado HW

    /* Inicializa el Environment Abstraction Layer (EAL) */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error con rte_eal_init()\n");

    argc -= ret;
    argv += ret;
    
    /* Preparo ficheros de entrada/salida */
    const char *ip_filename;
    int out_fd;

    switch(argc)
    {
        case 3:
            ip_filename = argv[1];
            out_fd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 00444);
            printf("Entrada: %s\nSalida: %s\n\n", ip_filename, argv[2]);
            break;

        case 2:
            ip_filename = argv[1];
            out_fd = 0;
            printf("Entrada: %s\nSalida: stdio\n\n", ip_filename);
            break;

        case 1:
            ip_filename = "banned";
            out_fd = 0;
            printf("Entrada por defecto: banned\nSalida por defecto: stdio\n\n");
            break;

        default:
            printf("Error parseando argumentos\n\n");
            break;
    }
    
    /* Inicializo el bloqueador software */
    blocker = createIPBlocker("hash_ip_blocker", "pool_ip_blocker", out_fd); 

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

    uint32_t hw_list_max_size;
    /* Inicializa los puertos seleccionados */
    hw_filter_supported &= init_port(ports[0], mbuf_pool, &hw_list_max_size);
    hw_filter_supported &= init_port(ports[1], mbuf_pool, NULL);

    registerIPs(blocker, hw_list_max_size, ip_filename, hw_filter_supported);    

    /* Verifica que tengamos al menos un lcore disponible */
    if (rte_lcore_count() > 1)
        printf("\nWARNING: Demasiados lcores habilitados. Solo se usa 1.\n");

    /* Llama al loop principal en el lcore principal */
    l2fwd_main_loop(ports, blocker);

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
