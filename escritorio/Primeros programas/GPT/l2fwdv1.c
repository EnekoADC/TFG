#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 256
#define PORT_ID 0   // Cambiar según la interfaz de red a usar
#define NUM_RX_DESC 128
#define NUM_TX_DESC 512

// Función que inicializa las interfaces de red
static int l2fwd_init(void) {
    struct rte_eth_dev_info dev_info;
    int ret;

    // Inicializa el EAL de DPDK
    ret = rte_eal_init(0, NULL);
    if (ret < 0) {
        printf("Error al inicializar EAL\n");
        return -1;
    }

    // Inicializa el pool de buffers de memoria
    struct rte_mempool *mbuf_pool = rte_mempool_create("mbuf_pool", NUM_MBUFS, RTE_MBUF_DEFAULT_BUF_SIZE,
            MBUF_CACHE_SIZE, sizeof(struct rte_pktmbuf_pool_private), rte_socket_id());
    if (mbuf_pool == NULL) {
        printf("Error al crear el pool de buffers\n");
        return -1;
    }

    // Inicializa la interfaz de red
    ret = rte_eth_dev_info_get(PORT_ID, &dev_info);
    if (ret != 0) {
        printf("Error al obtener información del dispositivo de red\n");
        return -1;
    }

    ret = rte_eth_dev_configure(PORT_ID, 1, 1, NULL);
    if (ret != 0) {
        printf("Error al configurar la interfaz de red\n");
        return -1;
    }

    // Configura las colas de recepción y transmisión
    ret = rte_eth_rx_queue_setup(PORT_ID, 0, NUM_RX_DESC, rte_eth_dev_socket_id(PORT_ID), NULL, mbuf_pool);
    if (ret < 0) {
        printf("Error al configurar la cola de recepción\n");
        return -1;
    }

    ret = rte_eth_tx_queue_setup(PORT_ID, 0, NUM_TX_DESC, rte_eth_dev_socket_id(PORT_ID), NULL);
    if (ret < 0) {
        printf("Error al configurar la cola de transmisión\n");
        return -1;
    }

    // Inicia la interfaz de red
    ret = rte_eth_dev_start(PORT_ID);
    if (ret < 0) {
        printf("Error al iniciar la interfaz de red\n");
        return -1;
    }

    printf("Interfaz de red iniciada con éxito\n");

    return 0;
}

// Función principal que realiza el forwarding de paquetes
int main(void) {
    struct rte_mbuf *pkt;
    uint16_t port_id = PORT_ID;
    int ret;

    // Inicializa DPDK
    ret = l2fwd_init();
    if (ret != 0) {
        return -1;
    }

    while (1) {
        // Recibe un paquete desde la interfaz de entrada
        pkt = rte_eth_rx_burst(port_id, 0, &pkt, 1);
        if (pkt) {
            // Imprime algunas estadísticas de los paquetes
            printf("Recibido paquete de %u bytes\n", rte_pktmbuf_data_len(pkt));

            // Reenvía el paquete a la misma interfaz (Forwarding)
            rte_eth_tx_burst(port_id, 0, &pkt, 1);

            // Libera el paquete recibido
            rte_pktmbuf_free(pkt);
        }
    }

    // Detiene la interfaz de red
    rte_eth_dev_stop(PORT_ID);
    rte_eth_dev_close(PORT_ID);
    return 0;
}
