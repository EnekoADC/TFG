#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_port.h>

// Definimos los ID de los puertos
#define PORT_ID_1 0   // Interfaz de entrada
#define PORT_ID_2 1   // Interfaz de salida

// Número de descriptores para las colas
#define NUM_RX_DESC 128
#define NUM_TX_DESC 128

// Pool de mbufs para almacenar los paquetes
#define MEMPOOL_SIZE 8192
struct rte_mempool *mbuf_pool;

int main(int argc, char **argv) {
    int ret;
    
    // Inicializar el entorno DPDK
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error al inicializar DPDK\n");
    }

    // Inicializar los puertos
    if (!rte_eth_dev_is_valid_port(PORT_ID_1) || !rte_eth_dev_is_valid_port(PORT_ID_2)) {
        rte_exit(EXIT_FAILURE, "Una de las interfaces no es válida.\n");
    }

    // Crear el pool de mbufs
    mbuf_pool = rte_mempool_create("mbuf_pool", MEMPOOL_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE,
                                   32, sizeof(struct rte_pktmbuf_pool_private), rte_socket_id(), NULL, NULL);
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Error al crear el pool de mbufs\n");
    }

    // Configurar el puerto de recepción (interfaz de entrada)
    struct rte_eth_conf port_conf = {0};
    ret = rte_eth_dev_configure(PORT_ID_1, 1, 1, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error al configurar el puerto %u\n", PORT_ID_1);
    }

    // Configurar el puerto de transmisión (interfaz de salida)
    ret = rte_eth_dev_configure(PORT_ID_2, 1, 1, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error al configurar el puerto %u\n", PORT_ID_2);
    }

    // Configurar las colas de recepción
    ret = rte_eth_rx_queue_setup(PORT_ID_1, 0, NUM_RX_DESC, rte_eth_dev_socket_id(PORT_ID_1), NULL, mbuf_pool);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error al configurar la cola RX para el puerto %u\n", PORT_ID_1);
    }

    // Configurar las colas de transmisión
    ret = rte_eth_tx_queue_setup(PORT_ID_2, 0, NUM_TX_DESC, rte_eth_dev_socket_id(PORT_ID_2), NULL);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error al configurar la cola TX para el puerto %u\n", PORT_ID_2);
    }

    // Iniciar los puertos
    ret = rte_eth_dev_start(PORT_ID_1);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error al iniciar el puerto %u\n", PORT_ID_1);
    }

    ret = rte_eth_dev_start(PORT_ID_2);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error al iniciar el puerto %u\n", PORT_ID_2);
    }

    printf("Interfaz de red configurada y lista para reenviar tráfico.\n");

    // Bucle principal de reenvío
    while (1) {
        struct rte_mbuf *pkts[32];
        uint16_t nb_rx;

        // Recibir paquetes desde la interfaz de entrada (PORT_ID_1)
        nb_rx = rte_eth_rx_burst(PORT_ID_1, 0, pkts, 32);
        if (nb_rx > 0) {
            // Reenviar los paquetes recibidos a la interfaz de salida (PORT_ID_2)
            uint16_t nb_tx = rte_eth_tx_burst(PORT_ID_2, 0, pkts, nb_rx);
            if (nb_tx < nb_rx) {
                // Si no hemos enviado todos los paquetes, liberamos los que no se enviaron
                for (int i = nb_tx; i < nb_rx; i++) {
                    rte_pktmbuf_free(pkts[i]);
                }
            }
        }
    }

    // Detener los puertos (aunque nunca llegaremos aquí, ya que el bucle es infinito)
    rte_eth_dev_stop(PORT_ID_1);
    rte_eth_dev_stop(PORT_ID_2);

    return 0;
}
