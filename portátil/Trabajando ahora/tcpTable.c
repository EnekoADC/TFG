/*
 - Decidir cómo se hace el análisis del estado en función del paquete que llegue
 - Crear funciones auxiliares para modificar el estado de la conexión guardada (gestión entendible de flags)
 - Crear funciones auxiliares para inicializar y modificar los timestamps
 */

#include <rte_mbuf.h>
#include <rte_jhash.h>
#include "tcpTable.h"

//Acción para manejar los errores
void error (const char *);

tcp_table tcpTableInit(const char *table_name, uint32_t size)
{
    if (table_name == NULL || size > RTE_HASH_ENTRIES_MAX)
        error("Parámetros de configuración de la tabla incorrectos");

    tcp_table t;

    struct rte_hash_parameters hash_table_params =
    {
        .name = table_name,
        .entries = size,
        .key_len = sizeof(tcp_connection),
        .hash_func = rte_jhash,
        .socket_id = rte_socket_id()
    };

    t.conn_table = rte_hash_create(&hash_table_params);

    t.lru_head = NULL;
    t.lru_tail = NULL;

    t.max_connections = size;
    t.n_connections = 0;

    return t;
}

void updateConnections(tcp_table *table, struct rte_mbuf *tcp_pck){}

void error (const char *error_type)
{
    printf("\n%s\n\n");
    exit(-1);
}
