#include "tcpTable.h"

#include <stdio.h>
#include <stddef.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>

struct conn_table* initTcpTable(const char *table_name)
{
    struct conn_table* tcp_table;

    struct rte_hash_parameters params = {
        .name = table_name,
        .entries = MAX_CONN,
        .key_len = sizeof(struct five_tuple),
        .hash_func = rte_jhash
    };

    tcp_table->connections = rte_hash_create(&params);
    tcp_table->current_flows = 0;

    return tcp_table;
}

void updateConnections(struct conn_table *tcp_table, struct five_tuple id, uint32_t pkt_len)
{
    int exists = rte_hash_lookup(tcp_table->connections, &id);

    if (exists != -ENOENT)
    {
       struct tcp_flow *flow;
       int ret = rte_hash_lookup_data(tcp_table->connections, &id, (void **)&flow);

        //Actualizar stats
        flow->last_seen = rte_rdtsc();
        flow->n_bytes += pkt_len;
        flow->n_packets += 1;
        //flow->tcp_state &= 0;     //A futuro revisar estado de la conexión
    }

    else
    {
        if (tcp_table->current_flows < MAX_CONN)
        {
            struct tcp_flow flow = {
                .first_seen = rte_rdtsc(),
                .last_seen = rte_rdtsc(),
                .id = id,
                .n_bytes = pkt_len,
                .n_packets = 1
                //.tcp_state = 0
            };

            int ret = rte_hash_add_key_data(tcp_table->connections, &id, &flow);
        }

        else
        {
            //Eliminar flow más viejo
            printf("\n\nEsta funcionalidad no se ha implementado todavía\n\n");
        }
    }
}

uint64_t now()
{
    return 0;
}