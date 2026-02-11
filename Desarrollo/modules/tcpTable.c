#include "tcpTable.h"

#include <stdio.h>
#include <stddef.h>
#include <arpa/inet.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_mempool.h>

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

void updateConnections(struct conn_table *tcp_table, struct rte_mempool *flow_pool, struct five_tuple id, uint32_t pkt_len)
{
    int32_t exists = rte_hash_lookup(tcp_table->connections, &id);

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
            struct tcp_flow *new_flow;
            if (rte_mempool_get(flow_pool, (void **)&new_flow) < 0)
                printf("Flow pool saturado temporalmente\n");

            else
            {
                new_flow->first_seen = rte_rdtsc();
                new_flow->last_seen = rte_rdtsc();
                new_flow->id = id;
                new_flow->n_bytes = pkt_len;
                new_flow->n_packets = 1;
                new_flow->tcp_state = 0;
            }

            int ret = rte_hash_add_key_data(tcp_table->connections, &id, new_flow);

            if (ret != 0)
            {
                printf("Flow no almacenado en la tabla!!!\n");
                printf("Devolviendo mempool\n");
                rte_mempool_put(flow_pool, new_flow);
            }

            else
                tcp_table->current_flows++;
        }

        else
        {
            //Eliminar flow más viejo
            printf("\n\nEsta funcionalidad no se ha implementado todavía\n\n");
        }
    }
}


void showConnections(struct conn_table *tcp_table)
{
    const void *key;
    void *data;
    uint32_t iter = 0;

    printf("TOTAL OF FLOWS: %d", tcp_table->current_flows);
    while (rte_hash_iterate(tcp_table->connections, &key, &data, &iter) >= 0)
    {
        const struct tcp_flow *flow = data;
        const struct five_tuple *id = key;

        char ip_src_str[INET_ADDRSTRLEN];
        char ip_dst_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &id->src_ip, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &id->dst_ip, ip_dst_str, INET_ADDRSTRLEN);

        printf("Showing flow %s:%d->%s:%d\n", ip_src_str, id->src_port, ip_dst_str, id->dst_port);
        printf("Packets: %-10u Bytes: %-10u\n", flow->n_packets, flow->n_bytes);
    }
}