#include "connectionTable.h"

#include <stdio.h>
#include <stddef.h>
#include <arpa/inet.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_errno.h>

struct conn_table* initConnectionTable(const char *table_name, const char *pool_name)
{
    struct conn_table* connections = rte_malloc("CONNECTIONS_TABLE", sizeof(struct conn_table), 0);

    if (connections == NULL)
        rte_exit(EXIT_FAILURE, "No se puede reservar memoria para la tabla de conexiones\n");

    struct rte_hash_parameters params = {
        .name = table_name,
        .entries = MAX_CONN,
        .key_len = sizeof(struct five_tuple),
        .hash_func = rte_jhash
    };
    
    connections->flow_hash = rte_hash_create(&params);

    if (connections ->flow_hash == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear la tabla hash\n");

    connections->flow_pool = rte_mempool_create(
        pool_name,
        MAX_CONN,
        sizeof(struct flow),
        0,
        0,
        NULL, NULL,
        NULL, NULL,
        rte_socket_id(),
        0
    );
    
    if (connections->flow_pool == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear el flow pool: %s\n", rte_strerror(rte_errno));

    connections->first_connection = NULL;
    connections->last_connection = NULL;

    connections->current_flows = 0;

    return connections;
}

void updateConnections(struct conn_table *connections, struct five_tuple id, uint32_t pkt_len)
{
    struct flow *new_flow;
    int ret = rte_hash_lookup_data(connections->flow_hash, &id, (void **)&new_flow);

    if (ret == -EINVAL)
        printf("\nParámetros incorrectos en la llamada a lookup data!!!\n");

    if (ret != -ENOENT)
    {
        //Actualizar orden temporal
        if (connections->first_connection != connections->last_connection)
        {
            if (connections->first_connection != new_flow)
            {
                if (new_flow->next_flow == NULL)    //Era el último flow
                    connections->last_connection = new_flow->prev_flow;

                new_flow->prev_flow->next_flow = new_flow->next_flow;
                if (new_flow->next_flow != NULL)
                    new_flow->next_flow->prev_flow = new_flow->prev_flow;

                new_flow->next_flow = connections->first_connection;
                new_flow->prev_flow = NULL;

                connections->first_connection->prev_flow = new_flow;
                connections->first_connection = new_flow;
            }
        }

        //Actualizar stats
        new_flow->last_seen = rte_rdtsc();
        new_flow->n_bytes += pkt_len;
        new_flow->n_packets += 1;
    }

    else
    {
        if (connections->current_flows >= MAX_CONN)
        {
            //Eliminar flow más viejo de la tabla hash
            rte_hash_del_key(connections->flow_hash, &connections->last_connection->id);

            //Eliminar flow más viejo de la lista
            connections->last_connection = connections->last_connection->prev_flow;
            rte_mempool_put(connections->flow_pool, connections->last_connection->next_flow);
            connections->last_connection->next_flow = NULL;

            connections->current_flows--;
        }

        if (rte_mempool_get(connections->flow_pool, (void **)&new_flow) < 0)
                printf("Flow pool saturado temporalmente\n");

        else
        {
            //Inserción en tabla hash
            new_flow->first_seen = rte_rdtsc();
            new_flow->last_seen = rte_rdtsc();
            new_flow->id = id;
            new_flow->n_bytes = pkt_len;
            new_flow->n_packets = 1;

            int ret = rte_hash_add_key_data(connections->flow_hash, &id, new_flow);

            if (ret != 0)
            {
                printf("Flow no almacenado en la tabla!!!\n");
                printf("Devolviendo mempool\n");
                rte_mempool_put(connections->flow_pool, new_flow);
            }

            else
            {   
                //Inserción en lista temporal
                if (connections->first_connection == NULL)  //Primera inserción
                {
                    new_flow->prev_flow = NULL;
                    new_flow->next_flow = NULL;
                    connections->first_connection = new_flow;
                    connections->last_connection = new_flow;
                }

                else
                {
                    new_flow->next_flow = connections->first_connection;
                    new_flow->prev_flow = NULL;
                    connections->first_connection = new_flow;
                    new_flow->next_flow->prev_flow = new_flow;
                }
                
                connections->current_flows++;
            }
        } 
     }
}


void showConnections(struct conn_table *connections)
{
    const void *key;
    void *data;
    uint32_t iter = 0;

    printf("\nTOTAL OF FLOWS: %d\n", connections->current_flows);

    printf("\tHash table:\n");
    while (rte_hash_iterate(connections->flow_hash, &key, &data, &iter) >= 0)
    {
        const struct flow *flow = data;
        const struct five_tuple *id = key;

        char ip_src_str[INET_ADDRSTRLEN];
        char ip_dst_str[INET_ADDRSTRLEN];
        char src_port_str[17];
        char dst_port_str[17];

        inet_ntop(AF_INET, &id->src_ip, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &id->dst_ip, ip_dst_str, INET_ADDRSTRLEN);
        sprintf(src_port_str, "%d", id->src_port);
        sprintf(dst_port_str, "%d", id->dst_port);

        printf("Showing flow %s%s%s->%s%s%s\n", ip_src_str,
                                                id->src_port != 0?":":"",
                                                id->src_port != 0?src_port_str:"",
                                                ip_dst_str,
                                                id->dst_port != 0?":":"",
                                                id->dst_port != 0?dst_port_str:"");

        printf("Packets: %-10u Bytes: %-10u\n", flow->n_packets, flow->n_bytes);
    }

    const struct flow *flow = data;
    
    printf("\n\tLinked list:\n");
    for (struct flow *flow = connections->first_connection; flow != NULL; flow = flow->next_flow)
    {
        const struct five_tuple *id = &(flow->id);

        char ip_src_str[INET_ADDRSTRLEN];
        char ip_dst_str[INET_ADDRSTRLEN];
        char src_port_str[17];
        char dst_port_str[17];

        inet_ntop(AF_INET, &id->src_ip, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &id->dst_ip, ip_dst_str, INET_ADDRSTRLEN);
        sprintf(src_port_str, "%d", id->src_port);
        sprintf(dst_port_str, "%d", id->dst_port);

        printf("Showing flow %s%s%s->%s%s%s\n", ip_src_str,
                                                id->src_port != 0?":":"",
                                                id->src_port != 0?src_port_str:"",
                                                ip_dst_str,
                                                id->dst_port != 0?":":"",
                                                id->dst_port != 0?dst_port_str:"");

        printf("Packets: %-10u Bytes: %-10u\n", flow->n_packets, flow->n_bytes);
    }
    
    printf("\n\n");
}