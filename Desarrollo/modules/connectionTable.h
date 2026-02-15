#ifndef EAD_TCP_TABLE
#define EAD_TCP_TABLE

#include <stdint.h>

#include <rte_hash.h>
#include <rte_mempool.h>

#define MAX_CONN 8

struct five_tuple
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
};

struct flow
{
    //ID de la conexión
    struct five_tuple id;

    //Timestamps
    uint64_t first_seen;
    uint64_t last_seen;

    //Estadísticas
    unsigned int n_bytes;
    unsigned int n_packets;

    //Referencias temporales
    struct flow *prev_flow;
    struct flow *next_flow;
};


struct conn_table
{
    struct rte_hash *flow_hash;
    struct rte_mempool *flow_pool;

    struct flow *first_connection;
    struct flow *last_connection;

    uint32_t current_flows;
};

struct conn_table* initConnectionTable(const char *, const char *);
void updateConnections(struct conn_table *, struct five_tuple, uint32_t);
void showConnections(struct conn_table *);

#endif