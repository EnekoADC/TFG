#ifndef EAD_TCP_TABLE
#define EAD_TCP_TABLE

#include <stdint.h>

#define MAX_CONN 1<<3

struct five_tuple
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
};

struct tcp_flow
{
    //ID de la conexión
    struct five_tuple id;

    //Timestamps
    uint64_t first_seen;
    uint64_t last_seen;

    //Flags de estado
    uint8_t tcp_state;

    //Estadísticas
    unsigned int n_bytes;
    unsigned int n_packets;
};


struct conn_table
{
    struct rte_hash *connections;

    uint32_t current_flows;
};

struct conn_table* initTcpTable(const char *);
void updateConnections(struct conn_table*, struct five_tuple, uint32_t);

#endif