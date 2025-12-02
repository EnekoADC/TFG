#ifndef EAD_TCP_TABLE
#define EAD_TCP_TABLE

#include <stdint.h>

//uint64_t tsc = rte_get_tsc_cycles();
//uint64_t now_ns = tsc * 1000000000ULL / rte_get_tsc_hz();

#define TABLE_SIZE 150

#define TCP_SYN_SENT        0x01
#define TCP_SYN_RECV        0x02
#define TCP_ESTABLISHED     0x04
#define TCP_HALF_CLOSED     0x08
#define TCP_CLOSED          0x10



typedef struct five_tuple_t
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} __attribute__((packed)) five_tuple;

typedef struct tcp_connection_t
{
    //ID de conexión (5-tupla)
    five_tuple id;

    //Timestamps de conexión
    uint64_t first_seen;
    uint64_t last_seen;

    //Flags de estado
    uint8_t tcp_state;

    //Estadísticas generales
    unsigned int n_packets;
    unsigned int n_bytes;
} tcp_connection;

typedef struct tcp_table_t
{
    //Hash table para acceder rápido a la información de cada conexión
    struct rte_hash *conn_table;

    //Punteros a la lista enlazada para añadir/eliminar eficientemente
    tcp_connection *lru_head;
    tcp_connection *lru_tail;

    //Índices para ver la capacidad de la tabla
    uint32_t max_connections;
    uint32_t n_connections;
} tcp_table;

tcp_table tcpTableInit(void);
void updateConnections();

//crear funciones de modificación de flags y timestamps

#endif
