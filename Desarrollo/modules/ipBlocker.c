#include "ipBlocker.h"

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_flow.h>

#include "common.h"
#include "snippets/snippet_match_ipv4_block.h"

#define MAX_STRING_LENGTH 150
#define LIST_CHUNK 512
#define INCOME_PORT 0
#define USE_TEMPLATE_API 1

//Auxiliar TAD dynamic vector
uint32_t *ip_list;
uint32_t ip_list_capacity = 0;
uint32_t ip_list_size = 0;

void addIP(uint32_t ip)
{
    if (ip_list_size == ip_list_capacity)
    {
        ip_list_capacity = ip_list_capacity ? ip_list_capacity * 2 : LIST_CHUNK;
        ip_list = (uint32_t *) realloc (ip_list, ip_list_capacity * sizeof(uint32_t));
    }

    ip_list[ip_list_size] = ip;
    ip_list_size++;
}
//End of aux TAD dynamic vector


//Headers for private functions
void
addHardwareRules(uint32_t *, uint32_t);

void
addSoftwareRules(struct banned_ips *, uint32_t *, uint32_t);


//Implementation of module methods
struct banned_ips* createIPBlocker(const char *table_name, const char *pool_name, int output_fd)
{
    struct banned_ips* ip_blocker = rte_malloc("IP BLOCKER", sizeof(struct banned_ips), 0);

    if (ip_blocker == NULL)
        rte_exit(EXIT_FAILURE, "No se puede reservar memoria para la tabla de conexiones\n");

    const struct rte_hash_parameters ip_hash_params = {
        .name = table_name,
        .entries = MAX_IPS,
        .hash_func = rte_jhash,
        .key_len = sizeof(uint32_t)
    };
    
    ip_blocker->hash_list = rte_hash_create(&ip_hash_params);

    if (ip_blocker ->hash_list == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear la tabla hash\n");

    ip_blocker->stats_pool = rte_mempool_create(
        pool_name,
        MAX_IPS,
        sizeof(struct blocked_ip_info),
        0,
        0,
        NULL, NULL,
        NULL, NULL,
        rte_socket_id(),
        0
    );
    
    if (ip_blocker->stats_pool == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear el stats pool: %s\n", rte_strerror(rte_errno));

    ip_blocker->output_fd = output_fd;

    return ip_blocker;
}



void destroyIPBlocker(struct banned_ips *);



void registerIPs(struct banned_ips *blocker,
                    uint32_t hw_list_max_size,
                    const char *ip_filename,
                    uint8_t hw_filter_supported)
{
    FILE *ip_file = fopen(ip_filename, "r");
    char buffer[MAX_STRING_LENGTH];
    uint32_t bin_ip;
    int n_ips = 0;

    //Obtengo IPs y las añado a la lista
    printf("Abriendo %s\n", ip_filename);
    if (ip_file != NULL)
    {
        char *ip_string;

        while ((fgets(buffer, MAX_STRING_LENGTH, ip_file) != NULL))
        {
            ip_string = strtok(buffer, "\n");   //Limpio la cadena

            if (ip_string != NULL)
            {
                if (inet_pton(AF_INET, ip_string, &bin_ip) == 1)
                    addIP(bin_ip);
                
                else
                   printf("Error en la línea %d: %s\n", n_ips+1, ip_string);      
            }

            n_ips++;
        }

        fclose(ip_file);
    }
    
    else
        printf("Error abriendo el fichero de IPs\n");

    //Separo HW IPs y SW IPs
    uint32_t hw_list_size = 0;
    uint32_t *hw_ip_list = NULL;

    if (hw_filter_supported)
    {
        hw_list_size = ip_list_size < hw_list_max_size ? ip_list_size : hw_list_max_size;
        
        if (hw_list_max_size != 0)
        {
            hw_ip_list = (uint32_t *) malloc (sizeof(uint32_t) * hw_list_size);
            memcpy(hw_ip_list, ip_list, hw_list_size * sizeof(uint32_t));

        }
    }

    uint32_t sw_list_size = ip_list_size < hw_list_max_size ? 0 : ip_list_size - hw_list_max_size;
    uint32_t *sw_ip_list = sw_list_size == 0 ? NULL : (uint32_t *) malloc (sizeof(uint32_t) * sw_list_size);

    if (sw_ip_list != NULL)
        memcpy(sw_ip_list, &ip_list[hw_list_size], sw_list_size * sizeof(uint32_t));

    if (hw_filter_supported)
        addHardwareRules(hw_ip_list, hw_list_size);
    addSoftwareRules(blocker, sw_ip_list, sw_list_size);
}



uint16_t blacklist(struct banned_ips* blocker,
                    struct rte_mbuf **raw_batch,
                    struct rte_mbuf **clean_batch,
                    int burst_size)
{
    struct rte_mbuf *pkt;
    struct blocked_ip_info *data;
    uint16_t offset, eth_type;
    uint16_t next_clean_pkt = 0;
    uint32_t ip;
    int ret;

    for (int i = 0; i < burst_size; i++)
    {
        offset = sizeof(struct rte_ether_hdr);
        pkt = raw_batch[i];

        eth_type = rte_be_to_cpu_16(rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *)->ether_type);

        while (eth_type == RTE_ETHER_TYPE_VLAN || eth_type == RTE_ETHER_TYPE_QINQ)
        {
            eth_type = rte_be_to_cpu_16(rte_pktmbuf_mtod_offset(pkt, struct rte_vlan_hdr *, offset)->eth_proto);
            offset += sizeof(struct rte_vlan_hdr);
        }
        
        if (eth_type == RTE_ETHER_TYPE_IPV4)
        {
            ip = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, offset)->dst_addr;

            ret = rte_hash_lookup_data(blocker->hash_list, (const void *) &ip, (void **) &data);
            if (ret >= 0)
            {
                data->n_pkts++;
                data->timestamp = rte_rdtsc();
            }

            else if (ret == -EINVAL)
                printf("Error en los parámetros de búsqueda (tabla hash)\n");            

            else if (ret == -ENOENT)
            {
                clean_batch[next_clean_pkt] = pkt;
                next_clean_pkt++;
                raw_batch[i] = NULL;
            }

            else
                printf("Error inesperado en la búsqueda en la tabla hash\n");
        }

        else
        {
            printf("No es un paquete IPv4 (ethertype: %u)\n", eth_type);

            clean_batch[next_clean_pkt] = pkt;
            next_clean_pkt++;
            raw_batch[i] = NULL;
        }
    }
    
    return next_clean_pkt;
}

void dumpStats(struct banned_ips *blocker)
{
    //Iteration variables
    const void *key;
    void *data;
    uint32_t iter = 0;

    //Time conversion variables
    uint64_t hz = rte_get_tsc_hz();
    uint64_t now, s_ago;

    printf("\nIniciando volcado de resultados\n");
    dprintf(blocker->output_fd, "\nBLOCKED INFO:\n");
    while (rte_hash_iterate(blocker->hash_list, &key, &data, &iter) >= 0)
    {
        const struct blocked_ip_info *ip_info = data;
        const uint32_t *id = key;

        char ip_str[INET_ADDRSTRLEN];
        
        if (inet_ntop(AF_INET, id, ip_str, INET_ADDRSTRLEN) == NULL)
        {
            dprintf(blocker->output_fd, "ERROR converting IP into string format (%d)", *id);
            strcpy(ip_str, "CONV_ERROR");
        }

        now = rte_rdtsc();
        s_ago = (now - ip_info->timestamp) / hz;

        dprintf(blocker->output_fd, "IP address: %s; %d packets, last accessed %ld s ago\n", ip_str, ip_info->n_pkts, s_ago);
    }

    dprintf(blocker->output_fd, "\n\n");
    printf("Fin del volcado de resultados\n\n");
}


void
addHardwareRules(uint32_t *hw_ip_list, uint32_t hw_list_size)
{
    if (hw_ip_list != NULL)
    {

        struct rte_flow_error *error = calloc(1, sizeof(struct rte_flow_error));

        snippet_ipv4_block_configure(hw_ip_list, hw_list_size);
        snippet_init_ipv4_block();
        
        if (generate_flow_skeleton((int)INCOME_PORT, error, (int)USE_TEMPLATE_API) == NULL)
           fprintf(stderr, "Failed to allocate block_flows array\n");
    }

    else
        printf("La lista de filtrado hardware es nula\n");
}


void
addSoftwareRules(struct banned_ips *blocker, uint32_t *sw_ip_list, uint32_t sw_list_size)
{
    if (sw_ip_list != NULL)
    {
        struct blocked_ip_info *ip_stats;    
        
        for (int i = 0; i < sw_list_size; i++)
        {
            if (rte_mempool_get(blocker->stats_pool, (void **)&ip_stats) < 0)
                printf("IP stats pool saturado temporalmente\n");
            
            else
            {
                ip_stats->n_pkts = 0;
                ip_stats->timestamp = rte_rdtsc();
                
                int ret = rte_hash_add_key_data(blocker->hash_list, &sw_ip_list[i], ip_stats);
                
                if (ret < 0)
                   printf("Error insertando IP %u en la lista hash\n", sw_ip_list[i]);
            }
        }
    }

    else
        printf("%s\n", ip_list_size ? "Todas las IP pueden bloquearse por hardware :)"
            :"No se está bloqueando ninguna IP...");
}