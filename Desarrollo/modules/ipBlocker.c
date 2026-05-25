#include "ipBlocker.h"

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>

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

static uint32_t reload_counter = 0;

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

void
loadIPsFromFile(const char *ip_filename);

void
reloadSoftwareRules(struct rte_hash *,
                    struct rte_mempool *,
                    struct rte_hash *,
                    uint32_t *,
                    uint32_t);


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
    
    struct rte_hash *hash_list = rte_hash_create(&ip_hash_params);

    if (hash_list == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear la tabla hash\n");

    struct rte_mempool *stats_pool = rte_mempool_create(
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
    
    if (stats_pool == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear el stats pool: %s\n", rte_strerror(rte_errno));

    atomic_store(&ip_blocker->hash_list,  hash_list);
    atomic_store(&ip_blocker->stats_pool, stats_pool);
    pthread_rwlock_init(&ip_blocker->rwlock, NULL);
    ip_blocker->output_fd = output_fd;

    return ip_blocker;
}



void destroyIPBlocker(struct banned_ips *ip_blocker)
{
    if (ip_blocker == NULL)
        return;
 
    struct rte_hash    *hash = atomic_load(&ip_blocker->hash_list);
    struct rte_mempool *pool = atomic_load(&ip_blocker->stats_pool);
 
    /* Devuelve todos los bloques de stats al pool antes de destruirlo */
    const void *key;
    void *data;
    uint32_t iter = 0;
    while (rte_hash_iterate(hash, &key, &data, &iter) >= 0)
        rte_mempool_put(pool, data);
 
    rte_hash_free(hash);
    rte_mempool_free(pool);
    pthread_rwlock_destroy(&ip_blocker->rwlock);
    if (ip_blocker->output_fd > 2)
        close(ip_blocker->output_fd);
    rte_free(ip_blocker);
}



void registerIPs(struct banned_ips *blocker,
                    uint32_t hw_list_max_size,
                    const char *ip_filename,
                    uint8_t hw_filter_supported)
{
    loadIPsFromFile(ip_filename);   

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



void reloadIPs(struct banned_ips *blocker, const char *ip_filename)
{
    ip_list_size = 0;

    loadIPsFromFile(ip_filename);

    uint32_t sw_list_size = ip_list_size;
    uint32_t *sw_ip_list = sw_list_size == 0 ? NULL : (uint32_t *) malloc (sizeof(uint32_t) * sw_list_size);

    if(sw_ip_list != NULL)
        memcpy(sw_ip_list, ip_list, sw_list_size * sizeof(uint32_t));

    char new_hash_name[MAX_STRING_LENGTH], new_pool_name[MAX_STRING_LENGTH];
    snprintf(new_hash_name, sizeof(new_hash_name), "hash_%u_%lu", ++reload_counter, (uint64_t)rte_rdtsc());
    snprintf(new_pool_name, sizeof(new_pool_name), "pool_%u_%lu", reload_counter, (uint64_t)rte_rdtsc());
 
    const struct rte_hash_parameters new_hash_params = {
        .name = new_hash_name,
        .entries = ip_list_size,
        .hash_func = rte_jhash,
        .key_len = sizeof(uint32_t)
    };
 
    struct rte_hash *new_hash = rte_hash_create(&new_hash_params);
    if (new_hash == NULL)
    {
        printf("Error creando nueva hash en recarga %u\n", reload_counter);
        free(sw_ip_list);

        return;
    }
 
    struct rte_mempool *new_pool = rte_mempool_create(
        new_pool_name,
        MAX_IPS,
        sizeof(struct blocked_ip_info),
        0, 0,
        NULL, NULL,
        NULL, NULL,
        rte_socket_id(),
        0
    );
 
    if (new_pool == NULL)
    {
        printf("Error creando nuevo pool en recarga %u: %s\n",
               reload_counter, rte_strerror(rte_errno));
        rte_hash_free(new_hash);
        free(sw_ip_list);

        return;
    }

    struct rte_hash *old_hash = atomic_load(&blocker->hash_list);

    //Preserve already gathered stats
    reloadSoftwareRules(new_hash, new_pool, old_hash, sw_ip_list, sw_list_size);
    free(sw_ip_list);

    struct rte_mempool *old_pool = atomic_load(&blocker->stats_pool);
 
    //Update blocker inner structures
    pthread_rwlock_wrlock(&blocker->rwlock);
    atomic_store(&blocker->hash_list, new_hash);
    atomic_store(&blocker->stats_pool, new_pool);
    pthread_rwlock_unlock(&blocker->rwlock);
  
    //Free old data
    const void *key;
    void *data;
    uint32_t iter = 0;
    while (rte_hash_iterate(old_hash, &key, &data, &iter) >= 0)
        rte_mempool_put(old_pool, data);
 
    rte_hash_free(old_hash);
    rte_mempool_free(old_pool);

    printf("Recarga %u completada: %u IPs SW bloqueadas\n", reload_counter, sw_list_size);
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

    pthread_rwlock_rdlock(&blocker->rwlock);
    struct rte_hash *hash = atomic_load(&blocker->hash_list);

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

            ret = rte_hash_lookup_data(hash, (const void *) &ip, (void **) &data);
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
    pthread_rwlock_unlock(&blocker->rwlock);

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

    pthread_rwlock_rdlock(&blocker->rwlock);
    struct rte_hash *hash = atomic_load(&blocker->hash_list);
    while (rte_hash_iterate(hash, &key, &data, &iter) >= 0)
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
    pthread_rwlock_unlock(&blocker->rwlock);

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
        
        pthread_rwlock_wrlock(&blocker->rwlock);
        struct rte_hash *hash = atomic_load(&blocker->hash_list);
        struct rte_mempool *pool = atomic_load(&blocker->stats_pool);

        for (int i = 0; i < sw_list_size; i++)
        {
            if (rte_mempool_get(pool, (void **)&ip_stats) < 0)
                printf("IP stats pool saturado temporalmente\n");
            
            else
            {
                ip_stats->n_pkts = 0;
                ip_stats->timestamp = rte_rdtsc();
                
                int ret = rte_hash_add_key_data(hash, &sw_ip_list[i], ip_stats);
                
                if (ret < 0)
                   printf("Error insertando IP %u en la lista hash\n", sw_ip_list[i]);
            }
        }

        pthread_rwlock_unlock(&blocker->rwlock);
    }

    else
        printf("%s\n", ip_list_size ? "Todas las IP pueden bloquearse por hardware :)"
            :"No se está bloqueando ninguna IP...");
}



void
loadIPsFromFile(const char *ip_filename)
{
    FILE *ip_file = fopen(ip_filename, "r");
    char buffer[MAX_STRING_LENGTH];
    uint32_t bin_ip;
    int n_ips = 0;
    
    //Obtengo IPs y las añado a la lista
    printf("\nAbriendo %s\n", ip_filename);
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
}



void reloadSoftwareRules(struct rte_hash *new_hash,
                        struct rte_mempool *new_pool,
                        struct rte_hash *old_hash,
                        uint32_t *sw_ip_list,
                        uint32_t sw_list_size)
{
    if (sw_ip_list != NULL)
    {
        struct blocked_ip_info *ip_stats;
 
        for (uint32_t i = 0; i < sw_list_size; i++)
        {
            if (rte_mempool_get(new_pool, (void **)&ip_stats) < 0)
                printf("IP stats pool saturado temporalmente\n");
 
            else
            {
                // Try to recover stats
                struct blocked_ip_info *old_stats = NULL;
                if (old_hash != NULL &&
                    rte_hash_lookup_data(old_hash, &sw_ip_list[i], (void **)&old_stats) >= 0)
                {
                    ip_stats->n_pkts = old_stats->n_pkts;
                    ip_stats->timestamp = old_stats->timestamp;
                }
                else
                {
                    /* IP nueva: stats a cero */
                    ip_stats->n_pkts   = 0;
                    ip_stats->timestamp = rte_rdtsc();
                }
                    
                int ret = rte_hash_add_key_data(new_hash, &sw_ip_list[i], ip_stats);
                if (ret < 0)
                    printf("Error insertando IP %u en la nueva hash\n", sw_ip_list[i]);
            }
        }
    }
}