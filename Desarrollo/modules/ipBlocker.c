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

#define MAX_STRING_LENGTH 150

struct ip_blocker* createIPBlocker(const char *table_name, const char *pool_name)
{
    struct ip_blocker* ip_blocker = rte_malloc("IP BLOCKER", sizeof(struct ip_blocker), 0);

    if (ip_blocker == NULL)
        rte_exit(EXIT_FAILURE, "No se puede reservar memoria para la tabla de conexiones\n");

    const struct rte_hash_parameters ip_hash_params = {
        .name = table_name,
        .entries = MAX_IPS,
        .hash_func = rte_jhash,
        .key_len = sizeof(uint32_t)
    };
    
    ip_blocker->banned_ips = rte_hash_create(&ip_hash_params);

    if (ip_blocker ->banned_ips == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear la tabla hash\n");

    ip_blocker->banned_ip_data = rte_mempool_create(
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
    
    if (ip_blocker->banned_ip_data == NULL)
        rte_exit(EXIT_FAILURE, "No se puede crear el flow pool: %s\n", strerror(rte_errno));
}



void destroyIPBlocker(struct ip_blocker *);



void registerIPs(struct ip_blocker *banned_ip_list, const char *ip_filename)
{
    FILE *ip_file = fopen(ip_filename, "r");
    char buffer[MAX_STRING_LENGTH];
    int32_t bin_ip;

    if (ip_file != NULL)
    {
        char *ip_string;
        int i = 1;
        while (!feof(ip_file))
        {
            if (fgets(buffer, MAX_STRING_LENGTH, ip_file) != NULL)
            {
                ip_string = strtok(buffer, "\n");   //Limpio la cadena
                if (inet_pton(AF_INET, ip_string, &bin_ip) == 1)
                {
                    int ret = rte_hash_add_key(banned_ip_list, &bin_ip);
                    if (ret < 0)
                        printf("Error insertando IP %s (%u) en la lista\n", buffer, bin_ip);
                }
                else
                    printf("Error en la línea %d: %s\n", i, ip_string);      
            }

            i++;
        }

        fclose(ip_file);
    }
    
    else
        printf("Error abriendo el fichero de IPs\n");
}



void blacklist(struct ip_blocker* banned_list, struct rte_mbuf **raw_batch, struct rte_mbuf **clean_batch, int burst_size)
{
    struct rte_mbuf *pkt;
    uint16_t offset;
    uint32_t ip;
    int next_clean_pkt = 0;

    for (int i = 0; i < burst_size; i++)
    {
        offset = sizeof(struct rte_ether_hdr);
        pkt = raw_batch[i];

        uint16_t eth_type = rte_be_to_cpu_16(rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *)->ether_type);

        while (eth_type == RTE_ETHER_TYPE_VLAN || eth_type == RTE_ETHER_TYPE_QINQ)
        {
            eth_type = rte_be_to_cpu_16(rte_pktmbuf_mtod_offset(pkt, struct rte_vlan_hdr *, offset)->eth_proto);
            offset += sizeof(struct rte_vlan_hdr);
        }
        
        if (eth_type == RTE_ETHER_TYPE_IPV4)
        {
            ip = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, offset)->dst_addr;

            int32_t ret = rte_hash_lookup(banned_list, (const void *) &ip);
            if (ret > 0)
            {
                //recopilar estadísticas
            }

            else if (ret == -EINVAL)
                printf("Error en los parámetros de búsqueda (tabla hash)\n");            

            else if (ret == -ENOENT)
            {
                clean_batch[next_clean_pkt] = pkt;
                next_clean_pkt++;
            }

            else
                printf("Error inesperado en la búsqueda en la tabla hash\n");
        }

        else
            printf("No es un paquete IPv4 (ethertype: %u)\n", eth_type);
    }
}