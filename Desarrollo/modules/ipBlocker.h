#ifndef EAD_IPBLOCKER_H
#define EAD_IPBLOCKER_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_mempool.h>

#define MAX_IPS 9999

struct blocked_ip_info
{
    uint64_t timestamp;
    uint32_t n_pkts;
};

struct banned_ips
{
    struct rte_hash *hash_list;
    struct rte_mempool *stats_pool;
};

struct banned_ips* createIPBlocker(const char *, const char *);
void destroyIPBlocker(struct banned_ips *);
void registerIPs(struct banned_ips *, uint32_t, const char *, uint8_t);
uint16_t blacklist(struct banned_ips *, struct rte_mbuf **, struct rte_mbuf **, int);
void dumpStats(struct banned_ips *);

#endif