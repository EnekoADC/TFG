#include <stdint.h>

#define MAX_IPS 9999

struct blocked_ip_info
{
    uint64_t timestamp;
    uint32_t n_pkts;
};

struct ip_blocker
{
    struct rte_hash *banned_ips;
    struct rte_mempool *banned_ip_data;
};

struct ip_blocker* createIPBlocker(const char *, const char *);
void destroyIPBlocker(struct ip_blocker *);
void registerIPs(struct ip_blocker *, const char *);
void blacklist(struct ip_blocker *, struct rte_mbuf **, struct rte_mbuf **, int);