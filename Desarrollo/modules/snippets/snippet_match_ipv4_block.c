/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <rte_errno.h>
#include <rte_flow.h>

#include "../common.h"
#include "snippet_match_ipv4_block.h"

static const uint32_t *ip_list = NULL;
static uint16_t n_ips = 0;
static struct rte_flow **block_flows = NULL;

void
snippet_init_ipv4_block(void)
{
    init_default_snippet();
}

void
snippet_ipv4_block_configure(const uint32_t *ips, uint16_t n)
{
    ip_list = ips;
    n_ips = n;
    block_flows = calloc(n, sizeof(struct rte_flow *));
    if (block_flows == NULL)
        fprintf(stderr, "Failed to allocate block_flows array\n");
}

void
snippet_ipv4_block_flow_create_actions(__rte_unused uint16_t port_id,
                                        struct rte_flow_action *actions)
{
    struct rte_flow_action_count *cnt =
        calloc(1, sizeof(struct rte_flow_action_count));

    if (cnt == NULL)
        fprintf(stderr, "Failed to allocate memory for count action\n");

    actions[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    actions[0].conf = cnt;          /* counter id defaults to 0 */

    actions[1].type = RTE_FLOW_ACTION_TYPE_DROP;
    actions[1].conf = NULL;

    actions[2].type = RTE_FLOW_ACTION_TYPE_END;
}


void
snippet_ipv4_block_flow_create_patterns(struct rte_flow_item *patterns)
{
    struct rte_flow_item_ipv4 *ip_spec =
        calloc(1, sizeof(struct rte_flow_item_ipv4));

    struct rte_flow_item_ipv4 *ip_mask =
        calloc(1, sizeof(struct rte_flow_item_ipv4));

    if (!ip_spec || !ip_mask)
        fprintf(stderr, "Failed to allocate memory for IP pattern\n");

    patterns[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    patterns[1].type            = RTE_FLOW_ITEM_TYPE_IPV4;
    ip_spec->hdr.src_addr       = htonl(0x00000000);   /* overridden per-rule */
    ip_mask->hdr.src_addr       = htonl(0xFFFFFFFF);   /* exact match on src  */
    ip_mask->hdr.dst_addr       = 0x00000000;          /* any destination     */
    patterns[1].spec            = ip_spec;
    patterns[1].mask            = ip_mask;

    patterns[2].type = RTE_FLOW_ITEM_TYPE_END;
}


static struct rte_flow_actions_template *
create_actions_template(uint16_t port_id, struct rte_flow_error *error)
{
    struct rte_flow_action tactions[MAX_ACTION_NUM] = {0};
    struct rte_flow_action masks[MAX_ACTION_NUM]    = {0};

    struct rte_flow_actions_template_attr attr = { .ingress = 1 };

    tactions[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    tactions[1].type = RTE_FLOW_ACTION_TYPE_DROP;
    tactions[2].type = RTE_FLOW_ACTION_TYPE_END;

    memcpy(masks, tactions, sizeof(masks));

    return rte_flow_actions_template_create(port_id, &attr, tactions, masks, error);
}


static struct rte_flow_pattern_template *
create_pattern_template(uint16_t port_id, struct rte_flow_error *error)
{
    struct rte_flow_item titems[MAX_PATTERN_NUM] = {0};
    struct rte_flow_item_ipv4 ip_mask = {0};

    struct rte_flow_pattern_template_attr attr = {
        .relaxed_matching = 1,
        .ingress = 1,
    };

    titems[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    titems[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    ip_mask.hdr.src_addr = htonl(0xFFFFFFFF);   // exact match on source IP
    ip_mask.hdr.dst_addr = 0x00000000;          // ignore destination
    titems[1].mask = &ip_mask;

    titems[2].type = RTE_FLOW_ITEM_TYPE_END;

    return rte_flow_pattern_template_create(port_id, &attr, titems, error);
}


struct rte_flow_template_table *
snippet_ipv4_block_flow_create_table(uint16_t port_id, struct rte_flow_error *error)
{
    struct rte_flow_pattern_template *pt;
    struct rte_flow_actions_template *at;

    struct rte_flow_template_table_attr table_attr = {
        .flow_attr = {
            .group    = 0,
            .priority = 0,
            .ingress  = 1,
            .egress   = 0,
            .transfer = 0,
        },
        .nb_flows = n_ips,  /* one slot per blocked IP */
    };

    pt = create_pattern_template(port_id, error);
    if (pt == NULL)
    {
        printf("Failed to create pattern template: %s (%s)\n",
               error->message, rte_strerror(rte_errno));

        return NULL;
    }

    at = create_actions_template(port_id, error);
    if (at == NULL)
    {
        printf("Failed to create actions template: %s (%s)\n",
               error->message, rte_strerror(rte_errno));

        return NULL;
    }

    return rte_flow_template_table_create(port_id, &table_attr, &pt, 1, &at, 1, error);
}


int
snippet_ipv4_block_install_rules(uint16_t port_id,
                                    uint16_t *n_ips_out,
                                    struct rte_flow **flows_out,
                                    struct rte_flow_error *error)
{
    printf("\n\niplist = %p, n_ips = %d, block_flows = %p\n\n", ip_list, n_ips, block_flows);
    if (ip_list == NULL || n_ips == 0 || block_flows == NULL)
    {
        fprintf(stderr, "Call snippet_ipv4_block_configure() first\n");
        return -1;
    }

    *n_ips_out = n_ips;
    flows_out = block_flows;

    struct rte_flow_template_table *table = snippet_ipv4_block_flow_create_table(port_id, error);

    if (table == NULL)
    {
        printf("Failed to create block table: %s (%s)\n",
               error->message, rte_strerror(rte_errno));

        return -1;
    }

    struct rte_flow_op_attr op_attr = { .postpone = 0 };
    int created = 0;

    for (uint16_t i = 0; i < n_ips; i++)
    {
        struct rte_flow_item patterns[MAX_PATTERN_NUM] = {0};
        struct rte_flow_item_ipv4 ip_spec = {0};
        struct rte_flow_item_ipv4 ip_mask = {0};

        patterns[0].type = RTE_FLOW_ITEM_TYPE_ETH;

        patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
        ip_spec.hdr.src_addr = htonl(ip_list[i]);    // exact source IP 
        ip_mask.hdr.src_addr = htonl(0xFFFFFFFF);
        patterns[1].spec = &ip_spec;
        patterns[1].mask = &ip_mask;

        patterns[2].type = RTE_FLOW_ITEM_TYPE_END;

        struct rte_flow_action actions[MAX_ACTION_NUM]  = {0};
        struct rte_flow_action_count cnt = {0};

        actions[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
        actions[0].conf = &cnt;
        actions[1].type = RTE_FLOW_ACTION_TYPE_DROP;
        actions[2].type = RTE_FLOW_ACTION_TYPE_END;

        block_flows[i] = rte_flow_async_create(
            port_id,
            1,          // flow queue
            &op_attr,
            table,
            patterns,
            0,          // pattern template index
            actions,
            0,          // actions template index
            (void *)(uintptr_t)i, // user data = rule index for later queries
            error);

        if (block_flows[i] == NULL)
        {
            printf("Failed to create block rule for IP #%u: %s (%s)\n",
                   i, error->message, rte_strerror(rte_errno));
            /* Non-fatal: keep going, report partial success. */
        }
        
        else
            created++;
    }

    //Push operations to be installed
    if (rte_flow_push(port_id, 1, error) < 0)
        printf("rte_flow_push warning: %s\n", error->message);

    printf("Installed %d / %u DROP+COUNT rules.\n", created, n_ips);

    return created;
}