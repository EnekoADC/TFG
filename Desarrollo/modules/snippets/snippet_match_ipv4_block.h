/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#ifndef SNIPPET_MATCH_IPV4_BLOCK_H
#define SNIPPET_MATCH_IPV4_BLOCK_H

#include <stdint.h>
#include <rte_flow.h>


#define MAX_PATTERN_NUM   3   /* ETH, IPV4, END */
#define MAX_ACTION_NUM    3   /* COUNT, DROP, END */

void
snippet_init_ipv4_block(void);
#define snippet_init snippet_init_ipv4_block

//Configure parameters while respecting snippet API
void
snippet_ipv4_block_configure(const uint32_t *ips, uint16_t n);

void
snippet_ipv4_block_flow_create_actions(uint16_t port_id, struct rte_flow_action *actions);
#define snippet_skeleton_flow_create_actions snippet_ipv4_block_flow_create_actions

void
snippet_ipv4_block_flow_create_patterns(struct rte_flow_item *patterns);
#define snippet_skeleton_flow_create_patterns snippet_ipv4_block_flow_create_patterns


struct rte_flow_template_table *
snippet_ipv4_block_flow_create_table(uint16_t port_id, struct rte_flow_error *error);
#define snippet_skeleton_flow_create_table snippet_ipv4_block_flow_create_table

int
snippet_ipv4_block_install_rules(uint16_t port_id,
                                    uint16_t *n_ips_out,
                                    struct rte_flow **flows_out,
                                    struct rte_flow_error *error);

#endif /* SNIPPET_MATCH_IPV4_BLOCK_H */