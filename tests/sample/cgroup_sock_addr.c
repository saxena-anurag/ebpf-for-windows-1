// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "socket_tests_common.h"

SEC("maps")
struct bpf_map_def egress_connection_policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(destination_entry_t),
    .value_size = sizeof(destination_entry_t),
    .max_entries = 100};

SEC("maps")
struct bpf_map_def egress_statistics_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(uint32_t), .value_size = sizeof(uint32_t), .max_entries = 4};

__inline void
update_statistics(bool redirected, bool v4)
{
    uint32_t* count = NULL;
    int key = 0;

    if (!v4) {
        key = 2;
    }
    if (redirected) {
        key++;
    }
    count = bpf_map_lookup_elem(&egress_statistics_map, &key);
    if (count != NULL) {
        (*count) = (*count) + 1;
    }
}

__inline int
authorize_v4(bpf_sock_addr_t* ctx, struct bpf_map_def* connection_policy_map)
{
    destination_entry_t tuple_key = {0};
    destination_entry_t* verdict = NULL;
    int result;
    bool redirected = false;
    uint32_t destination_ip = bpf_ntohl(ctx->user_ip4);

    tuple_key.destination_ip.ipv4 = ctx->user_ip4;
    tuple_key.destination_port = ctx->user_port;

    verdict = bpf_map_lookup_elem(connection_policy_map, &tuple_key);
    if (verdict == NULL) {
        // Now lookup without destination port.
        bpf_printk("entry not found 1 for %u:%u", destination_ip, ctx->user_port);
        tuple_key.destination_port = 0;
        verdict = bpf_map_lookup_elem(connection_policy_map, &tuple_key);
    }

    if (verdict != NULL) {
        bpf_printk("entry found for %u", destination_ip);
        ctx->user_ip4 = verdict->destination_ip.ipv4;
        if (tuple_key.destination_port != 0) {
            ctx->user_port = verdict->destination_port;
        }
        redirected = true;
    } else {
        bpf_printk("entry not found 2 for %u", destination_ip);
    }
    update_statistics(redirected, true);

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

__inline int
authorize_v6(bpf_sock_addr_t* ctx, struct bpf_map_def* connection_policy_map)
{
    update_statistics(false, false);
    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/connect4")
int
authorize_connect4(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx, &egress_connection_policy_map);
}

SEC("cgroup/connect6")
int
authorize_connect6(bpf_sock_addr_t* ctx)
{
    return authorize_v6(ctx, &egress_connection_policy_map);
}
