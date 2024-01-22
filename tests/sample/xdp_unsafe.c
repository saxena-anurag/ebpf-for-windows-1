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

#include "xdp_common.h"

inline void *
data_start(xdp_md_t *ctx)
{
	void *ptr;
	asm volatile("%0 = *(u32 *)(%1 + %2)"
        : "=r"(ptr) : "r"(ctx), "i"(__builtin_offsetof(xdp_md_t, data)));
	return ptr;
}

//
// This eBPF program intercepts inbound UDP packets destined to port REFLECTION_TEST_PORT and "reflects" it back
// by swapping the MAC and IP addresses. The program will only work for packets where UDP is the next header
// for IP header. For instance this will not work for AH packets.
//
SEC("xdp_test/unsafe")
int
unsafe_program(xdp_md_t* ctx)
{

    int rc = XDP_PASS;

    ETHERNET_HEADER* ethernet_header = NULL;
    char* next_header = data_start(ctx);
    if (next_header + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        goto Done;
    }

    ethernet_header = (ETHERNET_HEADER*)next_header;
    next_header = (char*)(ethernet_header + 1);
    if (ethernet_header->Type != ntohs(ETHERNET_TYPE_IPV4) && ethernet_header->Type != ntohs(ETHERNET_TYPE_IPV6)) {
        rc = XDP_DROP;
    }

Done:
    return rc;
}