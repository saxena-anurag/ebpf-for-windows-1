// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by netebpfext.sys for use by eBPF programs.

// XDP hook.  We use "struct xdp_md" for cross-platform compatibility.
typedef struct xdp_md
{
    void* data;               ///< Pointer to start of packet data.
    void* data_end;           ///< Pointer to end of packet data.
    uint64_t data_meta;       ///< Packet metadata.
    uint32_t ingress_ifindex; ///< Ingress interface index.

    /* size: 26, cachelines: 1, members: 4 */
    /* last cacheline: 26 bytes */
} xdp_md_t;

typedef enum _xdp_action
{
    XDP_PASS = 1, ///< Allow the packet to pass.
    XDP_DROP,     ///< Drop the packet.
    XDP_TX        ///< Bounce the received packet back out the same NIC it arrived on.
} xdp_action_t;

/**
 * @brief Handle an incoming packet as early as possible.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_XDP
 *
 * @param[in] context Packet metadata.
 * @retval XDP_PASS Allow the packet to pass.
 * @retval XDP_DROP Drop the packet.
 * @retval XDP_TX Bounce the received packet back out the same NIC it arrived on.
 */
typedef xdp_action_t
xdp_hook_t(xdp_md_t* context);

// XDP helper functions.
#define XDP_EXT_HELPER_FN_BASE 0xFFFF

#ifndef __doxygen
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_xdp_adjust_head = XDP_EXT_HELPER_FN_BASE + 1,
} ebpf_nethook_helper_id_t;

/**
 * @brief Adjust XDP context data pointer.
 *
 * @param[in] ctx XDP context.
 * @param[in] delta Number of bytes to move the data pointer by.
 *
 * @retval 0 The operation was successful.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_xdp_adjust_head, (xdp_md_t * ctx, int delta));
#ifndef __doxygen
#define bpf_xdp_adjust_head ((bpf_xdp_adjust_head_t)BPF_FUNC_xdp_adjust_head)
#endif

// BIND hook

typedef enum _bind_operation
{
    BIND_OPERATION_BIND,      ///< Entry to bind.
    BIND_OPERATION_POST_BIND, ///< After port allocation.
    BIND_OPERATION_UNBIND,    ///< Release port.
} bind_operation_t;

typedef struct _bind_md
{
    uint8_t* app_id_start;         ///< Pointer to start of App ID.
    uint8_t* app_id_end;           ///< Pointer to end of App ID.
    uint64_t process_id;           ///< Process ID.
    uint8_t socket_address[16];    ///< Socket address to bind to.
    uint8_t socket_address_length; ///< Length in bytes of the socket address.
    bind_operation_t operation;    ///< Operation to do.
    uint8_t protocol;              ///< Protocol number (e.g., IPPROTO_TCP).
} bind_md_t;

typedef enum _bind_action
{
    BIND_PERMIT,   ///< Permit the bind operation.
    BIND_DENY,     ///< Deny the bind operation.
    BIND_REDIRECT, ///< Change the bind endpoint.
} bind_action_t;

/**
 * @brief Handle an AF_INET socket bind() request.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_BIND
 *
 * @param[in] context Socket metadata.
 * @retval BIND_PERMIT Permit the bind operation.
 * @retval BIND_DENY Deny the bind operation.
 * @retval BIND_REDIRECT Change the bind endpoint.
 */
typedef bind_action_t
bind_hook_t(bind_md_t* context);

//
// CGROUP_SOCK_ADDR.
//

#define BPF_SOCK_ADDR_VERDICT_REJECT 0
#define BPF_SOCK_ADDR_VERDICT_PROCEED 1

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201)
#endif
/**
 *  @brief Data structure used as context for BPF_PROG_TYPE_CGROUP_SOCK_ADDR program type.
 */
typedef struct bpf_sock_addr
{
    uint32_t family; ///< IP address family.
    struct
    {
        /**
         * @brief Source IP address in network byte order.
         * Local for ingress, remote for egress.
         */
        union
        {
            uint32_t msg_src_ip4;
            uint32_t msg_src_ip6[4];
        };
        uint16_t msg_src_port; ///< Source port in network byte order.
    };
    struct
    {
        /* @brief Destination IP address in network byte order.
         * Local for egress, remote for ingress.
         */
        union
        {
            uint32_t user_ip4;
            uint32_t user_ip6[4];
        };
        uint16_t user_port; ///< Destination port in network byte order.
    };
    uint32_t protocol;       ///< IP protocol.
    uint32_t compartment_id; ///< Network compartment Id.
    uint64_t interface_luid; ///< Interface LUID.
    uint64_t process_id;     ///< Process Id.
} bpf_sock_addr_t;

/**
 * @brief Handle socket operation. Currently supports ingress/egress connection initialization.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_BIND
 *
 * Attach type(s):
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT
 *
 * @param[in] context \ref bpf_sock_addr_t
 * @retval BPF_SOCK_ADDR_VERDICT_PROCEED Block the socket operation.
 * @retval BPF_SOCK_ADDR_VERDICT_REJECT Allow the socket operation.
 *
 * Any other return value other than the two mentioned above is treated as BPF_SOCK_ADDR_VERDICT_REJECT.
 */
typedef int
sock_addr_hook_t(bpf_sock_addr_t* context);

typedef enum _bpf_sock_op_type
{
    /** @brief Indicates when an active (outbound) connection is established. **/
    BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
    /** @brief Indicates when a passive (inbound) connection is established. **/
    BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    /** @brief Indicates when a connection is deleted. **/
    BPF_SOCK_OPS_CONNECTION_DELETED_CB
} bpf_sock_op_type_t;

typedef struct _bpf_sock_ops
{
    bpf_sock_op_type_t op;
    uint32_t family; ///< IP address family.
    struct
    {
        union
        {
            uint32_t local_ip4;
            uint32_t local_ip6[4];
        }; ///< Local IP address.
        uint32_t local_port;
    }; ///< Local IP address and port stored in network byte order.
    struct
    {
        union
        {
            uint32_t remote_ip4;
            uint32_t remote_ip6[4];
        }; ///< Remote IP address.
        uint32_t remote_port;
    };                       ///< Remote IP address and port stored in network byte order.
    uint8_t protocol;        ///< IP protocol.
    uint32_t compartment_id; ///< Network compartment Id.
    uint64_t interface_luid; ///< Interface LUID.
} bpf_sock_ops_t;

/**
 * @brief Handle socket event notification. Currently notifies ingress/egress connection establishment and tear down.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_SOCK_OPS
 *
 * Attach type(s):
 *  \ref EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS
 *
 * @param[in] context \ref bpf_sock_ops_t
 * @return 0 on success, or error value in case of failure.
 *
 */
typedef int
sock_ops_hook_t(bpf_sock_ops_t* context);

#ifdef _MSC_VER
#pragma warning(pop)
#endif
