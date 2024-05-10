// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "bpf2c_structs.h"

#if defined(NO_CRT)
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#define bool _Bool
#define false 0
#define true 1
#define UINT32_MAX ((uint32_t)0xFFFFFFFF)

#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#define UBPF_STACK_SIZE 512

#define IMMEDIATE(X) (int32_t) X
#define OFFSET(X) (int16_t) X
#define POINTER(X) (uint64_t)(X)

#if !defined(htobe16)
#define htobe16(X) swap16(X)
#define htobe32(X) swap32(X)
#define htobe64(X) swap64(X)

#define htole16(X) (X)
#define htole32(X) (X)
#define htole64(X) (X)
#endif

#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))
#define EBPF_FIELD_SIZE(s, m) (sizeof(((s*)0)->m))
#define EBPF_SIZE_INCLUDING_FIELD(s, m) (EBPF_OFFSET_OF(s, m) + EBPF_FIELD_SIZE(s, m))

    // typedef struct _ebpf_extension_header
    // {
    //     uint16_t version; ///< Version of the extension data structure.
    //     size_t size;      ///< Size of the extension data structure.
    // } ebpf_extension_header_t;

    // typedef struct _map_address
    // {
    //     ebpf_extension_header_t header;
    //     void* address;
    // } map_address_t;

    /**
     * @brief Inline function used to implement the 16 bit EBPF_OP_LE/EBPF_OP_BE instruction.
     *
     * @param[in] value The value to swap.
     * @return The swapped value.
     */
    inline uint16_t
    swap16(uint16_t value)
    {
        return value << 8 | value >> 8;
    }

    /**
     * @brief Inline function used to implement the 32 bit EBPF_OP_LE/EBPF_OP_BE instruction.
     *
     * @param[in] value The value to swap.
     * @return The swapped value.
     */
    inline uint32_t
    swap32(uint32_t value)
    {
        return swap16(value >> 16) | ((uint32_t)swap16(value & ((1 << 16) - 1))) << 16;
    }

    /**
     * @brief Inline function used to implement the 64 bit EBPF_OP_LE/EBPF_OP_BE instruction.
     *
     * @param[in] value The value to swap.
     * @return The swapped value.
     */
    inline uint64_t
    swap64(uint64_t value)
    {
        return swap32(value >> 32) | ((uint64_t)swap32(value & ((1ull << 32ull) - 1))) << 32;
    }

#ifdef __cplusplus
}
#endif
