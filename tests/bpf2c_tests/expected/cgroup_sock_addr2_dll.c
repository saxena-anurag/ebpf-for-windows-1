// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr2.o

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <stdio.h>

#include "bpf2c.h"

#define metadata_table cgroup_sock_addr2##_metadata_table
extern metadata_table_t metadata_table;

BOOL APIENTRY
DllMain(_In_ HMODULE hModule, unsigned int ul_reason_for_call, _In_ void* lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void
division_by_zero(uint32_t address)
{
    fprintf(stderr, "Divide by zero at address %d\n", address);
}

#define FIND_METADATA_ENTRTY(NAME, X) \
    if (std::string(NAME) == #X)      \
        return &X;

__declspec(dllexport) metadata_table_t* get_metadata_table() { return &metadata_table; }

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}
#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         24,                // Size in bytes of a map key.
         24,                // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "policy_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t authorize_connect4_helpers[] = {
    {NULL, 14, "helper_id_14"},
    {NULL, 1, "helper_id_1"},
};

static GUID authorize_connect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_connect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_connect4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
authorize_connect4(void* context)
#line 105 "sample/cgroup_sock_addr2.c"
{
#line 105 "sample/cgroup_sock_addr2.c"
    // Prologue
#line 105 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 105 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 105 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 105 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr2.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r7 src=r0 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r7 offset=-8 imm=0
#line 40 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r7;
    // EBPF_OP_STXW pc=3 dst=r10 src=r7 offset=-12 imm=0
#line 40 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r7;
    // EBPF_OP_STXW pc=4 dst=r10 src=r7 offset=-16 imm=0
#line 40 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r7;
    // EBPF_OP_STXW pc=5 dst=r10 src=r7 offset=-20 imm=0
#line 40 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r7;
    // EBPF_OP_LDXW pc=6 dst=r3 src=r6 offset=24 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_STXW pc=7 dst=r10 src=r3 offset=-24 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r3;
    // EBPF_OP_LDXH pc=8 dst=r4 src=r6 offset=40 imm=0
#line 42 "sample/cgroup_sock_addr2.c"
    r4 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=9 dst=r10 src=r4 offset=-8 imm=0
#line 42 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint16_t)r4;
    // EBPF_OP_LDXW pc=10 dst=r1 src=r6 offset=44 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_STXW pc=11 dst=r10 src=r1 offset=-4 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=12 dst=r1 src=r0 offset=0 imm=29989
#line 43 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(29989);
    // EBPF_OP_STXH pc=13 dst=r10 src=r1 offset=-56 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=540702836
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)2318356710503905396;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-64 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1937075809
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7142773199232921185;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-72 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=20 dst=r10 src=r7 offset=-54 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-54)) = (uint8_t)r7;
    // EBPF_OP_MOV64_REG pc=21 dst=r1 src=r10 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r1 src=r0 offset=0 imm=-72
#line 45 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-72);
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=19
#line 45 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(19);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=14
#line 45 "sample/cgroup_sock_addr2.c"
    r0 = authorize_connect4_helpers[0].address
#line 45 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 45 "sample/cgroup_sock_addr2.c"
    if ((authorize_connect4_helpers[0].tail_call) && (r0 == 0))
#line 45 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_LDXW pc=25 dst=r1 src=r6 offset=44 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=26 dst=r1 src=r0 offset=1 imm=17
#line 47 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17))
#line 47 "sample/cgroup_sock_addr2.c"
        goto label_1;
        // EBPF_OP_JNE_IMM pc=27 dst=r1 src=r0 offset=63 imm=6
#line 47 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6))
#line 47 "sample/cgroup_sock_addr2.c"
        goto label_3;
label_1:
    // EBPF_OP_LDXW pc=28 dst=r1 src=r6 offset=0 imm=0
#line 51 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=29 dst=r1 src=r0 offset=61 imm=2
#line 51 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(2))
#line 51 "sample/cgroup_sock_addr2.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=30 dst=r2 src=r10 offset=0 imm=0
#line 51 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=31 dst=r2 src=r0 offset=0 imm=-24
#line 56 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=32 dst=r1 src=r0 offset=0 imm=0
#line 56 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=1
#line 56 "sample/cgroup_sock_addr2.c"
    r0 = authorize_connect4_helpers[1].address
#line 56 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 56 "sample/cgroup_sock_addr2.c"
    if ((authorize_connect4_helpers[1].tail_call) && (r0 == 0))
#line 56 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=35 dst=r8 src=r0 offset=0 imm=0
#line 56 "sample/cgroup_sock_addr2.c"
    r8 = r0;
    // EBPF_OP_JEQ_IMM pc=36 dst=r8 src=r0 offset=30 imm=0
#line 57 "sample/cgroup_sock_addr2.c"
    if (r8 == IMMEDIATE(0))
#line 57 "sample/cgroup_sock_addr2.c"
        goto label_2;
        // EBPF_OP_MOV64_IMM pc=37 dst=r1 src=r0 offset=0 imm=0
#line 57 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=38 dst=r10 src=r1 offset=-34 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-34)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=39 dst=r1 src=r0 offset=0 imm=29989
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(29989);
    // EBPF_OP_STXH pc=40 dst=r10 src=r1 offset=-36 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=41 dst=r1 src=r0 offset=0 imm=539784485
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(539784485);
    // EBPF_OP_STXW pc=42 dst=r10 src=r1 offset=-40 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=43 dst=r1 src=r0 offset=0 imm=1818326560
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)2322280112866817568;
    // EBPF_OP_STXDW pc=45 dst=r10 src=r1 offset=-48 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=46 dst=r1 src=r0 offset=0 imm=1696627064
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8751185043426146680;
    // EBPF_OP_STXDW pc=48 dst=r10 src=r1 offset=-56 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=49 dst=r1 src=r0 offset=0 imm=1684960623
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8030604369981240687;
    // EBPF_OP_STXDW pc=51 dst=r10 src=r1 offset=-64 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=52 dst=r1 src=r0 offset=0 imm=1937075809
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7358945981346704993;
    // EBPF_OP_STXDW pc=54 dst=r10 src=r1 offset=-72 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDXH pc=55 dst=r4 src=r8 offset=16 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    r4 = *(uint16_t*)(uintptr_t)(r8 + OFFSET(16));
    // EBPF_OP_LDXW pc=56 dst=r3 src=r8 offset=0 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=57 dst=r1 src=r10 offset=0 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=58 dst=r1 src=r0 offset=0 imm=-72
#line 58 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-72);
    // EBPF_OP_MOV64_IMM pc=59 dst=r2 src=r0 offset=0 imm=39
#line 58 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(39);
    // EBPF_OP_CALL pc=60 dst=r0 src=r0 offset=0 imm=14
#line 58 "sample/cgroup_sock_addr2.c"
    r0 = authorize_connect4_helpers[0].address
#line 58 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/cgroup_sock_addr2.c"
    if ((authorize_connect4_helpers[0].tail_call) && (r0 == 0))
#line 58 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_LDXW pc=61 dst=r1 src=r8 offset=0 imm=0
#line 59 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_STXW pc=62 dst=r6 src=r1 offset=24 imm=0
#line 59 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r6 + OFFSET(24)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=63 dst=r1 src=r8 offset=16 imm=0
#line 60 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r8 + OFFSET(16));
    // EBPF_OP_STXH pc=64 dst=r6 src=r1 offset=40 imm=0
#line 60 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=65 dst=r7 src=r0 offset=0 imm=1
#line 60 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JA pc=66 dst=r0 src=r0 offset=24 imm=0
#line 60 "sample/cgroup_sock_addr2.c"
    goto label_3;
label_2:
    // EBPF_OP_LDDW pc=67 dst=r1 src=r0 offset=0 imm=745874720
#line 60 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)32973392390202656;
    // EBPF_OP_STXDW pc=69 dst=r10 src=r1 offset=-32 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=70 dst=r1 src=r0 offset=0 imm=544370534
#line 64 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)4213510437162086246;
    // EBPF_OP_STXDW pc=72 dst=r10 src=r1 offset=-40 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=73 dst=r1 src=r0 offset=0 imm=1852121209
#line 64 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)2340027325789577337;
    // EBPF_OP_STXDW pc=75 dst=r10 src=r1 offset=-48 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=76 dst=r1 src=r0 offset=0 imm=543452777
#line 64 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8678280832871591529;
    // EBPF_OP_STXDW pc=78 dst=r10 src=r1 offset=-56 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=79 dst=r1 src=r0 offset=0 imm=1847616617
#line 64 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7359009813061198953;
    // EBPF_OP_STXDW pc=81 dst=r10 src=r1 offset=-64 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=82 dst=r1 src=r0 offset=0 imm=1937075809
#line 64 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7214830793270849121;
    // EBPF_OP_STXDW pc=84 dst=r10 src=r1 offset=-72 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDXH pc=85 dst=r4 src=r6 offset=40 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    r4 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_LDXW pc=86 dst=r3 src=r6 offset=24 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_MOV64_REG pc=87 dst=r1 src=r10 offset=0 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=88 dst=r1 src=r0 offset=0 imm=-72
#line 64 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-72);
    // EBPF_OP_MOV64_IMM pc=89 dst=r2 src=r0 offset=0 imm=48
#line 64 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(48);
    // EBPF_OP_CALL pc=90 dst=r0 src=r0 offset=0 imm=14
#line 64 "sample/cgroup_sock_addr2.c"
    r0 = authorize_connect4_helpers[0].address
#line 64 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/cgroup_sock_addr2.c"
    if ((authorize_connect4_helpers[0].tail_call) && (r0 == 0))
#line 64 "sample/cgroup_sock_addr2.c"
        return 0;
label_3:
    // EBPF_OP_MOV64_REG pc=91 dst=r0 src=r7 offset=0 imm=0
#line 107 "sample/cgroup_sock_addr2.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=92 dst=r0 src=r0 offset=0 imm=0
#line 107 "sample/cgroup_sock_addr2.c"
    return r0;
#line 107 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t authorize_connect6_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 12, "helper_id_12"},
};

static GUID authorize_connect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_connect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_connect6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
authorize_connect6(void* context)
#line 112 "sample/cgroup_sock_addr2.c"
{
#line 112 "sample/cgroup_sock_addr2.c"
    // Prologue
#line 112 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 112 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 112 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 112 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 112 "sample/cgroup_sock_addr2.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r7 src=r0 offset=0 imm=0
#line 112 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=2 dst=r10 src=r7 offset=-8 imm=0
#line 74 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r7;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r7 offset=-16 imm=0
#line 74 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r7;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r7 offset=-24 imm=0
#line 74 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r7;
    // EBPF_OP_LDXW pc=5 dst=r1 src=r6 offset=44 imm=0
#line 76 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=6 dst=r1 src=r0 offset=1 imm=17
#line 76 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17))
#line 76 "sample/cgroup_sock_addr2.c"
        goto label_1;
        // EBPF_OP_JNE_IMM pc=7 dst=r1 src=r0 offset=73 imm=6
#line 76 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6))
#line 76 "sample/cgroup_sock_addr2.c"
        goto label_3;
label_1:
    // EBPF_OP_LDXW pc=8 dst=r2 src=r6 offset=0 imm=0
#line 80 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=9 dst=r2 src=r0 offset=71 imm=23
#line 80 "sample/cgroup_sock_addr2.c"
    if (r2 != IMMEDIATE(23))
#line 80 "sample/cgroup_sock_addr2.c"
        goto label_3;
        // EBPF_OP_LDXW pc=10 dst=r2 src=r6 offset=36 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(36));
    // EBPF_OP_LSH64_IMM pc=11 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/cgroup_sock_addr2.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=12 dst=r3 src=r6 offset=32 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(32));
    // EBPF_OP_OR64_REG pc=13 dst=r2 src=r3 offset=0 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r2 offset=-16 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=15 dst=r2 src=r6 offset=28 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(28));
    // EBPF_OP_LSH64_IMM pc=16 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/cgroup_sock_addr2.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=17 dst=r3 src=r6 offset=24 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_OR64_REG pc=18 dst=r2 src=r3 offset=0 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r2 offset=-24 imm=0
#line 84 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_LDXH pc=20 dst=r2 src=r6 offset=40 imm=0
#line 85 "sample/cgroup_sock_addr2.c"
    r2 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=21 dst=r10 src=r2 offset=-8 imm=0
#line 85 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint16_t)r2;
    // EBPF_OP_STXW pc=22 dst=r10 src=r1 offset=-4 imm=0
#line 86 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=23 dst=r2 src=r10 offset=0 imm=0
#line 86 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r2 src=r0 offset=0 imm=-24
#line 84 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=25 dst=r1 src=r0 offset=0 imm=0
#line 89 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=1
#line 89 "sample/cgroup_sock_addr2.c"
    r0 = authorize_connect6_helpers[0].address
#line 89 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 89 "sample/cgroup_sock_addr2.c"
    if ((authorize_connect6_helpers[0].tail_call) && (r0 == 0))
#line 89 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=28 dst=r7 src=r0 offset=0 imm=0
#line 89 "sample/cgroup_sock_addr2.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=29 dst=r7 src=r0 offset=33 imm=0
#line 90 "sample/cgroup_sock_addr2.c"
    if (r7 == IMMEDIATE(0))
#line 90 "sample/cgroup_sock_addr2.c"
        goto label_2;
        // EBPF_OP_MOV64_REG pc=30 dst=r8 src=r6 offset=0 imm=0
#line 90 "sample/cgroup_sock_addr2.c"
    r8 = r6;
    // EBPF_OP_ADD64_IMM pc=31 dst=r8 src=r0 offset=0 imm=24
#line 90 "sample/cgroup_sock_addr2.c"
    r8 += IMMEDIATE(24);
    // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=0
#line 90 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=33 dst=r10 src=r1 offset=-34 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-34)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=34 dst=r1 src=r0 offset=0 imm=25973
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25973);
    // EBPF_OP_STXH pc=35 dst=r10 src=r1 offset=-36 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=36 dst=r1 src=r0 offset=0 imm=1818326560
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(1818326560);
    // EBPF_OP_STXW pc=37 dst=r10 src=r1 offset=-40 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=38 dst=r1 src=r0 offset=0 imm=1696627064
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8751185043426146680;
    // EBPF_OP_STXDW pc=40 dst=r10 src=r1 offset=-48 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=41 dst=r1 src=r0 offset=0 imm=1684960623
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8030604369981240687;
    // EBPF_OP_STXDW pc=43 dst=r10 src=r1 offset=-56 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=44 dst=r1 src=r0 offset=0 imm=1937075809
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7358945981346704993;
    // EBPF_OP_STXDW pc=46 dst=r10 src=r1 offset=-64 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=47 dst=r1 src=r10 offset=0 imm=0
#line 91 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=48 dst=r1 src=r0 offset=0 imm=-64
#line 91 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=49 dst=r2 src=r0 offset=0 imm=31
#line 91 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(31);
    // EBPF_OP_CALL pc=50 dst=r0 src=r0 offset=0 imm=12
#line 91 "sample/cgroup_sock_addr2.c"
    r0 = authorize_connect6_helpers[1].address
#line 91 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 91 "sample/cgroup_sock_addr2.c"
    if ((authorize_connect6_helpers[1].tail_call) && (r0 == 0))
#line 91 "sample/cgroup_sock_addr2.c"
        return 0;
        // EBPF_OP_LDXW pc=51 dst=r1 src=r7 offset=12 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(12));
    // EBPF_OP_STXW pc=52 dst=r8 src=r1 offset=12 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(12)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=53 dst=r1 src=r7 offset=8 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(8));
    // EBPF_OP_STXW pc=54 dst=r8 src=r1 offset=8 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(8)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=55 dst=r1 src=r7 offset=4 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(4));
    // EBPF_OP_STXW pc=56 dst=r8 src=r1 offset=4 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=57 dst=r1 src=r7 offset=0 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_STXW pc=58 dst=r8 src=r1 offset=0 imm=0
#line 92 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r8 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=59 dst=r1 src=r7 offset=16 imm=0
#line 93 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_STXH pc=60 dst=r6 src=r1 offset=40 imm=0
#line 93 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=61 dst=r7 src=r0 offset=0 imm=1
#line 93 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JA pc=62 dst=r0 src=r0 offset=18 imm=0
#line 93 "sample/cgroup_sock_addr2.c"
    goto label_3;
label_2:
    // EBPF_OP_LDDW pc=63 dst=r1 src=r0 offset=0 imm=1852121209
#line 93 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3348833642320568441;
    // EBPF_OP_STXDW pc=65 dst=r10 src=r1 offset=-40 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=543452777
#line 97 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)8678280832871591529;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r1 offset=-48 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=69 dst=r1 src=r0 offset=0 imm=1847616617
#line 97 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7359009813061198953;
    // EBPF_OP_STXDW pc=71 dst=r10 src=r1 offset=-56 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=1937075809
#line 97 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7214830793270849121;
    // EBPF_OP_STXDW pc=74 dst=r10 src=r1 offset=-64 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=75 dst=r7 src=r0 offset=0 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=76 dst=r10 src=r7 offset=-32 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint8_t)r7;
    // EBPF_OP_MOV64_REG pc=77 dst=r1 src=r10 offset=0 imm=0
#line 97 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=78 dst=r1 src=r0 offset=0 imm=-64
#line 97 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=79 dst=r2 src=r0 offset=0 imm=33
#line 97 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(33);
    // EBPF_OP_CALL pc=80 dst=r0 src=r0 offset=0 imm=12
#line 97 "sample/cgroup_sock_addr2.c"
    r0 = authorize_connect6_helpers[1].address
#line 97 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 97 "sample/cgroup_sock_addr2.c"
    if ((authorize_connect6_helpers[1].tail_call) && (r0 == 0))
#line 97 "sample/cgroup_sock_addr2.c"
        return 0;
label_3:
    // EBPF_OP_MOV64_REG pc=81 dst=r0 src=r7 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr2.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=82 dst=r0 src=r0 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr2.c"
    return r0;
#line 114 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        authorize_connect4,
        "cgroup~1",
        "cgroup/connect4",
        "authorize_connect4",
        authorize_connect4_maps,
        1,
        authorize_connect4_helpers,
        2,
        93,
        &authorize_connect4_program_type_guid,
        &authorize_connect4_attach_type_guid,
    },
    {
        0,
        authorize_connect6,
        "cgroup~2",
        "cgroup/connect6",
        "authorize_connect6",
        authorize_connect6_maps,
        1,
        authorize_connect6_helpers,
        2,
        83,
        &authorize_connect6_program_type_guid,
        &authorize_connect6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 2;
}

metadata_table_t cgroup_sock_addr2_metadata_table = {_get_programs, _get_maps, _get_hash};