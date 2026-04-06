// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from multiple_programs.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         10,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "canary"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t program1_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID program1_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID program1_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t program1_maps[] = {
    0,
};

#pragma code_seg(push, "bind_4")
static uint64_t
program1(void* context, const program_runtime_context_t* runtime_context)
#line 47 "sample/multiple_programs.c"
{
#line 47 "sample/multiple_programs.c"
    // Prologue.
#line 47 "sample/multiple_programs.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 47 "sample/multiple_programs.c"
    register uint64_t r0 = 0;
#line 47 "sample/multiple_programs.c"
    register uint64_t r1 = 0;
#line 47 "sample/multiple_programs.c"
    register uint64_t r2 = 0;
#line 47 "sample/multiple_programs.c"
    register uint64_t r10 = 0;

#line 47 "sample/multiple_programs.c"
    r1 = (uintptr_t)context;
#line 47 "sample/multiple_programs.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 47 "sample/multiple_programs.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    {
#line 29 "sample/multiple_programs.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 29 "sample/multiple_programs.c"
        if (_array_key < 1) {
#line 29 "sample/multiple_programs.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 29 "sample/multiple_programs.c"
        } else {
#line 29 "sample/multiple_programs.c"
            r0 = 0;
#line 29 "sample/multiple_programs.c"
        }
#line 29 "sample/multiple_programs.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_1;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=8 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=9 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_1:
    // EBPF_OP_MOV64_IMM pc=10 dst=r0 src=r0 offset=0 imm=1
#line 50 "sample/multiple_programs.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=11 dst=r0 src=r0 offset=0 imm=0
#line 50 "sample/multiple_programs.c"
    return r0;
#line 47 "sample/multiple_programs.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t program2_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID program2_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID program2_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t program2_maps[] = {
    0,
};

#pragma code_seg(push, "bind_3")
static uint64_t
program2(void* context, const program_runtime_context_t* runtime_context)
#line 55 "sample/multiple_programs.c"
{
#line 55 "sample/multiple_programs.c"
    // Prologue.
#line 55 "sample/multiple_programs.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 55 "sample/multiple_programs.c"
    register uint64_t r0 = 0;
#line 55 "sample/multiple_programs.c"
    register uint64_t r1 = 0;
#line 55 "sample/multiple_programs.c"
    register uint64_t r2 = 0;
#line 55 "sample/multiple_programs.c"
    register uint64_t r6 = 0;
#line 55 "sample/multiple_programs.c"
    register uint64_t r10 = 0;

#line 55 "sample/multiple_programs.c"
    r1 = (uintptr_t)context;
#line 55 "sample/multiple_programs.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 55 "sample/multiple_programs.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-8 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-8
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    {
#line 29 "sample/multiple_programs.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 29 "sample/multiple_programs.c"
        if (_array_key < 1) {
#line 29 "sample/multiple_programs.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 29 "sample/multiple_programs.c"
        } else {
#line 29 "sample/multiple_programs.c"
            r0 = 0;
#line 29 "sample/multiple_programs.c"
        }
#line 29 "sample/multiple_programs.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_1;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=8 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=9 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=11 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r2 src=r0 offset=0 imm=-4
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=13 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=15 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    {
#line 29 "sample/multiple_programs.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 29 "sample/multiple_programs.c"
        if (_array_key < 1) {
#line 29 "sample/multiple_programs.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 29 "sample/multiple_programs.c"
        } else {
#line 29 "sample/multiple_programs.c"
            r0 = 0;
#line 29 "sample/multiple_programs.c"
        }
#line 29 "sample/multiple_programs.c"
    }
    // EBPF_OP_JEQ_IMM pc=16 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_2;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=17 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=18 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_2:
    // EBPF_OP_MOV64_IMM pc=19 dst=r0 src=r0 offset=0 imm=2
#line 59 "sample/multiple_programs.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 59 "sample/multiple_programs.c"
    return r0;
#line 55 "sample/multiple_programs.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t program3_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID program3_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID program3_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t program3_maps[] = {
    0,
};

#pragma code_seg(push, "bind_2")
static uint64_t
program3(void* context, const program_runtime_context_t* runtime_context)
#line 37 "sample/multiple_programs.c"
{
#line 37 "sample/multiple_programs.c"
    // Prologue.
#line 37 "sample/multiple_programs.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 37 "sample/multiple_programs.c"
    register uint64_t r0 = 0;
#line 37 "sample/multiple_programs.c"
    register uint64_t r1 = 0;
#line 37 "sample/multiple_programs.c"
    register uint64_t r2 = 0;
#line 37 "sample/multiple_programs.c"
    register uint64_t r6 = 0;
#line 37 "sample/multiple_programs.c"
    register uint64_t r10 = 0;

#line 37 "sample/multiple_programs.c"
    r1 = (uintptr_t)context;
#line 37 "sample/multiple_programs.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 37 "sample/multiple_programs.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-12 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-12
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    {
#line 29 "sample/multiple_programs.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 29 "sample/multiple_programs.c"
        if (_array_key < 1) {
#line 29 "sample/multiple_programs.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 29 "sample/multiple_programs.c"
        } else {
#line 29 "sample/multiple_programs.c"
            r0 = 0;
#line 29 "sample/multiple_programs.c"
        }
#line 29 "sample/multiple_programs.c"
    }
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_1;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=8 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=9 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-8 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=11 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r2 src=r0 offset=0 imm=-8
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=13 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=15 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    {
#line 29 "sample/multiple_programs.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 29 "sample/multiple_programs.c"
        if (_array_key < 1) {
#line 29 "sample/multiple_programs.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 29 "sample/multiple_programs.c"
        } else {
#line 29 "sample/multiple_programs.c"
            r0 = 0;
#line 29 "sample/multiple_programs.c"
        }
#line 29 "sample/multiple_programs.c"
    }
    // EBPF_OP_JEQ_IMM pc=16 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_2;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=17 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=18 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_2:
    // EBPF_OP_MOV64_IMM pc=19 dst=r1 src=r0 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=20 dst=r10 src=r1 offset=-4 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=21 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r2 src=r0 offset=0 imm=-4
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=23 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    {
#line 29 "sample/multiple_programs.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 29 "sample/multiple_programs.c"
        if (_array_key < 1) {
#line 29 "sample/multiple_programs.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 29 "sample/multiple_programs.c"
        } else {
#line 29 "sample/multiple_programs.c"
            r0 = 0;
#line 29 "sample/multiple_programs.c"
        }
#line 29 "sample/multiple_programs.c"
    }
    // EBPF_OP_JEQ_IMM pc=26 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_3;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=28 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_3:
    // EBPF_OP_MOV64_IMM pc=29 dst=r0 src=r0 offset=0 imm=3
#line 42 "sample/multiple_programs.c"
    r0 = IMMEDIATE(3);
    // EBPF_OP_EXIT pc=30 dst=r0 src=r0 offset=0 imm=0
#line 42 "sample/multiple_programs.c"
    return r0;
#line 37 "sample/multiple_programs.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t program4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID program4_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID program4_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t program4_maps[] = {
    0,
};

#pragma code_seg(push, "bind_1")
static uint64_t
program4(void* context, const program_runtime_context_t* runtime_context)
#line 64 "sample/multiple_programs.c"
{
#line 64 "sample/multiple_programs.c"
    // Prologue.
#line 64 "sample/multiple_programs.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 64 "sample/multiple_programs.c"
    register uint64_t r0 = 0;
#line 64 "sample/multiple_programs.c"
    register uint64_t r1 = 0;
#line 64 "sample/multiple_programs.c"
    register uint64_t r2 = 0;
#line 64 "sample/multiple_programs.c"
    register uint64_t r3 = 0;
#line 64 "sample/multiple_programs.c"
    register uint64_t r4 = 0;
#line 64 "sample/multiple_programs.c"
    register uint64_t r5 = 0;
#line 64 "sample/multiple_programs.c"
    register uint64_t r6 = 0;
#line 64 "sample/multiple_programs.c"
    register uint64_t r10 = 0;

#line 64 "sample/multiple_programs.c"
    r1 = (uintptr_t)context;
#line 64 "sample/multiple_programs.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=0
#line 64 "sample/multiple_programs.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r6 offset=-4 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=2 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3 dst=r2 src=r0 offset=0 imm=-4
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=4 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=6 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=7 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_1;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=8 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=9 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_1:
    // EBPF_OP_STXW pc=10 dst=r10 src=r6 offset=-4 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=11 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r2 src=r0 offset=0 imm=-4
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=13 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=15 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=16 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_2;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=17 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=18 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_2:
    // EBPF_OP_STXW pc=19 dst=r10 src=r6 offset=-4 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-4
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=24 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=25 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_3;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=26 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=27 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_3:
    // EBPF_OP_STXW pc=28 dst=r10 src=r6 offset=-4 imm=0
#line 28 "sample/multiple_programs.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=29 dst=r2 src=r10 offset=0 imm=0
#line 28 "sample/multiple_programs.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=30 dst=r2 src=r0 offset=0 imm=-4
#line 28 "sample/multiple_programs.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=31 dst=r1 src=r1 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=1
#line 29 "sample/multiple_programs.c"
    {
#line 29 "sample/multiple_programs.c"
        uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
#line 29 "sample/multiple_programs.c"
        if (_array_key < 1) {
#line 29 "sample/multiple_programs.c"
            r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data + (uint64_t)_array_key * 4);
#line 29 "sample/multiple_programs.c"
        } else {
#line 29 "sample/multiple_programs.c"
            r0 = 0;
#line 29 "sample/multiple_programs.c"
        }
#line 29 "sample/multiple_programs.c"
    }
    // EBPF_OP_JEQ_IMM pc=34 dst=r0 src=r0 offset=2 imm=0
#line 30 "sample/multiple_programs.c"
    if (r0 == IMMEDIATE(0)) {
#line 30 "sample/multiple_programs.c"
        goto label_4;
#line 30 "sample/multiple_programs.c"
    }
    // EBPF_OP_MOV64_IMM pc=35 dst=r1 src=r0 offset=0 imm=1
#line 30 "sample/multiple_programs.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=36 dst=r0 src=r1 offset=0 imm=0
#line 31 "sample/multiple_programs.c"
    WRITE_ONCE_32(r0, (uint32_t)r1, OFFSET(0));
label_4:
    // EBPF_OP_MOV64_IMM pc=37 dst=r0 src=r0 offset=0 imm=4
#line 70 "sample/multiple_programs.c"
    r0 = IMMEDIATE(4);
    // EBPF_OP_EXIT pc=38 dst=r0 src=r0 offset=0 imm=0
#line 70 "sample/multiple_programs.c"
    return r0;
#line 64 "sample/multiple_programs.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        program1,
        "bind_4",
        "bind_4",
        "program1",
        program1_maps,
        1,
        program1_helpers,
        1,
        12,
        &program1_program_type_guid,
        &program1_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        program2,
        "bind_3",
        "bind_3",
        "program2",
        program2_maps,
        1,
        program2_helpers,
        1,
        21,
        &program2_program_type_guid,
        &program2_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        program3,
        "bind_2",
        "bind_2",
        "program3",
        program3_maps,
        1,
        program3_helpers,
        1,
        31,
        &program3_program_type_guid,
        &program3_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        program4,
        "bind_1",
        "bind_1",
        "program4",
        program4_maps,
        1,
        program4_helpers,
        1,
        39,
        &program4_program_type_guid,
        &program4_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 4;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 1;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t multiple_programs_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
