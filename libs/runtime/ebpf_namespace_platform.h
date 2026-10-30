// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_namespace.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_namespace_process
{
    uintptr_t identity;
    uint64_t start_key;
    void* reference;
    bool simulated;
} ebpf_namespace_process_t;

typedef void (*ebpf_namespace_process_exit_callback_t)(uintptr_t identity, uint64_t start_key);

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_platform_reference_current(_Out_ ebpf_namespace_process_t* process);

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_platform_reference_process(
    _In_ const ebpf_namespace_process_t* process, _Out_ ebpf_namespace_process_t* reference);

void
ebpf_namespace_platform_dereference_process(_In_ const ebpf_namespace_process_t* process);

bool
ebpf_namespace_platform_process_exiting(_In_ const ebpf_namespace_process_t* process);

_Must_inspect_result_ ebpf_result_t
ebpf_namespace_platform_register_exit(_In_ ebpf_namespace_process_exit_callback_t callback);

void
ebpf_namespace_platform_unregister_exit(void);

_Ret_maybenull_ void*
ebpf_namespace_platform_allocate(size_t size);

CXPLAT_EXTERN_C_END
