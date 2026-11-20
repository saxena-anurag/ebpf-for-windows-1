// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_namespace_state
{
    ebpf_lock_t lock;
    GUID namespace_id;
} ebpf_namespace_state_t;

typedef struct _ebpf_request_context
{
    GUID namespace_id;
    ebpf_namespace_state_t* namespace_target;
    struct _ebpf_core_object* referenced_object;
} ebpf_request_context_t;

void
ebpf_namespace_state_initialize(_Out_ ebpf_namespace_state_t* state);

void
ebpf_namespace_state_destroy(_Inout_ ebpf_namespace_state_t* state);

void
ebpf_namespace_state_capture(_Inout_ ebpf_namespace_state_t* state, _Out_ ebpf_request_context_t* context);

void
ebpf_namespace_state_set(_Inout_ ebpf_namespace_state_t* state, _In_ const GUID* namespace_id);

CXPLAT_EXTERN_C_END
