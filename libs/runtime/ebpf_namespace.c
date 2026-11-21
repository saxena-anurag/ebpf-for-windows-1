// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_namespace.h"

void
ebpf_namespace_state_initialize(_Out_ ebpf_namespace_state_t* state)
{
    memset(state, 0, sizeof(*state));
    ebpf_lock_create(&state->lock);
}

void
ebpf_namespace_state_destroy(_Inout_ ebpf_namespace_state_t* state)
{
    ebpf_lock_destroy(&state->lock);
}

void
ebpf_namespace_state_capture(_Inout_ ebpf_namespace_state_t* state, _Out_ ebpf_request_context_t* context)
{
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&state->lock);
    const ebpf_request_context_t snapshot = {
        .namespace_id = state->namespace_id,
        .namespace_target = state,
    };
    *context = snapshot;
    ebpf_lock_unlock(&state->lock, lock_state);
}

void
ebpf_namespace_state_set(_Inout_ ebpf_namespace_state_t* state, _In_ const GUID* namespace_id)
{
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&state->lock);
    state->namespace_id = *namespace_id;
    ebpf_lock_unlock(&state->lock, lock_state);
}
