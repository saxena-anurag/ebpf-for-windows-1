// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_request_context
{
    GUID namespace_id;
    uint64_t namespace_generation;
    uint64_t process_start_key;
} ebpf_request_context_t;

/**
 * @brief Initialize process selection and register process-exit notification.
 * Initialization and termination must be serialized by the driver's lifecycle.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_namespace_initiate(void);

/**
 * @brief Stop admission, unregister/drain callbacks and requests, then release all selections.
 * Already captured contexts contain no owned references and remain valid after termination.
 */
void
ebpf_namespace_terminate(void);

/**
 * @brief Capture the current caller's process-wide selection at PASSIVE_LEVEL.
 * Call in the original requestor's execution context, never a queued worker's context.
 * An unseen process returns GUID_NULL/generation zero without allocating registry state.
 * On failure the output is unchanged; no successful default-namespace fallback is performed.
 */
_IRQL_requires_(PASSIVE_LEVEL) _Must_inspect_result_ ebpf_result_t
    ebpf_namespace_capture_context(_Out_ ebpf_request_context_t* context);

/**
 * @brief Publish a process-wide selection in the current caller's execution context.
 * The caller must perform management authorization before invoking this internal function.
 * Repeating the current selection is idempotent, including its generation.
 */
_IRQL_requires_(PASSIVE_LEVEL) _Must_inspect_result_ ebpf_result_t
    ebpf_namespace_set_current(_In_ const GUID* namespace_id);

_IRQL_requires_(PASSIVE_LEVEL) _Must_inspect_result_ ebpf_result_t ebpf_namespace_get_current(_Out_ GUID* namespace_id);

CXPLAT_EXTERN_C_END
