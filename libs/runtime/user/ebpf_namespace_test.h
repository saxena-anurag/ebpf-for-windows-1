// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_namespace.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_namespace_test_process ebpf_namespace_test_process_t;

typedef enum _ebpf_namespace_test_failure
{
    EBPF_NAMESPACE_TEST_FAIL_NONE,
    EBPF_NAMESPACE_TEST_FAIL_REGISTER,
    EBPF_NAMESPACE_TEST_FAIL_REFERENCE_CURRENT,
    EBPF_NAMESPACE_TEST_FAIL_REFERENCE_ENTRY,
    EBPF_NAMESPACE_TEST_FAIL_ALLOCATE,
} ebpf_namespace_test_failure_t;

// These hooks exist only in runtime_user. Identity and start key are independent
// of a reusable numeric PID; selecting a process never installs a thread-local GUID.
_Ret_maybenull_ ebpf_namespace_test_process_t*
ebpf_namespace_test_create_process(uintptr_t identity, uint64_t start_key);

void
ebpf_namespace_test_destroy_process(_Frees_ptr_ ebpf_namespace_test_process_t* process);

void
ebpf_namespace_test_select_process(_In_opt_ ebpf_namespace_test_process_t* process);

void
ebpf_namespace_test_exit_process(_Inout_ ebpf_namespace_test_process_t* process);

// Deliver notification before making exit status observable, to exercise SET's
// cancellation independently of a process-exit-status query.
void
ebpf_namespace_test_notify_exit_process(_Inout_ ebpf_namespace_test_process_t* process);

size_t
ebpf_namespace_test_process_reference_count(_In_ const ebpf_namespace_test_process_t* process);

void
ebpf_namespace_test_fail_next(ebpf_namespace_test_failure_t failure);

typedef void (*ebpf_namespace_test_allocate_callback_t)(_Inout_opt_ void* context);

void
ebpf_namespace_test_set_allocate_callback(
    _In_opt_ ebpf_namespace_test_allocate_callback_t callback, _Inout_opt_ void* context);

size_t
ebpf_namespace_test_allocation_count(void);

size_t
ebpf_namespace_test_registration_count(void);

size_t
ebpf_namespace_test_unregistration_count(void);

CXPLAT_EXTERN_C_END
