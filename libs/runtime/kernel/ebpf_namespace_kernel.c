// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_namespace_platform.h"
#include "ebpf_tracelog.h"

// Include last to avoid ntstatus macro redefinitions.
#include "ebpf_error.h"

static ebpf_namespace_process_exit_callback_t _ebpf_namespace_exit_callback;

static void
_ebpf_namespace_notify_process(
    _Inout_ PEPROCESS process, HANDLE process_id, _Inout_opt_ PPS_CREATE_NOTIFY_INFO create_info)
{
    UNREFERENCED_PARAMETER(process_id);
    if (!create_info) {
        _ebpf_namespace_exit_callback((uintptr_t)process, PsGetProcessStartKey(process));
    }
}

ebpf_result_t
ebpf_namespace_platform_reference_current(_Out_ ebpf_namespace_process_t* process)
{
    PEPROCESS current = PsGetCurrentProcess();
    ObReferenceObject(current);
    uint64_t start_key = PsGetProcessStartKey(current);
    if (!start_key) {
        ObDereferenceObject(current);
        return EBPF_INVALID_STATE;
    }
    *process = (ebpf_namespace_process_t){.identity = (uintptr_t)current, .start_key = start_key, .reference = current};
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_namespace_platform_reference_process(
    _In_ const ebpf_namespace_process_t* process, _Out_ ebpf_namespace_process_t* reference)
{
    ObReferenceObject(process->reference);
    *reference = *process;
    return EBPF_SUCCESS;
}

void
ebpf_namespace_platform_dereference_process(_In_ const ebpf_namespace_process_t* process)
{
    ObDereferenceObject(process->reference);
}

bool
ebpf_namespace_platform_process_exiting(_In_ const ebpf_namespace_process_t* process)
{
    // Operations enter only in the original caller's context. Exit notification
    // runs after that process's final thread; suspended allocation retries are
    // additionally canceled by the module's in-flight attempt list.
    return PsGetProcessExitStatus((PEPROCESS)process->reference) != STATUS_PENDING;
}

ebpf_result_t
ebpf_namespace_platform_register_exit(_In_ ebpf_namespace_process_exit_callback_t callback)
{
    _ebpf_namespace_exit_callback = callback;
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(_ebpf_namespace_notify_process, FALSE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(
            EBPF_TRACELOG_KEYWORD_BASE,
            PsSetCreateProcessNotifyRoutineEx,
            status,
            "Register namespace process callback");
        _ebpf_namespace_exit_callback = NULL;
        return _ntstatus_to_ebpf_result(status);
    }
    return EBPF_SUCCESS;
}

void
ebpf_namespace_platform_unregister_exit(void)
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(_ebpf_namespace_notify_process, TRUE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(
            EBPF_TRACELOG_KEYWORD_BASE,
            PsSetCreateProcessNotifyRoutineEx,
            status,
            "Unregister namespace process callback");
        ebpf_assert(NT_SUCCESS(status));
        return;
    }
    _ebpf_namespace_exit_callback = NULL;
}

void*
ebpf_namespace_platform_allocate(size_t size)
{
    return cxplat_allocate(CXPLAT_POOL_FLAG_NON_PAGED, size, EBPF_POOL_TAG_STATE);
}
