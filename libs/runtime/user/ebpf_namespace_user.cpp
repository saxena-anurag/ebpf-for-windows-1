// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_namespace_platform.h"
#include "ebpf_namespace_test.h"
#include "ebpf_tracelog.h"
#include "ebpf_utilities.h"

#include <atomic>
#include <new>

// Include last to avoid ntstatus macro redefinitions.
#include "ebpf_error.h"

struct _ebpf_namespace_test_process
{
    uintptr_t identity;
    uint64_t start_key;
    std::atomic<bool> exiting{false};
    std::atomic<size_t> references{1};
};

static thread_local ebpf_namespace_test_process_t* _ebpf_namespace_test_current_process;
static std::atomic<ebpf_namespace_test_failure_t> _ebpf_namespace_test_failure;
static std::atomic<size_t> _ebpf_namespace_allocations;
static std::atomic<size_t> _ebpf_namespace_registrations;
static std::atomic<size_t> _ebpf_namespace_unregistrations;
static ebpf_namespace_test_allocate_callback_t _ebpf_namespace_allocate_callback;
static void* _ebpf_namespace_allocate_context;
static SRWLOCK _ebpf_namespace_callback_lock = SRWLOCK_INIT;
static ebpf_namespace_process_exit_callback_t _ebpf_namespace_exit_callback;

static ebpf_result_t
_ebpf_namespace_process_start_key(_Out_ uint64_t* start_key)
{
    FILETIME creation, exit, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
        return win32_error_code_to_ebpf_result(GetLastError());
    }
    // A retained process handle plus PID/creation time provides stable usersim
    // identity without relying on its optional NtQueryInformationProcess shim.
    *start_key = ((uint64_t)creation.dwHighDateTime << 32) | creation.dwLowDateTime;
    return *start_key ? EBPF_SUCCESS : EBPF_INVALID_STATE;
}

static bool
_ebpf_namespace_fail(ebpf_namespace_test_failure_t failure)
{
    return _ebpf_namespace_test_failure.compare_exchange_strong(failure, EBPF_NAMESPACE_TEST_FAIL_NONE);
}

static void
_ebpf_namespace_notify_process(
    _Inout_ PEPROCESS process, HANDLE process_id, _Inout_opt_ PPS_CREATE_NOTIFY_INFO create_info)
{
    if (create_info) {
        return;
    }
    AcquireSRWLockShared(&_ebpf_namespace_callback_lock);
    if (_ebpf_namespace_exit_callback) {
        if (process == PsGetCurrentProcess()) {
            uint64_t start_key;
            ebpf_result_t result = _ebpf_namespace_process_start_key(&start_key);
            ebpf_assert(result == EBPF_SUCCESS);
            if (result == EBPF_SUCCESS) {
                _ebpf_namespace_exit_callback((uintptr_t)process_id, start_key);
            }
        } else {
            auto* simulated = reinterpret_cast<ebpf_namespace_test_process_t*>(process);
            _ebpf_namespace_exit_callback(simulated->identity, simulated->start_key);
        }
    }
    ReleaseSRWLockShared(&_ebpf_namespace_callback_lock);
}

ebpf_result_t
ebpf_namespace_platform_reference_current(_Out_ ebpf_namespace_process_t* process)
{
    if (_ebpf_namespace_fail(EBPF_NAMESPACE_TEST_FAIL_REFERENCE_CURRENT)) {
        return EBPF_NO_MEMORY;
    }
    if (_ebpf_namespace_test_current_process) {
        auto* simulated = _ebpf_namespace_test_current_process;
        simulated->references.fetch_add(1);
        *process = {simulated->identity, simulated->start_key, simulated, true};
        return EBPF_SUCCESS;
    }

    uint64_t start_key;
    ebpf_result_t result = _ebpf_namespace_process_start_key(&start_key);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    // The executing caller keeps its own process alive. Only registry insertion
    // duplicates this pseudo-handle, so unseen reads allocate no process handles.
    *process = {(uintptr_t)GetCurrentProcessId(), start_key, GetCurrentProcess(), false};
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_namespace_platform_reference_process(
    _In_ const ebpf_namespace_process_t* process, _Out_ ebpf_namespace_process_t* reference)
{
    if (_ebpf_namespace_fail(EBPF_NAMESPACE_TEST_FAIL_REFERENCE_ENTRY)) {
        return EBPF_NO_MEMORY;
    }
    if (process->simulated) {
        static_cast<ebpf_namespace_test_process_t*>(process->reference)->references.fetch_add(1);
        *reference = *process;
        return EBPF_SUCCESS;
    }
    HANDLE handle;
    if (!DuplicateHandle(
            GetCurrentProcess(), process->reference, GetCurrentProcess(), &handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        return win32_error_code_to_ebpf_result(GetLastError());
    }
    *reference = *process;
    reference->reference = handle;
    return EBPF_SUCCESS;
}

void
ebpf_namespace_platform_dereference_process(_In_ const ebpf_namespace_process_t* process)
{
    if (process->simulated) {
        static_cast<ebpf_namespace_test_process_t*>(process->reference)->references.fetch_sub(1);
    } else if (process->reference != GetCurrentProcess()) {
        CloseHandle(process->reference);
    }
}

bool
ebpf_namespace_platform_process_exiting(_In_ const ebpf_namespace_process_t* process)
{
    if (process->simulated) {
        return static_cast<ebpf_namespace_test_process_t*>(process->reference)->exiting.load();
    }
    return WaitForSingleObject(process->reference, 0) != WAIT_TIMEOUT;
}

ebpf_result_t
ebpf_namespace_platform_register_exit(_In_ ebpf_namespace_process_exit_callback_t callback)
{
    if (_ebpf_namespace_fail(EBPF_NAMESPACE_TEST_FAIL_REGISTER)) {
        return EBPF_NO_MEMORY;
    }
    AcquireSRWLockExclusive(&_ebpf_namespace_callback_lock);
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(_ebpf_namespace_notify_process, FALSE);
    if (NT_SUCCESS(status)) {
        _ebpf_namespace_exit_callback = callback;
        _ebpf_namespace_registrations.fetch_add(1);
    } else {
        EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(
            EBPF_TRACELOG_KEYWORD_BASE,
            PsSetCreateProcessNotifyRoutineEx,
            status,
            "Register namespace process callback");
    }
    ReleaseSRWLockExclusive(&_ebpf_namespace_callback_lock);
    return _ntstatus_to_ebpf_result(status);
}

void
ebpf_namespace_platform_unregister_exit(void)
{
    // usersim's notification shim does not implement callback rundown itself.
    AcquireSRWLockExclusive(&_ebpf_namespace_callback_lock);
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(_ebpf_namespace_notify_process, TRUE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(
            EBPF_TRACELOG_KEYWORD_BASE,
            PsSetCreateProcessNotifyRoutineEx,
            status,
            "Unregister namespace process callback");
        ReleaseSRWLockExclusive(&_ebpf_namespace_callback_lock);
        ebpf_assert(NT_SUCCESS(status));
        return;
    }
    _ebpf_namespace_exit_callback = nullptr;
    _ebpf_namespace_unregistrations.fetch_add(1);
    ReleaseSRWLockExclusive(&_ebpf_namespace_callback_lock);
}

void*
ebpf_namespace_platform_allocate(size_t size)
{
    if (_ebpf_namespace_allocate_callback) {
        _ebpf_namespace_allocate_callback(_ebpf_namespace_allocate_context);
    }
    _ebpf_namespace_allocations.fetch_add(1);
    if (_ebpf_namespace_fail(EBPF_NAMESPACE_TEST_FAIL_ALLOCATE)) {
        return nullptr;
    }
    return cxplat_allocate(CXPLAT_POOL_FLAG_NON_PAGED, size, EBPF_POOL_TAG_STATE);
}

ebpf_namespace_test_process_t*
ebpf_namespace_test_create_process(uintptr_t identity, uint64_t start_key)
{
    if (!identity || !start_key) {
        return nullptr;
    }
    return new (std::nothrow) ebpf_namespace_test_process_t{identity, start_key};
}

void
ebpf_namespace_test_destroy_process(_Frees_ptr_ ebpf_namespace_test_process_t* process)
{
    ebpf_assert(process->references.load() == 1);
    delete process;
}

void
ebpf_namespace_test_select_process(_In_opt_ ebpf_namespace_test_process_t* process)
{
    _ebpf_namespace_test_current_process = process;
}

void
ebpf_namespace_test_exit_process(_Inout_ ebpf_namespace_test_process_t* process)
{
    process->exiting.store(true);
    ebpf_namespace_test_notify_exit_process(process);
}

void
ebpf_namespace_test_notify_exit_process(_Inout_ ebpf_namespace_test_process_t* process)
{
    usersime_invoke_process_creation_notify_routine(reinterpret_cast<PEPROCESS>(process), nullptr, nullptr);
}

size_t
ebpf_namespace_test_process_reference_count(_In_ const ebpf_namespace_test_process_t* process)
{
    return process->references.load();
}

void
ebpf_namespace_test_fail_next(ebpf_namespace_test_failure_t failure)
{
    _ebpf_namespace_test_failure.store(failure);
}

void
ebpf_namespace_test_set_allocate_callback(
    _In_opt_ ebpf_namespace_test_allocate_callback_t callback, _Inout_opt_ void* context)
{
    _ebpf_namespace_allocate_callback = callback;
    _ebpf_namespace_allocate_context = context;
}

size_t
ebpf_namespace_test_allocation_count(void)
{
    return _ebpf_namespace_allocations.load();
}

size_t
ebpf_namespace_test_registration_count(void)
{
    return _ebpf_namespace_registrations.load();
}

size_t
ebpf_namespace_test_unregistration_count(void)
{
    return _ebpf_namespace_unregistrations.load();
}
