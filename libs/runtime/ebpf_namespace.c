// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_namespace_platform.h"

typedef struct _ebpf_namespace_entry
{
    struct _ebpf_namespace_entry* next;
    ebpf_namespace_process_t process;
    GUID namespace_id;
    uint64_t generation;
} ebpf_namespace_entry_t;

typedef struct _ebpf_namespace_set_attempt
{
    struct _ebpf_namespace_set_attempt* next;
    ebpf_namespace_process_t process;
    bool exiting;
} ebpf_namespace_set_attempt_t;

// Membership and the complete GUID/generation publication share this lock.
// It survives module termination so rejected late callers never touch a destroyed lock.
static EX_PUSH_LOCK _ebpf_namespace_lock;
static cxplat_rundown_reference_t _ebpf_namespace_rundown;
static ebpf_namespace_entry_t* _ebpf_namespace_entries;
static ebpf_namespace_set_attempt_t* _ebpf_namespace_attempts;
static bool _ebpf_namespace_initialized;

static void
_ebpf_namespace_acquire_lock(void)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&_ebpf_namespace_lock);
}

static void
_ebpf_namespace_release_lock(void)
{
    ExReleasePushLockExclusive(&_ebpf_namespace_lock);
    KeLeaveCriticalRegion();
}

static bool
_ebpf_namespace_same_process(_In_ const ebpf_namespace_process_t* left, _In_ const ebpf_namespace_process_t* right)
{
    return left->identity == right->identity && left->start_key == right->start_key;
}

static ebpf_namespace_entry_t*
_ebpf_namespace_find(_In_ const ebpf_namespace_process_t* process)
{
    for (ebpf_namespace_entry_t* entry = _ebpf_namespace_entries; entry; entry = entry->next) {
        if (_ebpf_namespace_same_process(&entry->process, process)) {
            return entry;
        }
    }
    return NULL;
}

static void
_ebpf_namespace_free_entry(_Frees_ptr_opt_ ebpf_namespace_entry_t* entry)
{
    if (entry) {
        if (entry->process.reference) {
            ebpf_namespace_platform_dereference_process(&entry->process);
        }
        cxplat_free(entry, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_STATE);
    }
}

static void
_ebpf_namespace_process_exit(uintptr_t identity, uint64_t start_key)
{
    ebpf_namespace_process_t process = {.identity = identity, .start_key = start_key};
    ebpf_namespace_entry_t* removed = NULL;

    _ebpf_namespace_acquire_lock();
    for (ebpf_namespace_set_attempt_t* attempt = _ebpf_namespace_attempts; attempt; attempt = attempt->next) {
        if (_ebpf_namespace_same_process(&attempt->process, &process)) {
            attempt->exiting = true;
        }
    }
    for (ebpf_namespace_entry_t** entry = &_ebpf_namespace_entries; *entry; entry = &(*entry)->next) {
        if (_ebpf_namespace_same_process(&(*entry)->process, &process)) {
            removed = *entry;
            *entry = removed->next;
            break;
        }
    }
    _ebpf_namespace_release_lock();
    _ebpf_namespace_free_entry(removed);
}

ebpf_result_t
ebpf_namespace_initiate(void)
{
    _ebpf_namespace_acquire_lock();
    if (_ebpf_namespace_initialized) {
        _ebpf_namespace_release_lock();
        return EBPF_ALREADY_INITIALIZED;
    }
    _ebpf_namespace_release_lock();

    cxplat_initialize_rundown_protection(&_ebpf_namespace_rundown);
    ebpf_result_t result = ebpf_namespace_platform_register_exit(_ebpf_namespace_process_exit);
    if (result != EBPF_SUCCESS) {
        cxplat_wait_for_rundown_protection_release(&_ebpf_namespace_rundown);
        return result;
    }

    _ebpf_namespace_acquire_lock();
    _ebpf_namespace_initialized = true;
    _ebpf_namespace_release_lock();
    return EBPF_SUCCESS;
}

void
ebpf_namespace_terminate(void)
{
    _ebpf_namespace_acquire_lock();
    if (!_ebpf_namespace_initialized) {
        _ebpf_namespace_release_lock();
        return;
    }
    _ebpf_namespace_initialized = false;
    _ebpf_namespace_release_lock();

    // Unregistration must not hold the lock needed by an already running callback.
    ebpf_namespace_platform_unregister_exit();
    cxplat_wait_for_rundown_protection_release(&_ebpf_namespace_rundown);

    _ebpf_namespace_acquire_lock();
    ebpf_namespace_entry_t* entries = _ebpf_namespace_entries;
    _ebpf_namespace_entries = NULL;
    _ebpf_namespace_release_lock();
    while (entries) {
        ebpf_namespace_entry_t* next = entries->next;
        _ebpf_namespace_free_entry(entries);
        entries = next;
    }
}

static ebpf_result_t
_ebpf_namespace_begin(_Out_ ebpf_namespace_process_t* process)
{
    _ebpf_namespace_acquire_lock();
    bool admitted = _ebpf_namespace_initialized && cxplat_acquire_rundown_protection(&_ebpf_namespace_rundown);
    _ebpf_namespace_release_lock();
    if (!admitted) {
        return EBPF_INVALID_STATE;
    }

    ebpf_result_t result = ebpf_namespace_platform_reference_current(process);
    if (result != EBPF_SUCCESS) {
        cxplat_release_rundown_protection(&_ebpf_namespace_rundown);
    }
    return result;
}

static void
_ebpf_namespace_end(_In_ const ebpf_namespace_process_t* process)
{
    ebpf_namespace_platform_dereference_process(process);
    cxplat_release_rundown_protection(&_ebpf_namespace_rundown);
}

ebpf_result_t
ebpf_namespace_capture_context(_Out_ ebpf_request_context_t* context)
{
    if (!context) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_namespace_process_t process;
    ebpf_result_t result = _ebpf_namespace_begin(&process);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    _ebpf_namespace_acquire_lock();
    if (!_ebpf_namespace_initialized || ebpf_namespace_platform_process_exiting(&process)) {
        result = EBPF_INVALID_STATE;
    } else {
        ebpf_request_context_t snapshot = {.process_start_key = process.start_key};
        ebpf_namespace_entry_t* entry = _ebpf_namespace_find(&process);
        if (entry) {
            snapshot.namespace_id = entry->namespace_id;
            snapshot.namespace_generation = entry->generation;
        }
        *context = snapshot;
    }
    _ebpf_namespace_release_lock();
    _ebpf_namespace_end(&process);
    return result;
}

static ebpf_result_t
_ebpf_namespace_publish(_Inout_ ebpf_namespace_entry_t* entry, _In_ const GUID* namespace_id)
{
    if (memcmp(&entry->namespace_id, namespace_id, sizeof(*namespace_id)) == 0) {
        return EBPF_SUCCESS;
    }
    if (entry->generation == UINT64_MAX) {
        return EBPF_ARITHMETIC_OVERFLOW;
    }
    entry->namespace_id = *namespace_id;
    entry->generation++;
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_namespace_set_current(_In_ const GUID* namespace_id)
{
    if (!namespace_id) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_namespace_process_t process;
    ebpf_result_t result = _ebpf_namespace_begin(&process);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    ebpf_namespace_set_attempt_t attempt = {.process = process};
    ebpf_namespace_entry_t* candidate = NULL;

    _ebpf_namespace_acquire_lock();
    if (!_ebpf_namespace_initialized || ebpf_namespace_platform_process_exiting(&process)) {
        result = EBPF_INVALID_STATE;
        goto Unlock;
    }
    ebpf_namespace_entry_t* entry = _ebpf_namespace_find(&process);
    if (entry) {
        result = _ebpf_namespace_publish(entry, namespace_id);
        goto Unlock;
    }
    const GUID null_namespace = {0};
    if (memcmp(namespace_id, &null_namespace, sizeof(null_namespace)) == 0) {
        goto Unlock;
    }

    // Announce the attempt before dropping membership synchronization to allocate.
    // Exit cancels all such attempts, even if there is not yet an entry to remove.
    attempt.next = _ebpf_namespace_attempts;
    _ebpf_namespace_attempts = &attempt;
    _ebpf_namespace_release_lock();

    candidate = ebpf_namespace_platform_allocate(sizeof(*candidate));
    if (!candidate) {
        result = EBPF_NO_MEMORY;
    } else {
        memset(candidate, 0, sizeof(*candidate));
        result = ebpf_namespace_platform_reference_process(&process, &candidate->process);
    }

    _ebpf_namespace_acquire_lock();
    for (ebpf_namespace_set_attempt_t** current = &_ebpf_namespace_attempts; *current; current = &(*current)->next) {
        if (*current == &attempt) {
            *current = attempt.next;
            break;
        }
    }
    if (!_ebpf_namespace_initialized || attempt.exiting || ebpf_namespace_platform_process_exiting(&process)) {
        result = EBPF_INVALID_STATE;
    }
    if (result == EBPF_SUCCESS) {
        // Another SET may have won insertion while this attempt was allocating.
        entry = _ebpf_namespace_find(&process);
        if (!entry) {
            entry = candidate;
            candidate = NULL;
            entry->next = _ebpf_namespace_entries;
            _ebpf_namespace_entries = entry;
        }
        result = _ebpf_namespace_publish(entry, namespace_id);
    }

Unlock:
    _ebpf_namespace_release_lock();
    _ebpf_namespace_free_entry(candidate);
    _ebpf_namespace_end(&process);
    return result;
}

ebpf_result_t
ebpf_namespace_get_current(_Out_ GUID* namespace_id)
{
    if (!namespace_id) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_request_context_t context;
    ebpf_result_t result = ebpf_namespace_capture_context(&context);
    if (result == EBPF_SUCCESS) {
        *namespace_id = context.namespace_id;
    }
    return result;
}
