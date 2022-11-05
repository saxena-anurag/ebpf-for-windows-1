// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:

   This file implements the classifyFn, notifyFn, and flowDeleteFn callouts
   functions for:
   Layer 2 network receive
   Resource Acquire
   Resource Release

Environment:

    Kernel mode

--*/

#include "net_ebpf_ext.h"
#include "net_ebpf_ext_bind.h"
#include "net_ebpf_ext_sock_addr.h"
#include "net_ebpf_ext_sock_ops.h"
#include "net_ebpf_ext_xdp.h"

// Globals.
NDIS_HANDLE _net_ebpf_ext_ndis_handle = NULL;
NDIS_HANDLE _net_ebpf_ext_nbl_pool_handle = NULL;
HANDLE _net_ebpf_ext_l2_injection_handle = NULL;

static EX_SPIN_LOCK _net_ebpf_ext_filter_instance_list_lock;
_Guarded_by_(_net_ebpf_ext_filter_instance_list_lock) static LIST_ENTRY _net_ebpf_ext_filter_instance_list;

static void
_net_ebpf_ext_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context);

NTSTATUS
net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter);

static ebpf_result_t
_net_ebpf_extension_remove_filter_context_from_filter_instance(
    _In_ const net_ebpf_extension_wfp_filter_context_t* filter_context, uint64_t filter_id);

typedef struct _net_ebpf_ext_wfp_callout_state
{
    const GUID* callout_guid;
    const GUID* layer_guid;
    FWPS_CALLOUT_CLASSIFY_FN classify_fn;
    FWPS_CALLOUT_NOTIFY_FN notify_fn;
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN delete_fn;
    wchar_t* name;
    wchar_t* description;
    FWP_ACTION_TYPE filter_action_type;
    uint32_t assigned_callout_id;
} net_ebpf_ext_wfp_callout_state_t;

static net_ebpf_ext_wfp_callout_state_t _net_ebpf_ext_wfp_callout_states[] = {
    // EBPF_HOOK_OUTBOUND_L2
    {
        &EBPF_HOOK_OUTBOUND_L2_CALLOUT,
        &FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
        net_ebpf_ext_layer_2_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"L2 Outbound",
        L"L2 Outbound Callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_INBOUND_L2
    {
        &EBPF_HOOK_INBOUND_L2_CALLOUT,
        &FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
        net_ebpf_ext_layer_2_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"L2 Inbound",
        L"L2 Inbound Callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_ALLOC_V4
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOC_V4_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        net_ebpf_ext_resource_allocation_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Allocation v4",
        L"Resource Allocation v4 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_RELEASE_V4
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_V4_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
        net_ebpf_ext_resource_release_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Release v4",
        L"Resource Release v4 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_ALLOC_V6
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOC_V6_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        net_ebpf_ext_resource_allocation_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Allocation v6",
        L"Resource Allocation v6 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_RELEASE_V6
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_V6_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
        net_ebpf_ext_resource_release_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Release eBPF Callout v6",
        L"Resource Release callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_CONNECT_V4
    {
        &EBPF_HOOK_ALE_AUTH_CONNECT_V4_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Connect eBPF Callout v4",
        L"ALE Authorize Connect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_CONNECT_V6
    {
        &EBPF_HOOK_ALE_AUTH_CONNECT_V6_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Connect eBPF Callout v6",
        L"ALE Authorize Connect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4
    {
        &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        net_ebpf_extension_sock_addr_authorize_recv_accept_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Receive or Accept eBPF Callout v4",
        L"ALE Authorize Receive or Accept callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6
    {
        &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        net_ebpf_extension_sock_addr_authorize_recv_accept_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Receive or Accept eBPF Callout v6",
        L"ALE Authorize Receive or Accept callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4
    {
        &EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        net_ebpf_extension_sock_ops_flow_established_classify,
        net_ebpf_ext_filter_change_notify,
        net_ebpf_extension_sock_ops_flow_delete,
        L"ALE Flow Established Callout v4",
        L"ALE Flow Established callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6
    {
        &EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
        net_ebpf_extension_sock_ops_flow_established_classify,
        net_ebpf_ext_filter_change_notify,
        net_ebpf_extension_sock_ops_flow_delete,
        L"ALE Flow Established Callout v4",
        L"ALE Flow Established callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V4
    {
        &EBPF_HOOK_ALE_CONNECT_REDIRECT_V4_CALLOUT,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        net_ebpf_extension_sock_addr_redirect_connection_classify,
        net_ebpf_ext_connect_redirect_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Connect Redirect eBPF Callout v4",
        L"ALE Connect Redirect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V6
    {
        &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        net_ebpf_extension_sock_addr_redirect_connection_classify,
        net_ebpf_ext_connect_redirect_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Connect Redirect eBPF Callout v6",
        L"ALE Connect Redirect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    }};

// WFP globals
static HANDLE _fwp_engine_handle;

void
net_ebpf_ext_acquire_filter_instance_reference(_In_ net_ebpf_extension_wfp_filter_instance_t* filter_instance)
{
    InterlockedIncrement(&(filter_instance)->reference_count);
}

void
net_ebpf_ext_release_filter_instance_reference(_In_opt_ net_ebpf_extension_wfp_filter_instance_t* filter_instance)
{
    if (filter_instance != NULL) {
        if (InterlockedDecrement(&filter_instance->reference_count) == 0) {
            KIRQL irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock);
            RemoveEntryList(&filter_instance->list_entry);
            ExReleaseSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock, irql);
            if (filter_instance->filter_id) {
                FwpmFilterDeleteById(_fwp_engine_handle, filter_instance->filter_id);
            }
            if (filter_instance->conditions) {
                ExFreePool(filter_instance->conditions);
            }
            ExFreePool(filter_instance);
        }
    }
}

//
// WFP component management related utility functions.
//

ebpf_result_t
net_ebpf_extension_wfp_filter_context_create(
    size_t filter_context_size,
    _In_ const net_ebpf_extension_hook_client_t* client_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_wfp_filter_context_t* local_filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    *filter_context = NULL;

    // Allocate buffer for WFP filter context.
    local_filter_context = (net_ebpf_extension_wfp_filter_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, filter_context_size, NET_EBPF_EXTENSION_POOL_TAG);
    if (local_filter_context == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(local_filter_context, 0, filter_context_size);
    local_filter_context->reference_count = 1; // Initial reference.
    local_filter_context->client_context = client_context;

    *filter_context = local_filter_context;
    local_filter_context = NULL;
Exit:
    if (local_filter_context != NULL)
        ExFreePool(local_filter_context);

    NET_EBPF_EXT_RETURN_RESULT(result);
}

void
net_ebpf_extension_wfp_filter_context_cleanup(_Frees_ptr_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    // Since the hook client is detaching, the eBPF program should not be invoked any further.
    // The client_context field in filter_context is set to NULL for this reason. This way any
    // lingering WFP classify callbacks will exit as it would not find any hook client associated with the filter
    // context. This is best effort & no locks are held.
    filter_context->client_context = NULL;
    filter_context->filter_instances = NULL;
    DEREFERENCE_FILTER_CONTEXT(filter_context);
}

net_ebpf_extension_hook_id_t
net_ebpf_extension_get_hook_id_from_wfp_layer_id(uint16_t wfp_layer_id)
{
    net_ebpf_extension_hook_id_t hook_id = (net_ebpf_extension_hook_id_t)0;

    switch (wfp_layer_id) {
    case FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE:
        hook_id = EBPF_HOOK_OUTBOUND_L2;
        break;
    case FWPS_LAYER_INBOUND_MAC_FRAME_NATIVE:
        hook_id = EBPF_HOOK_INBOUND_L2;
        break;
    case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4:
        hook_id = EBPF_HOOK_ALE_RESOURCE_ALLOC_V4;
        break;
    case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6:
        hook_id = EBPF_HOOK_ALE_RESOURCE_ALLOC_V6;
        break;
    case FWPS_LAYER_ALE_RESOURCE_RELEASE_V4:
        hook_id = EBPF_HOOK_ALE_RESOURCE_RELEASE_V4;
        break;
    case FWPS_LAYER_ALE_RESOURCE_RELEASE_V6:
        hook_id = EBPF_HOOK_ALE_RESOURCE_RELEASE_V6;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        hook_id = EBPF_HOOK_ALE_AUTH_CONNECT_V4;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        hook_id = EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        hook_id = EBPF_HOOK_ALE_AUTH_CONNECT_V6;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        hook_id = EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6;
        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
        hook_id = EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4;
        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
        hook_id = EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6;
        break;
    case FWPS_LAYER_ALE_CONNECT_REDIRECT_V4:
        hook_id = EBPF_HOOK_ALE_CONNECT_REDIRECT_V4;
        break;
    case FWPS_LAYER_ALE_CONNECT_REDIRECT_V6:
        hook_id = EBPF_HOOK_ALE_CONNECT_REDIRECT_V6;
        break;
    default:
        ASSERT(FALSE);
        break;
    }

    return hook_id;
}

uint32_t
net_ebpf_extension_get_callout_id_for_hook(net_ebpf_extension_hook_id_t hook_id)
{
    uint32_t callout_id = 0;

    if (hook_id < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states))
        callout_id = _net_ebpf_ext_wfp_callout_states[hook_id].assigned_callout_id;

    return callout_id;
}
void
net_ebpf_extension_delete_wfp_filters(_In_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    NET_EBPF_EXT_LOG_ENTRY();
    for (uint32_t index = 0; index < filter_context->filter_instance_count; index++) {
        _net_ebpf_extension_remove_filter_context_from_filter_instance(
            filter_context, filter_context->filter_instances[index]->filter_id);
        // net_ebpf_ext_release_filter_instance_reference(filter_instances[index]);
        filter_context->filter_instances[index] = NULL;
    }
    ExFreePool(filter_context->filter_instances);
    filter_context->filter_instances = NULL;
    NET_EBPF_EXT_LOG_EXIT();
}

/**
 * @brief Check if an existing filter already exists for the provided parameters.
 *        If an existing filter instance exists, take a reference on the the
 *        instance and return a pointer to it. If it does not exist, create
 *        a new filter instance, insert it in the global list and return a
 *        pointer to it.
 *
 * @param[in] filter_parameters Pointer to the filter paramaters.
 * @param[in] condition_count Count of the filter conditions.
 * @param[in] conditions Pointer to list of filter conditions.
 * @param[out] filter_instance Pointer to the filter instance.
 *
 * @return Status of the operation.
 */
static ebpf_result_t
_net_ebpf_extension_create_or_update_filter_instance(
    _In_ const net_ebpf_extension_wfp_filter_parameters_t* filter_parameters,
    _In_ const net_ebpf_extension_wfp_filter_context_t* filter_context,
    uint32_t condition_count,
    _In_opt_count_(condition_count) const FWPM_FILTER_CONDITION* conditions,
    _Out_ net_ebpf_extension_wfp_filter_instance_t** filter_instance)
{
    ebpf_result_t result = EBPF_SUCCESS;
    KIRQL old_irql;
    net_ebpf_extension_wfp_filter_instance_t* matching_instance = NULL;
    net_ebpf_extension_wfp_filter_context_list_entry_t* context_list_entry = NULL;
    bool list_lock_acquired = false;
    bool new_instance = false;
    *filter_instance = NULL;

    // First find if a matching filter instance is present.
    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock);
    list_lock_acquired = true;

    LIST_ENTRY* list_entry = _net_ebpf_ext_filter_instance_list.Flink;
    while (list_entry != &_net_ebpf_ext_filter_instance_list) {
        net_ebpf_extension_wfp_filter_instance_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_wfp_filter_instance_t, list_entry);

        list_entry = list_entry->Flink;
        if (memcmp(&entry->layer, filter_parameters->layer_guid, sizeof(GUID))) {
            continue;
        }
        if (entry->condition_count != condition_count) {
            continue;
        }

        if (condition_count == 0) {
            matching_instance = entry;
            break;
        }

        __analysis_assume(conditions != NULL);

        bool conditions_matched = true;
        // Iterate over all the filter conditions.
        for (uint32_t i = 0; i < condition_count; i++) {
            bool found = false;
            const FWPM_FILTER_CONDITION* condition1 = &conditions[i];
            for (uint32_t j = 0; j < condition_count; j++) {
                FWPM_FILTER_CONDITION* condition2 = &entry->conditions[j];
                if (memcmp(condition1, condition2, sizeof(FWPM_FILTER_CONDITION)) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                conditions_matched = false;
                break;
            }
        }

        if (conditions_matched) {
            // Found a matching filter instance.
            matching_instance = entry;
            break;
        }
    }

    if (matching_instance == NULL) {
        new_instance = true;
        // Allocate a new filter instance.
        matching_instance = (net_ebpf_extension_wfp_filter_instance_t*)ExAllocatePoolUninitialized(
            NonPagedPoolNx, sizeof(net_ebpf_extension_wfp_filter_instance_t), NET_EBPF_EXTENSION_POOL_TAG);
        if (matching_instance == NULL) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        memset(matching_instance, 0, sizeof(net_ebpf_extension_wfp_filter_instance_t));
        matching_instance->reference_count = 1;
        matching_instance->layer = *(filter_parameters->layer_guid);
        InitializeListHead(&matching_instance->filter_contexts);
        matching_instance->condition_count = condition_count;
        if (condition_count > 0) {
            __analysis_assume(conditions != NULL);
            matching_instance->conditions = (FWPM_FILTER_CONDITION*)ExAllocatePoolUninitialized(
                NonPagedPoolNx, sizeof(FWPM_FILTER_CONDITION) * condition_count, NET_EBPF_EXTENSION_POOL_TAG);

            if (matching_instance->conditions == NULL) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }
            memcpy(matching_instance->conditions, conditions, sizeof(FWPM_FILTER_CONDITION) * condition_count);
        }
    } else {
        result = EBPF_OBJECT_ALREADY_EXISTS;
    }

    context_list_entry = (net_ebpf_extension_wfp_filter_context_list_entry_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_wfp_filter_context_list_entry_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (context_list_entry == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    context_list_entry->filter_context = filter_context;

    ExAcquireSpinLockExclusiveAtDpcLevel(&matching_instance->lock);
    InsertTailList(&matching_instance->filter_contexts, &context_list_entry->list_entry);
    matching_instance->filter_context_count++;
    ExReleaseSpinLockExclusiveFromDpcLevel(&matching_instance->lock);

    if (new_instance) {
        InsertTailList(&_net_ebpf_ext_filter_instance_list, &matching_instance->list_entry);
    } else {
        // Take a reference on the existing filter instance.
        net_ebpf_ext_acquire_filter_instance_reference(matching_instance);
    }

    // Take a query reference. Should be released by the caller.
    net_ebpf_ext_acquire_filter_instance_reference(matching_instance);
    *filter_instance = matching_instance;

Exit:
    if (list_lock_acquired) {
        ExReleaseSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock, old_irql);
    }
    if (result != EBPF_SUCCESS && result != EBPF_OBJECT_ALREADY_EXISTS) {
        if (new_instance) {
            if (matching_instance != NULL) {
                if (matching_instance->conditions != NULL) {
                    ExFreePool(matching_instance->conditions);
                    matching_instance->conditions = NULL;
                }
                ExFreePool(matching_instance);
                matching_instance = NULL;
            }
        }
        if (context_list_entry != NULL) {
            ExFreePool(context_list_entry);
        }
    }
    return result;
}

/**
 * @brief Find the filter instance corresponding to the provided filter id.
 *        If found, remove the provided filter context from the filter instance
 *        and release the reference to the filter instance.
 *
 * @param[in] filter_context Pointer to the filter context.
 * @param[in] filter_id Filter Id corresponding to the filter instance.
 *
 * @return Status of the operation.
 */
static ebpf_result_t
_net_ebpf_extension_remove_filter_context_from_filter_instance(
    _In_ const net_ebpf_extension_wfp_filter_context_t* filter_context, uint64_t filter_id)
{
    ebpf_result_t result = EBPF_SUCCESS;
    KIRQL old_irql;
    net_ebpf_extension_wfp_filter_instance_t* matching_instance = NULL;
    net_ebpf_extension_wfp_filter_context_list_entry_t* context_list_entry = NULL;
    bool list_lock_acquired = false;
    bool found = false;

    // First find the matching filter instance based on the filter id.
    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock);
    list_lock_acquired = true;

    LIST_ENTRY* list_entry = _net_ebpf_ext_filter_instance_list.Flink;
    while (list_entry != &_net_ebpf_ext_filter_instance_list) {
        net_ebpf_extension_wfp_filter_instance_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_wfp_filter_instance_t, list_entry);

        list_entry = list_entry->Flink;

        if (entry->filter_id == filter_id) {
            matching_instance = entry;
            break;
        }
    }

    if (matching_instance == NULL) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Exit;
    }

    // Iterate over all the filter contexts and find the matching one.
    ExAcquireSpinLockExclusiveAtDpcLevel(&matching_instance->lock);
    list_entry = matching_instance->filter_contexts.Flink;
    while (list_entry != &(matching_instance->filter_contexts)) {
        context_list_entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_wfp_filter_context_list_entry_t, list_entry);
        if (context_list_entry->filter_context == filter_context) {
            found = true;
            RemoveEntryList(&context_list_entry->list_entry);
            ExFreePool(context_list_entry);
            break;
        }
        list_entry = list_entry->Flink;
    }
    ExReleaseSpinLockExclusiveFromDpcLevel(&matching_instance->lock);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock, old_irql);
    list_lock_acquired = false;

    if (!found) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Exit;
    } else {
        net_ebpf_ext_release_filter_instance_reference(matching_instance);
    }

Exit:
    if (list_lock_acquired) {
        ExReleaseSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock, old_irql);
    }

    return result;
}

ebpf_result_t
net_ebpf_extension_get_filter_instance_by_id(
    uint64_t filter_id, _Outptr_ net_ebpf_extension_wfp_filter_instance_t** filter_instance)
{
    ebpf_result_t result = EBPF_SUCCESS;
    KIRQL old_irql;
    net_ebpf_extension_wfp_filter_instance_t* matching_instance = NULL;
    *filter_instance = NULL;

    // Check if a matching filter instance is present.
    old_irql = ExAcquireSpinLockShared(&_net_ebpf_ext_filter_instance_list_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_filter_instance_list.Flink;
    while (list_entry != &_net_ebpf_ext_filter_instance_list) {
        net_ebpf_extension_wfp_filter_instance_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_wfp_filter_instance_t, list_entry);

        if (entry->filter_id == filter_id) {
            matching_instance = entry;
            break;
        }

        list_entry = list_entry->Flink;
    }

    if (matching_instance != NULL) {
        // Take a query reference. Should be released by the caller.
        net_ebpf_ext_acquire_filter_instance_reference(matching_instance);
        *filter_instance = matching_instance;
    } else {
        result = EBPF_OBJECT_NOT_FOUND;
    }

    ExReleaseSpinLockShared(&_net_ebpf_ext_filter_instance_list_lock, old_irql);
    return result;
}

ebpf_result_t
net_ebpf_extension_get_client_context_from_filter_instance(
    uint64_t filter_id,

    _Outptr_ net_ebpf_extension_wfp_filter_instance_t** filter_instance)
{
    ebpf_result_t result = EBPF_SUCCESS;
    KIRQL old_irql;
    net_ebpf_extension_wfp_filter_instance_t* matching_instance = NULL;
    *filter_instance = NULL;

    // Check if a matching filter instance is present.
    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_filter_instance_list.Flink;
    while (list_entry != &_net_ebpf_ext_filter_instance_list) {
        net_ebpf_extension_wfp_filter_instance_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_wfp_filter_instance_t, list_entry);

        if (entry->filter_id == filter_id) {
            matching_instance = entry;
            break;
        }

        list_entry = list_entry->Flink;
    }

    if (matching_instance != NULL) {
        // Take a query reference. Should be released by the caller.
        net_ebpf_ext_acquire_filter_instance_reference(matching_instance);
        *filter_instance = matching_instance;
    } else {
        result = EBPF_OBJECT_NOT_FOUND;
    }

    ExReleaseSpinLockExclusive(&_net_ebpf_ext_filter_instance_list_lock, old_irql);
    return result;
}

ebpf_result_t
net_ebpf_extension_add_wfp_filters(
    uint32_t filter_count,
    _In_count_(filter_count) const net_ebpf_extension_wfp_filter_parameters_t* parameters,
    uint32_t condition_count,
    _In_opt_count_(condition_count) const FWPM_FILTER_CONDITION* conditions,
    _In_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Outptr_result_buffer_maybenull_(filter_count) net_ebpf_extension_wfp_filter_instance_t*** filter_instances)
{
    NTSTATUS status = STATUS_SUCCESS;
    ebpf_result_t result = EBPF_SUCCESS;
    BOOL is_in_transaction = FALSE;
    net_ebpf_extension_wfp_filter_instance_t** local_filter_ids = NULL;
    *filter_instances = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    if (filter_count == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    local_filter_ids = (net_ebpf_extension_wfp_filter_instance_t**)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_wfp_filter_instance_t*) * filter_count, NET_EBPF_EXTENSION_POOL_TAG);
    if (local_filter_ids == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(local_filter_ids, 0, sizeof(net_ebpf_extension_wfp_filter_instance_t*) * filter_count);

    status = FwpmTransactionBegin(_fwp_engine_handle, 0);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmTransactionBegin", status);
        goto Exit;
    }
    is_in_transaction = TRUE;

    for (uint32_t index = 0; index < filter_count; index++) {
        FWPM_FILTER filter = {0};
        const net_ebpf_extension_wfp_filter_parameters_t* filter_parameter = &parameters[index];
        net_ebpf_extension_wfp_filter_instance_t* filter_instance = NULL;

        // Check if a filter with same conditions exists in the same layer.
        result = _net_ebpf_extension_create_or_update_filter_instance(
            filter_parameter, filter_context, condition_count, conditions, &filter_instance);
        if (result != EBPF_SUCCESS && result != EBPF_OBJECT_ALREADY_EXISTS) {
            goto Exit;
        }
        local_filter_ids[index] = filter_instance;
        // Release the query reference.
        net_ebpf_ext_release_filter_instance_reference(filter_instance);
        if (result == EBPF_OBJECT_ALREADY_EXISTS) {
            // The filter instance already exists. Continue to tne next filter
            // parameter.
            result = EBPF_SUCCESS;
            continue;
        }

        filter.layerKey = *filter_parameter->layer_guid;
        filter.displayData.name = (wchar_t*)filter_parameter->name;
        filter.displayData.description = (wchar_t*)filter_parameter->description;
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = *filter_parameter->callout_guid;
        filter.filterCondition = (FWPM_FILTER_CONDITION*)conditions;
        filter.numFilterConditions = condition_count;
        filter.subLayerKey = EBPF_SUBLAYER;
        filter.weight.type = FWP_EMPTY; // auto-weight.
        REFERENCE_FILTER_CONTEXT(filter_context);
        filter.rawContext = (uint64_t)(uintptr_t)filter_context;

        status = FwpmFilterAdd(_fwp_engine_handle, &filter, NULL, &filter_instance->filter_id);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
                NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,
                "FwpmFilterAdd",
                status,
                "Failed to add filter",
                (char*)filter_parameter->name);
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
    }

    status = FwpmTransactionCommit(_fwp_engine_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmTransactionCommit", status);
        goto Exit;
    }
    is_in_transaction = FALSE;

    *filter_instances = local_filter_ids;

Exit:
    if (!NT_SUCCESS(status)) {
        // Iterate over local_filter_ids and release the reference for
        // each of the filter instances.
#pragma warning(push)
#pragma warning(disable : 6385) // the readable size is '_Old_7`sizeof(net_ebpf_extension_wfp_filter_instance_t
                                // *)*filter_count' bytes, but '16' bytes may be read.
        if (local_filter_ids != NULL) {
            for (uint32_t i = 0; i < filter_count; i++) {
                if (local_filter_ids[i] != NULL) {
                    net_ebpf_ext_release_filter_instance_reference(local_filter_ids[i]);
                    local_filter_ids[i] = NULL;
                }
            }
        }
#pragma warning(pop)
        ExFreePool(local_filter_ids);
        if (is_in_transaction)
            FwpmTransactionAbort(_fwp_engine_handle);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static NTSTATUS
_net_ebpf_ext_register_wfp_callout(_Inout_ net_ebpf_ext_wfp_callout_state_t* callout_state, _Inout_ void* device_object)
/* ++

   This function registers callouts and filters.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    FWPS_CALLOUT callout_register_state = {0};
    FWPM_CALLOUT callout_add_state = {0};

    FWPM_DISPLAY_DATA display_data = {0};

    BOOLEAN was_callout_registered = FALSE;

    callout_register_state.calloutKey = *callout_state->callout_guid;
    callout_register_state.classifyFn = callout_state->classify_fn;
    callout_register_state.notifyFn = callout_state->notify_fn;
    callout_register_state.flowDeleteFn = callout_state->delete_fn;
    callout_register_state.flags = 0;

    status = FwpsCalloutRegister(device_object, &callout_register_state, &callout_state->assigned_callout_id);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
            NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,
            "FwpsCalloutRegister",
            status,
            "Failed to register callout",
            (char*)callout_state->name);
        goto Exit;
    }
    was_callout_registered = TRUE;

    display_data.name = callout_state->name;
    display_data.description = callout_state->description;

    callout_add_state.calloutKey = *callout_state->callout_guid;
    callout_add_state.displayData = display_data;
    callout_add_state.applicableLayer = *callout_state->layer_guid;

    status = FwpmCalloutAdd(_fwp_engine_handle, &callout_add_state, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
            NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,
            "FwpmCalloutAdd",
            status,
            "Failed to add callout",
            (char*)callout_state->name);
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status)) {
        if (was_callout_registered) {
            status = FwpsCalloutUnregisterById(callout_state->assigned_callout_id);
            if (!NT_SUCCESS(status)) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpsCalloutUnregisterById", status);
            } else {
                callout_state->assigned_callout_id = 0;
            }
        }
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

NTSTATUS
net_ebpf_ext_initialize_ndis_handles(_In_ const DRIVER_OBJECT* driver_object)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_parameters = {0};

    NET_EBPF_EXT_LOG_ENTRY();

    _net_ebpf_ext_ndis_handle =
        NdisAllocateGenericObject((DRIVER_OBJECT*)driver_object, NET_EBPF_EXTENSION_POOL_TAG, 0);
    if (_net_ebpf_ext_ndis_handle == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "NdisAllocateGenericObject", status);
        goto Exit;
    }

    nbl_pool_parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbl_pool_parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_parameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_parameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    nbl_pool_parameters.fAllocateNetBuffer = TRUE;
    nbl_pool_parameters.DataSize = 0;
    nbl_pool_parameters.PoolTag = NET_EBPF_EXTENSION_POOL_TAG;

    _net_ebpf_ext_nbl_pool_handle = NdisAllocateNetBufferListPool(_net_ebpf_ext_ndis_handle, &nbl_pool_parameters);
    if (_net_ebpf_ext_nbl_pool_handle == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

Exit:
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_uninitialize_ndis_handles()
{
    if (_net_ebpf_ext_nbl_pool_handle != NULL)
        NdisFreeNetBufferListPool(_net_ebpf_ext_nbl_pool_handle);

    if (_net_ebpf_ext_ndis_handle != NULL)
        NdisFreeGenericObject((NDIS_GENERIC_OBJECT*)_net_ebpf_ext_ndis_handle);
}

NTSTATUS
net_ebpf_extension_initialize_wfp_components(_Inout_ void* device_object)
/* ++

   This function initializes various WFP related components.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SUBLAYER ebpf_hook_sub_layer;

    UNREFERENCED_PARAMETER(device_object);

    BOOLEAN is_engined_opened = FALSE;
    BOOLEAN is_in_transaction = FALSE;

    FWPM_SESSION session = {0};

    size_t index;

    NET_EBPF_EXT_LOG_ENTRY();

    if (_fwp_engine_handle != NULL) {
        // already registered
        goto Exit;
    }

    InitializeListHead(&_net_ebpf_ext_filter_instance_list);

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &_fwp_engine_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmEngineOpen", status);
        goto Exit;
    }
    is_engined_opened = TRUE;

    status = FwpmTransactionBegin(_fwp_engine_handle, 0);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmTransactionBegin", status);
        goto Exit;
    }
    is_in_transaction = TRUE;

    RtlZeroMemory(&ebpf_hook_sub_layer, sizeof(FWPM_SUBLAYER));

    ebpf_hook_sub_layer.subLayerKey = EBPF_SUBLAYER;
    ebpf_hook_sub_layer.displayData.name = L"EBPF Sub-Layer";
    ebpf_hook_sub_layer.displayData.description = L"Sub-Layer for use by EBPF callouts";
    ebpf_hook_sub_layer.flags = 0;
    ebpf_hook_sub_layer.weight = FWP_EMPTY; // auto-weight.

    status = FwpmSubLayerAdd(_fwp_engine_handle, &ebpf_hook_sub_layer, NULL);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmSubLayerAdd", status);
        goto Exit;
    }

    for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states); index++) {
        status = _net_ebpf_ext_register_wfp_callout(&_net_ebpf_ext_wfp_callout_states[index], device_object);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_MESSAGE_STRING(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,
                "_net_ebpf_ext_register_wfp_callout() failed to register callout",
                (char*)_net_ebpf_ext_wfp_callout_states[index].name);
            goto Exit;
        }
    }

    status = FwpmTransactionCommit(_fwp_engine_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmTransactionCommit", status);
        goto Exit;
    }
    is_in_transaction = FALSE;

    // Create L2 injection handle.
    status = FwpsInjectionHandleCreate(AF_LINK, FWPS_INJECTION_TYPE_L2, &_net_ebpf_ext_l2_injection_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpsInjectionHandleCreate", status);
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status)) {
        if (is_in_transaction) {
            status = FwpmTransactionAbort(_fwp_engine_handle);
            if (!NT_SUCCESS(status)) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, "FwpmTransactionAbort", status);
            }
        }
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_extension_uninitialize_wfp_components(void)
{
    size_t index;
    if (_fwp_engine_handle != NULL) {
        FwpmEngineClose(_fwp_engine_handle);
        _fwp_engine_handle = NULL;

        for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states); index++) {
            FwpsCalloutUnregisterById(_net_ebpf_ext_wfp_callout_states[index].assigned_callout_id);
        }
    }

    FwpsInjectionHandleDestroy(_net_ebpf_ext_l2_injection_handle);
}

NTSTATUS
net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter)
{
    NET_EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(filter_key);
    if (callout_notification_type == FWPS_CALLOUT_NOTIFY_DELETE_FILTER) {
        net_ebpf_extension_wfp_filter_context_t* filter_context =
            (net_ebpf_extension_wfp_filter_context_t*)(uintptr_t)filter->context;
        DEREFERENCE_FILTER_CONTEXT((filter_context));
    }

    NET_EBPF_EXT_LOG_FUNCTION_SUCCESS();
    return STATUS_SUCCESS;
}

static void
_net_ebpf_ext_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context)
/* ++

   This is the flowDeleteFn function of the L2 callout.

-- */
{
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
    UNREFERENCED_PARAMETER(flow_context);
    return;
}

NTSTATUS
net_ebpf_ext_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    status = net_ebpf_ext_xdp_register_providers();
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = net_ebpf_ext_bind_register_providers();
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = net_ebpf_ext_sock_addr_register_providers();
    if (status != STATUS_SUCCESS)
        goto Exit;

    status = net_ebpf_ext_sock_ops_register_providers();
    if (status != STATUS_SUCCESS)
        goto Exit;

Exit:
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_unregister_providers()
{
    net_ebpf_ext_xdp_unregister_providers();
    net_ebpf_ext_bind_unregister_providers();
    net_ebpf_ext_sock_addr_unregister_providers();
    net_ebpf_ext_sock_ops_unregister_providers();
}
