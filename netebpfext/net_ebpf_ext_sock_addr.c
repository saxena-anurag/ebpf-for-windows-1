// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file This file implements the hook for the CGROUP_SOCK_ADDR program type and associated attach types, on eBPF for
 * Windows.
 *
 */

#include "net_ebpf_ext.h"

#include "ebpf_store_helper.h"
#include "net_ebpf_ext_sock_addr.h"

#define TARGET_PROCESS_ID 1234

// 98849e11-b07d-11ec-9a30-18602489beee
DEFINE_GUID(
    EBPF_HOOK_ALE_CONNECT_REDIRECT_PROVIDER,
    0x98849e11,
    0xb07d,
    0x11ec,
    0x9a,
    0x30,
    0x18,
    0x60,
    0x24,
    0x89,
    0xbe,
    0xee);

typedef struct _net_ebpf_ext_redirection_record
{
    union
    {
        uint32_t v4_address;
        uint8_t v6_address[16];
    } destination_address;
    uint16_t destination_port;
} net_ebpf_ext_redirection_record_t;

typedef struct _net_ebpf_extension_connection_context
{
    LIST_ENTRY list_entry;
    bpf_sock_addr_t original_addr;
    bpf_sock_addr_t redirected_addr;
    bool redirected;
    uint32_t verdict;
    uint64_t transport_endpoint_handle;
    volatile long reference_count;
} net_ebpf_extension_connection_context_t;

typedef struct _net_ebpf_extension_redirect_handle_entry
{
    LIST_ENTRY list_entry;
    uint64_t filter_id;
    HANDLE redirect_handle;
} net_ebpf_extension_redirect_handle_entry_t;

typedef struct _net_ebpf_ext_sock_addr_globals
{
    EX_SPIN_LOCK _net_ebpf_ext_redirect_handle_lock;
} net_ebpf_ext_sock_addr_globals_t;

typedef struct _net_ebpf_ext_sock_addr_statistics
{
    volatile long permit_connection_count;
    volatile long redirect_connection_count;
    volatile long block_connection_count;
} net_ebpf_ext_sock_addr_statistics_t;

static net_ebpf_ext_sock_addr_statistics_t _net_ebpf_ext_statistics;

static EX_SPIN_LOCK _net_ebpf_ext_redirect_handle_lock;
_Guarded_by_(_net_ebpf_ext_redirect_handle_lock) static LIST_ENTRY _net_ebpf_ext_redirect_handle_list;
_Guarded_by_(_net_ebpf_ext_redirect_handle_lock) static LIST_ENTRY _net_ebpf_ext_connect_context_list;

#define REFERENCE_CONNECTION_CONTEXT(context)            \
    if (context != NULL) {                               \
        InterlockedIncrement(&context->reference_count); \
    }

#define DEREFERENCE_CONNECTION_CONTEXT(context)                                                \
    {                                                                                          \
        if (context != NULL) {                                                                 \
            if (InterlockedDecrement(&context->reference_count) == 0) {                        \
                KIRQL _irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock); \
                RemoveEntryList(&context->list_entry);                                         \
                ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, _irql);        \
                ExFreePool(context);                                                           \
                context = NULL;                                                                \
            }                                                                                  \
        }                                                                                      \
    }

//
// WFP filter related types & globals for SOCK_ADDR hook.
//

const ebpf_attach_type_t* _net_ebpf_extension_sock_addr_attach_types[] = {
    &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
    &EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
    &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
    &EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT};

const uint32_t _net_ebpf_extension_sock_addr_bpf_attach_types[] = {
    BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET4_RECV_ACCEPT, BPF_CGROUP_INET6_CONNECT, BPF_CGROUP_INET6_RECV_ACCEPT};

#define NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_sock_addr_attach_types)

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet4_connect_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
     &EBPF_HOOK_ALE_AUTH_CONNECT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},
    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet6_connect_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
     &EBPF_HOOK_ALE_AUTH_CONNECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},

    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet4_recv_accept_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
     &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet6_recv_accept_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
     &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

const net_ebpf_extension_wfp_filter_parameters_array_t _net_ebpf_extension_sock_addr_wfp_filter_parameters[] = {
    {EBPF_COUNT_OF(_cgroup_inet4_connect_filter_parameters), &_cgroup_inet4_connect_filter_parameters[0]},
    {EBPF_COUNT_OF(_cgroup_inet6_connect_filter_parameters), &_cgroup_inet6_connect_filter_parameters[0]},
    {EBPF_COUNT_OF(_cgroup_inet4_recv_accept_filter_parameters), &_cgroup_inet4_recv_accept_filter_parameters[0]},
    {EBPF_COUNT_OF(_cgroup_inet6_recv_accept_filter_parameters), &_cgroup_inet6_recv_accept_filter_parameters[0]},
};

typedef struct _net_ebpf_extension_sock_addr_wfp_filter_context
{
    net_ebpf_extension_wfp_filter_context_t base;
    uint32_t compartment_id;
} net_ebpf_extension_sock_addr_wfp_filter_context_t;

//
// SOCK_ADDR Program Information NPI Provider.
//

static ebpf_program_data_t _ebpf_sock_addr_program_data = {&_ebpf_sock_addr_program_info, NULL};

static ebpf_extension_data_t _ebpf_sock_addr_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_sock_addr_program_data), &_ebpf_sock_addr_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static net_ebpf_extension_program_info_provider_t* _ebpf_sock_addr_program_info_provider_context = NULL;

//
// SOCK_ADDR Hook NPI Provider.
//

ebpf_attach_provider_data_t _net_ebpf_sock_addr_hook_provider_data[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};
ebpf_extension_data_t _net_ebpf_extension_sock_addr_hook_provider_data[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_hook_provider_moduleid[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

static net_ebpf_extension_hook_provider_t*
    _ebpf_sock_addr_hook_provider_context[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

//
// NMR Registration Helper Routines.
//

static ebpf_result_t
_net_ebpf_extension_sock_addr_on_client_attach(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);
    uint32_t compartment_id;
    uint32_t wild_card_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    net_ebpf_extension_wfp_filter_parameters_array_t* filter_parameters = NULL;
    FWPM_FILTER_CONDITION condition = {0};
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    // SOCK_ADDR hook clients must always provide data.
    if (client_data == NULL) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (client_data->size > 0) {
        if ((client_data->size != sizeof(uint32_t)) || (client_data->data == NULL)) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        compartment_id = *(uint32_t*)client_data->data;
    } else {
        // If the client did not specify any attach parameters, we treat that as a wildcard compartment id.
        compartment_id = wild_card_compartment_id;
    }

    result = net_ebpf_extension_hook_check_attach_parameter(
        sizeof(compartment_id),
        &compartment_id,
        &wild_card_compartment_id,
        (net_ebpf_extension_hook_provider_t*)provider_context);
    if (result != EBPF_SUCCESS)
        goto Exit;

    if (client_data->data != NULL)
        compartment_id = *(uint32_t*)client_data->data;

    // Set compartment id (if not UNSPECIFIED_COMPARTMENT_ID) as WFP filter condition.
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
        condition.fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = compartment_id;
    }

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_sock_addr_wfp_filter_context_t),
        attaching_client,
        (net_ebpf_extension_wfp_filter_context_t**)&filter_context);
    if (result != EBPF_SUCCESS)
        goto Exit;
    filter_context->compartment_id = compartment_id;

    // Get the WFP filter parameters for this hook type.
    filter_parameters =
        (net_ebpf_extension_wfp_filter_parameters_array_t*)net_ebpf_extension_hook_provider_get_custom_data(
            provider_context);
    ASSERT(filter_parameters != NULL);

    // Add a single WFP filter at the WFP layer corresponding to the hook type, and set the hook NPI client as the
    // filter's raw context.
    result = net_ebpf_extension_add_wfp_filters(
        filter_parameters->count, // filter_count
        filter_parameters->filter_parameters,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? 0 : 1,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? NULL : &condition,
        (net_ebpf_extension_wfp_filter_context_t*)filter_context,
        &filter_context->base.filter_ids);
    if (result != EBPF_SUCCESS)
        goto Exit;

    // Set the filter context as the client context's provider data.
    net_ebpf_extension_hook_client_set_provider_data(
        (net_ebpf_extension_hook_client_t*)attaching_client, filter_context);

Exit:
    if (result != EBPF_SUCCESS) {
        if (filter_context != NULL)
            ExFreePool(filter_context);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_net_ebpf_extension_sock_addr_on_client_detach(_In_ const net_ebpf_extension_hook_client_t* detaching_client)
{
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context =
        (net_ebpf_extension_sock_addr_wfp_filter_context_t*)net_ebpf_extension_hook_client_get_provider_data(
            detaching_client);
    ASSERT(filter_context != NULL);
    net_ebpf_extension_delete_wfp_filters(1, filter_context->base.filter_ids);
    net_ebpf_extension_wfp_filter_context_cleanup((net_ebpf_extension_wfp_filter_context_t*)filter_context);
}

static NTSTATUS
_net_ebpf_sock_addr_update_store_entries()
{
    NTSTATUS status;

    // Update section information.
    uint32_t section_info_count = sizeof(_ebpf_sock_addr_section_info) / sizeof(ebpf_program_section_info_t);
    status = ebpf_store_update_section_information(&_ebpf_sock_addr_section_info[0], section_info_count);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Update program information.
    _ebpf_sock_addr_program_info.program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    status = ebpf_store_update_program_information(&_ebpf_sock_addr_program_info, 1);

    return status;
}

static void
_net_ebpf_sock_addr_initialize_globals()
{
    // KeInitializeSpinLock(&_net_ebpf_ext_redirect_handle_lock);
    InitializeListHead(&_net_ebpf_ext_redirect_handle_list);
    InitializeListHead(&_net_ebpf_ext_connect_context_list);
}

static NTSTATUS
_net_ebpf_ext_sock_addr_update_redirect_handle(uint64_t filter_id, HANDLE redirect_handle)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL old_irql;

    net_ebpf_extension_redirect_handle_entry_t* entry =
        (net_ebpf_extension_redirect_handle_entry_t*)ExAllocatePoolUninitialized(
            NonPagedPoolNx, sizeof(net_ebpf_extension_redirect_handle_entry_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (entry == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    memset(entry, 0, sizeof(net_ebpf_extension_redirect_handle_entry_t));
    entry->filter_id = filter_id;
    entry->redirect_handle = redirect_handle;

    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);
    InsertTailList(&_net_ebpf_ext_redirect_handle_list, &entry->list_entry);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);

Exit:
    return status;
}

static void
_net_ebpf_ext_sock_addr_delete_redirect_handle(uint64_t filter_id)
{
    KIRQL old_irql;

    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_redirect_handle_list.Flink;
    while (list_entry != &_net_ebpf_ext_redirect_handle_list) {
        net_ebpf_extension_redirect_handle_entry_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_redirect_handle_entry_t, list_entry);
        if (entry->filter_id == filter_id) {
            RemoveEntryList(list_entry);
            ExFreePool(entry);
            break;
        }
        list_entry = list_entry->Flink;
    }
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);
}

static NTSTATUS
_net_ebpf_ext_sock_addr_get_redirect_handle(uint64_t filter_id, _Out_ HANDLE* redirect_handle)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL old_irql;

    old_irql = ExAcquireSpinLockShared(&_net_ebpf_ext_redirect_handle_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_redirect_handle_list.Flink;
    while (list_entry != &_net_ebpf_ext_redirect_handle_list) {
        net_ebpf_extension_redirect_handle_entry_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_redirect_handle_entry_t, list_entry);
        if (entry->filter_id == filter_id) {
            *redirect_handle = entry->redirect_handle;
            status = STATUS_SUCCESS;
            break;
        }
        list_entry = list_entry->Flink;
    }

    ExReleaseSpinLockShared(&_net_ebpf_ext_redirect_handle_lock, old_irql);

    return status;
}

static void
_net_ebpf_ext_initialize_connection_context(
    _In_ const bpf_sock_addr_t* original_sock_addr,
    _In_ const bpf_sock_addr_t* redirected_sock_addr,
    bool redirected,
    uint32_t verdict,
    uint64_t transport_endpoint_handle,
    _Out_ net_ebpf_extension_connection_context_t* connection_context)
{
    RtlCopyMemory(&connection_context->original_addr, original_sock_addr, sizeof(bpf_sock_addr_t));
    RtlCopyMemory(&connection_context->redirected_addr, redirected_sock_addr, sizeof(bpf_sock_addr_t));
    connection_context->redirected = redirected;
    connection_context->verdict = verdict;
    connection_context->transport_endpoint_handle = transport_endpoint_handle;
    // One reference count for each time AUTH_CONNECT will be called for this connection.
    connection_context->reference_count = 2;
}

static NTSTATUS
_net_ebpf_ext_get_connection_context(
    uint64_t transport_endpoint_handle, _Out_ net_ebpf_extension_connection_context_t** connection_context)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL old_irql;

    *connection_context = NULL;
    old_irql = ExAcquireSpinLockShared(&_net_ebpf_ext_redirect_handle_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_connect_context_list.Flink;
    while (list_entry != &_net_ebpf_ext_connect_context_list) {
        net_ebpf_extension_connection_context_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_connection_context_t, list_entry);
        if (entry->transport_endpoint_handle == transport_endpoint_handle) {
            REFERENCE_CONNECTION_CONTEXT(entry);
            *connection_context = entry;
            status = STATUS_SUCCESS;
            break;
        }
        list_entry = list_entry->Flink;
    }

    ExReleaseSpinLockShared(&_net_ebpf_ext_redirect_handle_lock, old_irql);

    return status;
}

static void
_net_ebpf_ext_insert_connection_context_to_list(_In_ net_ebpf_extension_connection_context_t* connection_context)
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock);
    InsertTailList(&_net_ebpf_ext_connect_context_list, &connection_context->list_entry);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_redirect_handle_lock, old_irql);
}

NTSTATUS
net_ebpf_ext_sock_addr_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    status = _net_ebpf_sock_addr_update_store_entries();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    _net_ebpf_sock_addr_initialize_globals();

    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_sock_addr_program_info_provider_moduleid, &_ebpf_sock_addr_program_info_provider_data};

    NET_EBPF_EXT_LOG_ENTRY();

    _ebpf_sock_addr_program_info.program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    // Set the program type as the provider module id.
    _ebpf_sock_addr_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_sock_addr_program_info_provider_context);
    if (status != STATUS_SUCCESS)
        goto Exit;

    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++) {
        const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
            &_ebpf_sock_addr_hook_provider_moduleid[i], &_net_ebpf_extension_sock_addr_hook_provider_data[i]};

        _net_ebpf_sock_addr_hook_provider_data[i].supported_program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
        _net_ebpf_sock_addr_hook_provider_data[i].bpf_attach_type =
            (bpf_attach_type_t)_net_ebpf_extension_sock_addr_bpf_attach_types[i];
        _net_ebpf_sock_addr_hook_provider_data[i].link_type = BPF_LINK_TYPE_CGROUP;
        _net_ebpf_extension_sock_addr_hook_provider_data[i].version = EBPF_ATTACH_PROVIDER_DATA_VERSION;
        _net_ebpf_extension_sock_addr_hook_provider_data[i].data = &_net_ebpf_sock_addr_hook_provider_data[i];
        _net_ebpf_extension_sock_addr_hook_provider_data[i].size = sizeof(ebpf_attach_provider_data_t);

        // Set the attach type as the provider module id.
        _ebpf_sock_addr_hook_provider_moduleid[i].Length = sizeof(NPI_MODULEID);
        _ebpf_sock_addr_hook_provider_moduleid[i].Type = MIT_GUID;
        _ebpf_sock_addr_hook_provider_moduleid[i].Guid = *_net_ebpf_extension_sock_addr_attach_types[i];
        // Register the provider context and pass the pointer to the WFP filter parameters
        // corresponding to this hook type as custom data.
        status = net_ebpf_extension_hook_provider_register(
            &hook_provider_parameters,
            _net_ebpf_extension_sock_addr_on_client_attach,
            _net_ebpf_extension_sock_addr_on_client_detach,
            &_net_ebpf_extension_sock_addr_wfp_filter_parameters[i],
            &_ebpf_sock_addr_hook_provider_context[i]);
    }

    if (status != EBPF_SUCCESS)
        goto Exit;

Exit:
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_sock_addr_unregister_providers()
{
    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++)
        net_ebpf_extension_hook_provider_unregister(_ebpf_sock_addr_hook_provider_context[i]);
    net_ebpf_extension_program_info_provider_unregister(_ebpf_sock_addr_program_info_provider_context);
}

typedef enum _net_ebpf_extension_sock_addr_connection_direction
{
    EBPF_HOOK_SOCK_ADDR_INGRESS = 0,
    EBPF_HOOK_SOCK_ADDR_EGRESS
} net_ebpf_extension_sock_addr_connection_direction_t;

static net_ebpf_extension_sock_addr_connection_direction_t
_net_ebpf_extension_sock_addr_get_connection_direction_from_hook_id(net_ebpf_extension_hook_id_t hook_id)
{
    return ((hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V4) || (hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V6) ||
            (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4) || (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V6))
               ? EBPF_HOOK_SOCK_ADDR_EGRESS
               : EBPF_HOOK_SOCK_ADDR_INGRESS;
}

wfp_ale_layer_fields_t wfp_connection_fields[] = {
    // EBPF_HOOK_ALE_AUTH_CONNECT_V4
    {FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_INTERFACE},

    // EBPF_HOOK_ALE_AUTH_CONNECT_V6
    {FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_INTERFACE},

    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V4
    {
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL,
        0, // No direction field in this layer.
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_COMPARTMENT_ID,
        0 // No interface luid in this layer.
    },

    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V6
    {
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL,
        0, // No direction field in this layer.
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_COMPARTMENT_ID,
        0 // No interface luid in this layer.
    },

    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4
    {FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_INTERFACE},

    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6
    {FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_INTERFACE}};

static void
_net_ebpf_extension_sock_addr_copy_wfp_connection_fields(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values, _Out_ bpf_sock_addr_t* sock_addr_ctx)
{
    net_ebpf_extension_hook_id_t hook_id =
        net_ebpf_extension_get_hook_id_from_wfp_layer_id(incoming_fixed_values->layerId);
    net_ebpf_extension_sock_addr_connection_direction_t direction =
        _net_ebpf_extension_sock_addr_get_connection_direction_from_hook_id(hook_id);
    wfp_ale_layer_fields_t* fields = &wfp_connection_fields[hook_id - EBPF_HOOK_ALE_AUTH_CONNECT_V4];

    uint16_t source_ip_address_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->local_ip_address_field : fields->remote_ip_address_field;
    uint16_t source_port_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->local_port_field : fields->remote_port_field;
    uint16_t destination_ip_address_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->remote_ip_address_field : fields->local_ip_address_field;
    uint16_t destination_port_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->remote_port_field : fields->local_port_field;

    FWPS_INCOMING_VALUE0* incoming_values = incoming_fixed_values->incomingValue;

    // Copy IP address fields.
    if ((hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V4) || (hook_id == EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4) ||
        (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4)) {
        sock_addr_ctx->family = AF_INET;
        sock_addr_ctx->msg_src_ip4 = htonl(incoming_values[source_ip_address_field].value.uint32);
        sock_addr_ctx->user_ip4 = htonl(incoming_values[destination_ip_address_field].value.uint32);
    } else {
        sock_addr_ctx->family = AF_INET6;
        RtlCopyMemory(
            sock_addr_ctx->msg_src_ip6,
            incoming_values[source_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
        RtlCopyMemory(
            sock_addr_ctx->user_ip6,
            incoming_values[destination_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
    }
    sock_addr_ctx->msg_src_port = htons(incoming_values[source_port_field].value.uint16);
    sock_addr_ctx->user_port = htons(incoming_values[destination_port_field].value.uint16);
    sock_addr_ctx->protocol = incoming_values[fields->protocol_field].value.uint8;
    sock_addr_ctx->compartment_id = incoming_values[fields->compartment_id_field].value.uint32;

    if (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4 || hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V6) {
        sock_addr_ctx->interface_luid = 0;
    } else {
        sock_addr_ctx->interface_luid = *incoming_values[fields->interface_luid_field].value.uint64;
    }
}

NTSTATUS
net_ebpf_ext_connect_redirect_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ const FWPS_FILTER* filter)
{
    NET_EBPF_EXT_LOG_ENTRY();
    NTSTATUS status = STATUS_SUCCESS;

    if (callout_notification_type == FWPS_CALLOUT_NOTIFY_ADD_FILTER) {
        HANDLE redirect_handle;
        status = FwpsRedirectHandleCreate(&EBPF_HOOK_ALE_CONNECT_REDIRECT_PROVIDER, 0, &redirect_handle);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        status = _net_ebpf_ext_sock_addr_update_redirect_handle(filter->filterId, redirect_handle);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    } else if (callout_notification_type == FWPS_CALLOUT_NOTIFY_DELETE_FILTER) {
        _net_ebpf_ext_sock_addr_delete_redirect_handle(filter->filterId);
    }

    net_ebpf_ext_filter_change_notify(callout_notification_type, filter_key, filter);

Exit:
    NET_EBPF_EXT_RETURN_RESULT(status);
}

//
// WFP callout callback functions.
//

void
net_ebpf_extension_sock_addr_authorize_connection_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    uint32_t result;
    NTSTATUS status;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;
    bpf_sock_addr_t sock_addr_ctx = {0};
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    FWP_ACTION_TYPE action = FWP_ACTION_BLOCK;
    net_ebpf_extension_connection_context_t* connection_context = NULL;

    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL)
        goto Exit;

    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(incoming_fixed_values, &sock_addr_ctx);

    // Get the connection context for this connection.
    status =
        _net_ebpf_ext_get_connection_context(incoming_metadata_values->transportEndpointHandle, &connection_context);
    if (!NT_SUCCESS(status)) {
        // We did not find any connection context for this AUTH request. Permit.
        action = FWP_ACTION_PERMIT;
        goto Exit;
    }
    result = connection_context->verdict;

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx.compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx.compartment_id) {
        // The client is not interested in this compartment Id.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_addr eBPF program is not interested in this compartmentId",
            sock_addr_ctx.compartment_id);

        action = FWP_ACTION_PERMIT;
        goto Exit;
    }

    action = (result == BPF_SOCK_ADDR_VERDICT_PROCEED) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    if (classify_output->actionType == FWP_ACTION_BLOCK)
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;

Exit:
    classify_output->actionType = action;
    // Release reference for query.
    DEREFERENCE_CONNECTION_CONTEXT(connection_context);
    // Release the AUTH reference.
    DEREFERENCE_CONNECTION_CONTEXT(connection_context);
    return;
}

static bool
_net_ebpf_ext_destination_address_changed(_In_ const bpf_sock_addr_t* addr1, _In_ const bpf_sock_addr_t* addr2)
{
    ASSERT(addr1->family == addr2->family);

    if (addr1->family == AF_INET) {
        return addr1->user_ip4 != addr2->user_ip4;
    } else {
        return (memcmp(&addr1->user_ip6[0], &addr1->user_ip6[2], 16) != 0);
    }
}

static void
_net_ebpf_ext_populate_redirect_record(
    _In_ const bpf_sock_addr_t* sock_addr, _Out_ net_ebpf_ext_redirection_record_t* redirect_record)
{
    if (sock_addr->family == AF_INET) {
        redirect_record->destination_address.v4_address = sock_addr->user_ip4;
    } else {
        RtlCopyMemory(redirect_record->destination_address.v6_address, sock_addr->user_ip6, 16);
    }
    redirect_record->destination_port = sock_addr->user_port;
}

/*
 * Default action is BLOCK. If this callout is being invoked, it means at least one
 * eBPF program is attached. Hence no connection should be allowed unless allowed by
 * the eBPF program.
 */
void
net_ebpf_extension_sock_addr_redirect_connection_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    uint32_t result;
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;
    bpf_sock_addr_t sock_addr_ctx = {0};
    bpf_sock_addr_t sock_addr_ctx_original = {0};
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    FWPS_CONNECTION_REDIRECT_STATE redirect_state;
    HANDLE redirect_handle;
    uint64_t classify_handle = 0;
    FWPS_CONNECT_REQUEST* connect_request = NULL;
    net_ebpf_ext_redirection_record_t* redirect_record = NULL;
    net_ebpf_extension_connection_context_t* connection_context = NULL;
    bool address_changed = false;
    bool redirected = false;
    FWP_ACTION_TYPE action = FWP_ACTION_BLOCK;
    bool commit_layer_data = false;
    bool classify_handle_acquired = false;
    bool free_redirect_record = true;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);

    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(incoming_fixed_values, &sock_addr_ctx);
    sock_addr_ctx_original = sock_addr_ctx;

    if ((classify_output->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        // Do not modify anything and bail.
        return;
    }

    // Get the redirect handle for this filter.
    status = _net_ebpf_ext_sock_addr_get_redirect_handle(filter->filterId, &redirect_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "Failed to get redirect handle",
            filter->filterId,
            (uint64_t)sock_addr_ctx.compartment_id);
        goto Exit;
    }

    // Fetch redirect state.
    redirect_state = FwpsQueryConnectionRedirectState(incoming_metadata_values->redirectRecords, redirect_handle, NULL);
    if (redirect_state == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
        redirect_state == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "Connection redireced by self, ingnoring",
            filter->filterId,
            (uint64_t)sock_addr_ctx.compartment_id);

        // We have already looked at this connection. Permit and exit.
        classify_output->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Sanity check. We should not have a connection context with same endpoint handle
    // already present.
    ASSERT(
        _net_ebpf_ext_get_connection_context(incoming_metadata_values->transportEndpointHandle, &connection_context) ==
        STATUS_NOT_FOUND);

    // Acquire classify handle.
    status = FwpsAcquireClassifyHandle((void*)classify_context, 0, &classify_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "FwpsAcquireClassifyHandle",
            status,
            filter->filterId,
            (uint64_t)sock_addr_ctx.compartment_id);

        goto Exit;
    }
    classify_handle_acquired = true;

    status =
        FwpsAcquireWritableLayerDataPointer(classify_handle, filter->filterId, 0, &connect_request, classify_output);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "FwpsAcquireWritableLayerDataPointer",
            status,
            filter->filterId,
            (uint64_t)sock_addr_ctx.compartment_id);

        goto Exit;
    }
    commit_layer_data = true;

    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->client_context;
    if (attached_client == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        // Client is detaching, change action to permit.
        action = FWP_ACTION_PERMIT;
        goto Exit;
    }

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx.compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx.compartment_id) {
        // The client is not interested in this compartment Id. Change action to PERMIT.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_addr eBPF program is not interested in this compartmentId",
            sock_addr_ctx.compartment_id);

        action = FWP_ACTION_PERMIT;
        goto Exit;
    }

    // Allocate all the required memory before invoking the eBPF program.
    redirect_record = (net_ebpf_ext_redirection_record_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_ext_redirection_record_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (redirect_record == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    memset(redirect_record, 0, sizeof(net_ebpf_ext_redirection_record_t));

    connection_context = (net_ebpf_extension_connection_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_connection_context_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (connection_context == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    memset(connection_context, 0, sizeof(net_ebpf_extension_connection_context_t));

    if (net_ebpf_extension_hook_invoke_program(attached_client, &sock_addr_ctx, &result) != EBPF_SUCCESS) {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    if (result == BPF_SOCK_ADDR_VERDICT_PROCEED) {
        // Check if destination IP and/or port have been modified.
        address_changed = _net_ebpf_ext_destination_address_changed(&sock_addr_ctx, &sock_addr_ctx_original);
        if (sock_addr_ctx.user_port != sock_addr_ctx_original.user_port || address_changed) {
            redirected = true;
            InterlockedIncrement(&_net_ebpf_ext_statistics.redirect_connection_count);

            if (sock_addr_ctx.user_port != sock_addr_ctx_original.user_port) {
                INETADDR_SET_PORT((PSOCKADDR)&connect_request->remoteAddressAndPort, ntohs(sock_addr_ctx.user_port));
            }
            if (address_changed) {
                uint8_t* address;
                if (sock_addr_ctx.family == AF_INET) {
                    address = (uint8_t*)&sock_addr_ctx.user_ip4;
                } else {
                    address = (uint8_t*)&(sock_addr_ctx.user_ip6[0]);
                }
                INETADDR_SET_ADDRESS((PSOCKADDR)&connect_request->remoteAddressAndPort, address);
            }

            _net_ebpf_ext_populate_redirect_record(&sock_addr_ctx_original, redirect_record);
            connect_request->localRedirectContext = redirect_record;
            connect_request->localRedirectContextSize = sizeof(net_ebpf_ext_redirection_record_t);
            free_redirect_record = false;

            if (INETADDR_ISLOOPBACK((PSOCKADDR)&connect_request->remoteAddressAndPort)) {
                // Connection is being redirected to loopback. Set local redirect handle.
                connect_request->localRedirectHandle = redirect_handle;
            }
        } else {
            InterlockedIncrement(&_net_ebpf_ext_statistics.permit_connection_count);
        }
    } else {
        InterlockedIncrement(&_net_ebpf_ext_statistics.block_connection_count);
    }

    _net_ebpf_ext_initialize_connection_context(
        &sock_addr_ctx_original,
        &sock_addr_ctx,
        redirected,
        result,
        incoming_metadata_values->transportEndpointHandle,
        connection_context);
    _net_ebpf_ext_insert_connection_context_to_list(connection_context);

    // TODO: Should we return block here? Or wait till auth_connect?
    // TODO: What to do for redirection by multiple callouts (FWP_CONDITION_FLAG_IS_REAUTHORIZE).
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection#handling-connect-redirection-from-multiple-callouts

Exit:
    classify_output->actionType = action;
    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT || action == FWP_ACTION_BLOCK) {
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    if (commit_layer_data) {
        FwpsApplyModifiedLayerData(classify_handle, connect_request, 0);
    }
    if (classify_handle_acquired) {
        FwpsReleaseClassifyHandle(classify_handle);
    }
    if (!NT_SUCCESS(status)) {
        if (connection_context) {
            ExFreePool(connection_context);
        }
        if (redirect_record) {
            ExFreePool(redirect_record);
        }
    } else if (free_redirect_record) {
        ExFreePool(redirect_record);
    }
    if (attached_client)
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
}
