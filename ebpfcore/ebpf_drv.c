// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:
WDF based driver that does the following:
1. Initializes the eBPF execution context.
2. Opens an IOCTL surface that forwards commands to ebfp_core.

Environment:

    Kernel mode

--*/

// ntddk.h needs to be included first due to inter header dependencies on Windows.
#include <ntddk.h>

#include <netiodef.h>
#include <wdf.h>

#include "ebpf_core.h"
#include "ebpf_object.h"

// Driver global variables
static DEVICE_OBJECT* _ebpf_driver_device_object;
static BOOLEAN _ebpf_driver_unloading_flag = FALSE;

// SID for ebpfsvc (generated using command "sc.exe showsid ebpfsvc"):
// S-1-5-80-3453964624-2861012444-1105579853-3193141192-1897355174
//
// SDDL_DEVOBJ_SYS_ALL_ADM_ALL + SID for ebpfsvc.
#define EBPF_EXECUTION_CONTEXT_DEVICE_SDDL \
    L"D:P(A;;GA;;;S-1-5-80-3453964624-2861012444-1105579853-3193141192-1897355174)(A;;GA;;;BA)(A;;GA;;;SY)"

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
// Device type
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPFCTL_METHOD_BUFFERED CTL_CODE(EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Pre-Declarations
//
static EVT_WDF_FILE_CLOSE _ebpf_driver_file_close;
static EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL _ebpf_driver_io_device_control;
static EVT_WDFDEVICE_WDM_IRP_PREPROCESS _ebpf_driver_query_volume_information;
static EVT_WDF_REQUEST_CANCEL _ebpf_driver_io_device_control_cancel;
DRIVER_INITIALIZE DriverEntry;

static VOID
_ebpf_driver_io_device_control(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    size_t output_buffer_length,
    size_t input_buffer_length,
    ULONG io_control_code);

static _Function_class_(EVT_WDF_DRIVER_UNLOAD) _IRQL_requires_same_
    _IRQL_requires_max_(PASSIVE_LEVEL) void _ebpf_driver_unload(_In_ WDFDRIVER driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);

    _ebpf_driver_unloading_flag = TRUE;

    ebpf_core_terminate();
}

//
// Create a basic WDF driver, set up the device object
// for a callout driver and setup the ioctl surface
//
static NTSTATUS
_ebpf_driver_initialize_objects(
    _Inout_ DRIVER_OBJECT* driver_object,
    _In_ const UNICODE_STRING* registry_path,
    _Out_ WDFDRIVER* driver,
    _Out_ WDFDEVICE* device)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG driver_configuration;
    PWDFDEVICE_INIT device_initialize = NULL;
    WDF_IO_QUEUE_CONFIG io_queue_configuration;
    UNICODE_STRING ebpf_device_name;
    UNICODE_STRING ebpf_symbolic_device_name;
    BOOLEAN device_create_flag = FALSE;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_FILEOBJECT_CONFIG file_object_config;

    WDF_DRIVER_CONFIG_INIT(&driver_configuration, WDF_NO_EVENT_CALLBACK);

    DECLARE_CONST_UNICODE_STRING(security_descriptor, EBPF_EXECUTION_CONTEXT_DEVICE_SDDL);

    driver_configuration.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    driver_configuration.EvtDriverUnload = _ebpf_driver_unload;

    status = WdfDriverCreate(driver_object, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &driver_configuration, driver);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    device_initialize = WdfControlDeviceInitAllocate(
        *driver,
        &security_descriptor // only kernel/system, administrators, and ebpfsvc.
    );
    if (!device_initialize) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    WdfDeviceInitSetDeviceType(device_initialize, FILE_DEVICE_NULL);

    WdfDeviceInitSetCharacteristics(device_initialize, FILE_DEVICE_SECURE_OPEN, FALSE);

    WdfDeviceInitSetCharacteristics(device_initialize, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

    RtlInitUnicodeString(&ebpf_device_name, EBPF_DEVICE_NAME);
    status = WdfDeviceInitAssignName(device_initialize, &ebpf_device_name);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.SynchronizationScope = WdfSynchronizationScopeNone;
    WDF_FILEOBJECT_CONFIG_INIT(
        &file_object_config,
        NULL,
        _ebpf_driver_file_close,
        WDF_NO_EVENT_CALLBACK // No cleanup callback function
    );
    WdfDeviceInitSetFileObjectConfig(device_initialize, &file_object_config, &attributes);

    // WDF framework doesn't handle IRP_MJ_QUERY_VOLUME_INFORMATION.
    // Register a handler for this IRP.
    status = WdfDeviceInitAssignWdmIrpPreprocessCallback(
        device_initialize, _ebpf_driver_query_volume_information, IRP_MJ_QUERY_VOLUME_INFORMATION, NULL, 0);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = WdfDeviceCreate(&device_initialize, WDF_NO_OBJECT_ATTRIBUTES, device);

    if (!NT_SUCCESS(status)) {
        // do not free if any other call
        // after WdfDeviceCreate fails.
        WdfDeviceInitFree(device_initialize);
        device_initialize = NULL;
        goto Exit;
    }

    device_create_flag = TRUE;

    // Create symbolic link for control object for user mode.
    RtlInitUnicodeString(&ebpf_symbolic_device_name, EBPF_SYMBOLIC_DEVICE_NAME);
    status = WdfDeviceCreateSymbolicLink(*device, &ebpf_symbolic_device_name);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // parallel default queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&io_queue_configuration, WdfIoQueueDispatchParallel);

    io_queue_configuration.EvtIoDeviceControl = _ebpf_driver_io_device_control;

    status = WdfIoQueueCreate(
        *device,
        &io_queue_configuration,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE // pointer to default queue
    );
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = ebpf_result_to_ntstatus(ebpf_core_initiate());
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    WdfControlFinishInitializing(*device);

Exit:
    if (!NT_SUCCESS(status)) {
        if (device_create_flag && device != NULL) {
            //
            // Release the reference on the newly created object, since
            // we couldn't initialize it.
            //
            WdfObjectDelete(*device);
        }
    }
    return status;
}

static void
_ebpf_driver_file_close(WDFFILEOBJECT wdf_file_object)
{
    FILE_OBJECT* file_object = WdfFileObjectWdmGetFileObject(wdf_file_object);
    ebpf_base_object_t* base_object = file_object->FsContext2;
    if (base_object != NULL) {
        base_object->release_reference(base_object);
    }
}

static void
_ebpf_driver_io_device_control_complete(void* context, size_t output_buffer_length, ebpf_result_t result)
{
    NTSTATUS status;
    WDFREQUEST request = (WDFREQUEST)context;
    status = WdfRequestUnmarkCancelable(request);
    UNREFERENCED_PARAMETER(status);
    WdfRequestCompleteWithInformation(request, ebpf_result_to_ntstatus(result), output_buffer_length);
    WdfObjectDereference(request);
}

static void
_ebpf_driver_io_device_control_cancel(WDFREQUEST request)
{
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nc-wdfrequest-evt_wdf_request_cancel
    ebpf_core_cancel_protocol_handler(request);
}

static VOID
_ebpf_driver_io_device_control(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    size_t output_buffer_length,
    size_t input_buffer_length,
    ULONG io_control_code)
{
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE device;
    void* input_buffer = NULL;
    void* output_buffer = NULL;
    size_t actual_input_length = 0;
    size_t actual_output_length = 0;
    const struct _ebpf_operation_header* user_request = NULL;
    struct _ebpf_operation_header* user_reply = NULL;
    bool async = false;
    bool wdf_request_ref_acquired = false;

    device = WdfIoQueueGetDevice(queue);

    switch (io_control_code) {
    case IOCTL_EBPFCTL_METHOD_BUFFERED:
        // Verify that length of the input buffer supplied to the request object
        // is not zero
        if (input_buffer_length != 0) {
            // Retrieve the input buffer associated with the request object
            status = WdfRequestRetrieveInputBuffer(
                request,             // Request object
                input_buffer_length, // Length of input buffer
                &input_buffer,       // Pointer to buffer
                &actual_input_length // Length of buffer
            );

            if (!NT_SUCCESS(status)) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: Input buffer failure %d\n", status));
                goto Done;
            }

            if (input_buffer == NULL) {
                status = STATUS_INVALID_PARAMETER;
                goto Done;
            }

            if (input_buffer != NULL) {
                size_t minimum_request_size = 0;
                size_t minimum_reply_size = 0;
                void* async_context = NULL;

                user_request = input_buffer;
                if (actual_input_length < sizeof(struct _ebpf_operation_header)) {
                    status = STATUS_INVALID_PARAMETER;
                    goto Done;
                }

                status = ebpf_result_to_ntstatus(ebpf_core_get_protocol_handler_properties(
                    user_request->id, &minimum_request_size, &minimum_reply_size, &async));
                if (status != STATUS_SUCCESS)
                    goto Done;

                // Be aware: Input and output buffer point to the same memory.
                if (minimum_reply_size > 0) {
                    // Retrieve output buffer associated with the request object
                    status = WdfRequestRetrieveOutputBuffer(
                        request, output_buffer_length, &output_buffer, &actual_output_length);
                    if (!NT_SUCCESS(status)) {
                        KdPrintEx(
                            (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: Output buffer failure %d\n", status));
                        goto Done;
                    }
                    if (output_buffer == NULL) {
                        status = STATUS_INVALID_PARAMETER;
                        goto Done;
                    }

                    if (actual_output_length < minimum_reply_size) {
                        status = STATUS_BUFFER_TOO_SMALL;
                        goto Done;
                    }
                    user_reply = output_buffer;
                }

                if (async) {
                    WdfObjectReference(request);
                    async_context = request;
                    WdfRequestMarkCancelable(request, _ebpf_driver_io_device_control_cancel);
                    wdf_request_ref_acquired = true;
                }

                status = ebpf_result_to_ntstatus(ebpf_core_invoke_protocol_handler(
                    user_request->id,
                    user_request,
                    (uint16_t)actual_input_length,
                    user_reply,
                    (uint16_t)actual_output_length,
                    async_context,
                    _ebpf_driver_io_device_control_complete));

                goto Done;
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
        break;
    default:
        break;
    }

Done:
    if (status != STATUS_PENDING) {
        if (wdf_request_ref_acquired) {
            ebpf_assert(status != STATUS_SUCCESS);
            // Async operation failed. Remove cancellable marker.
            (void)WdfRequestUnmarkCancelable(request);
            WdfObjectDereference(request);
        }
        WdfRequestCompleteWithInformation(request, status, output_buffer_length);
    }
    return;
}

NTSTATUS
DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    WDFDRIVER driver;
    WDFDEVICE device;

    // Request NX Non-Paged Pool when available
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: DriverEntry\n"));

    status = _ebpf_driver_initialize_objects(driver_object, registry_path, &driver, &device);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    _ebpf_driver_device_object = WdfDeviceWdmGetDeviceObject(device);

Exit:
    return status;
}

DEVICE_OBJECT*
ebpf_driver_get_device_object()
{
    return _ebpf_driver_device_object;
}

// The C runtime queries the file type via GetFileType when creating a file
// descriptor. GetFileType queries volume information to get device type via
// FileFsDeviceInformation information class.
NTSTATUS
_ebpf_driver_query_volume_information(_In_ WDFDEVICE device, _Inout_ IRP* irp)
{
    NTSTATUS status;
    IO_STACK_LOCATION* irp_stack_location;
    UNREFERENCED_PARAMETER(device);
    irp_stack_location = IoGetCurrentIrpStackLocation(irp);

    switch (irp_stack_location->Parameters.QueryVolume.FsInformationClass) {
    case FileFsDeviceInformation:
        if (irp_stack_location->Parameters.DeviceIoControl.OutputBufferLength < sizeof(FILE_FS_DEVICE_INFORMATION)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            FILE_FS_DEVICE_INFORMATION* device_info = (FILE_FS_DEVICE_INFORMATION*)irp->AssociatedIrp.SystemBuffer;
            device_info->DeviceType = FILE_DEVICE_NULL;
            device_info->Characteristics = 0;
            status = STATUS_SUCCESS;
        }
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, 0);
    return status;
}