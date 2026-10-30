// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#include "catch_wrapper.hpp"
#include "device_helper.hpp"
#include "ebpf_protocol.h"
#include "usersim/ps.h"
#include "usersim/wdf.h"

#include <array>
#include <memory>
#include <type_traits>

// Include last to avoid redefining status macros from the usersim framework.
#include "ebpf_error.h"

extern "C" __declspec(dllimport) const WDFFUNC* UsersimWdfFunctions;

namespace {
thread_local NTSTATUS namespace_completion_status;
thread_local size_t namespace_output_length;
WdfRequestCompleteWithInformation_t* namespace_original_complete;
WdfRequestRetrieveOutputBuffer_t* namespace_original_output;

void
namespace_record_completion(PWDF_DRIVER_GLOBALS globals, WDFREQUEST request, NTSTATUS status, ULONG_PTR information)
{
    namespace_completion_status = status;
    namespace_original_complete(globals, request, status, information);
}

NTSTATUS
namespace_get_output(PWDF_DRIVER_GLOBALS globals, WDFREQUEST request, size_t minimum, void** buffer, size_t* length)
{
    // usersim allocates max(input, output) but reports input length for both views.
    NTSTATUS status = namespace_original_output(globals, request, minimum, buffer, length);
    if (status == STATUS_SUCCESS || status == STATUS_BUFFER_TOO_SMALL) {
        *length = namespace_output_length;
        return namespace_output_length < minimum ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
    }
    return status;
}

class namespace_wdf_observer
{
  public:
    namespace_wdf_observer()
    {
        auto table = const_cast<WDFFUNC*>(UsersimWdfFunctions);
        namespace_original_complete =
            reinterpret_cast<WdfRequestCompleteWithInformation_t*>(table[WdfRequestCompleteWithInformationTableIndex]);
        namespace_original_output =
            reinterpret_cast<WdfRequestRetrieveOutputBuffer_t*>(table[WdfRequestRetrieveOutputBufferTableIndex]);
        table[WdfRequestCompleteWithInformationTableIndex] = reinterpret_cast<WDFFUNC>(namespace_record_completion);
        table[WdfRequestRetrieveOutputBufferTableIndex] = reinterpret_cast<WDFFUNC>(namespace_get_output);
    }
    ~namespace_wdf_observer()
    {
        auto table = const_cast<WDFFUNC*>(UsersimWdfFunctions);
        table[WdfRequestCompleteWithInformationTableIndex] = reinterpret_cast<WDFFUNC>(namespace_original_complete);
        table[WdfRequestRetrieveOutputBufferTableIndex] = reinterpret_cast<WDFFUNC>(namespace_original_output);
    }
};

ULONGLONG
namespace_process_start_key(PEPROCESS process)
{
    if (process != PsGetCurrentProcess()) {
        return 0;
    }
    FILETIME creation = {}, exit = {}, kernel = {}, user = {};
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
        return 0;
    }
    return (static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
}

NTSTATUS
namespace_process_exit_status(PEPROCESS process)
{
    DWORD exit_code = 0;
    if (process != PsGetCurrentProcess() || !GetExitCodeProcess(GetCurrentProcess(), &exit_code)) {
        return STATUS_INVALID_PARAMETER;
    }
    return exit_code == STILL_ACTIVE ? STATUS_PENDING : STATUS_SUCCESS;
}

struct namespace_process_callbacks
{
    namespace_process_callbacks()
    {
        usersime_set_process_start_key_callback(namespace_process_start_key);
        usersime_set_process_exit_status_callback(namespace_process_exit_status);
    }
    ~namespace_process_callbacks()
    {
        usersime_set_process_start_key_callback(nullptr);
        usersime_set_process_exit_status_callback(nullptr);
    }
};
} // namespace

TEST_CASE("namespace_NU11_usersim_checks_effective_subject_on_every_management_request", "[namespace][usersim]")
{
    namespace_process_callbacks process_callbacks;
    const auto unload = [](HMODULE value) { FreeLibrary(value); };
    std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(unload)> module(
        LoadLibraryW(L"ebpfcore_usersim.dll"), unload);
    REQUIRE(module != nullptr);
    WDFDRIVER driver = usersim_get_driver_from_module(module.get());
    REQUIRE(driver != nullptr);
    WDFDEVICE device = usersim_get_device_by_name(driver, L"\\Device\\EbpfIoDevice");
    REQUIRE(device != nullptr);
    namespace_wdf_observer observer;

    HANDLE primary = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primary));
    const auto close = [](HANDLE value) { CloseHandle(value); };
    std::unique_ptr<void, decltype(close)> primary_owner(primary, close);
    std::array<uint8_t, SECURITY_MAX_SID_SIZE> sid_buffer = {};
    DWORD sid_size = static_cast<DWORD>(sid_buffer.size());
    REQUIRE(CreateWellKnownSid(WinNullSid, nullptr, sid_buffer.data(), &sid_size));
    SID_AND_ATTRIBUTES restricted_sid = {sid_buffer.data(), 0};
    HANDLE restricted = nullptr;
    REQUIRE(
        CreateRestrictedToken(primary, DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 1, &restricted_sid, &restricted));
    std::unique_ptr<void, decltype(close)> restricted_owner(restricted, close);

    ebpf_operation_get_namespace_request_t get = {{sizeof(get), EBPF_OPERATION_GET_NAMESPACE}};
    ebpf_operation_get_namespace_reply_t reply = {};
    DWORD bytes_returned = 0;
    namespace_output_length = sizeof(reply);
    const BOOL before = usersim_device_io_control(
        device, IOCTL_EBPF_CTL_METHOD_BUFFERED, &get, sizeof(get), &reply, sizeof(reply), &bytes_returned, nullptr);
    const NTSTATUS before_status = namespace_completion_status;
    REQUIRE((before_status == STATUS_SUCCESS || before_status == STATUS_ACCESS_DENIED));
    REQUIRE((before != FALSE) == (before_status == STATUS_SUCCESS));
    const GUID before_namespace = reply.namespace_id;

    {
        REQUIRE(ImpersonateLoggedOnUser(restricted));
        struct revert_guard
        {
            ~revert_guard() { RevertToSelf(); }
        } revert;
        ebpf_operation_set_namespace_request_t set = {
            {sizeof(set), EBPF_OPERATION_SET_NAMESPACE}, {0x12345678, 0xabcd, 0x4321, {1, 2, 3, 4, 5, 6, 7, 8}}};
        namespace_output_length = 0;
        REQUIRE_FALSE(usersim_device_io_control(
            device, IOCTL_EBPF_CTL_METHOD_BUFFERED, &set, sizeof(set), nullptr, 0, &bytes_returned, nullptr));
        REQUIRE(namespace_completion_status == STATUS_ACCESS_DENIED);
        namespace_output_length = sizeof(reply);
        REQUIRE_FALSE(usersim_device_io_control(
            device,
            IOCTL_EBPF_CTL_METHOD_BUFFERED,
            &get,
            sizeof(get),
            &reply,
            sizeof(reply),
            &bytes_returned,
            nullptr));
        REQUIRE(namespace_completion_status == STATUS_ACCESS_DENIED);
    }

    ebpf_operation_get_namespace_reply_t after_reply = {};
    const BOOL after = usersim_device_io_control(
        device,
        IOCTL_EBPF_CTL_METHOD_BUFFERED,
        &get,
        sizeof(get),
        &after_reply,
        sizeof(after_reply),
        &bytes_returned,
        nullptr);
    const NTSTATUS after_status = namespace_completion_status;
    REQUIRE(after == before);
    if (after) {
        REQUIRE(memcmp(&after_reply.namespace_id, &before_namespace, sizeof(GUID)) == 0);
    } else {
        REQUIRE(after_status == before_status);
    }
}

TEST_CASE("namespace_NU11_usersim_management_authorized_positive_control", "[namespace][usersim][requires_admin]")
{
    namespace_process_callbacks process_callbacks;
    const auto unload = [](HMODULE value) { FreeLibrary(value); };
    std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(unload)> module(
        LoadLibraryW(L"ebpfcore_usersim.dll"), unload);
    REQUIRE(module != nullptr);
    WDFDRIVER driver = usersim_get_driver_from_module(module.get());
    REQUIRE(driver != nullptr);
    WDFDEVICE device = usersim_get_device_by_name(driver, L"\\Device\\EbpfIoDevice");
    REQUIRE(device != nullptr);
    namespace_wdf_observer observer;
    ebpf_operation_get_namespace_request_t get = {{sizeof(get), EBPF_OPERATION_GET_NAMESPACE}};
    ebpf_operation_get_namespace_reply_t reply = {};
    namespace_output_length = sizeof(reply);
    DWORD returned = 0;
    const BOOL queried = usersim_device_io_control(
        device, IOCTL_EBPF_CTL_METHOD_BUFFERED, &get, sizeof(get), &reply, sizeof(reply), &returned, nullptr);
    if (!queried && namespace_completion_status == STATUS_ACCESS_DENIED) {
        SKIP("Authorized positive control requires an elevated Administrator, SYSTEM, or ebpfsvc token; "
             "the separate restricted-subject denial test still executes.");
    }
    REQUIRE(queried);
    REQUIRE(namespace_completion_status == STATUS_SUCCESS);
    const GUID original = reply.namespace_id;
    ebpf_operation_set_namespace_request_t set = {
        {sizeof(set), EBPF_OPERATION_SET_NAMESPACE}, {0x1a4fa58d, 0xad6a, 0x42b2, {1, 2, 3, 4, 5, 6, 7, 8}}};
    namespace_output_length = 0;
    REQUIRE(usersim_device_io_control(
        device, IOCTL_EBPF_CTL_METHOD_BUFFERED, &set, sizeof(set), nullptr, 0, &returned, nullptr));
    REQUIRE(namespace_completion_status == STATUS_SUCCESS);
    namespace_output_length = sizeof(reply);
    REQUIRE(usersim_device_io_control(
        device, IOCTL_EBPF_CTL_METHOD_BUFFERED, &get, sizeof(get), &reply, sizeof(reply), &returned, nullptr));
    REQUIRE(memcmp(&reply.namespace_id, &set.namespace_id, sizeof(GUID)) == 0);
    set.namespace_id = original;
    namespace_output_length = 0;
    REQUIRE(usersim_device_io_control(
        device, IOCTL_EBPF_CTL_METHOD_BUFFERED, &set, sizeof(set), nullptr, 0, &returned, nullptr));
}

TEST_CASE("DriverEntry", "[usersim]")
{
    HMODULE module = LoadLibraryW(L"ebpfcore_usersim.dll");
    REQUIRE(module != nullptr);

    WDFDRIVER driver = usersim_get_driver_from_module(module);
    REQUIRE(driver != nullptr);

    WDFDEVICE device = usersim_get_device_by_name(driver, L"\\Device\\EbpfIoDevice");
    REQUIRE(device != nullptr);

    // Test an unrecognized IO control code.
    DWORD bytes_returned;
    BOOL ok = usersim_device_io_control(device, 0, nullptr, 0, nullptr, 0, &bytes_returned, nullptr);
    REQUIRE(!ok);

    // Unsupported input buffer size.
    ok = usersim_device_io_control(
        device, IOCTL_EBPF_CTL_METHOD_BUFFERED, nullptr, 0, nullptr, 0, &bytes_returned, nullptr);
    REQUIRE(!ok);

    // Make an actual call.
    ebpf_operation_get_next_id_request_t request;
    request.header.id = EBPF_OPERATION_GET_NEXT_PROGRAM_ID;
    request.header.length = sizeof(request);
    request.start_id = 0;
    ebpf_operation_get_next_id_reply_t reply;
    ok = usersim_device_io_control(
        device,
        IOCTL_EBPF_CTL_METHOD_BUFFERED,
        &request,
        sizeof(request),
        &reply,
        sizeof(reply),
        &bytes_returned,
        nullptr);
    REQUIRE(!ok);

    FreeLibrary(module);
}
