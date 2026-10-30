// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_EXECUTION_CONTEXT_UNIT_TESTS

#include "catch_wrapper.hpp"
#include "ebpf_core.h"
#include "ebpf_handle.h"
#include "ebpf_maps.h"
#include "ebpf_namespace.h"
#include "ebpf_protocol_validator.h"
#include "execution_context_unit_test_jit.h"
#include "helpers.h"
#include "test_helper.hpp"

#include <array>
#include <limits>
#include <vector>

static const GUID _namespace_protocol_a = {0x01234567, 0x89ab, 0xcdef, {1, 2, 3, 4, 5, 6, 7, 8}};
static const GUID _namespace_protocol_b = {0xfedcba98, 0x7654, 0x3210, {8, 7, 6, 5, 4, 3, 2, 1}};

class namespace_core_handle
{
  public:
    explicit namespace_core_handle(ebpf_handle_t value) : _value(value) {}
    namespace_core_handle(const namespace_core_handle&) = delete;
    namespace_core_handle&
    operator=(const namespace_core_handle&) = delete;
    ~namespace_core_handle() { CHECK(ebpf_handle_close(_value) == EBPF_SUCCESS); }

  private:
    ebpf_handle_t _value;
};

static ebpf_result_t
_namespace_invoke(
    const ebpf_request_context_t& context,
    const ebpf_operation_header_t* request,
    size_t input_length,
    void* reply = nullptr,
    size_t reply_length = 0)
{
    REQUIRE(input_length <= UINT16_MAX);
    REQUIRE(reply_length <= UINT16_MAX);
    return ebpf_core_invoke_protocol_handler(
        &context,
        request->id,
        request,
        static_cast<uint16_t>(input_length),
        reply,
        static_cast<uint16_t>(reply_length),
        nullptr,
        nullptr);
}

TEST_CASE("namespace_NU47_fixed_messages_and_privileged_properties", "[namespace][execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    ebpf_request_context_t context = {};
    REQUIRE(ebpf_namespace_capture_context(&context) == EBPF_SUCCESS);

    for (auto operation : {
             EBPF_OPERATION_SET_NAMESPACE,
             EBPF_OPERATION_GET_NAMESPACE,
             EBPF_OPERATION_DELETE_PINNING_IF_MATCHES,
             EBPF_OPERATION_AUTHORIZE_NATIVE_MODULE,
             EBPF_OPERATION_GET_CODE_INTEGRITY_STATE,
         }) {
        size_t request_size = 0;
        size_t reply_size = 0;
        bool async = true;
        bool privileged = false;
        REQUIRE(
            ebpf_core_get_protocol_handler_properties(operation, &request_size, &reply_size, &async, &privileged) ==
            EBPF_SUCCESS);
        REQUIRE(privileged);
        REQUIRE_FALSE(async);
        REQUIRE(request_size >= sizeof(ebpf_operation_header_t));
        if (operation == EBPF_OPERATION_GET_NAMESPACE) {
            REQUIRE(request_size == sizeof(ebpf_operation_get_namespace_request_t));
            REQUIRE(reply_size == sizeof(ebpf_operation_get_namespace_reply_t));
        }
    }

    ebpf_operation_set_namespace_request_t set_request = {
        {sizeof(set_request), EBPF_OPERATION_SET_NAMESPACE}, _namespace_protocol_a};
    REQUIRE(ebpf_protocol_validate_ioctl_message(reinterpret_cast<const uint8_t*>(&set_request), sizeof(set_request)));
    REQUIRE(_namespace_invoke(context, &set_request.header, sizeof(set_request)) == EBPF_SUCCESS);
    REQUIRE(ebpf_namespace_capture_context(&context) == EBPF_SUCCESS);
    REQUIRE(memcmp(&context.namespace_id, &_namespace_protocol_a, sizeof(GUID)) == 0);

    ebpf_operation_get_namespace_request_t get_request = {{sizeof(get_request), EBPF_OPERATION_GET_NAMESPACE}};
    ebpf_operation_get_namespace_reply_t reply = {};
    REQUIRE(
        _namespace_invoke(context, &get_request.header, sizeof(get_request), &reply, sizeof(reply)) == EBPF_SUCCESS);
    REQUIRE(reply.header.length == sizeof(reply));
    REQUIRE(reply.header.id == EBPF_OPERATION_GET_NAMESPACE);
    REQUIRE(memcmp(&reply.namespace_id, &_namespace_protocol_a, sizeof(GUID)) == 0);

    const GUID null_namespace = {};
    REQUIRE(ebpf_namespace_set_current(&null_namespace) == EBPF_SUCCESS);
}

TEST_CASE("namespace_NU47_truncation_and_header_lengths_leave_selection_unchanged", "[namespace][execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    REQUIRE(ebpf_namespace_set_current(&_namespace_protocol_a) == EBPF_SUCCESS);
    ebpf_request_context_t context = {};
    REQUIRE(ebpf_namespace_capture_context(&context) == EBPF_SUCCESS);
    ebpf_operation_set_namespace_request_t request = {
        {sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, _namespace_protocol_b};

    for (uint16_t length = 0; length < sizeof(request); length++) {
        CAPTURE(length);
        REQUIRE(
            ebpf_core_invoke_protocol_handler(
                &context, EBPF_OPERATION_SET_NAMESPACE, &request, length, nullptr, 0, nullptr, nullptr) ==
            EBPF_INVALID_ARGUMENT);
    }
    for (uint16_t length = 0; length < sizeof(request); length++) {
        CAPTURE(length);
        request.header.length = length;
        REQUIRE(_namespace_invoke(context, &request.header, sizeof(request)) == EBPF_INVALID_ARGUMENT);
    }
    request.header.length = sizeof(request) + 1;
    REQUIRE(_namespace_invoke(context, &request.header, sizeof(request)) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_namespace_capture_context(&context) == EBPF_SUCCESS);
    REQUIRE(memcmp(&context.namespace_id, &_namespace_protocol_a, sizeof(GUID)) == 0);

    ebpf_operation_get_namespace_request_t get = {{sizeof(get), EBPF_OPERATION_GET_NAMESPACE}};
    std::array<uint8_t, sizeof(ebpf_operation_get_namespace_reply_t) + 1> output = {};
    for (size_t length = 0; length < output.size(); length++) {
        if (length == sizeof(ebpf_operation_get_namespace_reply_t)) {
            continue;
        }
        CAPTURE(length);
        REQUIRE(_namespace_invoke(context, &get.header, sizeof(get), output.data(), length) == EBPF_INVALID_ARGUMENT);
    }
    REQUIRE(
        ebpf_core_invoke_protocol_handler(
            nullptr,
            EBPF_OPERATION_GET_NAMESPACE,
            &get,
            sizeof(get),
            output.data(),
            sizeof(ebpf_operation_get_namespace_reply_t),
            nullptr,
            nullptr) == EBPF_INVALID_ARGUMENT);
    for (auto id : {static_cast<ebpf_operation_id_t>(-1), static_cast<ebpf_operation_id_t>(INT32_MAX)}) {
        REQUIRE(
            ebpf_core_invoke_protocol_handler(&context, id, &get, sizeof(get), nullptr, 0, nullptr, nullptr) ==
            EBPF_OPERATION_NOT_SUPPORTED);
    }
    const GUID null_namespace = {};
    REQUIRE(ebpf_namespace_set_current(&null_namespace) == EBPF_SUCCESS);
}

TEST_CASE("namespace_NU10_NU19_request_snapshot_controls_create_and_id_discovery", "[namespace][execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    REQUIRE(ebpf_namespace_set_current(&_namespace_protocol_a) == EBPF_SUCCESS);
    ebpf_request_context_t captured = {};
    REQUIRE(ebpf_namespace_capture_context(&captured) == EBPF_SUCCESS);
    REQUIRE(ebpf_namespace_set_current(&_namespace_protocol_b) == EBPF_SUCCESS);

    std::vector<uint8_t> bytes(offsetof(ebpf_operation_create_map_request_t, data));
    auto request = reinterpret_cast<ebpf_operation_create_map_request_t*>(bytes.data());
    request->header = {static_cast<uint16_t>(bytes.size()), EBPF_OPERATION_CREATE_MAP};
    request->ebpf_map_definition = {BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 4};
    request->inner_map_handle = ebpf_handle_invalid;
    ebpf_operation_create_map_reply_t reply = {};
    REQUIRE(_namespace_invoke(captured, &request->header, bytes.size(), &reply, sizeof(reply)) == EBPF_SUCCESS);
    namespace_core_handle owned_handle(reply.handle);

    ebpf_core_object_t* object = nullptr;
    REQUIRE(EBPF_OBJECT_REFERENCE_BY_HANDLE(reply.handle, EBPF_OBJECT_MAP, &object) == EBPF_SUCCESS);
    const ebpf_id_t id = object->id;
    REQUIRE(memcmp(&object->namespace_id, &_namespace_protocol_a, sizeof(GUID)) == 0);
    EBPF_OBJECT_RELEASE_REFERENCE(object);

    ebpf_request_context_t current = {};
    REQUIRE(ebpf_namespace_capture_context(&current) == EBPF_SUCCESS);
    ebpf_operation_get_namespace_request_t get = {{sizeof(get), EBPF_OPERATION_GET_NAMESPACE}};
    ebpf_operation_get_namespace_reply_t selected = {};
    REQUIRE(_namespace_invoke(captured, &get.header, sizeof(get), &selected, sizeof(selected)) == EBPF_SUCCESS);
    REQUIRE(memcmp(&selected.namespace_id, &_namespace_protocol_a, sizeof(GUID)) == 0);
    REQUIRE(_namespace_invoke(current, &get.header, sizeof(get), &selected, sizeof(selected)) == EBPF_SUCCESS);
    REQUIRE(memcmp(&selected.namespace_id, &_namespace_protocol_b, sizeof(GUID)) == 0);
    ebpf_operation_get_handle_by_id_request_t open = {{sizeof(open), EBPF_OPERATION_GET_MAP_HANDLE_BY_ID}, id};
    ebpf_operation_get_handle_by_id_reply_t open_reply = {};
    REQUIRE(
        _namespace_invoke(current, &open.header, sizeof(open), &open_reply, sizeof(open_reply)) == EBPF_KEY_NOT_FOUND);
    REQUIRE(_namespace_invoke(captured, &open.header, sizeof(open), &open_reply, sizeof(open_reply)) == EBPF_SUCCESS);
    namespace_core_handle opened_handle(open_reply.handle);

    ebpf_operation_get_next_id_request_t next = {{sizeof(next), EBPF_OPERATION_GET_NEXT_MAP_ID}, 0};
    ebpf_operation_get_next_id_reply_t next_reply = {};
    REQUIRE(_namespace_invoke(captured, &next.header, sizeof(next), &next_reply, sizeof(next_reply)) == EBPF_SUCCESS);
    REQUIRE(next_reply.next_id == id);
    REQUIRE(
        _namespace_invoke(current, &next.header, sizeof(next), &next_reply, sizeof(next_reply)) == EBPF_NO_MORE_KEYS);
    const GUID null_namespace = {};
    REQUIRE(ebpf_namespace_set_current(&null_namespace) == EBPF_SUCCESS);
}

TEST_CASE("namespace_NU47_extended_native_load_requires_complete_module_guid", "[namespace][execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    ebpf_operation_load_native_programs_ex_request_t request = {
        {sizeof(request), EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX}, _namespace_protocol_a};
    REQUIRE(ebpf_protocol_validate_ioctl_message(reinterpret_cast<const uint8_t*>(&request), sizeof(request)));
    for (uint32_t length = 0; length < sizeof(request); length++) {
        CAPTURE(length);
        REQUIRE_FALSE(ebpf_protocol_validate_ioctl_message(reinterpret_cast<const uint8_t*>(&request), length));
    }
    size_t minimum_request = 0;
    size_t minimum_reply = 0;
    bool async = true;
    bool privileged = true;
    REQUIRE(
        ebpf_core_get_protocol_handler_properties(
            EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX, &minimum_request, &minimum_reply, &async, &privileged) ==
        EBPF_SUCCESS);
    REQUIRE(minimum_request == sizeof(request));
    REQUIRE(minimum_reply == offsetof(ebpf_operation_load_native_programs_ex_reply_t, data) + sizeof(GUID));
    REQUIRE_FALSE(async);
    REQUIRE_FALSE(privileged);
}
