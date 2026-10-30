// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "device_helper.hpp"
#include "mock.h"
#include "platform.h"
#include "test_helper.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

namespace {
const GUID namespace_a = {0x691725bc, 0xa671, 0x102, {1, 2, 3, 4, 5, 6, 7, 8}};
const GUID namespace_b = {0x38e4e2d1, 0xb567, 0xfedc, {8, 7, 6, 5, 4, 3, 2, 1}};

class namespace_fixture
{
  public:
    namespace_fixture()
    {
        helper.initialize();
        REQUIRE(ebpf_get_namespace(&original) == EBPF_SUCCESS);
    }
    ~namespace_fixture() { CHECK(ebpf_set_namespace(&original) == EBPF_SUCCESS); }

  private:
    _test_helper_libbpf helper;
    GUID original{};
};

class map_fd
{
  public:
    explicit map_fd(uint32_t marker, bpf_map_type type = BPF_MAP_TYPE_ARRAY)
    {
        fd = bpf_map_create(type, "namespace", sizeof(uint32_t), sizeof(uint32_t), 1, nullptr);
        owner.fd = fd;
        REQUIRE(fd > 0);
        uint32_t key = 0;
        REQUIRE(bpf_map_update_elem(fd, &key, &marker, BPF_ANY) == 0);
    }
    uint32_t
    read() const
    {
        uint32_t key = 0, marker = 0;
        REQUIRE(bpf_map_lookup_elem(fd, &key, &marker) == 0);
        return marker;
    }
    int fd = ebpf_fd_invalid;

  private:
    struct fd_owner
    {
        ~fd_owner()
        {
            if (fd > 0) {
                CHECK(ebpf_close_fd(fd) == EBPF_SUCCESS);
            }
        }
        int fd = ebpf_fd_invalid;
    } owner;
};

class pinned_map
{
  public:
    pinned_map(int fd, const char* path, bool insert = true) : fd(fd), path(path)
    {
        if (insert) {
            REQUIRE(ebpf_object_pin(fd, path) == EBPF_SUCCESS);
        }
    }
    ~pinned_map() { ebpf_object_unpin_if_matches_cleanup(fd, path); }
    int fd;
    const char* path;
};

class transport_override
{
  public:
    transport_override() : original(device_io_control_handler) {}
    ~transport_override() { device_io_control_handler = original; }
    std::function<decltype(DeviceIoControl)> original;
};
} // namespace

TEST_CASE("namespace_NU47_API_null_and_binary_GUID_values", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(nullptr) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_get_namespace(nullptr) == EBPF_INVALID_ARGUMENT);
    GUID value{};
    for (size_t index = 0; index < sizeof(GUID); ++index) {
        auto bytes = reinterpret_cast<uint8_t*>(&value);
        bytes[index] = static_cast<uint8_t>(0xa0 + index);
        REQUIRE(ebpf_set_namespace(&value) == EBPF_SUCCESS);
        GUID result{};
        REQUIRE(ebpf_get_namespace(&result) == EBPF_SUCCESS);
        REQUIRE(IsEqualGUID(value, result));
        map_fd map(static_cast<uint32_t>(index));
        REQUIRE(map.read() == index);
        bytes[index] = 0;
    }
}

TEST_CASE("namespace_NU07_API_termination_and_transport_reopen_preserve_process_selection", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    ebpf_api_terminate();
    clean_up_sync_device_handle();
    REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);
    GUID current{};
    REQUIRE(ebpf_get_namespace(&current) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(current, namespace_a));
    map_fd created(707);
    bpf_map_info info{};
    uint32_t length = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(created.fd, &info, &length) == 0);
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    int hidden = bpf_map_get_fd_by_id(info.id);
    if (hidden > 0) {
        CHECK(ebpf_close_fd(hidden) == EBPF_SUCCESS);
    }
    REQUIRE(hidden == -ENOENT);
    REQUIRE(created.read() == 707);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    int visible = bpf_map_get_fd_by_id(info.id);
    REQUIRE(visible > 0);
    REQUIRE(ebpf_close_fd(visible) == EBPF_SUCCESS);
}

TEST_CASE("namespace_NU44_recursive_shared_sequence_excludes_SET", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::promise<void> entered;
    std::future<ebpf_result_t> setter;
    {
        ebpf_api_namespace_guard outer;
        ebpf_api_namespace_guard inner;
        setter = std::async(std::launch::async, [&]() {
            entered.set_value();
            return ebpf_set_namespace(&namespace_b);
        });
        entered.get_future().wait();
        REQUIRE(setter.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout);
        map_fd map(44);
        pinned_map pin(map.fd, "/namespace/NU44");
        GUID current{};
        REQUIRE(ebpf_get_namespace(&current) == EBPF_SUCCESS);
        REQUIRE(IsEqualGUID(current, namespace_a));
        REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_INVALID_ARGUMENT);
        REQUIRE(map.read() == 44);
    }
    REQUIRE(setter.get() == EBPF_SUCCESS);
    GUID current{};
    REQUIRE(ebpf_get_namespace(&current) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(current, namespace_b));
}

TEST_CASE("namespace_NU45_map_cache_and_public_unpin_are_current_relative", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    map_fd a(45);
    bpf_map wrapper{};
    struct path_cleanup
    {
        ~path_cleanup() { ebpf_free(map->pin_path); }
        bpf_map* map;
    } path_owner{&wrapper};
    wrapper.map_fd = a.fd;
    wrapper.map_handle = Platform::_get_osfhandle(a.fd);
    REQUIRE(ebpf_map_pin(&wrapper, "/namespace/NU45") == EBPF_SUCCESS);
    pinned_map wrapper_pin(a.fd, "/namespace/NU45", false);
    pinned_map original(a.fd, "/namespace/NU45-owned");
    REQUIRE(bpf_map__is_pinned(&wrapper));
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    map_fd b(450);
    pinned_map replacement(b.fd, "/namespace/NU45");
    REQUIRE_FALSE(bpf_map__is_pinned(&wrapper));
    REQUIRE(ebpf_map_pin(&wrapper, "/namespace/NU45") == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_map_unpin(&wrapper, nullptr) == EBPF_SUCCESS);
    REQUIRE(a.read() == 45);
    REQUIRE(b.read() == 450);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE(bpf_map__is_pinned(&wrapper));
    REQUIRE(ebpf_map_unpin(&wrapper, nullptr) == EBPF_SUCCESS);
}

TEST_CASE("namespace_NU35_NU46_conditional_rollback_preserves_replacement_and_foreign_pin", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    map_fd original(1), replacement(2);
    pinned_map owned(original.fd, "/namespace/rollback");
    REQUIRE(ebpf_object_unpin("/namespace/rollback") == EBPF_SUCCESS);
    pinned_map replaced(replacement.fd, "/namespace/rollback");
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    map_fd foreign(3);
    pinned_map b(foreign.fd, "/namespace/rollback");
    REQUIRE(ebpf_object_unpin_if_matches(original.fd, "/namespace/rollback") == EBPF_KEY_NOT_FOUND);
    REQUIRE(ebpf_object_unpin_if_matches(replacement.fd, "/namespace/rollback") == EBPF_SUCCESS);
    int fd;
    REQUIRE(ebpf_object_get("/namespace/rollback", &fd) == EBPF_SUCCESS);
    uint32_t key = 0, value = 0;
    REQUIRE(bpf_map_lookup_elem(fd, &key, &value) == 0);
    REQUIRE(value == 3);
    REQUIRE(ebpf_close_fd(fd) == EBPF_SUCCESS);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get("/namespace/rollback", &fd) == EBPF_KEY_NOT_FOUND);
    REQUIRE(original.read() == 1);
    REQUIRE(replacement.read() == 2);
}

TEST_CASE("namespace_NU48_old_driver_is_explicit_and_legacy_maps_still_work", "[namespace][api]")
{
    namespace_fixture fixture;
    transport_override transport;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        auto header = static_cast<ebpf_operation_header_t*>(input);
        if (header && (header->id == EBPF_OPERATION_SET_NAMESPACE || header->id == EBPF_OPERATION_GET_NAMESPACE)) {
            SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    GUID unchanged = namespace_a;
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_get_namespace(&unchanged) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(IsEqualGUID(unchanged, namespace_a));
    map_fd map(48);
    REQUIRE(map.read() == 48);
    REQUIRE(ebpf_object_pin(map.fd, "/namespace/legacy") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/namespace/legacy") == EBPF_SUCCESS);
    bpf_map wrapper{};
    wrapper.map_fd = map.fd;
    wrapper.map_handle = Platform::_get_osfhandle(map.fd);
    REQUIRE(ebpf_map_pin(&wrapper, "/namespace/legacy-cache") == EBPF_SUCCESS);
    std::unique_ptr<char, decltype(&ebpf_free)> path_owner(wrapper.pin_path, ebpf_free);
    pinned_map pin_cleanup(map.fd, "/namespace/legacy-cache", false);
    REQUIRE(bpf_map__is_pinned(&wrapper));
    REQUIRE(ebpf_map_unpin(&wrapper, nullptr) == EBPF_SUCCESS);
}

TEST_CASE("namespace_NU39_reuse_propagates_every_error_except_missing", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    auto error = GENERATE(
        ERROR_ACCESS_DENIED, ERROR_NOT_ENOUGH_MEMORY, ERROR_INVALID_PARAMETER, ERROR_GEN_FAILURE, ERROR_FILE_NOT_FOUND);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(object != nullptr);
    for (auto map : object->maps) {
        map->map_definition.pinning = LIBBPF_PIN_BY_NAME;
        REQUIRE(ebpf_map_set_pin_path(map, (std::string("/namespace/NU39/") + map->name).c_str()) == EBPF_SUCCESS);
    }
    transport_override transport;
    uint32_t creates = 0;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        auto header = static_cast<ebpf_operation_header_t*>(input);
        if (header && header->id == EBPF_OPERATION_GET_PINNED_OBJECT) {
            SetLastError(error);
            return FALSE;
        }
        if (header && header->id == EBPF_OPERATION_CREATE_MAP) {
            ++creates;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    REQUIRE(ebpf_object_load(object.get()) == win32_error_code_to_ebpf_result(error));
    REQUIRE(creates == 0);
    device_io_control_handler = transport.original;
    REQUIRE(bpf_map_get_next_id(0, &creates) == -ENOENT);
}

TEST_CASE("namespace_NU47_short_GET_reply_does_not_publish_output", "[namespace][api]")
{
    namespace_fixture fixture;
    auto corruption = GENERATE(0u, 1u, 2u);
    transport_override transport;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        BOOL result = transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
        if (result && static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_GET_NAMESPACE) {
            auto reply = static_cast<ebpf_operation_get_namespace_reply_t*>(output);
            if (corruption == 0) {
                --*returned;
            } else if (corruption == 1) {
                --reply->header.length;
            } else {
                reply->header.id = EBPF_OPERATION_SET_NAMESPACE;
            }
        }
        return result;
    };
    GUID value = namespace_b;
    REQUIRE(ebpf_get_namespace(&value) == EBPF_INVALID_ARGUMENT);
    REQUIRE(IsEqualGUID(value, namespace_b));
}

TEST_CASE("namespace_NU45_link_cache_preserves_owning_namespace", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("test_sample_ebpf_um.dll"), bpf_object__close);
    REQUIRE(object != nullptr);
    REQUIRE(bpf_object__load(object.get()) == 0);
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> link(
        bpf_program__attach(bpf_object__next_program(object.get(), nullptr)), bpf_link__destroy);
    REQUIRE(link != nullptr);
    REQUIRE(bpf_link__pin(link.get(), "/namespace/NU45-link") == 0);
    pinned_map link_pin(bpf_link__fd(link.get()), "/namespace/NU45-link", false);
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    map_fd b(451);
    pinned_map replacement(b.fd, "/namespace/NU45-link");
    REQUIRE(bpf_link__pin(link.get(), "/namespace/NU45-link") == -EINVAL);
    REQUIRE(bpf_link__unpin(link.get()) == 0);
    REQUIRE(link->pin_path != nullptr);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE(bpf_link__pin(link.get(), "/namespace/NU45-link") == -EBUSY);
    REQUIRE(bpf_link__unpin(link.get()) == 0);
    REQUIRE(link->pin_path == nullptr);
}

TEST_CASE("namespace_NU46_object_pin_failure_rollback_uses_expected_object_not_current_selection", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("test_sample_ebpf_um.dll"), bpf_object__close);
    REQUIRE(object != nullptr);
    REQUIRE(bpf_object__load(object.get()) == 0);
    bpf_map* map = bpf_object__next_map(object.get(), nullptr);
    bpf_program* program = bpf_object__next_program(object.get(), nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(program != nullptr);
    std::string root = "/namespace/NU46";
    std::string map_path = root + "/" + bpf_map__name(map);
    std::string section = bpf_program__section_name(program);
    std::replace(section.begin(), section.end(), '/', '_');
    std::string program_path = root + "/" + section;
    map_fd replacement(461), collision(462);
    pinned_map original_map_cleanup(map->map_fd, map_path.c_str(), false);
    pinned_map replacement_cleanup(replacement.fd, map_path.c_str(), false);
    pinned_map existing_program_path(collision.fd, program_path.c_str());
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    map_fd b(463);
    pinned_map foreign(b.fd, map_path.c_str());
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    transport_override transport;
    bool replaced = false;
    ebpf_result_t unpinned = EBPF_FAILED, pinned = EBPF_FAILED;
    BOOL switched = FALSE;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        auto header = static_cast<ebpf_operation_header_t*>(input);
        if (header->id == EBPF_OPERATION_DELETE_PINNING_IF_MATCHES && !replaced) {
            replaced = true;
            unpinned = ebpf_object_unpin(map_path.c_str());
            pinned = ebpf_object_pin(replacement.fd, map_path.c_str());
            ebpf_operation_set_namespace_request_t request{
                {sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, namespace_b};
            DWORD ignored;
            switched = transport.original(handle, code, &request, sizeof(request), nullptr, 0, &ignored, nullptr);
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    REQUIRE(bpf_object__pin(object.get(), root.c_str()) == -EEXIST);
    REQUIRE(replaced);
    REQUIRE(unpinned == EBPF_SUCCESS);
    REQUIRE(pinned == EBPF_SUCCESS);
    REQUIRE(switched);
    device_io_control_handler = transport.original;
    int opened;
    REQUIRE(ebpf_object_get(map_path.c_str(), &opened) == EBPF_SUCCESS);
    uint32_t key = 0, marker = 0;
    REQUIRE(bpf_map_lookup_elem(opened, &key, &marker) == 0);
    REQUIRE(marker == 463);
    REQUIRE(ebpf_close_fd(opened) == EBPF_SUCCESS);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get(map_path.c_str(), &opened) == EBPF_SUCCESS);
    REQUIRE(bpf_map_lookup_elem(opened, &key, &marker) == 0);
    REQUIRE(marker == 461);
    REQUIRE(ebpf_close_fd(opened) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin_if_matches(replacement.fd, map_path.c_str()) == EBPF_SUCCESS);
}

TEST_CASE("namespace_NU39_missing_pin_is_the_only_create_fallback", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(object != nullptr);
    for (auto map : object->maps) {
        map->map_definition.pinning = LIBBPF_PIN_BY_NAME;
        REQUIRE(
            ebpf_map_set_pin_path(map, (std::string("/namespace/NU39-missing/") + map->name).c_str()) == EBPF_SUCCESS);
    }
    transport_override transport;
    uint32_t lookups = 0, creates = 0;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        auto header = static_cast<ebpf_operation_header_t*>(input);
        if (header->id == EBPF_OPERATION_GET_PINNED_OBJECT) {
            ++lookups;
            SetLastError(ERROR_NOT_FOUND);
            return FALSE;
        }
        if (header->id == EBPF_OPERATION_CREATE_MAP) {
            ++creates;
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    REQUIRE(ebpf_object_load(object.get()) == EBPF_NO_MEMORY);
    REQUIRE(lookups == 1);
    REQUIRE(creates == 1);
}

TEST_CASE("namespace_NU46_failed_program_load_removes_only_new_auto_pins", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(object != nullptr);
    std::vector<std::string> paths;
    for (auto map : object->maps) {
        map->map_definition.pinning = LIBBPF_PIN_BY_NAME;
        paths.push_back(std::string("/namespace/NU46-load/") + map->name);
        REQUIRE(ebpf_map_set_pin_path(map, paths.back().c_str()) == EBPF_SUCCESS);
    }
    transport_override transport;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        if (static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_CREATE_PROGRAM) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
#if defined(CONFIG_BPF_JIT_DISABLED) && defined(CONFIG_BPF_INTERPRETER_DISABLED)
    REQUIRE(ebpf_object_load(object.get()) == EBPF_OPERATION_NOT_SUPPORTED);
#else
    REQUIRE(ebpf_object_load(object.get()) == EBPF_NO_MEMORY);
#endif
    device_io_control_handler = transport.original;
    for (auto& path : paths) {
        int fd;
        REQUIRE(ebpf_object_get(path.c_str(), &fd) == EBPF_KEY_NOT_FOUND);
    }
    uint32_t id;
    REQUIRE(bpf_map_get_next_id(0, &id) == -ENOENT);
}

TEST_CASE("namespace_NU37_NU40_native_template_ownership_and_loaded_object_state", "[namespace][api][native]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("map_reuse_um.dll"), bpf_object__close);
    REQUIRE(object != nullptr);
    REQUIRE(bpf_object__load(object.get()) == 0);
    int port = bpf_object__find_map_fd_by_name(object.get(), "port_map");
    int outer = bpf_object__find_map_fd_by_name(object.get(), "outer_map");
    REQUIRE(port > 0);
    REQUIRE(outer > 0);
    pinned_map port_cleanup(port, "/ebpf/global/port_map", false);
    pinned_map outer_cleanup(outer, "/ebpf/global/outer_map", false);
    bpf_map_info outer_info{};
    uint32_t size = sizeof(outer_info);
    REQUIRE(bpf_obj_get_info_by_fd(outer, &outer_info, &size) == 0);
    REQUIRE(outer_info.inner_map_id != 0);
    int template_fd = bpf_map_get_fd_by_id(outer_info.inner_map_id);
    REQUIRE(template_fd > 0);
    REQUIRE(ebpf_close_fd(template_fd) == EBPF_SUCCESS);
    uint32_t key = 0, marker = 3740;
    REQUIRE(bpf_map_update_elem(port, &key, &marker, BPF_ANY) == 0);
    bpf_program* program = bpf_object__next_program(object.get(), nullptr);
    REQUIRE(program != nullptr);
    bpf_prog_info program_info{};
    size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_program__fd(program), &program_info, &size) == 0);
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    REQUIRE(bpf_object__load(object.get()) == -EINVAL);
    REQUIRE(bpf_map_get_fd_by_id(outer_info.id) == -ENOENT);
    REQUIRE(bpf_map_get_fd_by_id(outer_info.inner_map_id) == -ENOENT);
    REQUIRE(bpf_prog_get_fd_by_id(program_info.id) == -ENOENT);
    REQUIRE(bpf_map_lookup_elem(port, &key, &marker) == 0);
    REQUIRE(marker == 3740);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    int found = bpf_obj_get("/ebpf/global/port_map");
    REQUIRE(found > 0);
    REQUIRE(bpf_map_lookup_elem(found, &key, &marker) == 0);
    REQUIRE(marker == 3740);
    REQUIRE(ebpf_close_fd(found) == EBPF_SUCCESS);
}

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("namespace_NU41_RPC_load_uses_client_objects_not_service_current_namespace", "[namespace][api]")
{
    namespace_fixture fixture;
    GUID service = namespace_a;
    service.Data1 ^= UINT32_MAX;
    transport_override transport;
    uint32_t code_loads = 0;
    bool service_set_succeeded = true;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        if (static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_LOAD_CODE) {
            ++code_loads;
            ebpf_operation_set_namespace_request_t request{{sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, service};
            DWORD ignored = 0;
            service_set_succeeded &=
                transport.original(handle, code, &request, sizeof(request), nullptr, 0, &ignored, nullptr) != FALSE;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    for (const GUID* client : {&namespace_a, &namespace_b}) {
        REQUIRE(ebpf_set_namespace(client) == EBPF_SUCCESS);
        std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
            bpf_object__open("test_sample_ebpf.o"), bpf_object__close);
        REQUIRE(object != nullptr);
        REQUIRE(bpf_object__load(object.get()) == 0);
        REQUIRE(service_set_succeeded);
        bpf_program* program = bpf_object__next_program(object.get(), nullptr);
        REQUIRE(program != nullptr);
        bpf_prog_info info{};
        uint32_t length = sizeof(info);
        REQUIRE(bpf_obj_get_info_by_fd(bpf_program__fd(program), &info, &length) == 0);
        GUID current{};
        REQUIRE(ebpf_get_namespace(&current) == EBPF_SUCCESS);
        REQUIRE(IsEqualGUID(current, service));
        REQUIRE(bpf_prog_get_fd_by_id(info.id) == -ENOENT);
        REQUIRE(ebpf_set_namespace(client) == EBPF_SUCCESS);
        int opened = bpf_prog_get_fd_by_id(info.id);
        REQUIRE(opened > 0);
        REQUIRE(ebpf_close_fd(opened) == EBPF_SUCCESS);
    }
    REQUIRE(code_loads == 2);
}

TEST_CASE("namespace_NU38_compatible_reuse_is_namespace_local_and_mismatch_is_not_missing", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> a(bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(a != nullptr);
    REQUIRE(bpf_object__load(a.get()) == 0);
    int a_port = bpf_object__find_map_fd_by_name(a.get(), "port_map");
    int a_outer = bpf_object__find_map_fd_by_name(a.get(), "outer_map");
    REQUIRE(a_port > 0);
    REQUIRE(a_outer > 0);
    pinned_map a_port_pin(a_port, "/ebpf/global/port_map", false);
    pinned_map a_outer_pin(a_outer, "/ebpf/global/outer_map", false);
    uint32_t key = 0, marker = 381;
    REQUIRE(bpf_map_update_elem(a_port, &key, &marker, BPF_ANY) == 0);
    bpf_map_info expected{};
    uint32_t length = sizeof(expected);
    REQUIRE(bpf_obj_get_info_by_fd(a_port, &expected, &length) == 0);
    {
        std::unique_ptr<bpf_object, decltype(&bpf_object__close)> reused(
            bpf_object__open("map_reuse.o"), bpf_object__close);
        REQUIRE(reused != nullptr);
        REQUIRE(bpf_object__load(reused.get()) == 0);
        bpf_map_info info{};
        length = sizeof(info);
        REQUIRE(bpf_obj_get_info_by_fd(bpf_object__find_map_fd_by_name(reused.get(), "port_map"), &info, &length) == 0);
        REQUIRE(info.id == expected.id);
    }
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> b(bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(b != nullptr);
    REQUIRE(bpf_object__load(b.get()) == 0);
    int b_port = bpf_object__find_map_fd_by_name(b.get(), "port_map");
    int b_outer = bpf_object__find_map_fd_by_name(b.get(), "outer_map");
    REQUIRE(b_port > 0);
    REQUIRE(b_outer > 0);
    pinned_map b_port_pin(b_port, "/ebpf/global/port_map", false);
    pinned_map b_outer_pin(b_outer, "/ebpf/global/outer_map", false);
    bpf_map_info foreign{};
    length = sizeof(foreign);
    REQUIRE(bpf_obj_get_info_by_fd(b_port, &foreign, &length) == 0);
    REQUIRE(foreign.id != expected.id);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
    map_fd incompatible(383, BPF_MAP_TYPE_HASH);
    pinned_map incompatible_pin(incompatible.fd, "/ebpf/global/port_map");
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> rejected(
        bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(rejected != nullptr);
    REQUIRE(bpf_object__load(rejected.get()) == -EINVAL);
    REQUIRE(incompatible.read() == 383);
    REQUIRE(bpf_map_lookup_elem(a_port, &key, &marker) == 0);
    REQUIRE(marker == 381);
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    REQUIRE(bpf_map_lookup_elem(b_port, &key, &marker) == 0);
    REQUIRE(marker == 0);
}
#endif

TEST_CASE("namespace_NU49_pending_subscription_survives_switch_and_drains_once", "[namespace][api]")
{
    namespace_fixture fixture;
    bool complete = GENERATE(false, true);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    int fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "namespace_async", 0, 0, 65536, nullptr);
    REQUIRE(fd > 0);
    struct fd_cleanup
    {
        ~fd_cleanup() { CHECK(ebpf_close_fd(fd) == EBPF_SUCCESS); }
        int fd;
    } close_guard{fd};
    std::promise<uint32_t> received;
    auto result = received.get_future();
    std::atomic<uint32_t> callbacks = 0;
    struct callback_context
    {
        std::promise<uint32_t>* received;
        std::atomic<uint32_t>* callbacks;
    } context{&received, &callbacks};
    ebpf_ring_buffer_opts opts{.sz = sizeof(opts), .flags = EBPF_RINGBUF_FLAG_AUTO_CALLBACK};
#pragma warning(suppress : 4996)
    ring_buffer* ring = ebpf_ring_buffer__new(
        fd,
        [](void* callback, void* data, size_t size) -> int {
            auto state = static_cast<callback_context*>(callback);
            if (state->callbacks->fetch_add(1) == 0) {
                uint32_t marker = 0;
                if (size == sizeof(marker)) {
                    memcpy(&marker, data, size);
                }
                state->received->set_value(marker);
            }
            return 0;
        },
        &context,
        &opts);
    REQUIRE(ring != nullptr);
    std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> ring_owner(ring, ring_buffer__free);
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    if (complete) {
        ebpf_protocol_buffer_t buffer(offsetof(ebpf_operation_map_write_data_request_t, data) + sizeof(uint32_t));
        auto write = reinterpret_cast<ebpf_operation_map_write_data_request_t*>(buffer.data());
        write->header = {static_cast<uint16_t>(buffer.size()), EBPF_OPERATION_MAP_WRITE_DATA};
        write->map_handle = Platform::_get_osfhandle(fd);
        uint32_t marker = 4901;
        memcpy(write->data, &marker, sizeof(marker));
        REQUIRE(invoke_ioctl(buffer) == ERROR_SUCCESS);
        REQUIRE(result.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        REQUIRE(result.get() == marker);
    }
    ring_owner.reset();
    REQUIRE(callbacks == (complete ? 1u : 0u));
    clean_up_async_device_handle();
    clean_up_sync_device_handle();
    GUID current{};
    REQUIRE(ebpf_get_namespace(&current) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(current, namespace_b));
}

TEST_CASE("namespace_NU46_each_API_map_create_and_pin_failure_cleans_prior_work", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    auto operation = GENERATE(EBPF_OPERATION_CREATE_MAP, EBPF_OPERATION_UPDATE_PINNING);
    auto occurrence = GENERATE(1u, 2u, 3u);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(object != nullptr);
    std::vector<std::string> paths;
    for (auto map : object->maps) {
        map->map_definition.pinning = LIBBPF_PIN_BY_NAME;
        paths.push_back(std::string("/namespace/NU46-phase/") + map->name);
        REQUIRE(ebpf_map_set_pin_path(map, paths.back().c_str()) == EBPF_SUCCESS);
    }
    transport_override transport;
    uint32_t seen = 0;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        auto header = static_cast<ebpf_operation_header_t*>(input);
        if (header->id == operation && ++seen == occurrence) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    REQUIRE(ebpf_object_load(object.get()) == EBPF_NO_MEMORY);
    REQUIRE(seen == occurrence);
    device_io_control_handler = transport.original;
    for (auto& path : paths) {
        int fd;
        REQUIRE(ebpf_object_get(path.c_str(), &fd) == EBPF_KEY_NOT_FOUND);
    }
    uint32_t id;
    REQUIRE(bpf_map_get_next_id(0, &id) == -ENOENT);
    map_fd recovered(466);
    pinned_map retry(recovered.fd, paths.front().c_str());
    REQUIRE(recovered.read() == 466);
}

TEST_CASE("namespace_NU46_each_API_fd_wrap_failure_releases_handles_and_pins", "[namespace][api]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
#if defined(CONFIG_BPF_JIT_DISABLED) && defined(CONFIG_BPF_INTERPRETER_DISABLED)
    auto fail_at = GENERATE(1u, 2u, 3u);
#else
    auto fail_at = GENERATE(1u, 2u, 3u, 4u);
#endif
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(object != nullptr);
    std::vector<std::string> paths;
    for (auto map : object->maps) {
        map->map_definition.pinning = LIBBPF_PIN_BY_NAME;
        paths.push_back(std::string("/namespace/NU46-fd/") + map->name);
        REQUIRE(ebpf_map_set_pin_path(map, paths.back().c_str()) == EBPF_SUCCESS);
    }
    struct descriptor_override
    {
        std::function<decltype(_open_osfhandle)> original = open_osfhandle_handler;
        ~descriptor_override() { open_osfhandle_handler = original; }
    } descriptors;
    uint32_t wrapped = 0;
    open_osfhandle_handler = [&](intptr_t handle, int flags) -> int {
        if (++wrapped == fail_at) {
            errno = EMFILE;
            return ebpf_fd_invalid;
        }
        return descriptors.original(handle, flags);
    };
    REQUIRE(ebpf_object_load(object.get()) == EBPF_NO_MEMORY);
    open_osfhandle_handler = descriptors.original;
    REQUIRE(wrapped == fail_at);
    for (auto& path : paths) {
        int fd;
        REQUIRE(ebpf_object_get(path.c_str(), &fd) == EBPF_KEY_NOT_FOUND);
    }
    uint32_t id;
    REQUIRE(bpf_map_get_next_id(0, &id) == -ENOENT);
    map_fd recovered(467);
    REQUIRE(recovered.read() == 467);
}

TEST_CASE("namespace_NU46_API_link_creation_failure_is_retryable", "[namespace][api][native]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("test_sample_ebpf_um.dll"), bpf_object__close);
    REQUIRE(object != nullptr);
    REQUIRE(bpf_object__load(object.get()) == 0);
    bpf_program* program = bpf_object__next_program(object.get(), nullptr);
    REQUIRE(program != nullptr);
    transport_override transport;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        if (static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_LINK_PROGRAM) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    REQUIRE(bpf_program__attach(program) == nullptr);
    REQUIRE(errno == ENOMEM);
    device_io_control_handler = transport.original;
    uint32_t id;
    REQUIRE(bpf_link_get_next_id(0, &id) == -ENOENT);
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> retried(bpf_program__attach(program), bpf_link__destroy);
    REQUIRE(retried != nullptr);
}

TEST_CASE(
    "namespace_NU40_native_module_repeated_load_preserves_existing_state_and_namespace", "[namespace][api][native]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    transport_override transport;
    ebpf_operation_load_native_programs_request_t captured{};
    bool saw_load = false;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        if (static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_LOAD_NATIVE_PROGRAMS ||
            static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX) {
            captured = *static_cast<ebpf_operation_load_native_programs_request_t*>(input);
            saw_load = true;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("test_sample_ebpf_um.dll"), bpf_object__close);
    REQUIRE(object != nullptr);
    REQUIRE(bpf_object__load(object.get()) == 0);
    REQUIRE(saw_load);
    device_io_control_handler = transport.original;
    bpf_program* program = bpf_object__next_program(object.get(), nullptr);
    REQUIRE(program != nullptr);
    bpf_prog_info before{};
    uint32_t length = sizeof(before);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_program__fd(program), &before, &length) == 0);
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    ebpf_protocol_buffer_t reply(4096);
    REQUIRE(invoke_ioctl(captured, reply) == ERROR_OBJECT_ALREADY_EXISTS);
    REQUIRE(bpf_prog_get_fd_by_id(before.id) == -ENOENT);
    bpf_prog_info after{};
    length = sizeof(after);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_program__fd(program), &after, &length) == 0);
    REQUIRE(after.id == before.id);
    REQUIRE(after.nr_map_ids == before.nr_map_ids);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    int opened = bpf_prog_get_fd_by_id(before.id);
    REQUIRE(opened > 0);
    REQUIRE(ebpf_close_fd(opened) == EBPF_SUCCESS);
}

namespace {
void
native_fd_wrap_rollback(uint32_t fail_at, bool by_fds, bool metadata_failure = false)
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    map_fd reused(4601);
    pinned_map reused_pin(reused.fd, "/ebpf/global/port_map");
    bpf_map_info before{};
    uint32_t length = sizeof(before);
    REQUIRE(bpf_obj_get_info_by_fd(reused.fd, &before, &length) == 0);
    REQUIRE(ebpf_set_namespace(&namespace_b) == EBPF_SUCCESS);
    map_fd foreign(4602);
    pinned_map foreign_pin(foreign.fd, "/ebpf/global/outer_map");
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        by_fds ? nullptr : bpf_object__open("map_reuse_um.dll"), bpf_object__close);
    if (!by_fds) {
        REQUIRE(object != nullptr);
    }
    struct descriptor_override
    {
        std::function<decltype(_open_osfhandle)> original = open_osfhandle_handler;
        ~descriptor_override() { open_osfhandle_handler = original; }
    } descriptors;
    uint32_t wraps = 0;
    bool failed = false, switched = false;
    auto fail = [&]() {
        failed = true;
        ebpf_operation_set_namespace_request_t request{{sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, namespace_b};
        switched = invoke_ioctl(request) == ERROR_SUCCESS;
    };
    transport_override transport;
    uint32_t queries = 0;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        if (metadata_failure && static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_GET_OBJECT_INFO &&
            ++queries == fail_at) {
            fail();
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    open_osfhandle_handler = [&](intptr_t handle, int flags) -> int {
        if (++wraps == fail_at && !metadata_failure) {
            fail();
            errno = EMFILE;
            return ebpf_fd_invalid;
        }
        return descriptors.original(handle, flags);
    };
    if (by_fds) {
        std::array<fd_t, 3> maps{ebpf_fd_invalid, ebpf_fd_invalid, ebpf_fd_invalid};
        std::array<fd_t, 1> programs{ebpf_fd_invalid};
        size_t map_count = maps.size(), program_count = programs.size();
        REQUIRE(
            ebpf_object_load_native_by_fds(
                "map_reuse_um.dll", &map_count, maps.data(), &program_count, programs.data()) == EBPF_NO_MEMORY);
        REQUIRE(std::all_of(maps.begin(), maps.end(), [](fd_t fd) { return fd == ebpf_fd_invalid; }));
        REQUIRE(programs.front() == ebpf_fd_invalid);
    } else {
        REQUIRE(ebpf_object_load(object.get()) == EBPF_NO_MEMORY);
    }
    open_osfhandle_handler = descriptors.original;
    device_io_control_handler = transport.original;
    REQUIRE(failed);
    REQUIRE(switched);
    GUID selected{};
    REQUIRE(ebpf_get_namespace(&selected) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(selected, namespace_b));
    int opened;
    REQUIRE(ebpf_object_get("/ebpf/global/outer_map", &opened) == EBPF_SUCCESS);
    uint32_t key = 0, marker = 0;
    REQUIRE(bpf_map_lookup_elem(opened, &key, &marker) == 0);
    REQUIRE(marker == 4602);
    REQUIRE(ebpf_close_fd(opened) == EBPF_SUCCESS);
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get("/ebpf/global/outer_map", &opened) == EBPF_KEY_NOT_FOUND);
    REQUIRE(ebpf_object_get("/ebpf/global/port_map", &opened) == EBPF_SUCCESS);
    bpf_map_info after{};
    length = sizeof(after);
    REQUIRE(bpf_obj_get_info_by_fd(opened, &after, &length) == 0);
    REQUIRE(after.id == before.id);
    REQUIRE(bpf_map_lookup_elem(opened, &key, &marker) == 0);
    REQUIRE(marker == 4601);
    REQUIRE(ebpf_close_fd(opened) == EBPF_SUCCESS);
}
} // namespace

TEST_CASE("namespace_NU46_native_object_each_fd_wrap_rolls_back_only_created_pins", "[namespace][api][native]")
{
    native_fd_wrap_rollback(GENERATE(1u, 2u, 3u, 4u, 5u), false);
}

TEST_CASE("namespace_NU46_native_by_fds_each_fd_wrap_rolls_back_only_created_pins", "[namespace][api][native]")
{
    native_fd_wrap_rollback(GENERATE(1u, 2u, 3u, 4u), true);
}

TEST_CASE("namespace_NU46_native_each_metadata_query_failure_rolls_back_only_created_pins", "[namespace][api][native]")
{
    native_fd_wrap_rollback(GENERATE(1u, 2u, 3u, 4u), false, true);
}

TEST_CASE("namespace_NU48_native_EX_falls_back_only_for_not_supported", "[namespace][api][native]")
{
    namespace_fixture fixture;
    DWORD query_error = GENERATE(ERROR_SUCCESS, ERROR_NOT_SUPPORTED, ERROR_ACCESS_DENIED);
    GUID expected_namespace = query_error == ERROR_NOT_SUPPORTED ? GUID{} : namespace_a;
    REQUIRE(ebpf_set_namespace(&expected_namespace) == EBPF_SUCCESS);
    DWORD error = GENERATE(ERROR_NOT_SUPPORTED, ERROR_ACCESS_DENIED);
    transport_override transport;
    uint32_t extended = 0, legacy = 0, queries = 0;
    bool legacy_header_reproduced = false;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        auto header = static_cast<ebpf_operation_header_t*>(input);
        if (header->id == EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX) {
            ++extended;
            SetLastError(error);
            return FALSE;
        }
        if (header->id == EBPF_OPERATION_GET_NAMESPACE) {
            ++queries;
            if (query_error != ERROR_SUCCESS) {
                SetLastError(query_error);
                return FALSE;
            }
        }
        if (header->id == EBPF_OPERATION_LOAD_NATIVE_PROGRAMS) {
            ++legacy;
            BOOL result =
                transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
            if (result) {
                static_cast<ebpf_operation_load_native_programs_reply_t*>(output)->header.length =
                    sizeof(ebpf_operation_load_native_programs_request_t);
                legacy_header_reproduced = true;
            }
            return result;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("map_reuse_um.dll"), bpf_object__close);
    REQUIRE(object != nullptr);
    bool fallback = error == ERROR_NOT_SUPPORTED && query_error == ERROR_NOT_SUPPORTED;
    ebpf_result_t expected = fallback ? EBPF_SUCCESS
                                      : ((error == ERROR_ACCESS_DENIED || query_error == ERROR_ACCESS_DENIED)
                                             ? EBPF_ACCESS_DENIED
                                             : EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_object_load(object.get()) == expected);
    REQUIRE(extended == 1);
    REQUIRE(queries == (error == ERROR_NOT_SUPPORTED ? 1u : 0u));
    REQUIRE(legacy == (fallback ? 1u : 0u));
    REQUIRE(legacy_header_reproduced == fallback);
    device_io_control_handler = transport.original;
    GUID actual{};
    REQUIRE(ebpf_get_namespace(&actual) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(actual, expected_namespace));
    if (fallback) {
        int port = bpf_object__find_map_fd_by_name(object.get(), "port_map");
        int outer = bpf_object__find_map_fd_by_name(object.get(), "outer_map");
        REQUIRE(port > 0);
        REQUIRE(outer > 0);
        pinned_map port_cleanup(port, "/ebpf/global/port_map", false);
        pinned_map outer_cleanup(outer, "/ebpf/global/outer_map", false);
    }
}

TEST_CASE("namespace_NU37_native_pin_cache_uses_captured_reply_GUID_after_raw_SET", "[namespace][api][native]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    transport_override transport;
    bool switched = false, set_succeeded = false;
    device_io_control_handler = [&](HANDLE handle,
                                    DWORD code,
                                    LPVOID input,
                                    DWORD input_size,
                                    LPVOID output,
                                    DWORD output_size,
                                    LPDWORD returned,
                                    LPOVERLAPPED overlapped) -> BOOL {
        if (static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX && !switched) {
            switched = true;
            ebpf_operation_set_namespace_request_t request{
                {sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, namespace_b};
            DWORD ignored = 0;
            set_succeeded =
                transport.original(handle, code, &request, sizeof(request), nullptr, 0, &ignored, nullptr) != FALSE;
        }
        return transport.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open("map_reuse_um.dll"), bpf_object__close);
    REQUIRE(object != nullptr);
    REQUIRE(ebpf_object_load(object.get()) == EBPF_SUCCESS);
    REQUIRE(switched);
    REQUIRE(set_succeeded);
    device_io_control_handler = transport.original;
    bpf_map* port = bpf_object__find_map_by_name(object.get(), "port_map");
    bpf_map* outer = bpf_object__find_map_by_name(object.get(), "outer_map");
    REQUIRE(port != nullptr);
    REQUIRE(outer != nullptr);
    REQUIRE(strcmp(bpf_map__name(port), "port_map") == 0);
    REQUIRE(strcmp(bpf_map__name(outer), "outer_map") == 0);
    REQUIRE(bpf_map__fd(port) > 0);
    REQUIRE(bpf_map__fd(outer) > 0);
    pinned_map port_cleanup(port->map_fd, "/ebpf/global/port_map", false);
    pinned_map outer_cleanup(outer->map_fd, "/ebpf/global/outer_map", false);
    REQUIRE(IsEqualGUID(port->pinned_namespace, namespace_b));
    REQUIRE(bpf_map__is_pinned(port));
    REQUIRE(ebpf_set_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE_FALSE(bpf_map__is_pinned(port));
    int missing;
    REQUIRE(ebpf_object_get("/ebpf/global/port_map", &missing) == EBPF_KEY_NOT_FOUND);
    uint32_t key = 0, marker = 3701;
    REQUIRE(bpf_map_update_elem(port->map_fd, &key, &marker, BPF_ANY) == 0);
    REQUIRE(bpf_map_lookup_elem(port->map_fd, &key, &marker) == 0);
    REQUIRE(marker == 3701);
}
