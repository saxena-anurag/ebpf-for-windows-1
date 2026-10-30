// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "..\socket\socket_tests_common.h"
#include "api_test.h"
#include "bpf/bpf.h"
#include "ebpf_protocol.h"
#include "namespace_tests.h"
#include "sample_ext_helpers.h"
#include "socket_helper.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <fcntl.h>
#include <future>
#include <io.h>
#include <memory>
#include <new>
#include <random>
#include <set>
#include <thread>
#include <utility>
#include <winioctl.h>

namespace {
constexpr DWORD namespace_ioctl = CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr wchar_t device_name[] = L"\\\\.\\EbpfIoDevice";
const GUID null_namespace{};

struct unique_handle
{
    explicit unique_handle(HANDLE value = nullptr) : value(value) {}
    unique_handle(const unique_handle&) = delete;
    unique_handle&
    operator=(const unique_handle&) = delete;
    ~unique_handle()
    {
        if (value && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
    HANDLE value;
};

struct unique_fd
{
    explicit unique_fd(int value = ebpf_fd_invalid) : value(value) {}
    unique_fd(const unique_fd&) = delete;
    unique_fd&
    operator=(const unique_fd&) = delete;
    unique_fd(unique_fd&& other) noexcept : value(std::exchange(other.value, ebpf_fd_invalid)) {}
    unique_fd&
    operator=(unique_fd&& other) noexcept
    {
        if (this != &other) {
            if (value > 0) {
                CHECK(ebpf_close_fd(value) == EBPF_SUCCESS);
            }
            value = std::exchange(other.value, ebpf_fd_invalid);
        }
        return *this;
    }
    ~unique_fd()
    {
        if (value > 0) {
            CHECK(ebpf_close_fd(value) == EBPF_SUCCESS);
        }
    }
    int value = ebpf_fd_invalid;
};

GUID
new_namespace()
{
    static std::atomic<uint16_t> counter{0};
    GUID value{};
    value.Data1 = GetCurrentProcessId();
    value.Data2 = ++counter;
    value.Data3 = 0xb79a;
    uint64_t tick = GetTickCount64();
    memcpy(value.Data4, &tick, sizeof(tick));
    return value;
}

std::string
guid_bytes(const GUID& guid)
{
    const auto bytes = reinterpret_cast<const uint8_t*>(&guid);
    std::string text;
    constexpr char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(guid); ++i) {
        text += hex[bytes[i] >> 4];
        text += hex[bytes[i] & 15];
    }
    return text;
}

GUID
parse_guid_bytes(const char* text)
{
    if (strlen(text) != sizeof(GUID) * 2) {
        throw std::runtime_error("Invalid child GUID");
    }
    GUID guid;
    auto bytes = reinterpret_cast<uint8_t*>(&guid);
    for (size_t i = 0; i < sizeof(guid); ++i) {
        char byte[] = {text[i * 2], text[i * 2 + 1], 0};
        char* end;
        bytes[i] = static_cast<uint8_t>(strtoul(byte, &end, 16));
        if (*end != 0) {
            throw std::runtime_error("Invalid child GUID byte");
        }
    }
    return guid;
}

std::string
new_path()
{
    return "/namespace/" + guid_bytes(new_namespace());
}

DWORD
raw_ioctl(HANDLE device, void* input, DWORD input_size, void* output = nullptr, DWORD output_size = 0)
{
    DWORD returned = 0;
    return DeviceIoControl(device, namespace_ioctl, input, input_size, output, output_size, &returned, nullptr)
               ? ERROR_SUCCESS
               : GetLastError();
}

DWORD
raw_get(HANDLE device, GUID& value)
{
    ebpf_operation_get_namespace_request_t request{{sizeof(request), EBPF_OPERATION_GET_NAMESPACE}};
    ebpf_operation_get_namespace_reply_t reply{};
    DWORD result = raw_ioctl(device, &request, sizeof(request), &reply, sizeof(reply));
    if (result == ERROR_SUCCESS) {
        if (reply.header.id != EBPF_OPERATION_GET_NAMESPACE || reply.header.length != sizeof(reply)) {
            return ERROR_INVALID_DATA;
        }
        value = reply.namespace_id;
    }
    return result;
}

DWORD
raw_set(HANDLE device, const GUID& value)
{
    ebpf_operation_set_namespace_request_t request{{sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, value};
    return raw_ioctl(device, &request, sizeof(request));
}

DWORD
raw_detach_by_context(HANDLE device, fd_t program_fd, const ebpf_attach_type_t& attach_type, uint32_t compartment)
{
    alignas(ebpf_operation_unlink_program_request_t)
        std::array<uint8_t, sizeof(ebpf_operation_unlink_program_request_t) + sizeof(compartment)>
            buffer{};
    auto request = reinterpret_cast<ebpf_operation_unlink_program_request_t*>(buffer.data());
    request->header = {
        static_cast<uint16_t>(offsetof(ebpf_operation_unlink_program_request_t, data) + sizeof(compartment)),
        EBPF_OPERATION_UNLINK_PROGRAM};
    request->link_handle = ebpf_handle_invalid;
    request->program_handle = program_fd == ebpf_fd_invalid ? ebpf_handle_invalid : _get_osfhandle(program_fd);
    request->attach_type = attach_type;
    request->attach_data_present = true;
    memcpy(request->data, &compartment, sizeof(compartment));
    return raw_ioctl(device, buffer.data(), request->header.length);
}

DWORD
conditional_unpin(HANDLE device, HANDLE expected, const std::string& path)
{
    char canonical[EBPF_MAX_PIN_PATH_LENGTH];
    if (ebpf_canonicalize_pin_path(canonical, sizeof(canonical), path.c_str()) != EBPF_SUCCESS) {
        return ERROR_INVALID_PARAMETER;
    }
    size_t length = strlen(canonical);
    std::vector<uint8_t> buffer(offsetof(ebpf_operation_delete_pinning_if_matches_request_t, path) + length);
    auto request = reinterpret_cast<ebpf_operation_delete_pinning_if_matches_request_t*>(buffer.data());
    request->header = {static_cast<uint16_t>(buffer.size()), EBPF_OPERATION_DELETE_PINNING_IF_MATCHES};
    request->handle = reinterpret_cast<ebpf_handle_t>(expected);
    memcpy(request->path, canonical, length);
    return raw_ioctl(device, buffer.data(), static_cast<DWORD>(buffer.size()));
}

class child_pin_cleanup
{
  public:
    explicit child_pin_cleanup(HANDLE device) : device(device) {}
    ~child_pin_cleanup()
    {
        for (auto& [selected, path] : owned) {
            if (ebpf_set_namespace(&selected) != EBPF_SUCCESS) {
                CHECK(false);
                continue;
            }
            int fd = bpf_obj_get(path.c_str());
            if (fd > 0) {
                DWORD result = conditional_unpin(device, reinterpret_cast<HANDLE>(_get_osfhandle(fd)), path);
                CHECK((result == ERROR_SUCCESS || result == ERROR_NOT_FOUND));
                CHECK(ebpf_close_fd(fd) == EBPF_SUCCESS);
            } else {
                CHECK(fd == -ENOENT);
            }
        }
    }
    HANDLE device;
    std::vector<std::pair<GUID, std::string>> owned;
};

template <typename Info>
void
verify_raw_open(HANDLE device, ebpf_operation_id_t operation, uint32_t id, bool visible)
{
    ebpf_operation_get_handle_by_id_request_t request{{sizeof(request), operation}, id};
    ebpf_operation_get_handle_by_id_reply_t reply{};
    DWORD result = raw_ioctl(device, &request, sizeof(request), &reply, sizeof(reply));
    if (!visible) {
        unique_handle unexpected(result == ERROR_SUCCESS ? reinterpret_cast<HANDLE>(reply.handle) : nullptr);
        REQUIRE(result == ERROR_NOT_FOUND);
        return;
    }
    REQUIRE(result == ERROR_SUCCESS);
    unique_handle handle(reinterpret_cast<HANDLE>(reply.handle));
    REQUIRE(reply.header.id == operation);
    REQUIRE(reply.header.length == sizeof(reply));
    unique_fd fd;
    fd.value = _open_osfhandle(reply.handle, _O_BINARY);
    if (fd.value > 0) {
        handle.value = nullptr;
    }
    REQUIRE(fd.value > 0);
    Info info{};
    uint32_t length = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(fd.value, &info, &length) == 0);
    REQUIRE(info.id == id);
}

void
verify_raw_next(HANDLE device, ebpf_operation_id_t operation, uint32_t previous, uint32_t expected)
{
    ebpf_operation_get_next_id_request_t request{{sizeof(request), operation}, previous};
    ebpf_operation_get_next_id_reply_t reply{};
    REQUIRE(raw_ioctl(device, &request, sizeof(request), &reply, sizeof(reply)) == ERROR_SUCCESS);
    REQUIRE(reply.header.id == operation);
    REQUIRE(reply.header.length == sizeof(reply));
    REQUIRE(reply.next_id == expected);
}

void
verify_deprecated_program_path(HANDLE device, const std::string& expected)
{
    ebpf_operation_header_t request{sizeof(request), EBPF_OPERATION_GET_NEXT_PINNED_PROGRAM_PATH};
    std::vector<uint8_t> buffer(
        offsetof(ebpf_operation_get_next_pinned_program_path_reply_t, next_path) + EBPF_MAX_PIN_PATH_LENGTH);
    REQUIRE(
        raw_ioctl(device, &request, sizeof(request), buffer.data(), static_cast<DWORD>(buffer.size())) ==
        ERROR_SUCCESS);
    auto reply = reinterpret_cast<ebpf_operation_get_next_pinned_program_path_reply_t*>(buffer.data());
    REQUIRE(reply->header.id == EBPF_OPERATION_GET_NEXT_PINNED_PROGRAM_PATH);
    REQUIRE(reply->header.length >= offsetof(ebpf_operation_get_next_pinned_program_path_reply_t, next_path));
    std::string actual(
        reinterpret_cast<char*>(reply->next_path),
        reply->header.length - offsetof(ebpf_operation_get_next_pinned_program_path_reply_t, next_path));
    char canonical[EBPF_MAX_PIN_PATH_LENGTH];
    REQUIRE(ebpf_canonicalize_pin_path(canonical, sizeof(canonical), expected.c_str()) == EBPF_SUCCESS);
    REQUIRE(actual == canonical);
    ebpf_operation_header_t small{};
    REQUIRE(raw_ioctl(device, &request, sizeof(request), &small, sizeof(small)) == ERROR_MORE_DATA);
}

class namespace_scope
{
  public:
    namespace_scope()
    {
        REQUIRE(ebpf_get_namespace(&restore.saved) == EBPF_SUCCESS);
        restore.active = true;
        REQUIRE(ebpf_set_namespace(&a) == EBPF_SUCCESS);
        REQUIRE(device.value != INVALID_HANDLE_VALUE);
        GUID raw{};
        REQUIRE(raw_get(device.value, raw) == ERROR_SUCCESS);
        REQUIRE(IsEqualGUID(raw, a)); // Proves the tests reach the installed device, not a mock.
    }
    GUID a = new_namespace(), b = new_namespace();
    unique_handle device{CreateFileW(device_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr)};

  private:
    struct restore_selection
    {
        ~restore_selection()
        {
            if (active) {
                CHECK(ebpf_set_namespace(&saved) == EBPF_SUCCESS);
            }
        }
        GUID saved{};
        bool active = false;
    } restore;
};

class test_map
{
  public:
    explicit test_map(uint32_t marker, bpf_map_type type = BPF_MAP_TYPE_ARRAY)
    {
        fd = bpf_map_create(type, "namespace_test", 4, 4, 1, nullptr);
        owner.value = fd;
        REQUIRE(fd > 0);
        uint32_t key = 0;
        REQUIRE(bpf_map_update_elem(fd, &key, &marker, BPF_ANY) == 0);
        bpf_map_info info{};
        uint32_t length = sizeof(info);
        REQUIRE(bpf_obj_get_info_by_fd(fd, &info, &length) == 0);
        id = info.id;
    }
    int fd = ebpf_fd_invalid;
    uint32_t id{};
    unique_fd owner;
};

uint32_t
read_marker(int fd)
{
    uint32_t key = 0, value = 0;
    REQUIRE(bpf_map_lookup_elem(fd, &key, &value) == 0);
    return value;
}

class test_pin
{
  public:
    test_pin(HANDLE device, int fd, std::string path, bool insert = true) : device(device), path(std::move(path))
    {
        REQUIRE(DuplicateHandle(
            GetCurrentProcess(),
            reinterpret_cast<HANDLE>(_get_osfhandle(fd)),
            GetCurrentProcess(),
            &expected.value,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS));
        if (insert) {
            REQUIRE(bpf_obj_pin(fd, this->path.c_str()) == 0);
        }
    }
    ~test_pin()
    {
        DWORD result = conditional_unpin(device, expected.value, path);
        CHECK((result == ERROR_SUCCESS || result == ERROR_NOT_FOUND));
    }
    HANDLE device;
    unique_handle expected;
    std::string path;
};

void
verify_pin(const std::string& path, uint32_t id, uint32_t marker)
{
    int fd = bpf_obj_get(path.c_str());
    REQUIRE(fd > 0);
    bpf_map_info info{};
    uint32_t length = sizeof(info);
    CHECK(bpf_obj_get_info_by_fd(fd, &info, &length) == 0);
    CHECK(info.id == id);
    CHECK(read_marker(fd) == marker);
    REQUIRE(ebpf_close_fd(fd) == EBPF_SUCCESS);
}

std::set<uint32_t>
visible_map_ids()
{
    std::set<uint32_t> ids;
    uint32_t id = 0, next = 0;
    while (bpf_map_get_next_id(id, &next) == 0) {
        REQUIRE(next > id);
        ids.insert(next);
        id = next;
    }
    REQUIRE(errno == ENOENT);
    return ids;
}

unique_handle*
duplicate_inheritable(HANDLE handle)
{
    auto result = std::make_unique<unique_handle>();
    REQUIRE(DuplicateHandle(
        GetCurrentProcess(), handle, GetCurrentProcess(), &result->value, 0, TRUE, DUPLICATE_SAME_ACCESS));
    return result.release();
}

class child_process
{
  public:
    child_process(std::string arguments, std::vector<HANDLE> inherited, HANDLE token = nullptr)
    {
        wchar_t executable[MAX_PATH];
        REQUIRE(GetModuleFileNameW(nullptr, executable, MAX_PATH) != 0);
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --namespace-child ";
        command.append(arguments.begin(), arguments.end());
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        std::vector<uint8_t> buffer(bytes);
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
        REQUIRE(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes));
        BOOL updated = UpdateProcThreadAttribute(
            startup.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited.data(),
            inherited.size() * sizeof(HANDLE),
            nullptr,
            nullptr);
        BOOL created = FALSE;
        if (updated) {
            if (token) {
                created = CreateProcessAsUserW(
                    token,
                    executable,
                    command.data(),
                    nullptr,
                    nullptr,
                    TRUE,
                    EXTENDED_STARTUPINFO_PRESENT,
                    nullptr,
                    nullptr,
                    &startup.StartupInfo,
                    &process);
            } else {
                created = CreateProcessW(
                    executable,
                    command.data(),
                    nullptr,
                    nullptr,
                    TRUE,
                    EXTENDED_STARTUPINFO_PRESENT,
                    nullptr,
                    nullptr,
                    &startup.StartupInfo,
                    &process);
            }
        }
        DWORD error = GetLastError();
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        INFO("CreateProcess error " << error);
        REQUIRE(updated);
        REQUIRE(created);
    }
    ~child_process()
    {
        if (process.hProcess) {
            if (WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
                CHECK(TerminateProcess(process.hProcess, 199));
                CHECK(WaitForSingleObject(process.hProcess, 30000) == WAIT_OBJECT_0);
            }
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }
    DWORD
    wait()
    {
        REQUIRE(WaitForSingleObject(process.hProcess, 30000) == WAIT_OBJECT_0);
        DWORD result;
        REQUIRE(GetExitCodeProcess(process.hProcess, &result));
        return result;
    }
    PROCESS_INFORMATION process{};
};

std::string
number(HANDLE handle)
{
    return std::to_string(reinterpret_cast<uintptr_t>(handle));
}

void
child_check(bool condition, const char* description)
{
    if (!condition) {
        fprintf(stderr, "Namespace child: %s (Win32=%lu, errno=%d)\n", description, GetLastError(), errno);
        throw std::runtime_error(description);
    }
}

constexpr size_t inventory_capacity = 4096;
constexpr size_t inventory_rounds = 2;
using next_id_function = int (*)(uint32_t, uint32_t*);
using open_id_function = int (*)(uint32_t);

struct object_inventory
{
    std::array<uint32_t, 3> count{};
    std::array<std::array<uint32_t, inventory_capacity>, 3> ids{};
};

struct inventory_channel
{
    HANDLE map_gate;
    HANDLE program_gate;
    HANDLE release_gate;
    object_inventory baseline;
    object_inventory owned;
    std::array<uint32_t, 3> pinned_ids;
    uint32_t rounds_completed;
};

void
append_inventory(object_inventory& inventory, size_t type, uint32_t id)
{
    child_check(id != 0 && inventory.count[type] < inventory_capacity, "inventory capacity and nonzero ID");
    auto end = inventory.ids[type].begin() + inventory.count[type];
    child_check(std::find(inventory.ids[type].begin(), end, id) == end, "inventory objects have distinct live IDs");
    inventory.ids[type][inventory.count[type]++] = id;
}

void
capture_inventory(object_inventory& inventory)
{
    const std::array<next_id_function, 3> functions{bpf_map_get_next_id, bpf_prog_get_next_id, bpf_link_get_next_id};
    for (size_t type = 0; type < functions.size(); ++type) {
        inventory.count[type] = 0;
        uint32_t cursor = 0, next = 0;
        int result;
        while ((result = functions[type](cursor, &next)) == 0) {
            child_check(next > cursor, "inventory enumeration is strictly increasing");
            append_inventory(inventory, type, next);
            cursor = next;
        }
        child_check(result == -ENOENT, "inventory exact enumeration end");
    }
}

template <typename Info>
uint32_t
child_object_id(int fd)
{
    Info info{};
    uint32_t size = sizeof(info);
    child_check(fd > 0 && bpf_obj_get_info_by_fd(fd, &info, &size) == 0, "inventory actual object metadata");
    return info.id;
}

std::string
inventory_file(DWORD process_id, const GUID& selected, size_t round, const std::string& cohort)
{
    auto separator = cohort.find_last_of("/\\");
    std::string suffix = separator == std::string::npos ? cohort : cohort.substr(separator + 1);
    return "namespace-inventory-" + std::to_string(process_id) + "-" + guid_bytes(selected) + "-" +
           std::to_string(round) + "-" + suffix + ".sys";
}

struct inventory_module
{
    std::string file;
    bool copied = false;
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object{nullptr, bpf_object__close};
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> link{nullptr, bpf_link__destroy};
    ~inventory_module()
    {
        link.reset();
        object.reset();
        if (copied) {
            DeleteFileA(file.c_str());
        }
    }
};

void
inventory_child(HANDLE control, HANDLE mapping, HANDLE ready, const GUID& selected, const char* path, uint32_t marker)
{
    auto shared =
        static_cast<inventory_channel*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(inventory_channel)));
    child_check(shared != nullptr, "inventory shared channel");
    struct unmap
    {
        ~unmap() { UnmapViewOfFile(address); }
        void* address;
    } view{shared};
    child_check(ebpf_set_namespace(&selected) == EBPF_SUCCESS, "inventory child selection");
    capture_inventory(shared->baseline);
    child_check(SetEvent(ready), "inventory baseline ready");
    child_check(WaitForSingleObject(shared->map_gate, 30000) == WAIT_OBJECT_0, "inventory map barrier");
    struct map_owner
    {
        int fd = ebpf_fd_invalid;
        ~map_owner()
        {
            if (fd > 0) {
                (void)ebpf_close_fd(fd);
            }
        }
    } map;
    std::vector<std::unique_ptr<inventory_module>> modules;
    modules.reserve(inventory_rounds);
    struct pins_owner
    {
        HANDLE control;
        std::vector<std::pair<HANDLE, std::string>> entries;
        ~pins_owner()
        {
            for (auto& [expected, pin_path] : entries) {
                DWORD result = conditional_unpin(control, expected, pin_path);
                if (result != ERROR_SUCCESS && result != ERROR_NOT_FOUND) {
                    fprintf(stderr, "Inventory child conditional cleanup failed: %lu\n", result);
                }
            }
        }
    } pins{control, {}};
    pins.entries.reserve(3);
    map.fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "inventory_marker", 4, 4, 1, nullptr);
    child_check(map.fd > 0, "inventory marker map");
    uint32_t key = 0;
    child_check(bpf_map_update_elem(map.fd, &key, &marker, BPF_ANY) == 0, "inventory distinct marker");
    append_inventory(shared->owned, 0, child_object_id<bpf_map_info>(map.fd));
    child_check(SetEvent(ready), "inventory marker ready");
    for (size_t round = 0; round < inventory_rounds; ++round) {
        child_check(WaitForSingleObject(shared->program_gate, 30000) == WAIT_OBJECT_0, "inventory program barrier");
        modules.push_back(std::make_unique<inventory_module>());
        auto module = modules.back().get();
        module->file = inventory_file(GetCurrentProcessId(), selected, round, path);
        child_check(
            CopyFileA("cgroup_sock_addr.sys", module->file.c_str(), TRUE), "inventory independent native image");
        module->copied = true;
        module->object.reset(bpf_object__open(module->file.c_str()));
        child_check(module->object != nullptr && bpf_object__load(module->object.get()) == 0, "inventory native load");
        bpf_map* native_map;
        bpf_object__for_each_map(native_map, module->object.get())
        {
            append_inventory(shared->owned, 0, child_object_id<bpf_map_info>(bpf_map__fd(native_map)));
        }
        bpf_program* program;
        bpf_object__for_each_program(program, module->object.get())
        {
            append_inventory(shared->owned, 1, child_object_id<bpf_prog_info>(bpf_program__fd(program)));
        }
        program = bpf_object__find_program_by_name(module->object.get(), "authorize_connect4");
        child_check(program != nullptr && bpf_program__fd(program) > 0, "inventory attachable program");
        uint32_t compartment = 0;
        bpf_link* link = nullptr;
        child_check(
            ebpf_program_attach_by_fd(
                bpf_program__fd(program),
                &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
                &compartment,
                sizeof(compartment),
                &link) == EBPF_SUCCESS,
            "inventory multi-attach link");
        module->link.reset(link);
        append_inventory(shared->owned, 2, child_object_id<bpf_link_info>(bpf_link__fd(link)));
        if (round == 0) {
            const std::array<int, 3> fds{map.fd, bpf_program__fd(program), bpf_link__fd(link)};
            shared->pinned_ids = {
                child_object_id<bpf_map_info>(fds[0]),
                child_object_id<bpf_prog_info>(fds[1]),
                child_object_id<bpf_link_info>(fds[2])};
            const std::array<const char*, 3> suffixes{"-map", "-program", "-link"};
            for (size_t type = 0; type < fds.size(); ++type) {
                std::string pin_path = std::string(path) + suffixes[type];
                child_check(bpf_obj_pin(fds[type], pin_path.c_str()) == 0, "inventory triplet pin");
                pins.entries.emplace_back(reinterpret_cast<HANDLE>(_get_osfhandle(fds[type])), std::move(pin_path));
            }
        }
        shared->rounds_completed = static_cast<uint32_t>(round + 1);
        child_check(SetEvent(ready), "inventory native round ready");
    }
    child_check(WaitForSingleObject(shared->release_gate, 120000) == WAIT_OBJECT_0, "inventory release barrier");
}

struct inventory_worker
{
    unique_handle mapping, ready, map_gate, program_gate, release_gate;
    inventory_channel* view = nullptr;
    std::unique_ptr<child_process> process;
    ~inventory_worker()
    {
        process.reset();
        if (view) {
            UnmapViewOfFile(view);
        }
    }
};

std::set<uint32_t>
inventory_ids(const object_inventory& inventory, size_t type)
{
    REQUIRE(inventory.count[type] <= inventory_capacity);
    return {inventory.ids[type].begin(), inventory.ids[type].begin() + inventory.count[type]};
}

template <typename Info>
void
verify_worker_inventory(
    HANDLE device,
    const std::vector<std::unique_ptr<inventory_worker>>& workers,
    size_t selected,
    size_t type,
    open_id_function open_id,
    next_id_function next_id,
    ebpf_operation_id_t raw_open_operation,
    ebpf_operation_id_t raw_next_operation)
{
    auto expected = inventory_ids(workers[selected]->view->baseline, type);
    auto owned = inventory_ids(workers[selected]->view->owned, type);
    expected.insert(owned.begin(), owned.end());
    std::set<uint32_t> observed;
    uint32_t previous = 0, current = 0;
    int enumeration_result;
    while ((enumeration_result = next_id(previous, &current)) == 0) {
        REQUIRE(current > previous);
        observed.insert(current);
        previous = current;
    }
    REQUIRE(enumeration_result == -ENOENT);
    REQUIRE(observed == expected);
    for (uint32_t id : owned) {
        unique_fd fd(open_id(id));
        REQUIRE(fd.value > 0);
        Info info{};
        uint32_t size = sizeof(info);
        REQUIRE(bpf_obj_get_info_by_fd(fd.value, &info, &size) == 0);
        REQUIRE(info.id == id);
        verify_raw_open<Info>(device, raw_open_operation, id, true);
    }
    std::set<uint32_t> cursors{0, UINT32_MAX};
    for (size_t other = 0; other < workers.size(); ++other) {
        if (other == selected) {
            continue;
        }
        for (uint32_t id : inventory_ids(workers[other]->view->owned, type)) {
            int result = open_id(id);
            unique_fd unexpected(result > 0 ? result : ebpf_fd_invalid);
            REQUIRE(result == -ENOENT);
            verify_raw_open<Info>(device, raw_open_operation, id, false);
            cursors.insert(id);
        }
    }
    int absent = open_id(0);
    unique_fd unexpected(absent > 0 ? absent : ebpf_fd_invalid);
    REQUIRE(absent == -ENOENT);
    verify_raw_open<Info>(device, raw_open_operation, 0, false);
    for (uint32_t cursor : cursors) {
        auto expected_next = expected.upper_bound(cursor);
        uint32_t id = 0;
        ebpf_operation_get_next_id_request_t request{{sizeof(request), raw_next_operation}, cursor};
        ebpf_operation_get_next_id_reply_t reply{};
        DWORD result = raw_ioctl(device, &request, sizeof(request), &reply, sizeof(reply));
        if (expected_next == expected.end()) {
            REQUIRE(next_id(cursor, &id) == -ENOENT);
            REQUIRE(result == ERROR_NO_MORE_MATCHES);
        } else {
            REQUIRE(next_id(cursor, &id) == 0);
            REQUIRE(id == *expected_next);
            REQUIRE(result == ERROR_SUCCESS);
            REQUIRE(reply.header.id == raw_next_operation);
            REQUIRE(reply.header.length == sizeof(reply));
            REQUIRE(reply.next_id == *expected_next);
        }
    }
}

unique_handle*
restricted_token()
{
    unique_handle original;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &original.value));
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    REQUIRE(AllocateAndInitializeSid(
        &authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators));
    SID_AND_ATTRIBUTES disabled{administrators, 0};
    auto token = std::make_unique<unique_handle>();
    BOOL created = CreateRestrictedToken(
        original.value, DISABLE_MAX_PRIVILEGE, 1, &disabled, 0, nullptr, 0, nullptr, &token->value);
    FreeSid(administrators);
    REQUIRE(created);
    return token.release();
}
} // namespace

int
namespace_test_child(int argc, char** argv)
{
    if (argc < 2 || strcmp(argv[1], "--namespace-child") != 0) {
        return -1;
    }
    try {
        child_check(argc == 10, "child argument count");
        const std::string mode = argv[2];
        HANDLE control = reinterpret_cast<HANDLE>(strtoull(argv[3], nullptr, 10));
        HANDLE object = reinterpret_cast<HANDLE>(strtoull(argv[4], nullptr, 10));
        GUID selected = parse_guid_bytes(argv[5]);
        const char* path = argv[6];
        uint32_t id = strtoul(argv[7], nullptr, 10);
        uint32_t marker = strtoul(argv[8], nullptr, 10);
        HANDLE signal = reinterpret_cast<HANDLE>(strtoull(argv[9], nullptr, 10));
        if (mode == "low") {
            unique_handle direct(
                CreateFileW(device_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
            child_check(direct.value == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "device DACL");
            GUID result{};
            child_check(raw_set(control, selected) == ERROR_ACCESS_DENIED, "duplicated control SET denied");
            child_check(raw_get(control, result) == ERROR_ACCESS_DENIED, "duplicated control GET denied");
            return 0;
        }
        if (mode == "legacy") {
            // Deliberately no SET or GET before this old-API workflow.
            int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "legacy_namespace", 4, 4, 1, nullptr);
            child_check(fd > 0, "legacy create");
            uint32_t key = 0;
            child_check(bpf_map_update_elem(fd, &key, &marker, BPF_ANY) == 0, "legacy update");
            child_check(bpf_obj_pin(fd, path) == 0, "legacy pin");
            int opened = bpf_obj_get(path);
            child_check(opened > 0, "legacy get pin");
            uint32_t value = 0;
            child_check(bpf_map_lookup_elem(opened, &key, &value) == 0 && value == marker, "legacy pin marker");
            child_check(ebpf_close_fd(opened) == EBPF_SUCCESS, "legacy close");
            std::unique_ptr<bpf_object, decltype(&bpf_object__close)> programs(
                bpf_object__open("test_sample_ebpf.sys"), bpf_object__close);
            child_check(programs != nullptr && bpf_object__load(programs.get()) == 0, "legacy native program load");
            bpf_program* program = bpf_object__next_program(programs.get(), nullptr);
            child_check(program != nullptr, "legacy program");
            std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> link(
                bpf_program__attach(program), bpf_link__destroy);
            child_check(link != nullptr, "legacy link attach");
            std::string program_path = std::string(path) + "-program";
            std::string link_path = std::string(path) + "-link";
            child_check(bpf_program__pin(program, program_path.c_str()) == 0, "legacy program pin");
            child_check(bpf_link__pin(link.get(), link_path.c_str()) == 0, "legacy link pin");
            bpf_prog_info program_info{};
            bpf_link_info link_info{};
            uint32_t size = sizeof(program_info);
            child_check(
                bpf_obj_get_info_by_fd(bpf_program__fd(program), &program_info, &size) == 0, "legacy program metadata");
            size = sizeof(link_info);
            child_check(
                bpf_obj_get_info_by_fd(bpf_link__fd(link.get()), &link_info, &size) == 0, "legacy link metadata");
            int found_program = bpf_prog_get_fd_by_id(program_info.id);
            int found_link = bpf_link_get_fd_by_id(link_info.id);
            child_check(found_program > 0 && found_link > 0, "legacy ID opens");
            child_check(ebpf_close_fd(found_program) == EBPF_SUCCESS, "legacy program close");
            child_check(ebpf_close_fd(found_link) == EBPF_SUCCESS, "legacy link close");
            child_check(bpf_program__unpin(program, program_path.c_str()) == 0, "legacy program unpin");
            child_check(bpf_link__unpin(link.get()) == 0, "legacy link unpin");
            child_check(ebpf_object_unpin(path) == EBPF_SUCCESS, "legacy unpin");
            child_check(ebpf_close_fd(fd) == EBPF_SUCCESS, "legacy final close");
        }
        GUID initial{};
        child_check(
            raw_get(control, initial) == ERROR_SUCCESS && IsEqualGUID(initial, null_namespace), "fresh process null");
        if (mode == "legacy" || mode == "fresh") {
            return 0;
        }
        if (mode == "inventory") {
            inventory_child(control, object, signal, selected, path, marker);
            return 0;
        }
        if (mode == "pin-exit" || mode == "pin-wait") {
            child_check(ebpf_set_namespace(&selected) == EBPF_SUCCESS, "creator SET");
            int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "exit_namespace", 4, 4, 1, nullptr);
            child_check(fd > 0, "creator map");
            uint32_t key = 0;
            child_check(bpf_map_update_elem(fd, &key, &marker, BPF_ANY) == 0, "creator marker");
            child_check(bpf_obj_pin(fd, path) == 0, "creator pin");
            if (mode == "pin-wait") {
                child_check(SetEvent(signal), "creator ready");
                unique_handle never(CreateEventW(nullptr, TRUE, FALSE, nullptr));
                child_check(never.value != nullptr, "creator wait event");
                child_check(WaitForSingleObject(never.value, INFINITE) == WAIT_OBJECT_0, "creator wait");
            }
            child_check(ebpf_close_fd(fd) == EBPF_SUCCESS, "creator close");
            return 0;
        }
        if (mode == "async-exit") {
            child_check(ebpf_set_namespace(&selected) == EBPF_SUCCESS, "async creator SET");
            int fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "exit_ring", 0, 0, 65536, nullptr);
            child_check(fd > 0, "async creator ring");
            child_check(bpf_obj_pin(fd, path) == 0, "async creator pin");
            unique_handle asynchronous(CreateFileW(
                device_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, nullptr));
            unique_handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            OVERLAPPED overlapped{};
            overlapped.hEvent = event.value;
            ebpf_operation_map_async_query_request_t request{
                {sizeof(request), EBPF_OPERATION_MAP_ASYNC_QUERY}, _get_osfhandle(fd), 0, 0};
            ebpf_operation_map_async_query_reply_t reply{};
            DWORD returned = 0;
            BOOL completed = DeviceIoControl(
                asynchronous.value,
                namespace_ioctl,
                &request,
                sizeof(request),
                &reply,
                sizeof(reply),
                &returned,
                &overlapped);
            child_check(!completed && GetLastError() == ERROR_IO_PENDING, "async creator pending");
            child_check(SetEvent(signal), "async creator ready");
            unique_handle never(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            child_check(never.value != nullptr, "async creator wait event");
            WaitForSingleObject(never.value, INFINITE);
            return 249;
        }
        if (mode == "load") {
            child_check(ebpf_set_namespace(&selected) == EBPF_SUCCESS, "RPC client SET");
            child_check(SetEvent(signal), "RPC client ready");
            child_check(WaitForSingleObject(object, 30000) == WAIT_OBJECT_0, "RPC concurrent start");
            std::unique_ptr<bpf_object, decltype(&bpf_object__close)> program(
                bpf_object__open("map_reuse.o"), bpf_object__close);
            child_check(program != nullptr, "RPC client open");
            child_check(
                ebpf_object_set_execution_type(program.get(), static_cast<ebpf_execution_type_t>(id)) == EBPF_SUCCESS,
                "RPC explicit execution mode");
            int loaded = bpf_object__load(program.get());
            if (loaded == -ENOTSUP) {
                return 42;
            }
#if !defined(CONFIG_BPF_JIT_DISABLED)
            if (loaded == -EOTHER && id == EBPF_EXECUTION_JIT) {
                ebpf_operation_get_code_integrity_state_request_t query{
                    {sizeof(query), EBPF_OPERATION_GET_CODE_INTEGRITY_STATE}};
                ebpf_operation_get_code_integrity_state_reply_t state{};
                child_check(
                    raw_ioctl(control, &query, sizeof(query), &state, sizeof(state)) == ERROR_SUCCESS &&
                        state.hypervisor_code_integrity_enabled,
                    "JIT generic libbpf error requires actual HVCI policy evidence");
                ebpf_operation_get_ec_function_request_t policy{
                    {sizeof(policy), EBPF_OPERATION_GET_EC_FUNCTION}, EBPF_EC_FUNCTION_LOG};
                ebpf_operation_get_ec_function_reply_t policy_reply{};
                child_check(
                    raw_ioctl(control, &policy, sizeof(policy), &policy_reply, sizeof(policy_reply)) ==
                        ERROR_CONTENT_BLOCKED,
                    "JIT-only request returns the exact blocked-by-policy error");
                return 41;
            }
#endif
            child_check(loaded == 0, "RPC concurrent load");
            int port = bpf_object__find_map_fd_by_name(program.get(), "port_map");
            int outer = bpf_object__find_map_fd_by_name(program.get(), "outer_map");
            int inner = bpf_object__find_map_fd_by_name(program.get(), "inner_map");
            child_check(port > 0 && outer > 0 && inner > 0, "RPC graph map handles");
            uint32_t key = 0;
            child_check(bpf_map_update_elem(inner, &key, &marker, BPF_ANY) == 0, "RPC inner marker");
            child_check(bpf_map_update_elem(outer, &key, &inner, BPF_ANY) == 0, "RPC same-client graph");
            bpf_program* entry = bpf_object__next_program(program.get(), nullptr);
            child_check(entry != nullptr, "RPC program");
            sample_program_context_t context{};
            bpf_test_run_opts run{};
            run.sz = sizeof(run);
            run.ctx_in = &context;
            run.ctx_size_in = sizeof(context);
            run.ctx_out = &context;
            run.ctx_size_out = sizeof(context);
            run.repeat = 1;
            child_check(bpf_prog_test_run_opts(bpf_program__fd(entry), &run) == 0, "RPC execute bound graph");
            child_check(run.retval == marker, "RPC never binds another client's map");
            int pinned = bpf_obj_get("/ebpf/global/port_map");
            child_check(pinned > 0, "RPC own pin");
            uint32_t value = 0;
            child_check(bpf_map_lookup_elem(pinned, &key, &value) == 0 && value == marker, "RPC own result marker");
            child_check(ebpf_close_fd(pinned) == EBPF_SUCCESS, "RPC pin close");
            child_check(
                conditional_unpin(control, reinterpret_cast<HANDLE>(_get_osfhandle(port)), "/ebpf/global/port_map") ==
                    ERROR_SUCCESS,
                "RPC port cleanup");
            child_check(
                conditional_unpin(control, reinterpret_cast<HANDLE>(_get_osfhandle(outer)), "/ebpf/global/outer_map") ==
                    ERROR_SUCCESS,
                "RPC outer cleanup");
            return 0;
        }
        if (mode == "stress") {
            child_check(ebpf_set_namespace(&selected) == EBPF_SUCCESS, "stress SET");
            child_check(SetEvent(signal), "stress ready");
            child_check(WaitForSingleObject(object, 30000) == WAIT_OBJECT_0, "stress start");
            int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "stress_namespace", 4, 4, 1, nullptr);
            child_check(fd > 0, "stress create");
            uint32_t key = 0;
            child_check(bpf_map_update_elem(fd, &key, &marker, BPF_ANY) == 0, "stress marker");
            std::minstd_rand random(id);
            for (unsigned step = 0; step < 128; ++step) {
                std::string pin_path = std::string(path) + "-" + std::to_string(random() % 4);
                switch (random() % 4) {
                case 0: {
                    int result = bpf_obj_pin(fd, pin_path.c_str());
                    child_check(result == 0 || result == -EEXIST, "stress insert exact result");
                    break;
                }
                case 1: {
                    int opened = bpf_obj_get(pin_path.c_str());
                    if (opened >= 0) {
                        uint32_t actual = 0;
                        child_check(
                            bpf_map_lookup_elem(opened, &key, &actual) == 0 && actual == marker,
                            "stress never reads foreign marker");
                        child_check(ebpf_close_fd(opened) == EBPF_SUCCESS, "stress close");
                    } else {
                        child_check(opened == -ENOENT, "stress lookup exact missing");
                    }
                    break;
                }
                case 2: {
                    ebpf_result_t result = ebpf_object_unpin(pin_path.c_str());
                    child_check(result == EBPF_SUCCESS || result == EBPF_KEY_NOT_FOUND, "stress unpin exact result");
                    break;
                }
                case 3: {
                    ebpf_object_type_t type = EBPF_OBJECT_MAP;
                    char next[EBPF_MAX_PIN_PATH_LENGTH]{};
                    ebpf_result_t result = ebpf_get_next_pinned_object_path("", next, sizeof(next), &type);
                    if (result == EBPF_SUCCESS) {
                        char expected[EBPF_MAX_PIN_PATH_LENGTH]{};
                        child_check(
                            ebpf_canonicalize_pin_path(expected, sizeof(expected), path) == EBPF_SUCCESS,
                            "stress canonical prefix");
                        child_check(
                            strncmp(next, expected, strlen(expected)) == 0 && type == EBPF_OBJECT_MAP,
                            "stress enumeration never discloses foreign path");
                    } else {
                        child_check(result == EBPF_NO_MORE_KEYS, "stress enumeration exact end");
                    }
                    break;
                }
                }
                if (step % 13 == 0) {
                    unique_handle reopened(
                        CreateFileW(device_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
                    GUID current{};
                    child_check(
                        raw_get(reopened.value, current) == ERROR_SUCCESS && IsEqualGUID(current, selected),
                        "stress reopen preserves process namespace");
                }
            }
            for (unsigned index = 0; index < 4; ++index) {
                std::string pin_path = std::string(path) + "-" + std::to_string(index);
                ebpf_result_t result = ebpf_object_unpin(pin_path.c_str());
                child_check(result == EBPF_SUCCESS || result == EBPF_KEY_NOT_FOUND, "stress cleanup");
            }
            child_check(ebpf_close_fd(fd) == EBPF_SUCCESS, "stress final close");
            return 0;
        }
        if (mode == "delegate-remote") {
            child_check(WaitForSingleObject(signal, 30000) == WAIT_OBJECT_0, "remote duplication published");
            const auto shared =
                static_cast<const uintptr_t*>(MapViewOfFile(object, FILE_MAP_READ, 0, 0, sizeof(uintptr_t)));
            child_check(shared != nullptr, "remote HANDLE channel");
            object = reinterpret_cast<HANDLE>(*shared);
            UnmapViewOfFile(shared);
        }
        int default_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "child_default", 4, 4, 1, nullptr);
        child_check(default_fd > 0, "child creates in default before its own SET");
        bpf_map_info default_info{};
        uint32_t default_size = sizeof(default_info);
        child_check(
            bpf_obj_get_info_by_fd(default_fd, &default_info, &default_size) == 0, "child default object identity");
        GUID other = selected;
        ++other.Data1;
        child_check(raw_set(control, other) == ERROR_SUCCESS, "child SET distinct namespace");
        child_check(bpf_map_get_fd_by_id(default_info.id) == -ENOENT, "child default object is not rehomed");
        child_check(ebpf_close_fd(default_fd) == EBPF_SUCCESS, "child default close");
        int fd = _open_osfhandle(reinterpret_cast<intptr_t>(object), _O_BINARY);
        child_check(fd > 0, "adopt inherited object handle");
        uint32_t key = 0, value = 0;
        child_check(bpf_map_lookup_elem(fd, &key, &value) == 0 && value == marker, "delegated handle remains useful");
        child_check(bpf_map_get_fd_by_id(id) == -ENOENT, "foreign ID is missing");
        child_check(bpf_obj_get(path) == -ENOENT, "foreign path is missing");
        child_check(bpf_obj_pin(fd, path) == -EINVAL, "foreign handle cannot be repinned");
        child_check(ebpf_set_namespace(&selected) == EBPF_SUCCESS, "join parent's GUID");
        int opened = bpf_obj_get(path);
        child_check(opened > 0, "same GUID resolves parent pin");
        bpf_map_info info{};
        uint32_t length = sizeof(info);
        child_check(bpf_obj_get_info_by_fd(opened, &info, &length) == 0 && info.id == id, "same GUID object identity");
        child_check(ebpf_close_fd(opened) == EBPF_SUCCESS, "close pin");
        child_check(ebpf_close_fd(fd) == EBPF_SUCCESS, "close delegated handle");
        return 0;
    } catch (const std::exception& error) {
        fprintf(stderr, "%s\n", error.what());
        return 250;
    }
}

TEST_CASE("namespace_ND01_fresh_legacy_API_process", "[namespace][driver]")
{
    namespace_scope scope;
    std::unique_ptr<unique_handle> control(duplicate_inheritable(scope.device.value));
    const std::string path = new_path();
    child_pin_cleanup cleanup(scope.device.value);
    for (const char* suffix : {"", "-program", "-link"}) {
        cleanup.owned.emplace_back(null_namespace, path + suffix);
    }
    child_process child(
        "legacy " + number(control->value) + " 0 " + guid_bytes(scope.a) + " " + path + " 0 101 0", {control->value});
    REQUIRE(child.wait() == 0);
}

TEST_CASE("namespace_ND06_three_process_barrier_inventory_all_object_types", "[namespace][driver][native]")
{
    namespace_scope scope;
    const std::array<GUID, 3> namespaces{scope.a, scope.b, null_namespace};
    const std::array<const char*, 3> suffixes{"-map", "-program", "-link"};
    const std::string root = new_path();
    struct image_cleanup
    {
        HANDLE device;
        std::vector<std::string> files;
        ~image_cleanup()
        {
            ebpf_operation_epoch_synchronize_request_t drain{{sizeof(drain), EBPF_OPERATION_EPOCH_SYNCHRONIZE}};
            CHECK(raw_ioctl(device, &drain, sizeof(drain)) == ERROR_SUCCESS);
            for (const auto& file : files) {
                bool removed = false;
                auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                do {
                    if (DeleteFileA(file.c_str())) {
                        removed = true;
                        break;
                    }
                    DWORD error = GetLastError();
                    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
                        removed = true;
                        break;
                    }
                    if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED) {
                        break;
                    }
                    Sleep(10);
                } while (std::chrono::steady_clock::now() < deadline);
                CHECK(removed);
            }
        }
    } images{scope.device.value, {}};
    child_pin_cleanup pins(scope.device.value);
    for (const GUID& selected : namespaces) {
        for (const char* suffix : suffixes) {
            pins.owned.emplace_back(selected, root + suffix);
        }
    }
    std::unique_ptr<unique_handle> control(duplicate_inheritable(scope.device.value));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    std::vector<std::unique_ptr<inventory_worker>> workers;
    for (size_t index = 0; index < namespaces.size(); ++index) {
        auto worker = std::make_unique<inventory_worker>();
        worker->mapping.value = CreateFileMappingW(
            INVALID_HANDLE_VALUE, &attributes, PAGE_READWRITE, 0, sizeof(inventory_channel), nullptr);
        worker->ready.value = CreateEventW(&attributes, TRUE, FALSE, nullptr);
        worker->map_gate.value = CreateEventW(&attributes, FALSE, FALSE, nullptr);
        worker->program_gate.value = CreateEventW(&attributes, FALSE, FALSE, nullptr);
        worker->release_gate.value = CreateEventW(&attributes, TRUE, FALSE, nullptr);
        REQUIRE(worker->mapping.value != nullptr);
        REQUIRE(worker->ready.value != nullptr);
        REQUIRE(worker->map_gate.value != nullptr);
        REQUIRE(worker->program_gate.value != nullptr);
        REQUIRE(worker->release_gate.value != nullptr);
        worker->view = static_cast<inventory_channel*>(
            MapViewOfFile(worker->mapping.value, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(inventory_channel)));
        REQUIRE(worker->view != nullptr);
        new (worker->view) inventory_channel{};
        worker->view->map_gate = worker->map_gate.value;
        worker->view->program_gate = worker->program_gate.value;
        worker->view->release_gate = worker->release_gate.value;
        worker->process = std::make_unique<child_process>(
            "inventory " + number(control->value) + " " + number(worker->mapping.value) + " " +
                guid_bytes(namespaces[index]) + " " + root + " 0 " + std::to_string(6060 + index) + " " +
                number(worker->ready.value),
            std::vector<HANDLE>{
                control->value,
                worker->mapping.value,
                worker->ready.value,
                worker->map_gate.value,
                worker->program_gate.value,
                worker->release_gate.value});
        for (size_t round = 0; round < inventory_rounds; ++round) {
            images.files.push_back(
                inventory_file(worker->process->process.dwProcessId, namespaces[index], round, root));
        }
        workers.push_back(std::move(worker));
    }
    for (auto& worker : workers) {
        REQUIRE(WaitForSingleObject(worker->ready.value, 30000) == WAIT_OBJECT_0);
        REQUIRE(ResetEvent(worker->ready.value));
    }
    for (auto& worker : workers) {
        REQUIRE(SetEvent(worker->map_gate.value));
        REQUIRE(WaitForSingleObject(worker->ready.value, 30000) == WAIT_OBJECT_0);
        REQUIRE(ResetEvent(worker->ready.value));
        REQUIRE(worker->view->owned.count[0] == 1);
    }
    for (size_t round = 0; round < inventory_rounds; ++round) {
        for (auto& worker : workers) {
            uint32_t previous_maps = worker->view->owned.count[0];
            uint32_t previous_programs = worker->view->owned.count[1];
            REQUIRE(SetEvent(worker->program_gate.value));
            REQUIRE(WaitForSingleObject(worker->ready.value, 30000) == WAIT_OBJECT_0);
            REQUIRE(ResetEvent(worker->ready.value));
            REQUIRE(worker->view->rounds_completed == round + 1);
            REQUIRE(worker->view->owned.count[0] > previous_maps);
            REQUIRE(worker->view->owned.count[1] > previous_programs);
            REQUIRE(worker->view->owned.count[2] == round + 1);
        }
    }
    for (size_t selected = 0; selected < workers.size(); ++selected) {
        REQUIRE(ebpf_set_namespace(&namespaces[selected]) == EBPF_SUCCESS);
        verify_worker_inventory<bpf_map_info>(
            scope.device.value,
            workers,
            selected,
            0,
            bpf_map_get_fd_by_id,
            bpf_map_get_next_id,
            EBPF_OPERATION_GET_MAP_HANDLE_BY_ID,
            EBPF_OPERATION_GET_NEXT_MAP_ID);
        verify_worker_inventory<bpf_prog_info>(
            scope.device.value,
            workers,
            selected,
            1,
            bpf_prog_get_fd_by_id,
            bpf_prog_get_next_id,
            EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID,
            EBPF_OPERATION_GET_NEXT_PROGRAM_ID);
        verify_worker_inventory<bpf_link_info>(
            scope.device.value,
            workers,
            selected,
            2,
            bpf_link_get_fd_by_id,
            bpf_link_get_next_id,
            EBPF_OPERATION_GET_LINK_HANDLE_BY_ID,
            EBPF_OPERATION_GET_NEXT_LINK_ID);
        for (size_t type = 0; type < 3; ++type) {
            auto owned = inventory_ids(workers[selected]->view->owned, type);
            REQUIRE(owned.size() >= 2);
            bool has_hidden_gap = false;
            for (size_t other = 0; other < workers.size(); ++other) {
                if (other == selected) {
                    continue;
                }
                for (uint32_t id : inventory_ids(workers[other]->view->owned, type)) {
                    has_hidden_gap |= id > *owned.begin() && id < *owned.rbegin();
                }
            }
            REQUIRE(has_hidden_gap);
        }
        verify_pin(root + "-map", workers[selected]->view->pinned_ids[0], static_cast<uint32_t>(6060 + selected));
        unique_fd program(bpf_obj_get((root + "-program").c_str()));
        unique_fd link(bpf_obj_get((root + "-link").c_str()));
        REQUIRE(program.value > 0);
        REQUIRE(link.value > 0);
        bpf_prog_info program_info{};
        bpf_link_info link_info{};
        uint32_t size = sizeof(program_info);
        REQUIRE(bpf_obj_get_info_by_fd(program.value, &program_info, &size) == 0);
        size = sizeof(link_info);
        REQUIRE(bpf_obj_get_info_by_fd(link.value, &link_info, &size) == 0);
        REQUIRE(program_info.id == workers[selected]->view->pinned_ids[1]);
        REQUIRE(link_info.id == workers[selected]->view->pinned_ids[2]);
        REQUIRE(link_info.prog_id == program_info.id);
    }
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    for (const char* suffix : suffixes) {
        REQUIRE(ebpf_object_unpin((root + suffix).c_str()) == EBPF_SUCCESS);
        REQUIRE(bpf_obj_get((root + suffix).c_str()) == -ENOENT);
    }
    for (size_t selected : {size_t{0}, size_t{2}}) {
        REQUIRE(ebpf_set_namespace(&namespaces[selected]) == EBPF_SUCCESS);
        verify_pin(root + "-map", workers[selected]->view->pinned_ids[0], static_cast<uint32_t>(6060 + selected));
        unique_fd program(bpf_obj_get((root + "-program").c_str()));
        unique_fd link(bpf_obj_get((root + "-link").c_str()));
        REQUIRE(program.value > 0);
        REQUIRE(link.value > 0);
        bpf_prog_info program_info{};
        bpf_link_info link_info{};
        uint32_t size = sizeof(program_info);
        REQUIRE(bpf_obj_get_info_by_fd(program.value, &program_info, &size) == 0);
        size = sizeof(link_info);
        REQUIRE(bpf_obj_get_info_by_fd(link.value, &link_info, &size) == 0);
        REQUIRE(program_info.id == workers[selected]->view->pinned_ids[1]);
        REQUIRE(link_info.id == workers[selected]->view->pinned_ids[2]);
        REQUIRE(link_info.prog_id == program_info.id);
    }
    for (auto& worker : workers) {
        REQUIRE(SetEvent(worker->release_gate.value));
    }
    for (auto& worker : workers) {
        REQUIRE(worker->process->wait() == 0);
    }
    ebpf_operation_epoch_synchronize_request_t drain{{sizeof(drain), EBPF_OPERATION_EPOCH_SYNCHRONIZE}};
    REQUIRE(raw_ioctl(scope.device.value, &drain, sizeof(drain)) == ERROR_SUCCESS);
    for (size_t selected = 0; selected < workers.size(); ++selected) {
        REQUIRE(ebpf_set_namespace(&namespaces[selected]) == EBPF_SUCCESS);
        auto after = std::make_unique<object_inventory>();
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool drained;
        do {
            REQUIRE(raw_ioctl(scope.device.value, &drain, sizeof(drain)) == ERROR_SUCCESS);
            capture_inventory(*after);
            drained = true;
            for (size_t type = 0; type < 3; ++type) {
                drained &= inventory_ids(*after, type) == inventory_ids(workers[selected]->view->baseline, type);
            }
            if (!drained) {
                std::this_thread::yield();
            }
        } while (!drained && std::chrono::steady_clock::now() < deadline);
        REQUIRE(drained);
        for (size_t type = 0; type < 3; ++type) {
            REQUIRE(inventory_ids(*after, type) == inventory_ids(workers[selected]->view->baseline, type));
        }
    }
}

TEST_CASE("namespace_ND02_ND06_ND07_ND09_maps_and_pins", "[namespace][driver]")
{
    namespace_scope scope;
    const std::string path = new_path();
    test_map a(102, BPF_MAP_TYPE_HASH);
    test_pin a_pin(scope.device.value, a.fd, path);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    REQUIRE(bpf_map_get_fd_by_id(a.id) == -ENOENT);
    verify_raw_open<bpf_map_info>(scope.device.value, EBPF_OPERATION_GET_MAP_HANDLE_BY_ID, a.id, false);
    REQUIRE(bpf_obj_get(path.c_str()) == -ENOENT);
    test_map b(202, BPF_MAP_TYPE_HASH);
    test_pin b_pin(scope.device.value, b.fd, path);
    REQUIRE(visible_map_ids() == std::set<uint32_t>{b.id});
    uint32_t next;
    REQUIRE(bpf_map_get_next_id(a.id, &next) == 0); // A hidden cursor must not terminate traversal.
    REQUIRE(next == b.id);
    verify_raw_next(scope.device.value, EBPF_OPERATION_GET_NEXT_MAP_ID, a.id, b.id);
    verify_raw_open<bpf_map_info>(scope.device.value, EBPF_OPERATION_GET_MAP_HANDLE_BY_ID, b.id, true);
    verify_pin(path, b.id, 202);
    REQUIRE(read_marker(a.fd) == 102);
    uint32_t key = 0, marker = 103, count = 1;
    bpf_map_batch_opts batch{};
    batch.sz = sizeof(batch);
    REQUIRE(bpf_map_update_batch(a.fd, &key, &marker, &count, &batch) == 0);
    REQUIRE(count == 1);
    REQUIRE(read_marker(a.fd) == 103);
    REQUIRE(read_marker(b.fd) == 202);
    REQUIRE(bpf_map_delete_elem(a.fd, &key) == 0);
    REQUIRE(bpf_map_lookup_elem(a.fd, &key, &marker) == -ENOENT);
    REQUIRE(read_marker(b.fd) == 202);
    marker = 102;
    REQUIRE(bpf_map_update_elem(a.fd, &key, &marker, BPF_ANY) == 0);
    REQUIRE(bpf_obj_pin(a.fd, (path + "-foreign").c_str()) == -EINVAL);
    REQUIRE(ebpf_object_unpin(path.c_str()) == EBPF_SUCCESS);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    verify_pin(path, a.id, 102);
    REQUIRE(ebpf_set_namespace(&null_namespace) == EBPF_SUCCESS);
    test_map legacy(302);
    test_pin legacy_pin(scope.device.value, legacy.fd, path);
    verify_pin(path, legacy.id, 302);
}

TEST_CASE("namespace_ND05_ND10_ND34_real_inherited_handles_and_same_GUID", "[namespace][driver]")
{
    namespace_scope scope;
    test_map map(510);
    const std::string path = new_path();
    test_pin pin(scope.device.value, map.fd, path);
    std::unique_ptr<unique_handle> control(duplicate_inheritable(scope.device.value));
    bool remote = GENERATE(false, true);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    unique_handle signal(CreateEventW(&attributes, TRUE, FALSE, nullptr));
    unique_handle channel(
        CreateFileMappingW(INVALID_HANDLE_VALUE, &attributes, PAGE_READWRITE, 0, sizeof(uintptr_t), nullptr));
    REQUIRE(signal.value != nullptr);
    REQUIRE(channel.value != nullptr);
    std::unique_ptr<unique_handle> object(duplicate_inheritable(reinterpret_cast<HANDLE>(_get_osfhandle(map.fd))));
    HANDLE passed = remote ? channel.value : object->value;
    child_process child(
        std::string(remote ? "delegate-remote " : "delegate ") + number(control->value) + " " + number(passed) + " " +
            guid_bytes(scope.a) + " " + path + " " + std::to_string(map.id) + " 510 " + number(signal.value),
        {control->value, passed, signal.value});
    if (remote) {
        HANDLE target = nullptr;
        REQUIRE(DuplicateHandle(
            GetCurrentProcess(),
            reinterpret_cast<HANDLE>(_get_osfhandle(map.fd)),
            child.process.hProcess,
            &target,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS));
        auto shared = static_cast<uintptr_t*>(MapViewOfFile(channel.value, FILE_MAP_WRITE, 0, 0, sizeof(uintptr_t)));
        REQUIRE(shared != nullptr);
        *shared = reinterpret_cast<uintptr_t>(target);
        REQUIRE(UnmapViewOfFile(shared));
        REQUIRE(SetEvent(signal.value));
    }
    REQUIRE(child.wait() == 0);
    GUID result{};
    REQUIRE(ebpf_get_namespace(&result) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(result, scope.a));
    verify_pin(path, map.id, 510);
}

TEST_CASE("namespace_ND11_ND13_restricted_subject_and_per_request_authorization", "[namespace][driver]")
{
    namespace_scope scope;
    std::unique_ptr<unique_handle> token(restricted_token());
    std::unique_ptr<unique_handle> control(duplicate_inheritable(scope.device.value));
    {
        child_process low(
            "low " + number(control->value) + " 0 " + guid_bytes(scope.b) + " " + new_path() + " 0 0 0",
            {control->value},
            token->value);
        REQUIRE(low.wait() == 0);
    }
    REQUIRE(ImpersonateLoggedOnUser(token->value));
    DWORD denied_set = raw_set(scope.device.value, scope.b);
    GUID denied{};
    DWORD denied_get = raw_get(scope.device.value, denied);
    BOOL reverted = RevertToSelf();
    REQUIRE(reverted);
    REQUIRE(denied_set == ERROR_ACCESS_DENIED);
    REQUIRE(denied_get == ERROR_ACCESS_DENIED);
    GUID current{};
    REQUIRE(raw_get(scope.device.value, current) == ERROR_SUCCESS);
    REQUIRE(IsEqualGUID(current, scope.a));
    REQUIRE(raw_set(scope.device.value, scope.b) == ERROR_SUCCESS);
    REQUIRE(raw_get(scope.device.value, current) == ERROR_SUCCESS);
    REQUIRE(IsEqualGUID(current, scope.b));
}

TEST_CASE("namespace_ND20_ND21_ND36_creator_exit_and_final_reference", "[namespace][driver]")
{
    namespace_scope scope;
    bool abnormal = GENERATE(false, true);
    const std::string path = new_path();
    child_pin_cleanup cleanup_pins(scope.device.value);
    cleanup_pins.owned.emplace_back(scope.b, path);
    std::unique_ptr<unique_handle> control(duplicate_inheritable(scope.device.value));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    unique_handle signal(CreateEventW(&attributes, TRUE, FALSE, nullptr));
    REQUIRE(signal.value != nullptr);
    std::string mode = abnormal ? "pin-wait" : "pin-exit";
    child_process creator(
        mode + " " + number(control->value) + " 0 " + guid_bytes(scope.b) + " " + path + " 0 2036 " +
            number(signal.value),
        {control->value, signal.value});
    if (abnormal) {
        REQUIRE(WaitForSingleObject(signal.value, 30000) == WAIT_OBJECT_0);
    } else {
        REQUIRE(creator.wait() == 0);
    }
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    int observed = bpf_obj_get(path.c_str());
    REQUIRE(observed > 0);
    bpf_map_info info{};
    uint32_t length = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(observed, &info, &length) == 0);
    {
        test_pin cleanup(scope.device.value, observed, path, false);
        if (abnormal) {
            REQUIRE(TerminateProcess(creator.process.hProcess, 77));
            REQUIRE(creator.wait() == 77);
        }
        REQUIRE(read_marker(observed) == 2036);
        REQUIRE(ebpf_object_unpin(path.c_str()) == EBPF_SUCCESS);
        REQUIRE(read_marker(observed) == 2036);
        REQUIRE(ebpf_close_fd(observed) == EBPF_SUCCESS);
    }
    ebpf_operation_epoch_synchronize_request_t drain{{sizeof(drain), EBPF_OPERATION_EPOCH_SYNCHRONIZE}};
    REQUIRE(raw_ioctl(scope.device.value, &drain, sizeof(drain)) == ERROR_SUCCESS);
    REQUIRE(bpf_map_get_fd_by_id(info.id) == -ENOENT);
    for (unsigned index = 0; index < 8; ++index) {
        child_process fresh(
            "fresh " + number(control->value) + " 0 " + guid_bytes(scope.a) + " " + new_path() + " 0 0 0",
            {control->value});
        REQUIRE(fresh.wait() == 0);
    }
}

TEST_CASE("namespace_ND35_binary_GUID_identity_all_bytes", "[namespace][driver]")
{
    namespace_scope scope;
    test_map original(35);
    for (size_t index = 0; index < sizeof(GUID); ++index) {
        GUID changed = scope.a;
        reinterpret_cast<uint8_t*>(&changed)[index] ^= 0x83;
        REQUIRE(ebpf_set_namespace(&changed) == EBPF_SUCCESS);
        GUID queried{};
        REQUIRE(ebpf_get_namespace(&queried) == EBPF_SUCCESS);
        REQUIRE(IsEqualGUID(queried, changed));
        REQUIRE(bpf_map_get_fd_by_id(original.id) == -ENOENT);
        test_map local(static_cast<uint32_t>(index));
        REQUIRE(visible_map_ids() == std::set<uint32_t>{local.id});
        REQUIRE(read_marker(original.fd) == 35);
    }
}

TEST_CASE("namespace_ND03_ND14_preopened_thread_and_overlapped_transports", "[namespace][driver]")
{
    namespace_scope scope;
    std::array<std::promise<void>, 3> ready;
    std::promise<void> release;
    auto gate = release.get_future().share();
    struct thread_result
    {
        unique_fd owner;
        bool selected;
    };
    std::array<std::future<thread_result>, 3> workers;
    for (size_t index = 0; index < workers.size(); ++index) {
        workers[index] = std::async(std::launch::async, [&, index]() {
            int before = bpf_map_create(BPF_MAP_TYPE_ARRAY, "before_switch", 4, 4, 1, nullptr);
            unique_handle raw(CreateFileW(
                device_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                index == 2 ? FILE_FLAG_OVERLAPPED : 0,
                nullptr));
            ready[index].set_value();
            gate.wait();
            GUID queried{};
            bool selected = before > 0;
            if (index == 2) {
                ebpf_operation_get_namespace_request_t request{{sizeof(request), EBPF_OPERATION_GET_NAMESPACE}};
                ebpf_operation_get_namespace_reply_t reply{};
                unique_handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
                OVERLAPPED overlapped{};
                overlapped.hEvent = event.value;
                DWORD returned = 0;
                BOOL completed = DeviceIoControl(
                    raw.value,
                    namespace_ioctl,
                    &request,
                    sizeof(request),
                    &reply,
                    sizeof(reply),
                    &returned,
                    &overlapped);
                if (!completed && GetLastError() == ERROR_IO_PENDING) {
                    completed = GetOverlappedResult(raw.value, &overlapped, &returned, TRUE);
                }
                selected &= completed && returned == sizeof(reply) && IsEqualGUID(reply.namespace_id, scope.b);
            } else {
                selected &= raw_get(raw.value, queried) == ERROR_SUCCESS && IsEqualGUID(queried, scope.b);
            }
            int after = bpf_map_create(BPF_MAP_TYPE_ARRAY, "after_switch", 4, 4, 1, nullptr);
            uint32_t key = 0, marker = static_cast<uint32_t>(index + 314);
            selected &= after > 0 && bpf_map_update_elem(after, &key, &marker, BPF_ANY) == 0;
            if (before > 0) {
                selected &= ebpf_close_fd(before) == EBPF_SUCCESS;
            }
            return thread_result{unique_fd(after), selected};
        });
    }
    for (auto& worker : ready) {
        worker.get_future().wait();
    }
    ebpf_result_t published = ebpf_set_namespace(&scope.b);
    release.set_value();
    REQUIRE(published == EBPF_SUCCESS);
    std::vector<unique_fd> created;
    for (size_t index = 0; index < workers.size(); ++index) {
        auto result = workers[index].get();
        CHECK(result.selected);
        int fd = result.owner.value;
        REQUIRE(fd > 0);
        REQUIRE(read_marker(fd) == index + 314);
        bpf_map_info info{};
        uint32_t length = sizeof(info);
        REQUIRE(bpf_obj_get_info_by_fd(fd, &info, &length) == 0);
        int opened = bpf_map_get_fd_by_id(info.id);
        CHECK(opened > 0);
        if (opened > 0) {
            CHECK(ebpf_close_fd(opened) == EBPF_SUCCESS);
        }
        created.push_back(std::move(result.owner));
    }
    auto late = std::async(
        std::launch::async, []() { return bpf_map_create(BPF_MAP_TYPE_ARRAY, "late_opener", 4, 4, 1, nullptr); });
    int late_fd = late.get();
    REQUIRE(late_fd > 0);
    created.emplace_back(late_fd);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    for (auto& owner : created) {
        int fd = owner.value;
        bpf_map_info info{};
        uint32_t length = sizeof(info);
        REQUIRE(bpf_obj_get_info_by_fd(fd, &info, &length) == 0);
        CHECK(bpf_map_get_fd_by_id(info.id) == -ENOENT);
    }
}

TEST_CASE("namespace_ND04_independent_transport_close_reopen_does_not_reset_process", "[namespace][driver]")
{
    namespace_scope scope;
    REQUIRE(CloseHandle(scope.device.value));
    scope.device.value = INVALID_HANDLE_VALUE;
    for (unsigned index = 0; index < 3; ++index) {
        unique_handle reopened(
            CreateFileW(device_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
        REQUIRE(reopened.value != INVALID_HANDLE_VALUE);
        GUID current{};
        REQUIRE(raw_get(reopened.value, current) == ERROR_SUCCESS);
        REQUIRE(IsEqualGUID(current, scope.a));
        test_map map(400 + index);
        verify_raw_open<bpf_map_info>(reopened.value, EBPF_OPERATION_GET_MAP_HANDLE_BY_ID, map.id, true);
        REQUIRE(read_marker(map.fd) == 400 + index);
    }
    GUID current{};
    REQUIRE(ebpf_get_namespace(&current) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(current, scope.a));
}

TEST_CASE("namespace_ND14_overlapping_SET_and_create_keep_whole_GUID_ownership", "[namespace][driver]")
{
    namespace_scope scope;
    for (size_t index = 0; index < sizeof(GUID); ++index) {
        reinterpret_cast<uint8_t*>(&scope.b)[index] =
            static_cast<uint8_t>(reinterpret_cast<const uint8_t*>(&scope.a)[index] ^ 0xff);
    }
    constexpr uint32_t iterations = 64;
    std::atomic<bool> start = false;
    auto writer = std::async(std::launch::async, [&]() {
        while (!start.load()) {
            std::this_thread::yield();
        }
        for (uint32_t index = 0; index < iterations; ++index) {
            if (ebpf_set_namespace(index % 2 ? &scope.a : &scope.b) != EBPF_SUCCESS) {
                return false;
            }
        }
        return true;
    });
    std::vector<std::unique_ptr<test_map>> maps;
    start = true;
    for (uint32_t index = 0; index < iterations; ++index) {
        maps.emplace_back(std::make_unique<test_map>(1400 + index));
    }
    REQUIRE(writer.get());
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    auto a_ids = visible_map_ids();
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    auto b_ids = visible_map_ids();
    for (uint32_t index = 0; index < iterations; ++index) {
        REQUIRE(a_ids.contains(maps[index]->id) != b_ids.contains(maps[index]->id));
        REQUIRE(read_marker(maps[index]->fd) == 1400 + index);
    }
    REQUIRE(a_ids.size() + b_ids.size() == iterations);
}

TEST_CASE("namespace_ND24_raw_namespace_protocol_boundaries", "[namespace][driver]")
{
    namespace_scope scope;
    ebpf_operation_set_namespace_request_t request{{sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, scope.b};
    REQUIRE(raw_set(scope.device.value, scope.a) == ERROR_SUCCESS);
    for (DWORD length = 0; length < sizeof(request); ++length) {
        INFO("SET truncation at " << length);
        REQUIRE(raw_ioctl(scope.device.value, &request, length) == ERROR_INVALID_PARAMETER);
        GUID unchanged{};
        REQUIRE(raw_get(scope.device.value, unchanged) == ERROR_SUCCESS);
        REQUIRE(IsEqualGUID(unchanged, scope.a));
    }
    for (uint16_t length : std::array<uint16_t, 4>{0, sizeof(request) - 1, sizeof(request) + 1, UINT16_MAX}) {
        request.header.length = length;
        REQUIRE(raw_ioctl(scope.device.value, &request, sizeof(request)) == ERROR_INVALID_PARAMETER);
    }
    ebpf_operation_get_namespace_request_t query{{sizeof(query), EBPF_OPERATION_GET_NAMESPACE}};
    ebpf_operation_get_namespace_reply_t reply{};
    for (DWORD length = 0; length < sizeof(query); ++length) {
        REQUIRE(raw_ioctl(scope.device.value, &query, length, &reply, sizeof(reply)) == ERROR_INVALID_PARAMETER);
    }
    for (DWORD length = 0; length < sizeof(reply); ++length) {
        INFO("GET short output at " << length);
        REQUIRE(raw_ioctl(scope.device.value, &query, sizeof(query), &reply, length) == ERROR_INSUFFICIENT_BUFFER);
    }
    std::vector<uint8_t> oversized(UINT16_MAX + size_t{1});
    memcpy(oversized.data(), &request, sizeof(request));
    REQUIRE(
        raw_ioctl(scope.device.value, oversized.data(), static_cast<DWORD>(oversized.size())) ==
        ERROR_INVALID_PARAMETER);
    for (auto opcode :
         {static_cast<ebpf_operation_id_t>(-1),
          static_cast<ebpf_operation_id_t>(EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX + 1)}) {
        ebpf_operation_header_t unknown{sizeof(unknown), opcode};
        REQUIRE(raw_ioctl(scope.device.value, &unknown, sizeof(unknown)) == ERROR_NOT_SUPPORTED);
    }
    GUID unchanged{};
    REQUIRE(raw_get(scope.device.value, unchanged) == ERROR_SUCCESS);
    REQUIRE(IsEqualGUID(unchanged, scope.a));
    REQUIRE(raw_set(scope.device.value, scope.b) == ERROR_SUCCESS);
    REQUIRE(raw_get(scope.device.value, unchanged) == ERROR_SUCCESS);
    REQUIRE(IsEqualGUID(unchanged, scope.b));
}

TEST_CASE("namespace_ND08_pin_enumeration_is_scoped_and_sorted", "[namespace][driver]")
{
    namespace_scope scope;
    const std::string root = new_path();
    test_map a(801);
    test_pin a0(scope.device.value, a.fd, root + "-a");
    test_pin a1(scope.device.value, a.fd, root + "-ab");
    test_pin hidden(scope.device.value, a.fd, root + "-hidden-" + std::string(100, 'z'));
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    test_map b(802);
    test_pin b0(scope.device.value, b.fd, root + "-a");
    test_pin b1(scope.device.value, b.fd, root + "-aa");
    std::string cursor;
    std::vector<std::string> paths;
    for (;;) {
        char next[EBPF_MAX_PIN_PATH_LENGTH]{};
        ebpf_object_type_t type = EBPF_OBJECT_MAP;
        ebpf_result_t result = ebpf_get_next_pinned_object_path(cursor.c_str(), next, sizeof(next), &type);
        if (result != EBPF_SUCCESS) {
            REQUIRE(result == EBPF_NO_MORE_KEYS);
            break;
        }
        REQUIRE(type == EBPF_OBJECT_MAP);
        REQUIRE(cursor < next);
        paths.emplace_back(next);
        cursor = next;
    }
    char canonical0[EBPF_MAX_PIN_PATH_LENGTH], canonical1[EBPF_MAX_PIN_PATH_LENGTH];
    REQUIRE(ebpf_canonicalize_pin_path(canonical0, sizeof(canonical0), b0.path.c_str()) == EBPF_SUCCESS);
    REQUIRE(ebpf_canonicalize_pin_path(canonical1, sizeof(canonical1), b1.path.c_str()) == EBPF_SUCCESS);
    REQUIRE(paths == std::vector<std::string>{canonical0, canonical1});
    uint16_t count = 0;
    ebpf_map_info_t* information = nullptr;
    REQUIRE(ebpf_api_get_pinned_map_info(&count, &information) == EBPF_SUCCESS);
    CHECK(count == 2);
    std::set<std::string> listed;
    for (uint16_t index = 0; index < count; ++index) {
        listed.emplace(information[index].pin_path);
    }
    CHECK(listed == std::set<std::string>{canonical0, canonical1});
    ebpf_api_map_info_free(count, information);
    ebpf_operation_get_pinned_map_info_request_t query{{sizeof(query), EBPF_OPERATION_GET_PINNED_MAP_INFO}};
    std::vector<uint8_t> large(4096);
    REQUIRE(
        raw_ioctl(scope.device.value, &query, sizeof(query), large.data(), static_cast<DWORD>(large.size())) ==
        ERROR_SUCCESS);
    auto raw = reinterpret_cast<ebpf_operation_get_pinned_map_info_reply_t*>(large.data());
    REQUIRE(raw->map_count == 2);
    REQUIRE(raw->size > 0);
    const size_t exact_size = offsetof(ebpf_operation_get_pinned_map_info_reply_t, data) + raw->size;
    REQUIRE(exact_size < large.size());
    std::vector<uint8_t> exact(exact_size);
    REQUIRE(
        raw_ioctl(scope.device.value, &query, sizeof(query), exact.data(), static_cast<DWORD>(exact.size())) ==
        ERROR_SUCCESS);
    REQUIRE(reinterpret_cast<ebpf_operation_get_pinned_map_info_reply_t*>(exact.data())->map_count == 2);
    REQUIRE(
        raw_ioctl(scope.device.value, &query, sizeof(query), exact.data(), static_cast<DWORD>(exact.size() - 1)) ==
        ERROR_MORE_DATA);
    char canonical_hidden[EBPF_MAX_PIN_PATH_LENGTH];
    REQUIRE(
        ebpf_canonicalize_pin_path(canonical_hidden, sizeof(canonical_hidden), hidden.path.c_str()) == EBPF_SUCCESS);
    REQUIRE(
        std::search(large.begin(), large.end(), canonical_hidden, canonical_hidden + strlen(canonical_hidden)) ==
        large.end());
    REQUIRE(read_marker(a.fd) == 801);
    REQUIRE(read_marker(b.fd) == 802);
}

namespace {
using object_ptr = std::unique_ptr<bpf_object, decltype(&bpf_object__close)>;

object_ptr
load_namespace_object(const char* prefix, ebpf_execution_type_t execution, bpf_prog_type type = BPF_PROG_TYPE_SAMPLE)
{
    std::string file = std::string(prefix) + (execution == EBPF_EXECUTION_NATIVE ? ".sys" : ".o");
    bpf_object* object = nullptr;
    int program_fd = ebpf_fd_invalid;
    int error = program_load_helper(file.c_str(), type, execution, &object, &program_fd);
    object_ptr result(object, bpf_object__close);
    REQUIRE(error == 0);
    REQUIRE(object != nullptr);
    REQUIRE(program_fd > 0);
    return result;
}

uint32_t
map_id(int fd)
{
    bpf_map_info info{};
    uint32_t length = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(fd, &info, &length) == 0);
    return info.id;
}

void
namespace_load_reuse(ebpf_execution_type_t execution)
{
    namespace_scope scope;
    auto a = load_namespace_object("map_reuse", execution);
    int a_port = bpf_object__find_map_fd_by_name(a.get(), "port_map");
    int a_outer = bpf_object__find_map_fd_by_name(a.get(), "outer_map");
    int a_inner = bpf_object__find_map_fd_by_name(a.get(), "inner_map");
    REQUIRE(a_port > 0);
    REQUIRE(a_outer > 0);
    REQUIRE(a_inner > 0);
    test_pin a_port_pin(scope.device.value, a_port, "/ebpf/global/port_map", false);
    test_pin a_outer_pin(scope.device.value, a_outer, "/ebpf/global/outer_map", false);
    uint32_t key = 0, a_marker = 1517;
    REQUIRE(bpf_map_update_elem(a_port, &key, &a_marker, BPF_ANY) == 0);
    REQUIRE(bpf_map_update_elem(a_outer, &key, &a_inner, BPF_ANY) == 0);
    uint32_t a_id = map_id(a_port);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    REQUIRE(bpf_obj_get("/ebpf/global/port_map") == -ENOENT);
    auto b = load_namespace_object("map_reuse", execution);
    int b_port = bpf_object__find_map_fd_by_name(b.get(), "port_map");
    int b_outer = bpf_object__find_map_fd_by_name(b.get(), "outer_map");
    REQUIRE(b_port > 0);
    REQUIRE(b_outer > 0);
    test_pin b_port_pin(scope.device.value, b_port, "/ebpf/global/port_map", false);
    test_pin b_outer_pin(scope.device.value, b_outer, "/ebpf/global/outer_map", false);
    uint32_t b_marker = 2517, b_id = map_id(b_port);
    REQUIRE(bpf_map_update_elem(b_port, &key, &b_marker, BPF_ANY) == 0);
    REQUIRE(a_id != b_id);
    REQUIRE(read_marker(a_port) == a_marker);
    REQUIRE(read_marker(b_port) == b_marker);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    {
        auto reused = load_namespace_object("map_reuse", execution);
        int reused_port = bpf_object__find_map_fd_by_name(reused.get(), "port_map");
        REQUIRE(reused_port > 0);
        REQUIRE(map_id(reused_port) == a_id);
        REQUIRE(read_marker(reused_port) == a_marker);
    }
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
    unique_fd incompatible;
    incompatible.value = bpf_map_create(BPF_MAP_TYPE_HASH, "incompatible", 4, 4, 1, nullptr);
    REQUIRE(incompatible.value > 0);
    test_pin wrong(scope.device.value, incompatible.value, "/ebpf/global/port_map");
    std::string file = execution == EBPF_EXECUTION_NATIVE ? "map_reuse.sys" : "map_reuse.o";
    native_module_helper_t native_copy;
    if (execution == EBPF_EXECUTION_NATIVE) {
        native_copy.initialize("map_reuse", execution);
        file = native_copy.get_file_name();
    }
    object_ptr rejected(bpf_object__open(file.c_str()), bpf_object__close);
    REQUIRE(rejected != nullptr);
    REQUIRE(ebpf_object_set_execution_type(rejected.get(), execution) == EBPF_SUCCESS);
    REQUIRE(bpf_object__load(rejected.get()) == -EINVAL);
    REQUIRE(read_marker(a_port) == a_marker);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    verify_pin("/ebpf/global/port_map", b_id, b_marker);
}
} // namespace

TEST_CASE("namespace_ND15_ND17_native_templates_and_namespace_local_reuse", "[namespace][driver][native]")
{
    namespace_load_reuse(EBPF_EXECUTION_NATIVE);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("namespace_ND16_ND17_JIT_namespace_local_reuse", "[namespace][driver][jit]")
{
    namespace_load_reuse(EBPF_EXECUTION_JIT);
}
#endif

TEST_CASE("namespace_ND32_seeded_cross_process_pin_stress", "[namespace][driver][stress]")
{
    namespace_scope scope;
    constexpr uint32_t seed = 0x5eed0a11;
    INFO("Replay seed: " << seed);
    const std::array<GUID, 3> namespaces{scope.a, scope.b, new_namespace()};
    const std::string root = new_path();
    child_pin_cleanup cleanup(scope.device.value);
    for (const GUID& selected : namespaces) {
        for (unsigned index = 0; index < 4; ++index) {
            cleanup.owned.emplace_back(selected, root + "-" + std::to_string(index));
        }
    }
    std::unique_ptr<unique_handle> control(duplicate_inheritable(scope.device.value));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    unique_handle start(CreateEventW(&attributes, TRUE, FALSE, nullptr));
    REQUIRE(start.value != nullptr);
    std::vector<std::unique_ptr<unique_handle>> ready;
    std::vector<std::unique_ptr<child_process>> workers;
    for (size_t index = 0; index < 6; ++index) {
        ready.emplace_back(std::make_unique<unique_handle>(CreateEventW(&attributes, TRUE, FALSE, nullptr)));
        REQUIRE(ready.back()->value != nullptr);
        workers.emplace_back(std::make_unique<child_process>(
            "stress " + number(control->value) + " " + number(start.value) + " " + guid_bytes(namespaces[index % 3]) +
                " " + root + " " + std::to_string(seed + static_cast<uint32_t>(index)) + " " +
                std::to_string(3200 + index % 3) + " " + number(ready.back()->value),
            std::vector<HANDLE>{control->value, start.value, ready.back()->value}));
    }
    for (auto& event : ready) {
        REQUIRE(WaitForSingleObject(event->value, 30000) == WAIT_OBJECT_0);
    }
    REQUIRE(SetEvent(start.value));
    for (auto& worker : workers) {
        REQUIRE(worker->wait() == 0);
    }
    for (auto& selected : namespaces) {
        REQUIRE(ebpf_set_namespace(&selected) == EBPF_SUCCESS);
        uint16_t count = 0;
        ebpf_map_info_t* maps = nullptr;
        REQUIRE(ebpf_api_get_pinned_map_info(&count, &maps) == EBPF_SUCCESS);
        CHECK(count == 0);
        ebpf_api_map_info_free(count, maps);
        REQUIRE(visible_map_ids().empty());
    }
}

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("namespace_ND16_two_real_RPC_clients_load_and_execute_concurrently", "[namespace][driver]")
{
    namespace_scope scope;
#if !defined(CONFIG_BPF_JIT_DISABLED) && !defined(CONFIG_BPF_INTERPRETER_DISABLED)
    auto execution = GENERATE(EBPF_EXECUTION_JIT, EBPF_EXECUTION_INTERPRET);
#elif !defined(CONFIG_BPF_JIT_DISABLED)
    auto execution = EBPF_EXECUTION_JIT;
#else
    auto execution = EBPF_EXECUTION_INTERPRET;
#endif
    child_pin_cleanup cleanup(scope.device.value);
    for (const GUID* selected : {&scope.a, &scope.b}) {
        cleanup.owned.emplace_back(*selected, "/ebpf/global/port_map");
        cleanup.owned.emplace_back(*selected, "/ebpf/global/outer_map");
    }
    std::unique_ptr<unique_handle> control(duplicate_inheritable(scope.device.value));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    unique_handle start(CreateEventW(&attributes, TRUE, FALSE, nullptr));
    unique_handle a_ready(CreateEventW(&attributes, TRUE, FALSE, nullptr));
    unique_handle b_ready(CreateEventW(&attributes, TRUE, FALSE, nullptr));
    REQUIRE(start.value != nullptr);
    REQUIRE(a_ready.value != nullptr);
    REQUIRE(b_ready.value != nullptr);
    const std::string mode = std::to_string(static_cast<uint32_t>(execution));
    child_process a(
        "load " + number(control->value) + " " + number(start.value) + " " + guid_bytes(scope.a) + " unused " + mode +
            " 1611 " + number(a_ready.value),
        {control->value, start.value, a_ready.value});
    child_process b(
        "load " + number(control->value) + " " + number(start.value) + " " + guid_bytes(scope.b) + " unused " + mode +
            " 1622 " + number(b_ready.value),
        {control->value, start.value, b_ready.value});
    REQUIRE(WaitForSingleObject(a_ready.value, 30000) == WAIT_OBJECT_0);
    REQUIRE(WaitForSingleObject(b_ready.value, 30000) == WAIT_OBJECT_0);
    REQUIRE(SetEvent(start.value));
    DWORD a_result = a.wait(), b_result = b.wait();
    INFO("RPC child outcomes: 0=executed, 41=blocked by policy, 42=unsupported: " << a_result << "," << b_result);
    REQUIRE(a_result == b_result);
    REQUIRE((a_result == 0 || a_result == 41 || a_result == 42));
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    REQUIRE(visible_map_ids().empty());
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    REQUIRE(visible_map_ids().empty());
}
#endif

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("namespace_ND16_ND17_interpreter_namespace_local_reuse", "[namespace][driver][interpreter]")
{
    namespace_load_reuse(EBPF_EXECUTION_INTERPRET);
}
#endif

TEST_CASE("namespace_ND02_ND06_ND09_program_link_discovery_and_retained_handles", "[namespace][driver][native]")
{
    namespace_scope scope;
    auto a = load_namespace_object("test_sample_ebpf", EBPF_EXECUTION_NATIVE);
    bpf_program* a_program = bpf_object__next_program(a.get(), nullptr);
    REQUIRE(a_program != nullptr);
    int a_fd = bpf_program__fd(a_program);
    test_map a_bound(901);
    unique_fd a_array;
    a_array.value = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, "a_programs", 4, 4, 1, nullptr);
    REQUIRE(a_array.value > 0);
    uint32_t key = 0;
    REQUIRE(bpf_map_update_elem(a_array.value, &key, &a_fd, BPF_ANY) == 0);
    bpf_prog_info program_info{};
    uint32_t size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(a_fd, &program_info, &size) == 0);
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> a_link(bpf_program__attach(a_program), bpf_link__destroy);
    REQUIRE(a_link != nullptr);
    bpf_link_info link_info{};
    size = sizeof(link_info);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_link__fd(a_link.get()), &link_info, &size) == 0);
    const std::string path = new_path();
    test_pin program_pin(scope.device.value, a_fd, path + "-program");
    test_pin link_pin(scope.device.value, bpf_link__fd(a_link.get()), path + "-link");
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    REQUIRE(bpf_prog_get_fd_by_id(program_info.id) == -ENOENT);
    REQUIRE(bpf_link_get_fd_by_id(link_info.id) == -ENOENT);
    verify_raw_open<bpf_prog_info>(scope.device.value, EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID, program_info.id, false);
    verify_raw_open<bpf_link_info>(scope.device.value, EBPF_OPERATION_GET_LINK_HANDLE_BY_ID, link_info.id, false);
    REQUIRE(bpf_obj_get((path + "-program").c_str()) == -ENOENT);
    REQUIRE(bpf_obj_get((path + "-link").c_str()) == -ENOENT);
    bpf_prog_info held_program{};
    size = sizeof(held_program);
    REQUIRE(bpf_obj_get_info_by_fd(a_fd, &held_program, &size) == 0);
    REQUIRE(held_program.id == program_info.id);
    REQUIRE(bpf_prog_bind_map(a_fd, a_bound.fd, nullptr) == 0);
    REQUIRE(bpf_map_update_elem(a_array.value, &key, &a_fd, BPF_ANY) == 0);
    REQUIRE(bpf_program__attach(a_program) == nullptr);
    REQUIRE(errno == EINVAL);
    REQUIRE(bpf_link_detach(bpf_link__fd(a_link.get())) == 0);
    REQUIRE(bpf_obj_pin(a_fd, (path + "-foreign").c_str()) == -EINVAL);
    auto b = load_namespace_object("test_sample_ebpf", EBPF_EXECUTION_NATIVE);
    bpf_program* b_program = bpf_object__next_program(b.get(), nullptr);
    REQUIRE(b_program != nullptr);
    bpf_prog_info b_info{};
    size = sizeof(b_info);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_program__fd(b_program), &b_info, &size) == 0);
    test_map b_bound(902);
    REQUIRE(bpf_prog_bind_map(bpf_program__fd(b_program), b_bound.fd, nullptr) == 0);
    bpf_prog_info before_bind{};
    size = sizeof(before_bind);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_program__fd(b_program), &before_bind, &size) == 0);
    REQUIRE(bpf_prog_bind_map(bpf_program__fd(b_program), a_bound.fd, nullptr) == -EINVAL);
    bpf_prog_info after_bind{};
    size = sizeof(after_bind);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_program__fd(b_program), &after_bind, &size) == 0);
    REQUIRE(after_bind.nr_map_ids == before_bind.nr_map_ids);
    unique_fd b_array;
    b_array.value = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, "b_programs", 4, 4, 1, nullptr);
    REQUIRE(b_array.value > 0);
    int b_fd = bpf_program__fd(b_program);
    REQUIRE(bpf_map_update_elem(b_array.value, &key, &b_fd, BPF_ANY) == 0);
    REQUIRE(bpf_map_update_elem(b_array.value, &key, &a_fd, BPF_ANY) == -EINVAL);
    uint32_t preserved_program = 0;
    REQUIRE(bpf_map_lookup_elem(b_array.value, &key, &preserved_program) == 0);
    REQUIRE(preserved_program == b_info.id);
    REQUIRE(read_marker(a_bound.fd) == 901);
    REQUIRE(read_marker(b_bound.fd) == 902);
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> b_link(bpf_program__attach(b_program), bpf_link__destroy);
    REQUIRE(b_link != nullptr);
    bpf_link_info b_link_info{};
    size = sizeof(b_link_info);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_link__fd(b_link.get()), &b_link_info, &size) == 0);
    test_pin b_program_pin(scope.device.value, bpf_program__fd(b_program), path + "-program");
    test_pin b_link_pin(scope.device.value, bpf_link__fd(b_link.get()), path + "-link");
    verify_deprecated_program_path(scope.device.value, path + "-program");
    uint32_t enumerated;
    REQUIRE(bpf_prog_get_next_id(0, &enumerated) == 0);
    REQUIRE(enumerated == b_info.id);
    REQUIRE(bpf_prog_get_next_id(enumerated, &enumerated) == -ENOENT);
    REQUIRE(bpf_link_get_next_id(0, &enumerated) == 0);
    REQUIRE(enumerated == b_link_info.id);
    REQUIRE(bpf_link_get_next_id(enumerated, &enumerated) == -ENOENT);
    verify_raw_next(scope.device.value, EBPF_OPERATION_GET_NEXT_PROGRAM_ID, program_info.id, b_info.id);
    verify_raw_next(scope.device.value, EBPF_OPERATION_GET_NEXT_LINK_ID, link_info.id, b_link_info.id);
    verify_raw_open<bpf_prog_info>(scope.device.value, EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID, b_info.id, true);
    verify_raw_open<bpf_link_info>(scope.device.value, EBPF_OPERATION_GET_LINK_HANDLE_BY_ID, b_link_info.id, true);
    REQUIRE(ebpf_set_namespace(&null_namespace) == EBPF_SUCCESS);
    REQUIRE(bpf_prog_get_fd_by_id(program_info.id) == -ENOENT);
    REQUIRE(bpf_prog_get_fd_by_id(b_info.id) == -ENOENT);
    REQUIRE(bpf_link_get_fd_by_id(link_info.id) == -ENOENT);
    REQUIRE(bpf_link_get_fd_by_id(b_link_info.id) == -ENOENT);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    int found_program = bpf_prog_get_fd_by_id(program_info.id);
    int found_link = bpf_link_get_fd_by_id(link_info.id);
    REQUIRE(found_program > 0);
    REQUIRE(found_link > 0);
    REQUIRE(ebpf_close_fd(found_program) == EBPF_SUCCESS);
    REQUIRE(ebpf_close_fd(found_link) == EBPF_SUCCESS);
    REQUIRE(bpf_prog_get_fd_by_id(b_info.id) == -ENOENT);
    REQUIRE(bpf_link_get_fd_by_id(b_link_info.id) == -ENOENT);
    REQUIRE(bpf_link_detach(bpf_link__fd(b_link.get())) == 0);
    REQUIRE(bpf_link__unpin(a_link.get()) == -ENOENT); // Raw pin does not fabricate a libbpf cache entry.
}

TEST_CASE("namespace_ND18_foreign_inner_template_and_map_graph_edges", "[namespace][driver]")
{
    namespace_scope scope;
    test_map a(1801);
    bpf_map_create_opts opts{};
    opts.sz = sizeof(opts);
    opts.inner_map_fd = a.fd;
    unique_fd a_outer;
    a_outer.value = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "a_outer", 4, 4, 1, &opts);
    REQUIRE(a_outer.value > 0);
    uint32_t key = 0;
    REQUIRE(bpf_map_update_elem(a_outer.value, &key, &a.fd, BPF_ANY) == 0);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    REQUIRE(bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "foreign_template", 4, 4, 1, &opts) == -EINVAL);
    std::vector<uint8_t> bytes(offsetof(ebpf_operation_create_map_request_t, data));
    auto raw_create = reinterpret_cast<ebpf_operation_create_map_request_t*>(bytes.data());
    raw_create->header = {static_cast<uint16_t>(bytes.size()), EBPF_OPERATION_CREATE_MAP};
    raw_create->ebpf_map_definition.type = BPF_MAP_TYPE_HASH_OF_MAPS;
    raw_create->ebpf_map_definition.key_size = 4;
    raw_create->ebpf_map_definition.value_size = 4;
    raw_create->ebpf_map_definition.max_entries = 1;
    raw_create->inner_map_handle = _get_osfhandle(a.fd);
    ebpf_operation_create_map_reply_t rejected{};
    REQUIRE(
        raw_ioctl(scope.device.value, bytes.data(), static_cast<DWORD>(bytes.size()), &rejected, sizeof(rejected)) ==
        ERROR_INVALID_PARAMETER);
    test_map b(1802);
    opts.inner_map_fd = b.fd;
    unique_fd b_outer;
    b_outer.value = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "b_outer", 4, 4, 1, &opts);
    REQUIRE(b_outer.value > 0);
    REQUIRE(bpf_map_update_elem(b_outer.value, &key, &b.fd, BPF_ANY) == 0);
    REQUIRE(bpf_map_update_elem(b_outer.value, &key, &a.fd, BPF_ANY) == -EINVAL);
    uint32_t retained_id = 0;
    REQUIRE(bpf_map_lookup_elem(b_outer.value, &key, &retained_id) == 0);
    REQUIRE(retained_id == b.id);
    REQUIRE(bpf_map_update_elem(a_outer.value, &key, &a.fd, BPF_ANY) == 0);
    REQUIRE(read_marker(a.fd) == 1801);
    REQUIRE(read_marker(b.fd) == 1802);
}

TEST_CASE("namespace_ND03_ND22_SDK_global_async_transport_across_switch", "[namespace][driver]")
{
    namespace_scope scope;
    unique_fd first_map(bpf_map_create(BPF_MAP_TYPE_RINGBUF, "namespace_sdk_async", 0, 0, 65536, nullptr));
    unique_fd second_map;
    REQUIRE(first_map.value > 0);
    const uint32_t first_id = map_id(first_map.value);
    struct callback_context
    {
        std::promise<uint32_t> received;
        std::atomic<uint32_t> count{0};
    } first_callback, second_callback;
    auto subscribe = [](int fd, callback_context& context) {
        // Auto-callback mode exercises the SDK's shared async device, not a replacement raw handle.
        ebpf_ring_buffer_opts options{.sz = sizeof(options), .flags = EBPF_RINGBUF_FLAG_AUTO_CALLBACK};
#pragma warning(suppress : 4996)
        auto ring = ebpf_ring_buffer__new(
            fd,
            [](void* callback, void* data, size_t size) -> int {
                auto state = static_cast<callback_context*>(callback);
                if (state->count.fetch_add(1) == 0) {
                    uint32_t marker = 0;
                    if (size == sizeof(marker)) {
                        memcpy(&marker, data, size);
                    }
                    state->received.set_value(marker);
                }
                return 0;
            },
            &context,
            &options);
        REQUIRE(ring != nullptr);
        return std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)>(ring, ring_buffer__free);
    };
    auto first = subscribe(first_map.value, first_callback);
    auto first_received = first_callback.received.get_future();
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    second_map.value = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "namespace_sdk_async", 0, 0, 65536, nullptr);
    REQUIRE(second_map.value > 0);
    const uint32_t second_id = map_id(second_map.value);
    auto second = subscribe(second_map.value, second_callback);
    auto second_received = second_callback.received.get_future();
    unique_fd hidden_first(bpf_map_get_fd_by_id(first_id));
    REQUIRE(hidden_first.value == -ENOENT);
    unique_fd visible_second(bpf_map_get_fd_by_id(second_id));
    REQUIRE(visible_second.value > 0);
    auto write = [](int fd, uint32_t marker) {
#pragma warning(suppress : 4996)
        auto result = ebpf_ring_buffer_map_write(fd, &marker, sizeof(marker));
        REQUIRE(result == EBPF_SUCCESS);
    };
    write(first_map.value, 3101);
    write(second_map.value, 3102);
    REQUIRE(first_received.wait_for(std::chrono::seconds(30)) == std::future_status::ready);
    REQUIRE(second_received.wait_for(std::chrono::seconds(30)) == std::future_status::ready);
    REQUIRE(first_received.get() == 3101);
    REQUIRE(second_received.get() == 3102);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    unique_fd visible_first(bpf_map_get_fd_by_id(first_id));
    REQUIRE(visible_first.value > 0);
    unique_fd hidden_second(bpf_map_get_fd_by_id(second_id));
    REQUIRE(hidden_second.value == -ENOENT);
    second.reset();
    first.reset();
    REQUIRE(first_callback.count == 1);
    REQUIRE(second_callback.count == 1);
    GUID selected{};
    REQUIRE(ebpf_get_namespace(&selected) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(selected, scope.a));
}

TEST_CASE("namespace_ND22_pending_async_query_switch_and_terminal_order", "[namespace][driver]")
{
    namespace_scope scope;
    auto terminal_order = GENERATE(0u, 1u, 2u); // Cancel, complete, or close the transport while pending.
    unique_fd ring;
    ring.value = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "namespace_async", 0, 0, 65536, nullptr);
    REQUIRE(ring.value > 0);
    unique_handle asynchronous(CreateFileW(
        device_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, nullptr));
    REQUIRE(asynchronous.value != INVALID_HANDLE_VALUE);
    unique_handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    REQUIRE(event.value != nullptr);
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.value;
    ebpf_operation_map_async_query_request_t request{
        {sizeof(request), EBPF_OPERATION_MAP_ASYNC_QUERY}, _get_osfhandle(ring.value), 0, 0};
    ebpf_operation_map_async_query_reply_t reply{};
    DWORD returned = 0;
    REQUIRE_FALSE(DeviceIoControl(
        asynchronous.value, namespace_ioctl, &request, sizeof(request), &reply, sizeof(reply), &returned, &overlapped));
    REQUIRE(GetLastError() == ERROR_IO_PENDING);
    struct pending_cleanup
    {
        ~pending_cleanup()
        {
            if (active) {
                CancelIoEx(device, overlapped);
                CHECK(WaitForSingleObject(overlapped->hEvent, 30000) == WAIT_OBJECT_0);
            }
        }
        HANDLE device;
        OVERLAPPED* overlapped;
        bool active = true;
    } pending{asynchronous.value, &overlapped};
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    if (terminal_order == 0) {
        REQUIRE(CancelIoEx(asynchronous.value, &overlapped));
    } else if (terminal_order == 2) {
        REQUIRE(CloseHandle(asynchronous.value));
        asynchronous.value = nullptr;
    } else {
        alignas(ebpf_operation_map_write_data_request_t)
            std::array<uint8_t, offsetof(ebpf_operation_map_write_data_request_t, data) + sizeof(uint32_t)>
                buffer{};
        auto write = reinterpret_cast<ebpf_operation_map_write_data_request_t*>(buffer.data());
        write->header = {static_cast<uint16_t>(buffer.size()), EBPF_OPERATION_MAP_WRITE_DATA};
        write->map_handle = _get_osfhandle(ring.value);
        uint32_t marker = 2201;
        memcpy(write->data, &marker, sizeof(marker));
        REQUIRE(raw_ioctl(scope.device.value, buffer.data(), static_cast<DWORD>(buffer.size())) == ERROR_SUCCESS);
    }
    REQUIRE(WaitForSingleObject(event.value, 30000) == WAIT_OBJECT_0);
    pending.active = false;
    if (terminal_order == 2) {
        REQUIRE(static_cast<uint32_t>(overlapped.Internal) == 0xc0000120u); // STATUS_CANCELLED.
    } else if (terminal_order == 0) {
        BOOL completed = GetOverlappedResult(asynchronous.value, &overlapped, &returned, FALSE);
        REQUIRE_FALSE(completed);
        REQUIRE(GetLastError() == ERROR_OPERATION_ABORTED);
    } else {
        BOOL completed = GetOverlappedResult(asynchronous.value, &overlapped, &returned, FALSE);
        REQUIRE(completed);
        REQUIRE(returned == sizeof(reply));
        REQUIRE(reply.async_query_result.producer > reply.async_query_result.consumer);
        REQUIRE_FALSE(CancelIoEx(asynchronous.value, &overlapped));
        REQUIRE(GetLastError() == ERROR_NOT_FOUND);
    }
    GUID current{};
    REQUIRE(raw_get(scope.device.value, current) == ERROR_SUCCESS);
    REQUIRE(IsEqualGUID(current, scope.b));
}

TEST_CASE(
    "namespace_ND25_conditional_rollback_does_not_delete_replacement_or_current_namespace_pin", "[namespace][driver]")
{
    namespace_scope scope;
    const std::string path = new_path();
    test_map original(251), replacement(252);
    test_pin owned(scope.device.value, original.fd, path);
    REQUIRE(ebpf_object_unpin(path.c_str()) == EBPF_SUCCESS);
    test_pin changed(scope.device.value, replacement.fd, path);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    test_map foreign(253);
    test_pin b(scope.device.value, foreign.fd, path);
    REQUIRE(
        conditional_unpin(scope.device.value, reinterpret_cast<HANDLE>(_get_osfhandle(original.fd)), path) ==
        ERROR_NOT_FOUND);
    verify_pin(path, foreign.id, 253);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    verify_pin(path, replacement.id, 252);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    REQUIRE(
        conditional_unpin(scope.device.value, reinterpret_cast<HANDLE>(_get_osfhandle(replacement.fd)), path) ==
        ERROR_SUCCESS);
    verify_pin(path, foreign.id, 253);
    REQUIRE(read_marker(original.fd) == 251);
    REQUIRE(read_marker(replacement.fd) == 252);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    REQUIRE(bpf_obj_get(path.c_str()) == -ENOENT);
}

TEST_CASE("namespace_ND22_worker_exit_cancels_pending_request_without_destroying_held_pin", "[namespace][driver]")
{
    namespace_scope scope;
    const std::string path = new_path();
    child_pin_cleanup cleanup(scope.device.value);
    cleanup.owned.emplace_back(scope.b, path);
    std::unique_ptr<unique_handle> control(duplicate_inheritable(scope.device.value));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    unique_handle ready(CreateEventW(&attributes, TRUE, FALSE, nullptr));
    REQUIRE(ready.value != nullptr);
    child_process child(
        "async-exit " + number(control->value) + " 0 " + guid_bytes(scope.b) + " " + path + " 0 0 " +
            number(ready.value),
        {control->value, ready.value});
    REQUIRE(WaitForSingleObject(ready.value, 30000) == WAIT_OBJECT_0);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    unique_fd observer;
    observer.value = bpf_obj_get(path.c_str());
    REQUIRE(observer.value > 0);
    test_pin pin(scope.device.value, observer.value, path, false);
    bpf_map_info before{};
    uint32_t size = sizeof(before);
    REQUIRE(bpf_obj_get_info_by_fd(observer.value, &before, &size) == 0);
    REQUIRE(before.type == BPF_MAP_TYPE_RINGBUF);
    REQUIRE(TerminateProcess(child.process.hProcess, 78));
    REQUIRE(child.wait() == 78);
    bpf_map_info after{};
    size = sizeof(after);
    REQUIRE(bpf_obj_get_info_by_fd(observer.value, &after, &size) == 0);
    REQUIRE(after.id == before.id);
    REQUIRE(after.type == BPF_MAP_TYPE_RINGBUF);
    GUID current{};
    REQUIRE(ebpf_get_namespace(&current) == EBPF_SUCCESS);
    REQUIRE(IsEqualGUID(current, scope.b));
}

TEST_CASE("namespace_ND26_high_level_native_load_serializes_with_API_SET", "[namespace][driver][native]")
{
    namespace_scope scope;
    std::promise<void> start;
    auto gate = start.get_future();
    auto setter = std::async(std::launch::async, [&]() {
        gate.wait();
        return ebpf_set_namespace(&scope.b);
    });
    start.set_value();
    auto object = load_namespace_object("map_reuse", EBPF_EXECUTION_NATIVE);
    REQUIRE(setter.get() == EBPF_SUCCESS);
    int port = bpf_object__find_map_fd_by_name(object.get(), "port_map");
    int outer = bpf_object__find_map_fd_by_name(object.get(), "outer_map");
    REQUIRE(port > 0);
    REQUIRE(outer > 0);
    test_pin port_pin(scope.device.value, port, "/ebpf/global/port_map", false);
    test_pin outer_pin(scope.device.value, outer, "/ebpf/global/outer_map", false);
    std::vector<uint32_t> map_ids;
    bpf_map* map;
    bpf_object__for_each_map(map, object.get()) { map_ids.push_back(map_id(bpf_map__fd(map))); }
    bpf_program* program = bpf_object__next_program(object.get(), nullptr);
    REQUIRE(program != nullptr);
    bpf_prog_info info{};
    uint32_t length = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_program__fd(program), &info, &length) == 0);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    auto a_ids = visible_map_ids();
    int a_program = bpf_prog_get_fd_by_id(info.id);
    bool created_in_a = a_program > 0;
    if (a_program > 0) {
        REQUIRE(ebpf_close_fd(a_program) == EBPF_SUCCESS);
    } else {
        REQUIRE(a_program == -ENOENT);
    }
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    auto b_ids = visible_map_ids();
    int b_program = bpf_prog_get_fd_by_id(info.id);
    REQUIRE((b_program > 0) != created_in_a);
    if (b_program > 0) {
        REQUIRE(ebpf_close_fd(b_program) == EBPF_SUCCESS);
    } else {
        REQUIRE(b_program == -ENOENT);
    }
    for (uint32_t id : map_ids) {
        REQUIRE(a_ids.contains(id) == created_in_a);
        REQUIRE(b_ids.contains(id) != created_in_a);
    }
    uint32_t key = 0, marker = 2601;
    REQUIRE(bpf_map_update_elem(port, &key, &marker, BPF_ANY) == 0);
    REQUIRE(read_marker(port) == marker);
}

TEST_CASE(
    "namespace_ND19_multi_attach_context_detach_is_scoped_and_held_link_detach_is_not", "[namespace][driver][native]")
{
    namespace_scope scope;
    wsa_helper_t wsa;
    struct socket_owner
    {
        socket_owner() : value(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) {}
        ~socket_owner()
        {
            if (value != INVALID_SOCKET) {
                closesocket(value);
            }
        }
        SOCKET value;
    } server;
    REQUIRE(server.value != INVALID_SOCKET);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(bind(server.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    int address_length = sizeof(address);
    REQUIRE(getsockname(server.value, reinterpret_cast<sockaddr*>(&address), &address_length) == 0);
    REQUIRE(listen(server.value, 4) == 0);
    auto a = load_namespace_object("cgroup_sock_addr", EBPF_EXECUTION_NATIVE, BPF_PROG_TYPE_CGROUP_SOCK_ADDR);
    bpf_program* a_program = bpf_object__find_program_by_name(a.get(), "authorize_connect4");
    REQUIRE(a_program != nullptr);
    REQUIRE(bpf_program__fd(a_program) > 0);
    uint32_t compartment = 0;
    bpf_link* attached_a = nullptr;
    REQUIRE(
        ebpf_program_attach_by_fd(
            bpf_program__fd(a_program),
            &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
            &compartment,
            sizeof(compartment),
            &attached_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> a_link(attached_a, bpf_link__destroy);
    REQUIRE(a_link != nullptr);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    auto b = load_namespace_object("cgroup_sock_addr", EBPF_EXECUTION_NATIVE, BPF_PROG_TYPE_CGROUP_SOCK_ADDR);
    bpf_program* b_program = bpf_object__find_program_by_name(b.get(), "authorize_connect4");
    REQUIRE(b_program != nullptr);
    REQUIRE(bpf_program__fd(b_program) > 0);
    bpf_link* attached_b = nullptr;
    REQUIRE(
        ebpf_program_attach_by_fd(
            bpf_program__fd(b_program),
            &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
            &compartment,
            sizeof(compartment),
            &attached_b) == EBPF_SUCCESS);
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> b_link(attached_b, bpf_link__destroy);
    REQUIRE(b_link != nullptr);
    int a_cookies = bpf_object__find_map_fd_by_name(a.get(), "socket_cookie_map");
    int b_cookies = bpf_object__find_map_fd_by_name(b.get(), "socket_cookie_map");
    REQUIRE(a_cookies > 0);
    REQUIRE(b_cookies > 0);
    connection_tuple_t key{};
    key.remote_ip.ipv4 = address.sin_addr.s_addr;
    key.remote_port = address.sin_port;
    key.protocol = IPPROTO_TCP;
    socket_owner first;
    REQUIRE(first.value != INVALID_SOCKET);
    REQUIRE(connect(first.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    uint64_t a_first = 0, b_first = 0;
    REQUIRE(bpf_map_lookup_elem(a_cookies, &key, &a_first) == 0);
    REQUIRE(bpf_map_lookup_elem(b_cookies, &key, &b_first) == 0);
    REQUIRE(a_first != 0);
    REQUIRE(b_first != 0);
    REQUIRE(
        raw_detach_by_context(
            scope.device.value, bpf_program__fd(a_program), EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, compartment) ==
        ERROR_SUCCESS);
    bpf_link_info still_a{};
    uint32_t length = sizeof(still_a);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_link__fd(a_link.get()), &still_a, &length) == 0);
    REQUIRE(still_a.prog_id != 0);
    REQUIRE(
        raw_detach_by_context(
            scope.device.value, ebpf_fd_invalid, EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, compartment) == ERROR_SUCCESS);
    bpf_link_info detached_b{};
    length = sizeof(detached_b);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_link__fd(b_link.get()), &detached_b, &length) == 0);
    REQUIRE(detached_b.prog_id == 0);
    socket_owner second;
    REQUIRE(second.value != INVALID_SOCKET);
    REQUIRE(connect(second.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    uint64_t a_second = 0, b_second = 0;
    REQUIRE(bpf_map_lookup_elem(a_cookies, &key, &a_second) == 0);
    REQUIRE(bpf_map_lookup_elem(b_cookies, &key, &b_second) == 0);
    REQUIRE(a_second != a_first);
    REQUIRE(b_second == b_first);
    REQUIRE(bpf_link_detach(bpf_link__fd(a_link.get())) == 0);
    length = sizeof(still_a);
    REQUIRE(bpf_obj_get_info_by_fd(bpf_link__fd(a_link.get()), &still_a, &length) == 0);
    REQUIRE(still_a.prog_id == 0);
}

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("namespace_ND25_failed_load_preserves_reused_and_foreign_pins", "[namespace][driver]")
{
    namespace_scope scope;
    test_map reused(2501);
    test_pin reused_pin(scope.device.value, reused.fd, "/ebpf/global/port_map");
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    test_map foreign(2502);
    test_pin foreign_pin(scope.device.value, foreign.fd, "/ebpf/global/outer_map");
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
    object_ptr rejected(bpf_object__open("map_reuse.o"), bpf_object__close);
    REQUIRE(rejected != nullptr);
    bpf_program* program = bpf_object__next_program(rejected.get(), nullptr);
    REQUIRE(program != nullptr);
    REQUIRE(bpf_program__set_type(program, static_cast<bpf_prog_type>(UINT32_MAX)) == 0);
    REQUIRE(bpf_object__load(rejected.get()) == -EINVAL);
    REQUIRE(bpf_obj_get("/ebpf/global/outer_map") == -ENOENT);
    verify_pin("/ebpf/global/port_map", reused.id, 2501);
    REQUIRE(ebpf_set_namespace(&scope.b) == EBPF_SUCCESS);
    verify_pin("/ebpf/global/outer_map", foreign.id, 2502);
    REQUIRE(ebpf_set_namespace(&scope.a) == EBPF_SUCCESS);
#if !defined(CONFIG_BPF_JIT_DISABLED)
    auto retried = load_namespace_object("map_reuse", EBPF_EXECUTION_JIT);
#else
    auto retried = load_namespace_object("map_reuse", EBPF_EXECUTION_INTERPRET);
#endif
    int outer = bpf_object__find_map_fd_by_name(retried.get(), "outer_map");
    REQUIRE(outer > 0);
    test_pin successful_retry(scope.device.value, outer, "/ebpf/global/outer_map", false);
    REQUIRE(map_id(bpf_object__find_map_fd_by_name(retried.get(), "port_map")) == reused.id);
    REQUIRE(read_marker(reused.fd) == 2501);
}
#endif
