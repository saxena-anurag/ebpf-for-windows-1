// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "maps.h"
#include "platform.h"
#include "tokens.h"
#include "utilities.h"

#include <cerrno>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <vector>

namespace {
class map_command_fd
{
  public:
    explicit map_command_fd(fd_t fd = ebpf_fd_invalid) : _fd(fd) {}
    ~map_command_fd()
    {
        if (_fd >= 0) {
            Platform::_close(_fd);
        }
    }
    map_command_fd(const map_command_fd&) = delete;
    map_command_fd&
    operator=(const map_command_fd&) = delete;
    fd_t
    get() const
    {
        return _fd;
    }

  private:
    fd_t _fd;
};

unsigned long
map_error(const char* operation, int error = errno)
{
    std::cerr << "error " << error << ": could not " << operation << "\n";
    return ERROR_SUPPRESS_OUTPUT;
}

unsigned long
map_input_error(const char* message)
{
    std::cerr << "error: " << message << "\n";
    return ERROR_SUPPRESS_OUTPUT;
}

template <size_t N>
unsigned long
parse_map_arguments(LPWSTR* argv, DWORD current_index, DWORD argc, TAG_TYPE (&tags)[N], const wchar_t* (&values)[N])
{
    unsigned long tag_type[N]{};
    auto status = PreprocessCommand(nullptr, argv, current_index, argc, tags, N, 0, N, tag_type);
    if (status != NO_ERROR) {
        return status;
    }
    for (DWORD i = current_index; i < argc; i++) {
        auto index = tag_type[i - current_index];
        if (index >= N || values[index] != nullptr) {
            return ERROR_INVALID_SYNTAX;
        }
        values[index] = argv[i];
    }
    for (size_t i = 0; i < N; i++) {
        if ((tags[i].dwRequired & NS_REQ_PRESENT) && values[i] == nullptr) {
            return ERROR_INVALID_SYNTAX;
        }
    }
    return NO_ERROR;
}

int
hex_digit(wchar_t digit)
{
    if (digit >= L'0' && digit <= L'9') {
        return digit - L'0';
    }
    if (digit >= L'a' && digit <= L'f') {
        return digit - L'a' + 10;
    }
    if (digit >= L'A' && digit <= L'F') {
        return digit - L'A' + 10;
    }
    return -1;
}

bool
parse_map_bytes(const wchar_t* text, size_t size, std::vector<uint8_t>& bytes)
{
    if (text == nullptr || size > SIZE_MAX / 2 || wcslen(text) != size * 2) {
        return false;
    }
    bytes.resize(size);
    for (size_t i = 0; i < size; i++) {
        int high = hex_digit(text[2 * i]);
        int low = hex_digit(text[2 * i + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        bytes[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

void
print_map_bytes(const char* label, const std::vector<uint8_t>& bytes)
{
    std::cout << label;
    for (auto byte : bytes) {
        printf("%02x", byte);
    }
    std::cout << "\n";
}

enum class map_operation
{
    lookup,
    update,
    remove,
    getnext,
    dump
};

unsigned long
map_element_command(LPWSTR* argv, DWORD current_index, DWORD argc, map_operation operation)
{
    TAG_TYPE tags[] = {
        {TOKEN_ID, NS_REQ_PRESENT, FALSE},
        {TOKEN_MAP_KEY, NS_REQ_ZERO, FALSE},
        {TOKEN_MAP_VALUE, NS_REQ_ZERO, FALSE},
        {TOKEN_MAP_FLAGS, NS_REQ_ZERO, FALSE},
    };
    const wchar_t* values[_countof(tags)]{};
    auto status = parse_map_arguments(argv, current_index, argc, tags, values);
    if (status != NO_ERROR) {
        return status;
    }
    uint32_t id;
    if (!parse_uint32(values[0], id) || id == 0) {
        return map_input_error("invalid map ID");
    }
    if ((operation != map_operation::update && (values[2] || values[3])) ||
        (operation == map_operation::dump && values[1])) {
        return ERROR_INVALID_SYNTAX;
    }
    map_command_fd fd(bpf_map_get_fd_by_id(id));
    if (fd.get() < 0) {
        return map_error("open map");
    }
    bpf_map_info info{};
    uint32_t info_size = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd.get(), &info, &info_size) < 0) {
        return map_error("get map information");
    }
    size_t value_size = info.value_size;
    if (BPF_MAP_TYPE_PER_CPU(info.type)) {
        auto cpu_count = libbpf_num_possible_cpus();
        uint64_t expanded_size = ((static_cast<uint64_t>(value_size) + 7) & ~7ull) * cpu_count;
        if (cpu_count <= 0 || expanded_size > (std::numeric_limits<uint32_t>::max)()) {
            return map_input_error("invalid per-CPU value size");
        }
        value_size = static_cast<size_t>(expanded_size);
    }

    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
    bool needs_key = operation != map_operation::dump && operation != map_operation::getnext;
    if (info.key_size == 0) {
        if (values[1]) {
            return map_input_error("this map does not accept a key");
        }
    } else if ((needs_key || values[1]) && !parse_map_bytes(values[1], info.key_size, key)) {
        return map_input_error("key must contain exactly keysize bytes as hexadecimal pairs");
    }

    switch (operation) {
    case map_operation::lookup:
        value.resize(value_size);
        if (bpf_map_lookup_elem(fd.get(), key.empty() ? nullptr : key.data(), value.data()) < 0) {
            return map_error("look up map element");
        }
        print_map_bytes("value: ", value);
        break;
    case map_operation::update: {
        if (!parse_map_bytes(values[2], value_size, value)) {
            return map_input_error("value must contain exactly valuesize bytes as hexadecimal pairs");
        }
        uint64_t update_flags = BPF_ANY;
        if (values[3]) {
            if (_wcsicmp(values[3], L"noexist") == 0) {
                update_flags = BPF_NOEXIST;
            } else if (_wcsicmp(values[3], L"exist") == 0) {
                update_flags = BPF_EXIST;
            } else if (_wcsicmp(values[3], L"any") != 0) {
                return map_input_error("flags must be any, noexist, or exist");
            }
        }
        // Lookup returns IDs for object-valued maps; updates consume an opened object fd instead.
        fd_t object_fd = ebpf_fd_invalid;
        if (info.type == BPF_MAP_TYPE_PROG_ARRAY || info.type == BPF_MAP_TYPE_HASH_OF_MAPS ||
            info.type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
            uint32_t object_id;
            if (value.size() != sizeof(object_id)) {
                return map_input_error("object-valued maps require a four-byte object ID");
            }
            memcpy(&object_id, value.data(), sizeof(object_id));
            object_fd = info.type == BPF_MAP_TYPE_PROG_ARRAY ? bpf_prog_get_fd_by_id(object_id)
                                                             : bpf_map_get_fd_by_id(object_id);
            if (object_fd < 0) {
                return map_error("open map value object");
            }
            memcpy(value.data(), &object_fd, sizeof(object_fd));
        }
        map_command_fd object(object_fd);
        if (bpf_map_update_elem(fd.get(), key.empty() ? nullptr : key.data(), value.data(), update_flags) < 0) {
            return map_error("update map element");
        }
        break;
    }
    case map_operation::remove:
        if (info.type == BPF_MAP_TYPE_QUEUE || info.type == BPF_MAP_TYPE_STACK) {
            value.resize(value_size);
            if (bpf_map_lookup_and_delete_elem(fd.get(), nullptr, value.data()) < 0) {
                return map_error("delete map element");
            }
        } else if (bpf_map_delete_elem(fd.get(), key.empty() ? nullptr : key.data()) < 0) {
            return map_error("delete map element");
        }
        break;
    case map_operation::getnext: {
        if (info.key_size == 0) {
            return map_input_error("this map does not support key iteration");
        }
        std::vector<uint8_t> next_key(info.key_size);
        if (bpf_map_get_next_key(fd.get(), key.empty() ? nullptr : key.data(), next_key.data()) < 0) {
            return map_error("get next map key");
        }
        print_map_bytes("key: ", next_key);
        break;
    }
    case map_operation::dump: {
        if (info.key_size == 0) {
            return map_input_error("this map does not support nondestructive key iteration");
        }
        std::set<std::vector<uint8_t>> visited;
        std::vector<uint8_t> next_key(info.key_size);
        value.resize(value_size);
        for (;;) {
            if (bpf_map_get_next_key(fd.get(), key.empty() ? nullptr : key.data(), next_key.data()) < 0) {
                if (errno == ENOENT) {
                    break;
                }
                return map_error("get next map key");
            }
            // Concurrent deletion can restart iteration. Never loop indefinitely or claim a full dump.
            if (visited.size() >= info.max_entries || !visited.insert(next_key).second) {
                return map_input_error("map changed during dump; retry");
            }
            if (bpf_map_lookup_elem(fd.get(), next_key.data(), value.data()) < 0) {
                return map_error("look up map element during dump");
            }
            print_map_bytes("key: ", next_key);
            print_map_bytes("value: ", value);
            key = next_key;
        }
        break;
    }
    }
    return NO_ERROR;
}
} // namespace

unsigned long
handle_ebpf_add_map(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
try {
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);
    TAG_TYPE tags[] = {
        {TOKEN_TYPE, NS_REQ_PRESENT, FALSE},
        {TOKEN_MAP_KEYSIZE, NS_REQ_PRESENT, FALSE},
        {TOKEN_MAP_VALUESIZE, NS_REQ_PRESENT, FALSE},
        {TOKEN_MAP_MAXENTRIES, NS_REQ_PRESENT, FALSE},
        {TOKEN_PINPATH, NS_REQ_PRESENT, FALSE},
        {TOKEN_MAP_NAME, NS_REQ_ZERO, FALSE},
        {TOKEN_MAP_INNERID, NS_REQ_ZERO, FALSE},
    };
    const wchar_t* values[_countof(tags)]{};
    auto status = parse_map_arguments(argv, current_index, argc, tags, values);
    if (status != NO_ERROR) {
        return status;
    }
    auto name = values[5] ? down_cast_from_wstring(values[5]) : std::string();
    auto type_name = down_cast_from_wstring(values[0]);
    bpf_map_type type = BPF_MAP_TYPE_UNSPEC;
    for (int candidate = 1; candidate < BPF_MAP_TYPE_MAX; candidate++) {
        const auto candidate_name = libbpf_bpf_map_type_str(static_cast<bpf_map_type>(candidate));
        if (candidate_name && type_name == candidate_name) {
            type = static_cast<bpf_map_type>(candidate);
            break;
        }
    }
    uint32_t key_size, value_size, max_entries, inner_id = 0;
    if (type == BPF_MAP_TYPE_UNSPEC) {
        return map_input_error("invalid map type");
    }
    if (!parse_uint32(values[1], key_size) || !parse_uint32(values[2], value_size) ||
        !parse_uint32(values[3], max_entries) || max_entries == 0 ||
        (values[6] && (!parse_uint32(values[6], inner_id) || inner_id == 0))) {
        return map_input_error("invalid map dimensions or inner map ID");
    }
    if (name.size() >= BPF_OBJ_NAME_LEN || *values[4] == L'\0') {
        return map_input_error("invalid map name or pin path");
    }
    bool map_in_map = type == BPF_MAP_TYPE_HASH_OF_MAPS || type == BPF_MAP_TYPE_ARRAY_OF_MAPS;
    if (map_in_map != (inner_id != 0)) {
        return map_input_error("innerid is required only for map-in-map types");
    }
    map_command_fd inner(inner_id ? bpf_map_get_fd_by_id(inner_id) : ebpf_fd_invalid);
    if (inner_id && inner.get() < 0) {
        return map_error("open inner map");
    }
    bpf_map_create_opts options{};
    options.sz = sizeof(options);
    if (inner_id) {
        options.inner_map_fd = inner.get();
    }
    map_command_fd fd(bpf_map_create(type, name.c_str(), key_size, value_size, max_entries, &options));
    if (fd.get() < 0) {
        return map_error("create map");
    }
    bpf_map_info info{};
    uint32_t info_size = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd.get(), &info, &info_size) < 0) {
        return map_error("get map information");
    }
    auto pinpath = down_cast_from_wstring(values[4]);
    if (bpf_obj_pin(fd.get(), pinpath.c_str()) < 0) {
        return map_error("pin new map");
    }
    std::cout << "Created with ID " << info.id << "\n";
    return NO_ERROR;
} catch (const std::bad_alloc&) {
    return map_error("create map", ENOMEM);
} catch (const std::exception&) {
    return map_input_error("invalid map argument");
}

#define MAP_ELEMENT_HANDLER(name, operation)                                                                   \
    unsigned long name(                                                                                        \
        LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done) \
    try {                                                                                                      \
        UNREFERENCED_PARAMETER(machine);                                                                       \
        UNREFERENCED_PARAMETER(flags);                                                                         \
        UNREFERENCED_PARAMETER(data);                                                                          \
        UNREFERENCED_PARAMETER(done);                                                                          \
        return map_element_command(argv, current_index, argc, map_operation::operation);                       \
    } catch (const std::bad_alloc&) {                                                                          \
        return map_error("access map", ENOMEM);                                                                \
    } catch (const std::exception&) {                                                                          \
        return map_input_error("invalid map argument");                                                        \
    }

MAP_ELEMENT_HANDLER(handle_ebpf_lookup_map, lookup)
MAP_ELEMENT_HANDLER(handle_ebpf_update_map, update)
MAP_ELEMENT_HANDLER(handle_ebpf_delete_map, remove)
MAP_ELEMENT_HANDLER(handle_ebpf_getnext_map, getnext)
MAP_ELEMENT_HANDLER(handle_ebpf_dump_map, dump)

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_maps(
    IN LPCWSTR machine,
    _Inout_updates_(argc) LPWSTR* argv,
    IN DWORD current_index,
    IN DWORD argc,
    IN DWORD flags,
    IN LPCVOID data,
    OUT BOOL* done)
{
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(current_index);
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    std::cout << "\n";
    std::cout << "                              Key  Value      Max  Inner\n";
    std::cout << "     ID            Map Type  Size   Size  Entries     ID  Pins  Name\n";
    std::cout << "=======  ==================  ====  =====  =======  =====  ====  ========\n";

    uint32_t map_id = 0;
    for (;;) {
        if (bpf_map_get_next_id(map_id, &map_id) < 0) {
            break;
        }

        fd_t map_fd = bpf_map_get_fd_by_id(map_id);
        if (map_fd < 0) {
            break;
        }

        struct bpf_map_info info;
        uint32_t info_size = (uint32_t)sizeof(info);
        if (bpf_obj_get_info_by_fd(map_fd, &info, &info_size) == 0) {
            printf(
                "%7u  %18s%6u%7u%9u%7d%6u  %s\n",
                info.id,
                libbpf_bpf_map_type_str(info.type),
                info.key_size,
                info.value_size,
                info.max_entries,
                info.inner_map_id,
                info.pinned_path_count,
                info.name);
        }

        Platform::_close(map_fd);
    }
    return NO_ERROR;
}

template <typename F>
unsigned long
handle_ebpf_pinunpin_map_common(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done, F&& f)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_ID, NS_REQ_PRESENT, FALSE},
        {TOKEN_PINPATH, NS_REQ_ZERO, FALSE},
    };
    const int ID_INDEX = 0;
    const int PINPATH_INDEX = 1;

    unsigned long tag_type[_countof(tags)]{};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);
    if (status != EBPF_SUCCESS) {
        return status;
    }

    std::string pinpath;
    uint32_t id = 0;

    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case PINPATH_INDEX:
            pinpath = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;

        case ID_INDEX:
            id = wcstoul(argv[current_index + i], nullptr, 0);
            break;
        }
    }

    auto fd = bpf_map_get_fd_by_id(id);
    if (fd < 0)
        return ERROR_INVALID_PARAMETER;

    if (pinpath.empty()) {
        bpf_map_info info{};
        uint32_t size = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &size) == 0) {
            pinpath = info.name;
        }
    }
    if (!pinpath.empty()) {
        status = f(fd, pinpath.c_str());
    } else {
        status = ERROR_INVALID_PARAMETER;
    }
    Platform::_close(fd);

    return status;
}

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_pin_map(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    return handle_ebpf_pinunpin_map_common(
        machine, argv, current_index, argc, flags, data, done, [](auto fd, auto pinpath) {
            return bpf_obj_pin(fd, pinpath);
        });
}

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_unpin_map(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    // Unpin map from a specific pin path.
    return handle_ebpf_pinunpin_map_common(
        machine, argv, current_index, argc, flags, data, done, [](auto, auto pinpath) {
            return ebpf_object_unpin(pinpath);
        });
}
