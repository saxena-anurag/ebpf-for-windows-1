// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "links.h"
#include "platform.h"
#include "tokens.h"
#include "utilities.h"

#include <windows.h>
#include <iomanip>
#include <iostream>
#include <netsh.h>
#include <string>
#include <vector>

namespace {
enum class link_operation
{
    detach,
    pin,
    unpin
};

unsigned long
link_command(LPWSTR* argv, DWORD current_index, DWORD argc, link_operation operation)
{
    TAG_TYPE tags[] = {
        {TOKEN_ID, NS_REQ_PRESENT, FALSE},
        {TOKEN_PINPATH, NS_REQ_PRESENT, FALSE},
    };
    unsigned long tag_type[_countof(tags)]{};
    auto count = operation == link_operation::detach ? 1ul : 2ul;
    auto status = PreprocessCommand(nullptr, argv, current_index, argc, tags, count, count, count, tag_type);
    if (status != NO_ERROR) {
        return status;
    }
    const wchar_t* values[2]{};
    for (DWORD i = current_index; i < argc; i++) {
        auto index = tag_type[i - current_index];
        if (index >= count || values[index]) {
            return ERROR_INVALID_SYNTAX;
        }
        values[index] = argv[i];
    }
    uint32_t id;
    if (!parse_uint32(values[0], id) || !id) {
        std::cerr << "error: invalid link ID\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    std::string path = values[1] ? down_cast_from_wstring(values[1]) : std::string();
    if (operation != link_operation::detach && path.empty()) {
        return ERROR_INVALID_SYNTAX;
    }
    auto fd = bpf_link_get_fd_by_id(id);
    if (fd < 0) {
        std::cerr << "error " << errno << ": could not open link\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    int error = 0;
    switch (operation) {
    case link_operation::detach:
        if (bpf_link_detach(fd) < 0) {
            error = errno;
        }
        break;
    case link_operation::pin:
        if (bpf_obj_pin(fd, path.c_str()) < 0) {
            error = errno;
        }
        break;
    case link_operation::unpin: {
        auto pinned_fd = bpf_obj_get(path.c_str());
        if (pinned_fd < 0) {
            error = errno;
            break;
        }
        bpf_link_info info{};
        uint32_t size = sizeof(info);
        ebpf_object_type_t type;
        auto result = ebpf_object_get_info_by_fd(pinned_fd, &info, &size, &type);
        if (result != EBPF_SUCCESS || type != EBPF_OBJECT_LINK || info.id != id) {
            error = EINVAL;
        } else {
            result = ebpf_object_unpin(path.c_str());
            if (result != EBPF_SUCCESS) {
                error = static_cast<int>(result);
            }
        }
        Platform::_close(pinned_fd);
        break;
    }
    }
    Platform::_close(fd);
    if (error) {
        std::cerr << "error " << error << ": could not manage link\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    return NO_ERROR;
}
} // namespace

#define LINK_HANDLER(name, operation)                                                                          \
    unsigned long name(                                                                                        \
        LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done) \
    try {                                                                                                      \
        UNREFERENCED_PARAMETER(machine);                                                                       \
        UNREFERENCED_PARAMETER(flags);                                                                         \
        UNREFERENCED_PARAMETER(data);                                                                          \
        UNREFERENCED_PARAMETER(done);                                                                          \
        return link_command(argv, current_index, argc, link_operation::operation);                             \
    } catch (const std::bad_alloc&) {                                                                          \
        return ERROR_OUTOFMEMORY;                                                                              \
    } catch (const std::exception&) {                                                                          \
        return ERROR_INVALID_PARAMETER;                                                                        \
    }

LINK_HANDLER(handle_ebpf_delete_link, detach)
LINK_HANDLER(handle_ebpf_pin_link, pin)
LINK_HANDLER(handle_ebpf_unpin_link, unpin)

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_links(
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
    std::cout << "   Link  Program  Attach\n";
    std::cout << "     ID       ID  Type\n";
    std::cout << "=======  =======  =============\n";

    uint32_t link_id = 0;
    for (;;) {
        if (bpf_link_get_next_id(link_id, &link_id) < 0) {
            break;
        }

        fd_t link_fd = bpf_link_get_fd_by_id(link_id);
        if (link_fd < 0) {
            break;
        }

        struct bpf_link_info info;
        uint32_t info_size = (uint32_t)sizeof(info);
        if (bpf_obj_get_info_by_fd(link_fd, &info, &info_size) == 0) {
            const char* attach_type_name = ebpf_get_attach_type_name(&info.attach_type_uuid);

            printf("%7u%9u  %s\n", info.id, info.prog_id, attach_type_name);
        }

        Platform::_close(link_fd);
    }
    return EBPF_SUCCESS;
}
