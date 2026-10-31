// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "pins.h"
#include "platform.h"
#include "tokens.h"

#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_pins(
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
    std::cout << "     ID     Type  Path\n";
    std::cout << "=======  =======  ==============\n";

    // Read all pin paths.  Currently we get them in a non-deterministic
    // order, so we use a std::set to sort them in code point order.
    char pinpath[EBPF_MAX_PIN_PATH_LENGTH] = "";
    std::set<std::string> paths;
    for (;;) {
        ebpf_object_type_t object_type = EBPF_OBJECT_UNKNOWN;
        auto result = ebpf_get_next_pinned_object_path(pinpath, pinpath, sizeof(pinpath), &object_type);
        if (result == EBPF_NO_MORE_KEYS) {
            break;
        }
        if (result != EBPF_SUCCESS) {
            std::cerr << "error " << result << ": could not enumerate pins\n";
            return ERROR_SUPPRESS_OUTPUT;
        }
        paths.insert(pinpath);
    }

    // Now walk through all paths in code point order.
    for (auto path : paths) {
        int fd = bpf_obj_get(path.c_str());
        if (fd < 0) {
            if (errno == ENOENT) {
                continue;
            }
            std::cerr << "error " << errno << ": could not open pinned object\n";
            return ERROR_SUPPRESS_OUTPUT;
        }

        union
        {
            bpf_prog_info program;
            bpf_map_info map;
            bpf_link_info link;
        } info{};
        uint32_t info_size = (uint32_t)sizeof(info);
        ebpf_object_type_t type = EBPF_OBJECT_UNKNOWN;
        auto result = ebpf_object_get_info_by_fd(fd, &info, &info_size, &type);
        Platform::_close(fd);
        if (result != EBPF_SUCCESS) {
            std::cerr << "error " << result << ": could not get pinned object information\n";
            return ERROR_SUPPRESS_OUTPUT;
        }
        switch (type) {
        case EBPF_OBJECT_PROGRAM:
            printf("%7u  Program  %s\n", info.program.id, path.c_str());
            break;
        case EBPF_OBJECT_MAP:
            printf("%7u      Map  %s\n", info.map.id, path.c_str());
            break;
        case EBPF_OBJECT_LINK:
            printf("%7u     Link  %s\n", info.link.id, path.c_str());
            break;
        default:
            std::cerr << "error: unsupported pinned object type\n";
            return ERROR_SUPPRESS_OUTPUT;
        }
    }
    return NO_ERROR;
}
