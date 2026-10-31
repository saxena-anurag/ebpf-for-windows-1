// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_api.h"
#include "namespaces.h"
#include "tokens.h"

#include <iostream>
#include <rpc.h>
#include <string>

unsigned long
handle_ebpf_set_namespace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {{TOKEN_NAMESPACE, NS_REQ_PRESENT, FALSE}};
    unsigned long tag_type[1]{};
    auto status = PreprocessCommand(nullptr, argv, current_index, argc, tags, 1, 1, 1, tag_type);
    if (status != NO_ERROR) {
        return status;
    }

    // UuidFromString also accepts noncanonical forms. Require the documented CLI spelling.
    const auto text = argv[current_index];
    GUID namespace_id{};
    wchar_t uuid[37]{};
    bool valid = wcslen(text) == 38 && text[0] == L'{' && text[37] == L'}';
    if (valid) {
        memcpy(uuid, text + 1, 36 * sizeof(wchar_t));
        valid = UuidFromStringW(reinterpret_cast<RPC_WSTR>(uuid), &namespace_id) == RPC_S_OK;
    }
    if (!valid) {
        std::cerr << "error: invalid namespace GUID; expected {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\n";
        return ERROR_SUPPRESS_OUTPUT;
    }

    auto result = ebpf_set_namespace(&namespace_id);
    if (result != EBPF_SUCCESS) {
        std::cerr << "error " << result << ": could not set namespace\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    return NO_ERROR;
}

unsigned long
handle_ebpf_show_namespace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);
    if (current_index != argc) {
        return ERROR_INVALID_SYNTAX;
    }

    GUID namespace_id{};
    auto result = ebpf_get_namespace(&namespace_id);
    if (result != EBPF_SUCCESS) {
        std::cerr << "error " << result << ": could not get namespace\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    RPC_CSTR text = nullptr;
    auto status = UuidToStringA(&namespace_id, &text);
    if (status != RPC_S_OK) {
        return status;
    }
    std::cout << "{" << reinterpret_cast<const char*>(text) << "}\n";
    RpcStringFreeA(&text);
    return NO_ERROR;
}
