// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Contains user mode registry related helper APIs.

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <codecvt>
#include <map>
#include <mutex>
#include <stdexcept>
#include "api_common.hpp"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "platform.h"
#include "platform.hpp"
#include "um_registry_helper.h"

#define GUID_STRING_LENGTH 38 // not inlcuding the null terminator.

static std::wstring
_get_wstring_from_string(std::string text)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wide = converter.from_bytes(text);

    return wide;
}

void
close_registry_key(_In_ ebpf_registry_key_t* key)
{
    if (key->key != nullptr) {
        RegCloseKey(key->key);
        key->key = nullptr;
    }
}

uint32_t
write_registry_value_binary(
    _In_ const ebpf_registry_key_t* key,
    _In_ const wchar_t* value_name,
    _In_reads_(value_size) uint8_t* value,
    _In_ size_t value_size)
{
    ebpf_assert(value_name);
    ebpf_assert(value);

    return RegSetValueEx(key->key, value_name, 0, REG_BINARY, value, (DWORD)value_size);
}

uint32_t
write_registry_value_wide_string(
    _In_ const ebpf_registry_key_t* key, _In_ const wchar_t* value_name, _In_z_ const wchar_t* value)
{
    ebpf_assert(value_name);
    ebpf_assert(value);

    auto length = (wcslen(value) + 1) * sizeof(wchar_t);
    return RegSetValueEx(key->key, value_name, 0, REG_SZ, (uint8_t*)value, (DWORD)length);
}

uint32_t
write_registry_value_ansi_string(
    _In_ const ebpf_registry_key_t* key, _In_ const wchar_t* value_name, _In_z_ const char* value)
{
    uint32_t result;
    try {
        auto wide_string = _get_wstring_from_string(value);
        result = write_registry_value_wide_string(key, value_name, wide_string.c_str());
    } catch (...) {
        result = ERROR_NOT_ENOUGH_MEMORY;
    }

    return result;
}

uint32_t
write_registry_value_dword(_In_ const ebpf_registry_key_t* key, _In_z_ const wchar_t* value_name, uint32_t value)
{
    ebpf_assert(key->key);
    return RegSetValueEx(key->key, value_name, 0, REG_DWORD, (PBYTE)&value, sizeof(value));
}

uint32_t
create_registry_key(
    _In_opt_ const ebpf_registry_key_t* root_key,
    _In_ const wchar_t* sub_key,
    uint32_t flags,
    _Out_ ebpf_registry_key_t* key)
{
    key->key = nullptr;
    if (root_key == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    return RegCreateKeyEx(root_key->key, sub_key, 0, nullptr, 0, flags, nullptr, &key->key, nullptr);
}

uint32_t
open_registry_key(
    _In_ const ebpf_registry_key_t* root_key,
    _In_opt_z_ const wchar_t* sub_key,
    uint32_t flags,
    _Out_ ebpf_registry_key_t* key)
{
    ebpf_assert(root_key != nullptr);

    return RegOpenKeyEx(root_key->key, sub_key, 0, flags, &key->key);
}

uint32_t
delete_registry_key(_In_ const ebpf_registry_key_t* root_key, _In_z_ const wchar_t* sub_key)
{
    return RegDeleteKeyEx(root_key->key, sub_key, 0, 0);
}

uint32_t
delete_registry_tree(_In_ const ebpf_registry_key_t* root_key, _In_opt_z_ const wchar_t* sub_key)
{
    return RegDeleteTree(root_key->key, sub_key);
}

uint32_t
create_registry_key_ansi(
    _In_ const ebpf_registry_key_t* root_key,
    _In_z_ const char* sub_key,
    uint32_t flags,
    _Out_ ebpf_registry_key_t* key)
{
    uint32_t result;
    try {
        auto wide_string = _get_wstring_from_string(sub_key);
        result = create_registry_key(root_key, wide_string.c_str(), flags, key);
    } catch (...) {
        result = ERROR_NOT_ENOUGH_MEMORY;
    }

    return result;
}

ebpf_result_t
read_registry_value_string(HKEY key, _In_ const wchar_t* value_name, _Out_ wchar_t** value)
{
    uint32_t status = NO_ERROR;
    DWORD type = REG_SZ;
    DWORD value_size = 0;
    wchar_t* string_value = nullptr;

    *value = nullptr;
    status = RegQueryValueEx(key, value_name, 0, &type, nullptr, &value_size);
    if (status != ERROR_SUCCESS || type != REG_SZ) {
        return win32_error_code_to_ebpf_result(status);
    }

    string_value = (wchar_t*)ebpf_allocate((value_size + sizeof(wchar_t)));
    if (string_value == nullptr) {
        status = ERROR_NOT_ENOUGH_MEMORY;
        return win32_error_code_to_ebpf_result(status);
    }

    status = RegQueryValueEx(key, value_name, 0, &type, (PBYTE)string_value, &value_size);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }
    *value = string_value;
    string_value = nullptr;

Exit:
    if (string_value) {
        ebpf_free(string_value);
    }
    return win32_error_code_to_ebpf_result(status);
}

ebpf_result_t
read_registry_value_dword(_In_ HKEY key, _In_ const wchar_t* value_name, _Out_ uint32_t* value)
{
    uint32_t status = NO_ERROR;
    DWORD type = REG_QWORD;
    DWORD key_size = sizeof(uint32_t);
    status = RegQueryValueEx(key, value_name, 0, &type, (PBYTE)value, &key_size);
    return win32_error_code_to_ebpf_result(status);
}

ebpf_result_t
read_registry_value_binary(
    _In_ HKEY key, _In_ const wchar_t* value_name, _Out_writes_(value_size) uint8_t* value, _In_ size_t value_size)
{
    uint32_t status = NO_ERROR;
    DWORD type = REG_BINARY;
    DWORD local_value_size = (DWORD)value_size;

    status = RegQueryValueEx(key, value_name, 0, &type, value, &local_value_size);
    if (status != ERROR_SUCCESS || type != REG_BINARY || local_value_size != value_size) {
        if (status != ERROR_SUCCESS) {
            status = ERROR_INVALID_PARAMETER;
        }
        goto Exit;
    }

Exit:
    return win32_error_code_to_ebpf_result(status);
}

_Success_(return == 0) uint32_t
    convert_guid_to_string(_In_ const GUID* guid, _Out_writes_all_(string_size) wchar_t* string, size_t string_size)
{
    uint32_t status = ERROR_SUCCESS;
    wchar_t* value_name = nullptr;

    try {
        if (string_size < GUID_STRING_LENGTH + 1) {
            return ERROR_INSUFFICIENT_BUFFER;
        }

        // Convert program type GUID to string
        RPC_STATUS rpc_status = UuidToString(guid, (RPC_WSTR*)&value_name);
        if (rpc_status != RPC_S_OK) {
            return ERROR_INVALID_PARAMETER;
        }

        std::wstring value_name_string(value_name);

        // UuidToString returns string without braces. Add braces to the resulting string.
        value_name_string = L"{" + value_name_string + L"}";

        // Copy the buffer to the output string.
        memcpy(string, value_name_string.c_str(), GUID_STRING_LENGTH * 2);
        string[GUID_STRING_LENGTH] = L'\0';
    } catch (...) {
        status = ERROR_NOT_ENOUGH_MEMORY;
    }

    return status;
}
