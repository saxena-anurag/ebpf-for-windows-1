// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define WIN32_NO_STATUS
#include <Windows.h>
#include <sddl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

extern "C" LONG
ebpf_driver_usersim_materialize_security_descriptor(const wchar_t* sddl, void* output, ULONG* length)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD size = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, &size)) {
        return STATUS_INVALID_PARAMETER;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    GENERIC_MAPPING mapping = {1, 1, 1, 1};
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present || dacl == nullptr) {
        LocalFree(descriptor);
        return STATUS_INVALID_PARAMETER;
    }
    for (DWORD index = 0; index < dacl->AceCount; index++) {
        void* ace = nullptr;
        if (!GetAce(dacl, index, &ace) || static_cast<ACE_HEADER*>(ace)->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            LocalFree(descriptor);
            return STATUS_INVALID_PARAMETER;
        }
        MapGenericMask(&static_cast<ACCESS_ALLOWED_ACE*>(ace)->Mask, &mapping);
    }
    LONG status = STATUS_SUCCESS;
    if (output == nullptr || *length < size) {
        status = STATUS_BUFFER_TOO_SMALL;
    } else {
        memcpy(output, descriptor, size);
    }
    *length = size;
    LocalFree(descriptor);
    return status;
}

extern "C" BOOLEAN
ebpf_driver_usersim_access_check(
    PSECURITY_DESCRIPTOR descriptor, ACCESS_MASK desired_access, ACCESS_MASK* granted_access, LONG* status)
{
    HANDLE token = nullptr;
    HANDLE impersonation_token = nullptr;
    BOOLEAN result = FALSE;
    GENERIC_MAPPING mapping = {};
    PRIVILEGE_SET privileges = {};
    DWORD privileges_size = sizeof(privileges);
    BOOL permitted = FALSE;

    // usersim's SeAccessCheck stub allows every subject. Use the OS access
    // check here so the driver scaffolding exercises its actual management DACL.
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)) {
        if (GetLastError() != ERROR_NO_TOKEN ||
            !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token)) {
            goto Exit;
        }
    }
    if (!DuplicateToken(token, SecurityImpersonation, &impersonation_token) || !AccessCheck(
                                                                                   descriptor,
                                                                                   impersonation_token,
                                                                                   desired_access,
                                                                                   &mapping,
                                                                                   &privileges,
                                                                                   &privileges_size,
                                                                                   granted_access,
                                                                                   &permitted)) {
        goto Exit;
    }
    result = permitted ? TRUE : FALSE;
    *status = permitted ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;

Exit:
    if (impersonation_token != nullptr) {
        CloseHandle(impersonation_token);
    }
    if (token != nullptr) {
        CloseHandle(token);
    }
    if (!result) {
        *granted_access = 0;
        *status = STATUS_ACCESS_DENIED;
    }
    return result;
}
