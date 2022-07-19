// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

uint32_t
test_ioctl_load_native_module(
    _In_ const std::wstring& service_path,
    _In_ const GUID* module_id,
    _Out_ size_t* count_of_maps,
    _Out_ size_t* count_of_programs);

uint32_t
test_ioctl_load_native_programs(
    _In_ const GUID* module_id,
    _In_opt_ const ebpf_program_type_t* program_type,
    size_t count_of_maps,
    _Out_writes_(count_of_maps) ebpf_handle_t* map_handles,
    size_t count_of_programs,
    _Out_writes_(count_of_programs) ebpf_handle_t* program_handles);

ebpf_result_t
test_ioctl_create_map(
    _In_opt_ const char* name,
    size_t name_length,
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    ebpf_result_t expected_result,
    _Out_ ebpf_handle_t* map_handle);
