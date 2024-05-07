// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_structs.h"

#define NATIVE_MODULE_HELPER_INFO_VERSION_1 1
#define NATIVE_MODULE_HELPER_INFO_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(helper_function_entry_info_t, name)

#define NATIVE_MODULE_HELPER_DATA_VERSION_1 1
#define NATIVE_MODULE_HELPER_DATA_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(helper_function_entry_data_t, tail_call)

#define NATIVE_MODULE_MAP_ENTRY_VERSION_1 1
#define NATIVE_MODULE_MAP_ENTRY_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(map_entry_t, name)

#define NATIVE_MODULE_MAP_DEFINITION_VERSION_1 1
#define NATIVE_MODULE_MAP_DEFINITION_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(map_definition_entry_t, definition)

#define NATIVE_MODULE_MAP_INITIAL_VALUES_VERSION_1 1
#define NATIVE_MODULE_MAP_INITIAL_VALUES_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(map_initial_values_t, values)

#define NATIVE_MODULE_PROGRAM_ENTRY_VERSION_1 1
#define NATIVE_MODULE_PROGRAM_ENTRY_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(program_entry_t, program_info_hash_type)

#define NATIVE_MODULE_METADATA_TABLE_VERSION_1 1
#define NATIVE_MODULE_METADATA_TABLE_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(metadata_table_t, map_initial_values)

#define EBPF_NATIVE_HELPER_INFO_CURRENT_VERSION NATIVE_MODULE_HELPER_INFO_VERSION_1
#define EBPF_NATIVE_HELPER_INFO_CURRENT_VERSION_SIZE NATIVE_MODULE_HELPER_INFO_VERSION_SIZE_1

#define EBPF_NATIVE_HELPER_DATA_CURRENT_VERSION NATIVE_MODULE_HELPER_DATA_VERSION_1
#define EBPF_NATIVE_HELPER_DATA_CURRENT_VERSION_SIZE NATIVE_MODULE_HELPER_DATA_VERSION_SIZE_1

#define EBPF_NATIVE_MAP_ENTRY_CURRENT_VERSION NATIVE_MODULE_MAP_ENTRY_VERSION_1
#define EBPF_NATIVE_MAP_ENTRY_CURRENT_VERSION_SIZE NATIVE_MODULE_MAP_ENTRY_VERSION_SIZE_1

#define EBPF_NATIVE_MAP_DEFINITION_CURRENT_VERSION NATIVE_MODULE_MAP_DEFINITION_VERSION_1
#define EBPF_NATIVE_MAP_DEFINITION_CURRENT_VERSION_SIZE NATIVE_MODULE_MAP_DEFINITION_VERSION_SIZE_1

#define EBPF_NATIVE_MAP_INITIAL_VALUES_CURRENT_VERSION NATIVE_MODULE_MAP_INITIAL_VALUES_VERSION_1
#define EBPF_NATIVE_MAP_INITIAL_VALUES_CURRENT_VERSION_SIZE NATIVE_MODULE_MAP_INITIAL_VALUES_VERSION_SIZE_1

#define EBPF_NATIVE_PROGRAM_ENTRY_CURRENT_VERSION NATIVE_MODULE_PROGRAM_ENTRY_VERSION_1
#define EBPF_NATIVE_PROGRAM_ENTRY_CURRENT_VERSION_SIZE NATIVE_MODULE_PROGRAM_ENTRY_VERSION_SIZE_1

#define EBPF_NATIVE_METADATA_TABLE_CURRENT_VERSION NATIVE_MODULE_METADATA_TABLE_VERSION_1
#define EBPF_NATIVE_METADATA_TABLE_CURRENT_VERSION_SIZE NATIVE_MODULE_METADATA_TABLE_VERSION_SIZE_1

/**
 * @brief Helper function entry info.
 * This structure defines a helper function entry info in the metadata table that is provided by the native
 * module to the eBPF runtime.
 */
typedef struct _helper_function_entry_info
{
    ebpf_extension_header_t header;
    // uint64_t (*address)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
    uint32_t helper_id;
    const char* name;
    // bool tail_call;
} helper_function_entry_info_t;

/**
 * @brief Helper function entry info.
 * This structure contains the helper function data that is populated by eBPF runtime and used by the native
 * module.
 */
typedef struct _helper_function_entry_data
{
    ebpf_extension_header_t header;
    uint64_t (*address)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
    bool tail_call;
} helper_function_entry_data_t;

// typedef struct _helper_function_address
// {
//     ebpf_extension_header_t header;
//     uint64_t (*address)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
// } helper_function_address_t;

typedef struct _map_definition_entry
{
    ebpf_extension_header_t header;
    ebpf_map_definition_in_file_t definition;
} map_definition_entry_t;

/**
 * @brief Map entry.
 * This structure contains the address of the map and the map definition. The address is written into the entry
 * during load time. The map definition is used to initialize the map when the program is loaded.
 */
typedef struct _map_entry
{
    // DLLs put the strings into the same section, so add a marker
    // at the start of a map entry to make it easy to find
    // entries in the maps section.
    uint64_t zero;

    ebpf_extension_header_t header;
    // map_address_t* address;
    map_definition_entry_t* map_definition;
    const char* name;
} map_entry_t;

/**
 * @brief Map initial values.
 * This structure contains the initial values for a map. The values are used to initialize the map when the
 * program is loaded. Values are specified as strings and are converted to the appropriate type based on the
 * map definition. Only BPF_MAP_TYPE_ARRAY_OF_MAPS and BPF_MAP_TYPE_PROG_ARRAY map types are supported.
 */
typedef struct _map_initial_values
{
    ebpf_extension_header_t header;
    const char* name;    // Name of the map.
    size_t count;        // Number of values in the map.
    const char** values; // Array of strings containing the initial values.
} map_initial_values_t;

/**
 * @brief Program entry.
 * This structure contains the address of the program and additional information about the program.
 */
typedef struct _program_entry
{
    // DLLs put the strings into the same section, so add a marker
    // at the start of a program entry to make it easy to find
    // entries in the programs section.
    uint64_t zero;

    ebpf_extension_header_t header;                  ///< Header for the program entry.
    uint64_t (*function)(void*);                     ///< Address of the program.
    const char* pe_section_name;                     ///< Name of the PE section containing the program.
    const char* section_name;                        ///< Name of the section containing the program.
    const char* program_name;                        ///< Name of the program.
    uint16_t* referenced_map_indices;                ///< List of map indices referenced by the program.
    uint16_t referenced_map_count;                   ///< Number of maps referenced by the program.
    uint16_t helper_count;                           ///< Number of helper functions used by the program.
    const helper_function_entry_info_t* helper_info; ///< List of helper function info used by the program.
    helper_function_entry_data_t* helper_data;       ///< List of helper function data used by the program.
    uint64_t* helper_addresses;                      ///< List of helper function addresses used by the program.
    size_t bpf_instruction_count;                    ///< Number of BPF instructions in the program.
    ebpf_program_type_t* program_type;               ///< Type of the program.
    ebpf_attach_type_t* expected_attach_type;        ///< Expected attach type of the program.
    const uint8_t* program_info_hash;                ///< Hash of the program info.
    size_t program_info_hash_length;                 ///< Length of the program info hash.
    const char* program_info_hash_type;              ///< Type of the program info hash
} program_entry_t;

/**
 * @brief Version information for the bpf2c compiler.
 * This structure contains the version information for the bpf2c compiler that generated the module. It can be
 * used to determine if the module is compatible with the current version of the eBPF for Windows runtime.
 */
typedef struct _bpf2c_version
{
    uint32_t major;
    uint32_t minor;
    uint32_t revision;
} bpf2c_version_t;

/**
 * @brief Metadata table for a module.
 * This structure is returned by the module's metadata function, get_metadata_table and contains
 * information about the module including the list of programs and maps.
 */
typedef struct _metadata_table
{
    ebpf_extension_header_t header;
    // TODO: "size" needs to be removed.
    // size_t size;
    void (*programs)(
        _Outptr_result_buffer_maybenull_(*count) program_entry_t** programs,
        _Out_ size_t* count); ///< Returns the list of programs in this module.
    void (*maps)(
        _Outptr_result_buffer_maybenull_(*count) map_entry_t** maps,
        _Outptr_result_buffer_maybenull_(*count) void*** maps_addresses,
        _Out_ size_t* count); ///< Returns the list of maps and map addresses in this module.
    void (*hash)(
        _Outptr_result_buffer_maybenull_(*size) const uint8_t** hash,
        _Out_ size_t* size); ///< Returns the hash of the ELF file used to generate this module.
    void (*version)(_Out_ bpf2c_version_t* version);
    void (*map_initial_values)(
        _Outptr_result_buffer_maybenull_(*count) map_initial_values_t** map_initial_values,
        _Out_ size_t* count); ///< Returns the list of initial values for maps in this module.
} metadata_table_t;