// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#define CMD_EBPF_ADD_MAP L"map"
#define CMD_EBPF_ADD_PROGRAM L"program"
#define CMD_EBPF_DELETE_LINK L"link"
#define CMD_EBPF_DELETE_MAP L"map"
#define CMD_EBPF_DELETE_PROGRAM L"program"
#define CMD_EBPF_SET_NAMESPACE L"namespace"
#define CMD_EBPF_SET_PROGRAM L"program"
#define CMD_EBPF_SHOW_DISASSEMBLY L"disassembly"
#define CMD_EBPF_SHOW_HASH L"hash"
#define CMD_EBPF_SHOW_LINKS L"links"
#define CMD_EBPF_SHOW_MAPS L"maps"
#define CMD_EBPF_SHOW_NAMESPACE L"namespace"
#define CMD_EBPF_SHOW_PINS L"pins"
#define CMD_EBPF_SHOW_PROCESSES L"processes"
#define CMD_EBPF_SHOW_PROGRAMS L"programs"
#define CMD_EBPF_SHOW_SECTIONS L"sections"
#define CMD_EBPF_SHOW_VERIFICATION L"verification"
#define CMD_EBPF_PIN_LINK L"link"
#define CMD_EBPF_PIN_MAP L"map"
#define CMD_EBPF_PIN_PROGRAM L"program"
#define CMD_EBPF_UNPIN_LINK L"link"
#define CMD_EBPF_UNPIN_MAP L"map"
#define CMD_EBPF_UNPIN_PROGRAM L"program"
#define CMD_EBPF_LOOKUP_MAP L"map"
#define CMD_EBPF_UPDATE_MAP L"map"
#define CMD_EBPF_GETNEXT_MAP L"map"
#define CMD_EBPF_DUMP_MAP L"map"

// Keep every command/help/handler identical across the supported netsh command-table ABIs.
#define EBPF_ADD_COMMANDS(ENTRY) \
    ENTRY(EBPF_ADD_MAP, handle_ebpf_add_map), ENTRY(EBPF_ADD_PROGRAM, handle_ebpf_add_program),
#define EBPF_DELETE_COMMANDS(ENTRY)                                                                   \
    ENTRY(EBPF_DELETE_LINK, handle_ebpf_delete_link), ENTRY(EBPF_DELETE_MAP, handle_ebpf_delete_map), \
        ENTRY(EBPF_DELETE_PROGRAM, handle_ebpf_delete_program),
#define EBPF_SET_COMMANDS(ENTRY) \
    ENTRY(EBPF_SET_NAMESPACE, handle_ebpf_set_namespace), ENTRY(EBPF_SET_PROGRAM, handle_ebpf_set_program),
#define EBPF_SHOW_COMMANDS(ENTRY)                                                                                     \
    ENTRY(EBPF_SHOW_DISASSEMBLY, handle_ebpf_show_disassembly), ENTRY(EBPF_SHOW_HASH, handle_ebpf_show_hash),         \
        ENTRY(EBPF_SHOW_LINKS, handle_ebpf_show_links), ENTRY(EBPF_SHOW_MAPS, handle_ebpf_show_maps),                 \
        ENTRY(EBPF_SHOW_NAMESPACE, handle_ebpf_show_namespace), ENTRY(EBPF_SHOW_PINS, handle_ebpf_show_pins),         \
        ENTRY(EBPF_SHOW_PROCESSES, handle_ebpf_show_processes), ENTRY(EBPF_SHOW_PROGRAMS, handle_ebpf_show_programs), \
        ENTRY(EBPF_SHOW_SECTIONS, handle_ebpf_show_sections),                                                         \
        ENTRY(EBPF_SHOW_VERIFICATION, handle_ebpf_show_verification),
#define EBPF_PIN_COMMANDS(ENTRY)                                                          \
    ENTRY(EBPF_PIN_LINK, handle_ebpf_pin_link), ENTRY(EBPF_PIN_MAP, handle_ebpf_pin_map), \
        ENTRY(EBPF_PIN_PROGRAM, handle_ebpf_pin_program),
#define EBPF_UNPIN_COMMANDS(ENTRY)                                                                \
    ENTRY(EBPF_UNPIN_LINK, handle_ebpf_unpin_link), ENTRY(EBPF_UNPIN_MAP, handle_ebpf_unpin_map), \
        ENTRY(EBPF_UNPIN_PROGRAM, handle_ebpf_unpin_program),
#define EBPF_LOOKUP_COMMANDS(ENTRY) ENTRY(EBPF_LOOKUP_MAP, handle_ebpf_lookup_map),
#define EBPF_UPDATE_COMMANDS(ENTRY) ENTRY(EBPF_UPDATE_MAP, handle_ebpf_update_map),
#define EBPF_GETNEXT_COMMANDS(ENTRY) ENTRY(EBPF_GETNEXT_MAP, handle_ebpf_getnext_map),
#define EBPF_DUMP_COMMANDS(ENTRY) ENTRY(EBPF_DUMP_MAP, handle_ebpf_dump_map),
