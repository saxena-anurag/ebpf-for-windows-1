// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "..\..\tools\netsh\resource.h"
#include "commands.h"
#include "cxplat_fault_injection.h"
#include "ebpf_epoch.h"
#include "hash.h"
#include "netsh_test_helper.h"
#include "platform.h"
#include "test_helper.hpp"
#include "utilities.h"

#include <winsock2.h>
#include <windows.h>
#include <algorithm>
#include <exception>
#include <format>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <netsh.h>
#include <regex>
#include <sstream>
#include <string.h>

extern std::vector<struct bpf_object*> _ebpf_netsh_objects;

class netsh_namespace_restore
{
  public:
    netsh_namespace_restore() { REQUIRE(ebpf_get_namespace(&_previous) == EBPF_SUCCESS); }
    ~netsh_namespace_restore() { CHECK(ebpf_set_namespace(&_previous) == EBPF_SUCCESS); }

  private:
    GUID _previous{};
};

class _test_helper_netsh
{
  public:
    _test_helper_netsh();
    ~_test_helper_netsh();
    void
    initialize();

  private:
    _test_helper_libbpf test_helper_libbpf;
};

_test_helper_netsh::_test_helper_netsh() { _ebpf_netsh_objects.clear(); }

_test_helper_netsh::~_test_helper_netsh()
{
    if (!cxplat_fault_injection_is_enabled() && std::uncaught_exceptions() == 0) {
        CHECK(_ebpf_netsh_objects.empty());
    }
    for (auto& object : _ebpf_netsh_objects) {
        bpf_object__close(object);
    }
    _ebpf_netsh_objects.clear();
}

void
_test_helper_netsh::initialize()
{
    test_helper_libbpf.initialize();
}

TEST_CASE("NU50 netsh namespace selection and canonical GUID validation", "[netsh][namespace]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    netsh_namespace_restore restore;
    int result;
    auto output = run_netsh_command_with_args(handle_ebpf_show_namespace, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "{00000000-0000-0000-0000-000000000000}\n");

    const wchar_t* selected = L"{12345678-9ABC-0000-0000-123456789ABC}";
    REQUIRE(run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, selected).empty());
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_show_namespace, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "{12345678-9abc-0000-0000-123456789abc}\n");

    for (const auto invalid :
         {L"",
          L"null",
          L"all",
          L"12345678-9abc-0000-0000-123456789abc",
          L"{12345678-9abc-0000-0000-123456789abz}",
          L"{123456789abc-0000-0000-123456789abc}",
          L"{12345678-9abc-0000-0000-123456789abc}suffix"}) {
        output = run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, invalid);
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
        REQUIRE(output == "error: invalid namespace GUID; expected {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\n");
        output = run_netsh_command_with_args(handle_ebpf_show_namespace, &result, 0);
        REQUIRE(result == NO_ERROR);
        REQUIRE(output == "{12345678-9abc-0000-0000-123456789abc}\n");
    }
    run_netsh_command_with_args(handle_ebpf_show_namespace, &result, 1, L"all");
    REQUIRE(result == ERROR_INVALID_SYNTAX);
    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 0);
    REQUIRE(result == ERROR_INVALID_SYNTAX);
    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 2, selected, selected);
    REQUIRE(result == ERROR_INVALID_SYNTAX);
    output = run_netsh_command_with_args(
        handle_ebpf_set_namespace, &result, 1, L"namespace={00000000-0000-0000-0000-000000000000}");
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.empty());
    output = run_netsh_command_with_args(handle_ebpf_show_namespace, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "{00000000-0000-0000-0000-000000000000}\n");
}

TEST_CASE("NU50 netsh shared command and help registrations", "[netsh][namespace]")
{
    // The production normal/original/long ABI tables all expand these same command lists.
#define TEST_COMMAND_ENTRY(token, handler) {CMD_##token, handler, HLP_##token, HLP_##token##_EX}
    struct command_entry
    {
        const wchar_t* name;
        FN_HANDLE_CMD* handler;
        uint32_t help;
        uint32_t help_ex;
    };
    const command_entry set[] = {EBPF_SET_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry show[] = {EBPF_SHOW_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry add[] = {EBPF_ADD_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry remove[] = {EBPF_DELETE_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry pin[] = {EBPF_PIN_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry unpin[] = {EBPF_UNPIN_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry lookup[] = {EBPF_LOOKUP_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry update[] = {EBPF_UPDATE_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry getnext[] = {EBPF_GETNEXT_COMMANDS(TEST_COMMAND_ENTRY)};
    const command_entry dump[] = {EBPF_DUMP_COMMANDS(TEST_COMMAND_ENTRY)};
#undef TEST_COMMAND_ENTRY
    auto check = [](const auto& table, const wchar_t* name, FN_HANDLE_CMD* handler) {
        auto found = std::find_if(
            std::begin(table), std::end(table), [name](const auto& entry) { return wcscmp(entry.name, name) == 0; });
        REQUIRE(found != std::end(table));
        REQUIRE(found->handler == handler);
        REQUIRE(found->help != 0);
        REQUIRE(found->help_ex == found->help + 1);
    };
    check(set, L"namespace", handle_ebpf_set_namespace);
    check(show, L"namespace", handle_ebpf_show_namespace);
    check(add, L"map", handle_ebpf_add_map);
    check(remove, L"map", handle_ebpf_delete_map);
    check(remove, L"link", handle_ebpf_delete_link);
    check(pin, L"link", handle_ebpf_pin_link);
    check(unpin, L"link", handle_ebpf_unpin_link);
    check(lookup, L"map", handle_ebpf_lookup_map);
    check(update, L"map", handle_ebpf_update_map);
    check(getnext, L"map", handle_ebpf_getnext_map);
    check(dump, L"map", handle_ebpf_dump_map);
}

static uint32_t
create_netsh_test_map(const wchar_t* type, const wchar_t* path, const wchar_t* keysize = L"4")
{
    int result;
    auto output = run_netsh_command_with_args(
        handle_ebpf_add_map, &result, 6, type, keysize, L"4", L"8", path, L"name=netsh_namespace_map");
    REQUIRE(result == NO_ERROR);
    uint32_t id = 0;
    REQUIRE(sscanf_s(output.c_str(), "Created with ID %u\n", &id) == 1);
    REQUIRE(id != 0);
    return id;
}

TEST_CASE("NU51 netsh map CRUD and dump are scoped to the selected namespace", "[netsh][namespace][maps]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    netsh_namespace_restore restore;
    int result;
    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, L"{12345678-1234-4234-8234-123456789abc}");
    REQUIRE(result == NO_ERROR);
    auto selected_id = create_netsh_test_map(L"hash", L"netsh_namespace_map");
    auto selected = std::to_wstring(selected_id);
    auto output =
        run_netsh_command_with_args(handle_ebpf_update_map, &result, 3, selected.c_str(), L"01000000", L"2a000000");
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.empty());

    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, L"{00000000-0000-0000-0000-000000000000}");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_show_maps, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.find("netsh_namespace_map") == std::string::npos);
    output = run_netsh_command_with_args(handle_ebpf_show_pins, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.find("netsh_namespace_map") == std::string::npos);
    for (auto command :
         {handle_ebpf_lookup_map, handle_ebpf_delete_map, handle_ebpf_getnext_map, handle_ebpf_dump_map}) {
        output = run_netsh_command_with_args(command, &result, 1, selected.c_str());
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
        REQUIRE(output == "error 2: could not open map\n");
    }
    output =
        run_netsh_command_with_args(handle_ebpf_update_map, &result, 3, selected.c_str(), L"01000000", L"ff000000");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error 2: could not open map\n");
    auto default_id = create_netsh_test_map(L"hash", L"netsh_namespace_map");
    auto default_string = std::to_wstring(default_id);
    REQUIRE(default_id != selected_id);
    run_netsh_command_with_args(handle_ebpf_update_map, &result, 3, default_string.c_str(), L"01000000", L"ff000000");
    REQUIRE(result == NO_ERROR);

    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, L"{12345678-1234-4234-8234-123456789abc}");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_show_pins, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.find(std::format("{:7}      Map  BPF:\\netsh_namespace_map\n", selected_id)) != std::string::npos);
    REQUIRE(output.find(std::format("{:7}      Map  BPF:\\netsh_namespace_map\n", default_id)) == std::string::npos);
    output = run_netsh_command_with_args(handle_ebpf_lookup_map, &result, 2, selected.c_str(), L"01000000");
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "value: 2a000000\n");
    output = run_netsh_command_with_args(handle_ebpf_getnext_map, &result, 1, selected.c_str());
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "key: 01000000\n");
    output = run_netsh_command_with_args(handle_ebpf_dump_map, &result, 1, selected.c_str());
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "key: 01000000\nvalue: 2a000000\n");
    auto inner_option = L"innerid=" + selected;
    output = run_netsh_command_with_args(
        handle_ebpf_add_map, &result, 6, L"array_of_maps", L"4", L"4", L"1", L"netsh_outer", inner_option.c_str());
    REQUIRE(result == NO_ERROR);
    uint32_t outer_id;
    REQUIRE(sscanf_s(output.c_str(), "Created with ID %u\n", &outer_id) == 1);
    auto outer = std::to_wstring(outer_id);
    auto id_bytes = [](uint32_t id) {
        return std::format(L"{:02x}{:02x}{:02x}{:02x}", id & 0xff, (id >> 8) & 0xff, (id >> 16) & 0xff, id >> 24);
    };
    auto foreign_value = id_bytes(default_id);
    output = run_netsh_command_with_args(
        handle_ebpf_update_map, &result, 3, outer.c_str(), L"00000000", foreign_value.c_str());
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error 2: could not open map value object\n");
    auto own_value = id_bytes(selected_id);
    output =
        run_netsh_command_with_args(handle_ebpf_update_map, &result, 3, outer.c_str(), L"00000000", own_value.c_str());
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_lookup_map, &result, 2, outer.c_str(), L"00000000");
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "value: {:02x}{:02x}{:02x}{:02x}\n",
                      selected_id & 0xff,
                      (selected_id >> 8) & 0xff,
                      (selected_id >> 16) & 0xff,
                      selected_id >> 24));
    run_netsh_command_with_args(handle_ebpf_unpin_map, &result, 2, outer.c_str(), L"netsh_outer");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_getnext_map, &result, 2, selected.c_str(), L"01000000");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error 2: could not get next map key\n");
    output = run_netsh_command_with_args(handle_ebpf_delete_map, &result, 2, selected.c_str(), L"01000000");
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.empty());
    output = run_netsh_command_with_args(handle_ebpf_dump_map, &result, 1, selected.c_str());
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.empty());
    output = run_netsh_command_with_args(handle_ebpf_unpin_map, &result, 2, selected.c_str(), L"netsh_namespace_map");
    REQUIRE(result == NO_ERROR);

    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, L"{00000000-0000-0000-0000-000000000000}");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_lookup_map, &result, 2, default_string.c_str(), L"01000000");
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "value: ff000000\n");
    run_netsh_command_with_args(handle_ebpf_unpin_map, &result, 2, default_string.c_str(), L"netsh_namespace_map");
    REQUIRE(result == NO_ERROR);
}

TEST_CASE("netsh map byte and numeric validation", "[netsh][namespace][maps]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    auto id = std::to_wstring(create_netsh_test_map(L"hash", L"netsh_validation"));
    int result;
    for (auto invalid_key : {L"", L"0", L"000000", L"0000000000", L"0000000g", L"0x00000000"}) {
        auto output = run_netsh_command_with_args(handle_ebpf_lookup_map, &result, 2, id.c_str(), invalid_key);
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
        REQUIRE(output == "error: key must contain exactly keysize bytes as hexadecimal pairs\n");
    }
    for (auto invalid_value : {L"", L"0", L"000000", L"0000000000", L"0000000g"}) {
        auto output =
            run_netsh_command_with_args(handle_ebpf_update_map, &result, 3, id.c_str(), L"01000000", invalid_value);
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
        REQUIRE(output == "error: value must contain exactly valuesize bytes as hexadecimal pairs\n");
    }
    for (auto invalid_id : {L"-1", L"0", L"4294967296", L"1junk", L" 1"}) {
        auto output = run_netsh_command_with_args(handle_ebpf_dump_map, &result, 1, invalid_id);
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
        REQUIRE(output == "error: invalid map ID\n");
    }
    auto output = run_netsh_command_with_args(
        handle_ebpf_update_map, &result, 4, id.c_str(), L"01000000", L"01000000", L"flags=invalid");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: flags must be any, noexist, or exist\n");
    output = run_netsh_command_with_args(
        handle_ebpf_update_map, &result, 4, id.c_str(), L"01000000", L"01000000", L"noexist");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(
        handle_ebpf_update_map, &result, 4, id.c_str(), L"01000000", L"02000000", L"noexist");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error 17: could not update map element\n");
    output =
        run_netsh_command_with_args(handle_ebpf_update_map, &result, 4, id.c_str(), L"01000000", L"02000000", L"exist");
    REQUIRE(result == NO_ERROR);
    run_netsh_command_with_args(handle_ebpf_dump_map, &result, 2, id.c_str(), L"key=01000000");
    REQUIRE(result == ERROR_INVALID_SYNTAX);
    output = run_netsh_command_with_args(handle_ebpf_unpin_map, &result, 2, id.c_str(), L"netsh_validation");
    REQUIRE(result == NO_ERROR);

    for (auto invalid_size : {L"-1", L"4294967296", L"4garbage"}) {
        output = run_netsh_command_with_args(
            handle_ebpf_add_map, &result, 5, L"hash", invalid_size, L"4", L"8", L"netsh_invalid");
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
        REQUIRE(output == "error: invalid map dimensions or inner map ID\n");
    }
    output =
        run_netsh_command_with_args(handle_ebpf_add_map, &result, 5, L"invalid", L"4", L"4", L"8", L"netsh_invalid");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: invalid map type\n");
}

TEST_CASE("netsh per-CPU and keyless map values", "[netsh][namespace][maps]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    int result;
    auto id = std::to_wstring(create_netsh_test_map(L"percpu_array", L"netsh_percpu"));
    std::wstring bytes;
    for (int cpu = 0; cpu < libbpf_num_possible_cpus(); cpu++) {
        bytes += L"2a00000000000000";
    }
    auto output =
        run_netsh_command_with_args(handle_ebpf_update_map, &result, 3, id.c_str(), L"00000000", bytes.c_str());
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_lookup_map, &result, 2, id.c_str(), L"00000000");
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "value: " + down_cast_from_wstring(bytes) + "\n");
    run_netsh_command_with_args(handle_ebpf_unpin_map, &result, 2, id.c_str(), L"netsh_percpu");
    REQUIRE(result == NO_ERROR);

    id = std::to_wstring(create_netsh_test_map(L"queue", L"netsh_queue", L"0"));
    output = run_netsh_command_with_args(handle_ebpf_update_map, &result, 2, id.c_str(), L"value=2a000000");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_lookup_map, &result, 1, id.c_str());
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "value: 2a000000\n");
    output = run_netsh_command_with_args(handle_ebpf_dump_map, &result, 1, id.c_str());
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: this map does not support nondestructive key iteration\n");
    output = run_netsh_command_with_args(handle_ebpf_delete_map, &result, 1, id.c_str());
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.empty());
    output = run_netsh_command_with_args(handle_ebpf_lookup_map, &result, 1, id.c_str());
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error 2: could not look up map element\n");
    run_netsh_command_with_args(handle_ebpf_unpin_map, &result, 2, id.c_str(), L"netsh_queue");
    REQUIRE(result == NO_ERROR);
}

std::string
strip_paths(const std::string& original_string)
{
    std::stringstream input_stream(original_string);
    std::stringstream output_stream;
    std::string line;
    while (std::getline(input_stream, line)) {
        auto output = std::regex_replace(line, std::regex("\\\\"), "/");
        output_stream << std::regex_replace(output, std::regex("^.*tests/sample"), "; ./tests/sample") << "\n";
    }
    return output_stream.str();
}

void
test_expected_output_line_by_line(const std::string& expected_output, const std::string& actual_output)
{
    // If the expected and actual output are the same, the test passes.
    if (expected_output == actual_output)
        return;

    std::cerr << "Expected output:\n" << expected_output << "\n";
    std::cerr << "Actual output:\n" << actual_output << "\n";

    // If the expected and actual output are not the same, compare them line by line.
    std::istringstream expected_output_stream(expected_output);
    std::istringstream actual_output_stream(actual_output);

    std::string expected_line;
    std::string actual_line;
    while (std::getline(expected_output_stream, expected_line) && std::getline(actual_output_stream, actual_line)) {
        REQUIRE(expected_line == actual_line);
    }
}

TEST_CASE("show disassembly bpf_call.o", "[netsh][disassembly]")
{
    // Start the test helper so the netsh command can get helper prototypes.
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf_call.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    output = strip_paths(output);
    std::string expected_output =
        "; ./tests/sample/undocked/bpf_call.c:25\n"
        "; SEC(\"sample_ext\") int func(sample_program_context_t* ctx)\n"
        "       0:	r1 = 0\n"
        "; ./tests/sample/undocked/bpf_call.c:27\n"
        ";     uint32_t key = 0;\n"
        "       1:	*(u32 *)(r10 - 4) = r1\n"
        "       2:	r1 = 42\n"
        "; ./tests/sample/undocked/bpf_call.c:28\n"
        ";     uint32_t value = 42;\n"
        "       3:	*(u32 *)(r10 - 8) = r1\n"
        "       4:	r2 = r10\n"
        "; ./tests/sample/undocked/bpf_call.c:0\n"
        "; \n"
        "       5:	r2 += -4\n"
        "; ./tests/sample/undocked/bpf_call.c:28\n"
        ";     uint32_t value = 42;\n"
        "       6:	r3 = r10\n"
        "       7:	r3 += -8\n"
        "; ./tests/sample/undocked/bpf_call.c:29\n"
        ";     int result = bpf_map_update_elem(&map, &key, &value, 0);\n"
        "       8:	r1 = map_fd 1\n"
        "      10:	r4 = 0\n"
        "      11:	r0 = bpf_map_update_elem:2(map_fd r1, map_key r2, map_value r3, uint64_t r4)\n"
        "; ./tests/sample/undocked/bpf_call.c:30\n"
        ";     return result;\n"
        "      12:	exit\n\n";
    test_expected_output_line_by_line(expected_output, output);
}

TEST_CASE("show disassembly bpf.o nosuchsection", "[netsh][disassembly]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"bpf.o", L"nosuchsection", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: Section not found\n");
}

TEST_CASE("show disassembly nosuchfile.o", "[netsh][disassembly]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_disassembly, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections nosuchfile.o", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show sections bpf.o", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                                                                     Size\n"
                  "                       Section                   Program       Type  (bytes)\n"
                  "==============================  ========================  =========  =======\n"
                  "                         .text                      func     unspec       16\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n");
}

// Test specifying a section name.
TEST_CASE("show sections bpf.o .text", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.o", L".text", nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "Section      : .text\n"
                  "Program      : func\n"
                  "Program Type : unspec\n"
                  "Size         : 16 bytes\n"
                  "Instructions : 2\n"
                  "arith        : 0\n"
                  "arith32      : 0\n"
                  "arith64      : 1\n"
                  "assign       : 1\n"
                  "call_1       : 0\n"
                  "call_mem     : 0\n"
                  "call_nomem   : 0\n"
                  "instructions : 4\n"
                  "joins        : 0\n"
                  "jumps        : 0\n"
                  "load         : 0\n"
                  "load_store   : 0\n"
                  "map_in_map   : 0\n"
                  "other        : 3\n"
                  "packet_access: 0\n"
                  "reallocate   : 0\n"
                  "store        : 0\n"
                  "\n"
                  "                     Key  Value      Max\n"
                  "          Map Type  Size   Size  Entries  Name\n"
                  "==================  ====  =====  =======  ========\n");
}

// Test a .sys file.
TEST_CASE("show sections bpf.sys", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"bpf.sys", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    // Use regex to match output, allowing any code size value.
    const std::string expected_pattern =
        "\n"
        "                                                                     Size\n"
        "                       Section                   Program       Type  \\(bytes\\)\n"
        "==============================  ========================  =========  =======\n"
        "                         \\.text                      func       bind  +\\d+\n"
        "\n"
        "                     Key  Value      Max\n"
        "          Map Type  Size   Size  Entries  Name\n"
        "==================  ====  =====  =======  ========\n";
    const std::regex expected_output_regex(expected_pattern);
    bool output_matches = std::regex_match(output, expected_output_regex);
    if (!output_matches) {
        std::cerr << "Expected regex:\n" << expected_pattern << "\n";
        std::cerr << "Actual output:\n" << output << "\n";
    }

    REQUIRE(output_matches);
}

// Test a DLL with multiple maps in the map section.
TEST_CASE("show sections map_reuse_um.dll", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_sections, L"map_reuse_um.dll", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    // Use regex to match output, allowing any code size value.
    const std::string expected_pattern =
        "\n"
        "                                                                     Size\n"
        "                       Section                   Program       Type  \\(bytes\\)\n"
        "==============================  ========================  =========  =======\n"
        "                    sample_ext             lookup_update     sample  +\\d+\n"
        "\n"
        "                     Key  Value      Max\n"
        "          Map Type  Size   Size  Entries  Name\n"
        "==================  ====  =====  =======  ========\n"
        "      hash_of_maps     4      4        1  outer_map\n"
        "             array     4      4        1  port_map\n"
        "             array     4      4        1  inner_map\n";
    const std::regex expected_output_regex(expected_pattern);
    bool output_matches = std::regex_match(output, expected_output_regex);
    if (!output_matches) {
        std::cerr << "Expected regex:\n" << expected_pattern << "\n";
        std::cerr << "Actual output:\n" << output << "\n";
    }

    REQUIRE(output_matches);
}

// Test a .dll file with multiple programs.
TEST_CASE("show sections tail_call_multiple_um.dll", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_sections, L"tail_call_multiple_um.dll", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    // Use regex to match output, allowing any code size value.
    const std::string expected_pattern =
        "\n"
        "                                                                     Size\n"
        "                       Section                   Program       Type  \\(bytes\\)\n"
        "==============================  ========================  =========  =======\n"
        "                  sample_ext/0                   callee0     sample  +\\d+\n"
        "                  sample_ext/1                   callee1     sample  +\\d+\n"
        "                    sample_ext                    caller     sample  +\\d+\n"
        "\n"
        "                     Key  Value      Max\n"
        "          Map Type  Size   Size  Entries  Name\n"
        "==================  ====  =====  =======  ========\n"
        "        prog_array     4      4       10  map\n";
    const std::regex expected_output_regex(expected_pattern);
    bool output_matches = std::regex_match(output, expected_output_regex);
    if (!output_matches) {
        std::cerr << "Expected regex:\n" << expected_pattern << "\n";
        std::cerr << "Actual output:\n" << output << "\n";
    }

    REQUIRE(output_matches);
}

// Test a .sys file with multiple programs, including ones with long names.
TEST_CASE("show sections cgroup_sock_addr.sys", "[netsh][sections]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_sections, L"cgroup_sock_addr.sys", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    // Use regex to match output, allowing any code size value.
    const std::string expected_pattern =
        "\n"
        "                                                                     Size\n"
        "                       Section                   Program       Type  \\(bytes\\)\n"
        "==============================  ========================  =========  =======\n"
        "               cgroup/connect4        authorize_connect4  sock_addr  +\\d+\n"
        "               cgroup/connect6        authorize_connect6  sock_addr  +\\d+\n"
        "                cgroup/listen4         authorize_listen4  sock_addr  +\\d+\n"
        "                cgroup/listen6         authorize_listen6  sock_addr  +\\d+\n"
        "           cgroup/recv_accept4    authorize_recv_accept4  sock_addr  +\\d+\n"
        "           cgroup/recv_accept6    authorize_recv_accept6  sock_addr  +\\d+\n"
        " cgroup/connect_authorization4    connect_authorization4  sock_addr  +\\d+\n"
        " cgroup/connect_authorization6    connect_authorization6  sock_addr  +\\d+\n"
        "\n"
        "                     Key  Value      Max\n"
        "          Map Type  Size   Size  Entries  Name\n"
        "==================  ====  =====  =======  ========\n"
        "              hash    56      4        1  egress_connection_policy_map\n"
        "              hash    56      4        1  ingress_connection_policy_map\n"
        "              hash    56      4        1  listen_connection_policy_map\n"
        "              hash    56      8     1000  socket_cookie_map\n";
    const std::regex expected_output_regex(expected_pattern);
    bool output_matches = std::regex_match(output, expected_output_regex);
    if (!output_matches) {
        std::cerr << "Expected regex:\n" << expected_pattern << "\n";
        std::cerr << "Actual output:\n" << output << "\n";
    }

    REQUIRE(output_matches);
}

TEST_CASE("show verification nosuchfile.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_verification, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show verification bpf.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"bpf.o", L"program=func", L"type=bind", &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "Verification succeeded\n"
                  "Program terminates within 0 loop iterations\n");
}

TEST_CASE("show verification bindmonitor_bpf2bpf.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"bindmonitor_bpf2bpf.o", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "Verification succeeded\n"
                  "Program terminates within 0 loop iterations\n");
}

TEST_CASE("show verification printk_unsafe.o", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_show_verification, L"printk_unsafe.o", L"bind", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    output = strip_paths(output);
    std::string expected_output = "Verification failed\n"
                                  "\n"
                                  "Verification report:\n"
                                  "\n"
                                  "; ./tests/sample/unsafe/printk_unsafe.c:22\n"
                                  ";     bpf_printk(\"ctx: %u\", (uint64_t)ctx);\n"
                                  "\n"
                                  "7: Invalid type (r3.type == number)\n"
                                  "\n"
                                  "1 errors\n"
                                  "\n";
    test_expected_output_line_by_line(expected_output, output);
}

TEST_CASE("show verification map value as array key", "[netsh][verification]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    for (const auto& [program, expected_result] : std::vector<std::pair<const wchar_t*, int>>{
             {L"program=prog1", ERROR_SUPPRESS_OUTPUT}, {L"program=prog2", NO_ERROR}, {L"program=prog3", NO_ERROR}}) {
        int result;
        std::string output = _run_netsh_command(
            handle_ebpf_show_verification, L"map_value_as_key.o", program, L"type=sample_ext", &result);
        REQUIRE(result == expected_result);
        REQUIRE(output.starts_with(expected_result == NO_ERROR ? "Verification succeeded\n" : "Verification failed\n"));
    }
}

TEST_CASE("show verification stack variable as array key", "[netsh][verification][!mayfail]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    for (const auto& [program, expected_result] : std::vector<std::pair<const wchar_t*, int>>{
             {L"program=prog1", ERROR_SUPPRESS_OUTPUT}, {L"program=prog2", NO_ERROR}}) {
        int result;
        std::string output = _run_netsh_command(
            handle_ebpf_show_verification, L"stack_key_size.o", program, L"type=sample_ext", &result);
        REQUIRE(result == expected_result);
        REQUIRE(output.starts_with(expected_result == NO_ERROR ? "Verification succeeded\n" : "Verification failed\n"));
    }
}

void
verify_no_programs_exist()
{
    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n");
}

struct _netsh_tail_call_parameters
{
    const wchar_t* file_name;
    const char* mode;
    const char* first_program;
    const char* second_program;
    const char* first_section;
    const char* second_section;
    const char* first_pin;
    const char* second_pin;
    ebpf_id_t first_id;
    ebpf_id_t second_id;
};

static _netsh_tail_call_parameters
_get_netsh_tail_call_parameters(ebpf_execution_type_t execution_type)
{
    // bpf2c orders callee before caller, unlike the ELF loader.
    if (execution_type == EBPF_EXECUTION_NATIVE) {
        return {
            L"tail_call_um.dll",
            "NATIVE",
            "callee",
            "caller",
            "sample_ext/0",
            "sample_ext",
            "sample_ext_0",
            "sample_ext",
            4,
            5};
    }
    return {
        L"tail_call.o", "JIT", "caller", "callee", "sample_ext", "sample_ext/0", "sample_ext", "sample_ext_0", 5, 6};
}

static void
_test_pin_first_program(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const auto parameters = _get_netsh_tail_call_parameters(execution_type);
    const auto first_id = std::to_wstring(parameters.first_id);

    // Load a program to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, parameters.file_name, L"sample_ext", L"pinpath=mypinpath", &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{3:6}     1      1  {0:<9}  sample         {1}\n"
                      "{4:6}     0      0  {0:<9}  sample         {2}\n",
                      parameters.mode,
                      parameters.first_program,
                      parameters.second_program,
                      parameters.first_id,
                      parameters.second_id));

    output = _run_netsh_command(handle_ebpf_delete_program, first_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\mypinpath\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

// Netsh loads ELF programs using JIT, so these scenarios have JIT and native variants.
DECLARE_JIT_TEST_CASES("pin first program", "[netsh][programs]", _test_pin_first_program);

static void
_test_pin_all_programs(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const auto parameters = _get_netsh_tail_call_parameters(execution_type);
    const auto first_id = std::to_wstring(parameters.first_id);
    const auto second_id = std::to_wstring(parameters.second_id);

    // Load programs to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, parameters.file_name, L"pinpath=mypinpath", L"pinned=all", &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{3:6}     1      1  {0:<9}  sample         {1}\n"
                      "{4:6}     1      0  {0:<9}  sample         {2}\n",
                      parameters.mode,
                      parameters.first_program,
                      parameters.second_program,
                      parameters.first_id,
                      parameters.second_id));

    output = _run_netsh_command(handle_ebpf_delete_program, first_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\mypinpath\\{}\n", parameters.first_id, parameters.first_pin));
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_delete_program, second_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(
        output == std::format("Unpinned {} from BPF:\\mypinpath\\{}\n", parameters.second_id, parameters.second_pin));
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

DECLARE_JIT_TEST_CASES("pin all programs", "[netsh][programs]", _test_pin_all_programs);

static void
_test_show_programs(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const auto parameters = _get_netsh_tail_call_parameters(execution_type);
    const auto first_id = std::to_wstring(parameters.first_id);

    // Load a program to show.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, parameters.file_name, L"pinpath=mypinname", nullptr, &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    // Show programs in normal (table) format.
    output = _run_netsh_command(handle_ebpf_show_programs, L"sample_ext", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{3:6}     1      1  {0:<9}  sample         {1}\n"
                      "{4:6}     0      0  {0:<9}  sample         {2}\n",
                      parameters.mode,
                      parameters.first_program,
                      parameters.second_program,
                      parameters.first_id,
                      parameters.second_id));

    // Test filtering by "attached=yes".
    output = _run_netsh_command(handle_ebpf_show_programs, L"attached=yes", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{:6}     1      1  {:<9}  sample         {}\n",
                      parameters.first_id,
                      parameters.mode,
                      parameters.first_program));

    // Test filtering by "attached=no".
    output = _run_netsh_command(handle_ebpf_show_programs, L"attached=no", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{:6}     0      0  {:<9}  sample         {}\n",
                      parameters.second_id,
                      parameters.mode,
                      parameters.second_program));

    // Test filtering by "pinned=yes".
    output = _run_netsh_command(handle_ebpf_show_programs, L"pinned=yes", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{:6}     1      1  {:<9}  sample         {}\n",
                      parameters.first_id,
                      parameters.mode,
                      parameters.first_program));

    // Test filtering by "pinned=no".
    output = _run_netsh_command(handle_ebpf_show_programs, L"pinned=no", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{:6}     0      0  {:<9}  sample         {}\n",
                      parameters.second_id,
                      parameters.mode,
                      parameters.second_program));

    // Test verbose output format.
    output = _run_netsh_command(handle_ebpf_show_programs, L"level=verbose", nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    // Native programs are loaded by service name and report no file name.
    const char* file_name = execution_type == EBPF_EXECUTION_NATIVE ? "" : "tail_call.o";
    const char* caller_maps = execution_type == EBPF_EXECUTION_NATIVE
                                  ? "# map IDs      : 2\nmap IDs        : 2\n                 3\n"
                                  : "# map IDs      : 2\nmap IDs        : 3\n                 4\n";
    const char* callee_maps = "# map IDs      : 0\n";
    REQUIRE(
        output == std::format(
                      "\n"
                      "ID             : {8}\n"
                      "File name      : {0}\n"
                      "Section        : {1}\n"
                      "Name           : {2}\n"
                      "Program type   : sample\n"
                      "Mode           : {3}\n"
                      "{4}"
                      "# pinned paths : 1\n"
                      "# links        : 1\n"
                      "\n"
                      "ID             : {9}\n"
                      "File name      : {0}\n"
                      "Section        : {5}\n"
                      "Name           : {6}\n"
                      "Program type   : sample\n"
                      "Mode           : {3}\n"
                      "{7}"
                      "# pinned paths : 0\n"
                      "# links        : 0\n",
                      file_name,
                      parameters.first_section,
                      parameters.first_program,
                      parameters.mode,
                      execution_type == EBPF_EXECUTION_NATIVE ? callee_maps : caller_maps,
                      parameters.second_section,
                      parameters.second_program,
                      execution_type == EBPF_EXECUTION_NATIVE ? caller_maps : callee_maps,
                      parameters.first_id,
                      parameters.second_id));

    output = _run_netsh_command(handle_ebpf_delete_program, first_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\mypinname\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

DECLARE_JIT_TEST_CASES("show programs", "[netsh][programs]", _test_show_programs);

static void
_test_set_program(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const auto parameters = _get_netsh_tail_call_parameters(execution_type);
    const auto first_id = std::to_wstring(parameters.first_id);

    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, parameters.file_name, L"pinned=none", nullptr, &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    // Detach the program. This won't delete the program since
    // the containing object is still associated with the netsh process,
    // and could still be enumerated by it with bpf_object__next().
    output = _run_netsh_command(handle_ebpf_set_program, first_id.c_str(), L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{3:6}     0      0  {0:<9}  sample         {1}\n"
                      "{4:6}     0      0  {0:<9}  sample         {2}\n",
                      parameters.mode,
                      parameters.first_program,
                      parameters.second_program,
                      parameters.first_id,
                      parameters.second_id));

    // Try to detach an unattached program.
    output = _run_netsh_command(handle_ebpf_set_program, first_id.c_str(), L"", nullptr, &result);
    REQUIRE(output == "error 1168: could not detach program\n");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);

    RPC_WSTR attach_type_string;
    REQUIRE(UuidToStringW(&EBPF_ATTACH_TYPE_SAMPLE, &attach_type_string) == 0);

    // Attach the program.
    output = _run_netsh_command(handle_ebpf_set_program, first_id.c_str(), L"sample_ext", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    // Detach the program again.
    output = _run_netsh_command(handle_ebpf_set_program, first_id.c_str(), L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    // Verify we can delete a detached program.
    RpcStringFreeW(&attach_type_string);
    output = _run_netsh_command(handle_ebpf_delete_program, first_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == NO_ERROR);

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

DECLARE_JIT_TEST_CASES("set program", "[netsh][programs]", _test_set_program);

static void
_test_show_maps(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const wchar_t* file_name = execution_type == EBPF_EXECUTION_NATIVE ? L"map_in_map_btf_um.dll" : L"map_in_map_btf.o";
    const ebpf_id_t program_id = execution_type == EBPF_EXECUTION_NATIVE ? 4 : 5;
    const auto id = std::to_wstring(program_id);
    const ebpf_id_t inner_map_id = execution_type == EBPF_EXECUTION_NATIVE ? 2 : 3;
    const ebpf_id_t outer_map_id = execution_type == EBPF_EXECUTION_NATIVE ? 3 : 4;

    int result;
    std::string output = _run_netsh_command(handle_ebpf_add_program, file_name, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == std::format("Loaded with ID {}\n", program_id));

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "                              Key  Value      Max  Inner\n"
                      "     ID            Map Type  Size   Size  Entries     ID  Pins  Name\n"
                      "=======  ==================  ====  =====  =======  =====  ====  ========\n"
                      "{0:7}                hash     4      4        1      0     0  inner_map\n"
                      "{1:7}       array_of_maps     4      4        1  {0:5}     0  outer_map\n",
                      inner_map_id,
                      outer_map_id));

    output = _run_netsh_command(handle_ebpf_delete_program, id.c_str(), nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\lookup\n", program_id));
    verify_no_programs_exist();

    ebpf_epoch_synchronize();

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "                              Key  Value      Max  Inner\n"
                  "     ID            Map Type  Size   Size  Entries     ID  Pins  Name\n"
                  "=======  ==================  ====  =====  =======  =====  ====  ========\n");
}

DECLARE_JIT_TEST_CASES("show maps", "[netsh][maps]", _test_show_maps);

static void
_test_show_links(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const auto parameters = _get_netsh_tail_call_parameters(execution_type);
    const auto first_id = std::to_wstring(parameters.first_id);

    // Load and attach a program.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, parameters.file_name, L"pinned=none", nullptr, &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_show_links, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "   Link  Program  Attach\n"
                      "     ID       ID  Type\n"
                      "=======  =======  =============\n"
                      "{:7}  {:7}  sample_ext\n",
                      parameters.second_id + 1,
                      parameters.first_id));

    output = _run_netsh_command(handle_ebpf_delete_program, first_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == NO_ERROR);
    verify_no_programs_exist();

    output = _run_netsh_command(handle_ebpf_show_links, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == "\n"
                  "   Link  Program  Attach\n"
                  "     ID       ID  Type\n"
                  "=======  =======  =============\n");
}

DECLARE_JIT_TEST_CASES("show links", "[netsh][links]", _test_show_links);

static void
_test_show_pins(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const auto parameters = _get_netsh_tail_call_parameters(execution_type);
    const auto first_id = std::to_wstring(parameters.first_id);
    const auto second_id = std::to_wstring(parameters.second_id);

    // Load and pin programs.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, parameters.file_name, L"pinned=all", L"pinpath=mypinpath", &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_show_pins, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "     ID     Type  Path\n"
                      "=======  =======  ==============\n"
                      "{:7}  Program  BPF:\\mypinpath\\sample_ext\n"
                      "{:7}  Program  BPF:\\mypinpath\\sample_ext_0\n",
                      execution_type == EBPF_EXECUTION_NATIVE ? parameters.second_id : parameters.first_id,
                      execution_type == EBPF_EXECUTION_NATIVE ? parameters.first_id : parameters.second_id));

    output = _run_netsh_command(handle_ebpf_delete_program, first_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\mypinpath\\{}\n", parameters.first_id, parameters.first_pin));
    REQUIRE(result == NO_ERROR);

    output = _run_netsh_command(handle_ebpf_delete_program, second_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(
        output == std::format("Unpinned {} from BPF:\\mypinpath\\{}\n", parameters.second_id, parameters.second_pin));
    REQUIRE(result == NO_ERROR);

    verify_no_programs_exist();
}

DECLARE_JIT_TEST_CASES("show pins", "[netsh][pins]", _test_show_pins);

static void
_test_delete_pinned_program(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const auto parameters = _get_netsh_tail_call_parameters(execution_type);
    const auto first_id = std::to_wstring(parameters.first_id);

    // Load a program unpinned.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, parameters.file_name, L"pinned=none", nullptr, &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    // Pin the program.
    output = _run_netsh_command(handle_ebpf_set_program, first_id.c_str(), L"pinpath=mypinname", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Pin the program to a second path.
    output = _run_netsh_command(handle_ebpf_set_program, first_id.c_str(), L"pinpath=mypinname2", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Verify we can delete a pinned program.
    output = _run_netsh_command(handle_ebpf_delete_program, first_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(
        output ==
        std::format("Unpinned {0} from BPF:\\mypinname\nUnpinned {0} from BPF:\\mypinname2\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

DECLARE_JIT_TEST_CASES("delete pinned program", "[netsh][programs]", _test_delete_pinned_program);

static void
_test_unpin_program(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const auto parameters = _get_netsh_tail_call_parameters(execution_type);
    const auto first_id = std::to_wstring(parameters.first_id);

    // Load a program pinned.
    int result;
    std::string output =
        _run_netsh_command(handle_ebpf_add_program, parameters.file_name, L"sample_ext", L"mypinname", &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    // Unpin the program.
    output = _run_netsh_command(handle_ebpf_set_program, first_id.c_str(), L"", nullptr, &result);
    REQUIRE(result == ERROR_OKAY);
    REQUIRE(output == "");

    // Verify we can delete the unpinned program.
    output = _run_netsh_command(handle_ebpf_delete_program, first_id.c_str(), nullptr, nullptr, &result);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\mypinname\n", parameters.first_id));
    REQUIRE(result == NO_ERROR);

    // Verify the program ID doesn't exist any more.
    verify_no_programs_exist();
}

DECLARE_JIT_TEST_CASES("unpin program", "[netsh][programs]", _test_unpin_program);

static void
_test_xdp_interface_parameter(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const wchar_t* file_name = execution_type == EBPF_EXECUTION_NATIVE ? L"droppacket_um.dll" : L"droppacket.o";
    const wchar_t* bind_file_name = execution_type == EBPF_EXECUTION_NATIVE ? L"bindmonitor_um.dll" : L"bindmonitor.o";
    const char* mode = execution_type == EBPF_EXECUTION_NATIVE ? "NATIVE" : "JIT";
    const ebpf_id_t first_id = execution_type == EBPF_EXECUTION_NATIVE ? 4 : 5;
    const ebpf_id_t second_id = execution_type == EBPF_EXECUTION_NATIVE ? 8 : 10;
    const ebpf_id_t third_id = execution_type == EBPF_EXECUTION_NATIVE ? 12 : 15;
    const ebpf_id_t last_id = execution_type == EBPF_EXECUTION_NATIVE ? 23 : 29;
    const auto last_id_string = std::to_wstring(last_id);

    // Load a program pinned.
    int result;

    // Load program with pinpath and loopback interface alias.
    std::string output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, file_name, L"xdp", L"mypinpath", L"Loopback Pseudo-Interface 1");
    REQUIRE(output == std::format("Loaded with ID {}\n", first_id));
    REQUIRE(result == NO_ERROR);
    output =
        _run_netsh_command(handle_ebpf_delete_program, std::to_wstring(first_id).c_str(), nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\mypinpath\n", first_id));
    verify_no_programs_exist();

    // Load program with pinpath and loopback interface name.
    output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, file_name, L"xdp", L"mypinpath", L"loopback_0");
    REQUIRE(output == std::format("Loaded with ID {}\n", second_id));
    REQUIRE(result == NO_ERROR);
    output =
        _run_netsh_command(handle_ebpf_delete_program, std::to_wstring(second_id).c_str(), nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\mypinpath\n", second_id));
    verify_no_programs_exist();

    // Load program with loopback interface index.
    output = _run_netsh_command(handle_ebpf_add_program, file_name, L"xdp", L"interface=1", &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", third_id));
    REQUIRE(result == NO_ERROR);
    output =
        _run_netsh_command(handle_ebpf_delete_program, std::to_wstring(third_id).c_str(), nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == std::format("Unpinned {} from BPF:\\DropPacket\n", third_id));
    verify_no_programs_exist();

    // (Negative) Load program with incorrect interface name.
    output = _run_netsh_command(handle_ebpf_add_program, file_name, L"xdp", L"interface=foo", &result);
    REQUIRE(strcmp(output.c_str(), "Interface parameter is invalid.\n") == 0);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    verify_no_programs_exist();

    // (Negative) Load program with program type that does not support the interface parameter.
    output = _run_netsh_command(handle_ebpf_add_program, bind_file_name, L"bind", L"interface=1", &result);
    REQUIRE(
        strcmp(
            output.c_str(), "Interface parameter is not allowed for program types that don't support interfaces.\n") ==
        0);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    verify_no_programs_exist();

    // Add program with no interface parameter.
    output = _run_netsh_command(handle_ebpf_add_program, file_name, nullptr, nullptr, &result);
    REQUIRE(output == std::format("Loaded with ID {}\n", last_id));
    REQUIRE(result == NO_ERROR);

    // Detach the program.
    output = _run_netsh_command(handle_ebpf_set_program, last_id_string.c_str(), L"", nullptr, &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);

    output = _run_netsh_command(handle_ebpf_show_programs, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(
        output == std::format(
                      "\n"
                      "    ID  Pins  Links  Mode       Type           Name\n"
                      "======  ====  =====  =========  =============  ====================\n"
                      "{:6}     1      0  {:<9}  xdp            DropPacket\n",
                      last_id,
                      mode));

    // Re-attach the program with interface index parameter.
    output = _run_netsh_command(handle_ebpf_set_program, last_id_string.c_str(), nullptr, L"interface=1", &result);
    REQUIRE(output == "");
    REQUIRE(result == ERROR_OKAY);
    output = _run_netsh_command(handle_ebpf_delete_program, last_id_string.c_str(), nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);

    ebpf_epoch_synchronize();
}

DECLARE_JIT_TEST_CASES("xdp interface parameter", "[netsh][programs]", _test_xdp_interface_parameter);

static void
_test_cgroup_sock_addr_compartment_parameter(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    const wchar_t* file_name =
        execution_type == EBPF_EXECUTION_NATIVE ? L"cgroup_sock_addr_um.dll" : L"cgroup_sock_addr.o";
    const wchar_t* bind_file_name = execution_type == EBPF_EXECUTION_NATIVE ? L"bindmonitor_um.dll" : L"bindmonitor.o";

    // Load a program pinned.
    int result;

    // Load program with pinpath and compartment=1.
    std::string output = run_netsh_command_with_args(
        handle_ebpf_add_program, &result, 4, file_name, L"cgroup/connect4", L"mypinpath", L"compartment=1");
    // Parse the program ID from the output (format: "Loaded with ID <N>\n").
    // The ID depends on the number of maps/programs in the file, so we don't hardcode it.
    unsigned int program_id = 0;
    REQUIRE(sscanf_s(output.c_str(), "Loaded with ID %u\n", &program_id) == 1);
    REQUIRE(program_id > 0);
    REQUIRE(result == NO_ERROR);
    std::string id_str = std::to_string(program_id);
    std::wstring id_wstr(id_str.begin(), id_str.end());
    output = _run_netsh_command(handle_ebpf_delete_program, id_wstr.c_str(), nullptr, nullptr, &result);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output == "Unpinned " + id_str + " from BPF:\\mypinpath\n");
    verify_no_programs_exist();

    // (Negative) Load program with incorrect compartment id.
    output = _run_netsh_command(handle_ebpf_add_program, file_name, L"cgroup/connect4", L"compartment=0", &result);
    REQUIRE(strcmp(output.c_str(), "Compartment parameter is invalid.\n") == 0);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    verify_no_programs_exist();

    // (Negative) Load program with program type that does not support the compartment parameter.
    output = _run_netsh_command(handle_ebpf_add_program, bind_file_name, L"bind", L"compartment=1", &result);
    REQUIRE(
        strcmp(
            output.c_str(),
            "Compartment parameter is not allowed for program types that don't support compartments.\n") == 0);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    verify_no_programs_exist();

    ebpf_epoch_synchronize();
}
DECLARE_JIT_TEST_CASES(
    "cgroup_sock_addr compartment parameter", "[netsh][programs]", _test_cgroup_sock_addr_compartment_parameter);

TEST_CASE("show processes", "[netsh][processes]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    int result;
    std::string output = run_netsh_command_with_args(handle_ebpf_show_processes, &result, 0);

    TOKEN_ELEVATION token_elevation = {0};
    DWORD return_length = 0;
    if (!GetTokenInformation(
            GetCurrentProcessToken(), TokenElevation, &token_elevation, sizeof(token_elevation), &return_length) ||
        !token_elevation.TokenIsElevated) {
        REQUIRE(output == "This command requires running as Administrator\n");
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    } else {
        // There are no real eBPF handles used in this test so the result should be empty.
        REQUIRE(
            output == "\n"
                      "Host-wide process handle diagnostics (not namespace-scoped)\n"
                      "  PID  Name\n"
                      "=====  ==============\n");
        REQUIRE(result == NO_ERROR);
    }
}

static void
_test_pin_unpin_program(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    int result = 0;
    const wchar_t* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? L"bindmonitor_um.dll" : L"bindmonitor.o");
    auto output = _run_netsh_command(handle_ebpf_add_program, file_name, nullptr, L"pinpath=bindmonitor", &result);
    REQUIRE(result == EBPF_SUCCESS);
    const char prefix[] = "Loaded with ID";
    REQUIRE(output.substr(0, sizeof(prefix) - 1) == prefix);

    // Get program ID.
    auto id = strtoul(output.c_str() + output.rfind(' '), nullptr, 10);
    auto sid = std::to_wstring(id);
    _run_netsh_command(handle_ebpf_pin_program, sid.c_str(), L"bindmonitorpin", nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);

    output = _run_netsh_command(handle_ebpf_show_pins, nullptr, nullptr, nullptr, &result);
    REQUIRE(
        output == std::format(
                      "\n"
                      "     ID     Type  Path\n"
                      "=======  =======  ==============\n"
                      "      {0}  Program  BPF:\\bindmonitor\n"
                      "      {0}  Program  BPF:\\bindmonitorpin\n",
                      id));

    _run_netsh_command(handle_ebpf_unpin_program, sid.c_str(), L"random", nullptr, &result);
    REQUIRE(result != EBPF_SUCCESS);

    _run_netsh_command(handle_ebpf_unpin_program, sid.c_str(), L"bindmonitorpin", nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);

    output = _run_netsh_command(handle_ebpf_show_pins, nullptr, nullptr, nullptr, &result);
    REQUIRE(
        output == std::format(
                      "\n"
                      "     ID     Type  Path\n"
                      "=======  =======  ==============\n"
                      "      {}  Program  BPF:\\bindmonitor\n",
                      id));

    _run_netsh_command(handle_ebpf_delete_program, sid.c_str(), nullptr, nullptr, &result);
}

DECLARE_ALL_TEST_CASES("pin/unpin program", "[netsh][pin]", _test_pin_unpin_program);

static void
_test_pin_unpin_map(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    int result = 0;
    const wchar_t* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? L"bindmonitor_um.dll" : L"bindmonitor.o");
    auto output = _run_netsh_command(handle_ebpf_add_program, file_name, L"bind", L"pinpath=bindmonitor", &result);
    REQUIRE(result == EBPF_SUCCESS);
    const char prefix[] = "Loaded with ID";
    REQUIRE(output.substr(0, sizeof(prefix) - 1) == prefix);
    auto pid = strtoul(output.c_str() + output.rfind(' '), nullptr, 10);

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);

    // Grab the first map ID.
    auto digit = output.find_first_of("123456789");
    auto id = strtoul(output.c_str() + digit, nullptr, 10);
    REQUIRE(id > 0);
    auto sid = std::to_wstring(id);

    const char* map_name = (execution_type == EBPF_EXECUTION_NATIVE ? "limits_map" : "audit_map");
    auto offset = output.find(map_name, digit + 1);
    REQUIRE(offset != std::string::npos);
    auto pins = strtoul(output.c_str() + offset - 4, nullptr, 10);
    REQUIRE(pins == 0);

    // Pin map with default name (map name).
    output = _run_netsh_command(handle_ebpf_pin_map, sid.c_str(), nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);

    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    pins = strtoul(output.c_str() + offset - 4, nullptr, 10);
    REQUIRE(pins == 1);

    // Pin map with custom name.
    output = _run_netsh_command(handle_ebpf_pin_map, sid.c_str(), L"custompin", nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    pins = strtoul(output.c_str() + offset - 4, nullptr, 10);
    REQUIRE(pins == 2);

    // Unpin twice.
    output = _run_netsh_command(handle_ebpf_unpin_map, sid.c_str(), nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    output = _run_netsh_command(handle_ebpf_unpin_map, sid.c_str(), L"custompin", nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    output = _run_netsh_command(handle_ebpf_show_maps, nullptr, nullptr, nullptr, &result);
    REQUIRE(result == EBPF_SUCCESS);
    pins = strtoul(output.c_str() + offset - 4, nullptr, 10);
    REQUIRE(pins == 0);

    _run_netsh_command(handle_ebpf_delete_program, std::to_wstring(pid).c_str(), nullptr, nullptr, &result);
}

DECLARE_ALL_TEST_CASES("pin/unpin map", "[netsh][pin]", _test_pin_unpin_map);

static void
_test_namespace_program_management(ebpf_execution_type_t execution_type)
{
    _test_helper_netsh test_helper;
    test_helper.initialize();
    netsh_namespace_restore restore;
    auto parameters = _get_netsh_tail_call_parameters(execution_type);
    int result;
    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, L"{12345678-1234-4234-8234-123456789abc}");
    REQUIRE(result == NO_ERROR);
    auto output =
        run_netsh_command_with_args(handle_ebpf_add_program, &result, 2, parameters.file_name, L"pinned=none");
    REQUIRE(result == NO_ERROR);
    uint32_t program_id;
    REQUIRE(sscanf_s(output.c_str(), "Loaded with ID %u\n", &program_id) == 1);
    auto program = std::to_wstring(program_id);
    run_netsh_command_with_args(handle_ebpf_pin_program, &result, 2, program.c_str(), L"netsh_namespace_program");
    REQUIRE(result == NO_ERROR);
    uint32_t link_id;
    REQUIRE(bpf_link_get_next_id(0, &link_id) == 0);
    auto link = std::to_wstring(link_id);
    run_netsh_command_with_args(handle_ebpf_pin_link, &result, 2, link.c_str(), L"netsh_namespace_link");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_show_links, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.find("sample_ext") != std::string::npos);
    output = run_netsh_command_with_args(handle_ebpf_show_pins, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.find("netsh_namespace_link") != std::string::npos);
    REQUIRE(output.find("netsh_namespace_program") != std::string::npos);
    REQUIRE(output.find(std::format("{:7}     Link  BPF:\\netsh_namespace_link\n", link_id)) != std::string::npos);

    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, L"{00000000-0000-0000-0000-000000000000}");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_show_programs, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.find("sample_ext") == std::string::npos);
    output = run_netsh_command_with_args(handle_ebpf_show_links, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.find("sample_ext") == std::string::npos);
    output = run_netsh_command_with_args(handle_ebpf_show_pins, &result, 0);
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.find("netsh_namespace_") == std::string::npos);
    for (auto command : {handle_ebpf_pin_link, handle_ebpf_unpin_link}) {
        output = run_netsh_command_with_args(command, &result, 2, link.c_str(), L"netsh_namespace_link");
        REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
        REQUIRE(output == "error 2: could not open link\n");
    }
    output = run_netsh_command_with_args(handle_ebpf_delete_link, &result, 1, link.c_str());
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error 2: could not open link\n");
    output = run_netsh_command_with_args(handle_ebpf_delete_program, &result, 1, program.c_str());
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "Program not found\n");
    REQUIRE(_ebpf_netsh_objects.size() == 1);
    output = run_netsh_command_with_args(
        handle_ebpf_set_program, &result, 2, program.c_str(), L"pinpath=netsh_namespace_program_foreign");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "Program not found.\n");

    run_netsh_command_with_args(handle_ebpf_set_namespace, &result, 1, L"{12345678-1234-4234-8234-123456789abc}");
    REQUIRE(result == NO_ERROR);
    output = run_netsh_command_with_args(handle_ebpf_unpin_link, &result, 2, link.c_str(), L"netsh_namespace_program");
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "error 22: could not manage link\n");
    output = run_netsh_command_with_args(handle_ebpf_delete_link, &result, 1, link.c_str());
    REQUIRE(result == NO_ERROR);
    REQUIRE(output.empty());
    run_netsh_command_with_args(handle_ebpf_unpin_link, &result, 2, link.c_str(), L"netsh_namespace_link");
    REQUIRE(result == NO_ERROR);
    run_netsh_command_with_args(handle_ebpf_set_program, &result, 2, program.c_str(), L"sample_ext");
    REQUIRE(result == ERROR_OKAY);
    run_netsh_command_with_args(handle_ebpf_set_program, &result, 2, program.c_str(), L"");
    REQUIRE(result == ERROR_OKAY);
    run_netsh_command_with_args(handle_ebpf_unpin_program, &result, 2, program.c_str(), L"netsh_namespace_program");
    REQUIRE(result == NO_ERROR);
    run_netsh_command_with_args(handle_ebpf_delete_program, &result, 1, program.c_str());
    REQUIRE(result == NO_ERROR);
    verify_no_programs_exist();
}

DECLARE_JIT_TEST_CASES(
    "NU51 namespace program and link management",
    "[netsh][namespace][programs][links]",
    _test_namespace_program_management);

// Test cases for show hash functionality.
TEST_CASE("show hash nosuchfile.o", "[netsh][hash]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_hash, L"nosuchfile.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "Error: No such file or directory opening nosuchfile.o\n");
}

TEST_CASE("show hash bpf.o", "[netsh][hash]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_hash, L"bpf.o", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "Error: No hash section found in bpf.o\n");
}

TEST_CASE("show hash PE file with hash section", "[netsh][hash]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    // Test with a PE file that has a hash section.
    std::string output = _run_netsh_command(handle_ebpf_show_hash, L"map_reuse_um.dll", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUCCESS);
    REQUIRE(output.find("Hash for map_reuse_um.dll:") != std::string::npos);
    REQUIRE(output.find("Size: 32 bytes") != std::string::npos);
    REQUIRE(output.find("Data: ") != std::string::npos);
}

TEST_CASE("show hash PE file without hash section", "[netsh][hash]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    // Test with a PE file that doesn't have a hash section.
    std::string output = _run_netsh_command(handle_ebpf_show_hash, L"EbpfApi.dll", nullptr, nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "Error: No hash section found in EbpfApi.dll\n");
}

TEST_CASE("show hash PE file with hash section hashonly", "[netsh][hash]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    // Test with a PE file that has a hash section, hashonly format.
    std::string output = _run_netsh_command(handle_ebpf_show_hash, L"map_reuse_um.dll", L"hashonly", nullptr, &result);
    REQUIRE(result == ERROR_SUCCESS);

    // Verify output is exactly 64 hex characters (32 bytes) + newline, all uppercase, no spaces.
    REQUIRE(output.length() == 65); // 64 characters + newline
    REQUIRE(output[64] == '\n');

    // Check that all characters are uppercase hex.
    for (int i = 0; i < 64; i++) {
        REQUIRE(((output[i] >= '0' && output[i] <= '9') || (output[i] >= 'A' && output[i] <= 'F')));
    }

    // Verify no spaces in the hash.
    REQUIRE(output.find(' ') == std::string::npos);

    // Independently compute SHA-256 of the source ELF file and validate the hash matches.
    // SHA256 is the algorithm used by bpf2c (EBPF_HASH_ALGORITHM in bpf_code_generator.h).
    std::ifstream elf_file("map_reuse.o", std::ios::binary);
    REQUIRE(elf_file.good());
    std::string elf_contents((std::istreambuf_iterator<char>(elf_file)), std::istreambuf_iterator<char>());
    REQUIRE(!elf_contents.empty());

    hash_t hasher("SHA256");
    std::vector<uint8_t> expected_hash = hasher.hash_string(elf_contents);
    REQUIRE(expected_hash.size() == 32);

    // Convert to uppercase hex string.
    std::ostringstream hex_stream;
    hex_stream << std::uppercase << std::hex << std::setfill('0');
    for (uint8_t byte : expected_hash) {
        hex_stream << std::setw(2) << static_cast<int>(byte);
    }
    std::string expected_hex = hex_stream.str() + "\n";

    REQUIRE(output == expected_hex);
}

TEST_CASE("show hash PE file without hash section hashonly", "[netsh][hash]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    // Test with a PE file that doesn't have a hash section, hashonly format.
    std::string output = _run_netsh_command(handle_ebpf_show_hash, L"EbpfApi.dll", L"hashonly", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "Error: No hash section found in EbpfApi.dll\n");
}

TEST_CASE("show hash nosuchfile.o hashonly", "[netsh][hash]")
{
    _test_helper_netsh test_helper;
    test_helper.initialize();

    int result;
    std::string output = _run_netsh_command(handle_ebpf_show_hash, L"nosuchfile.o", L"hashonly", nullptr, &result);
    REQUIRE(result == ERROR_SUPPRESS_OUTPUT);
    REQUIRE(output == "Error: No such file or directory opening nosuchfile.o\n");
}
