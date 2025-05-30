// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#define CATCH_CONFIG_MAIN

#include "bpf_code_generator.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#define main test_main
#include "bpf2c.cpp"
#undef main

#define INDENT "    "

template <typename stream_t>
std::vector<std::string>
read_contents(const std::string& source, std::vector<std::function<std::string(const std::string&)>> transforms)
{
    std::vector<std::string> return_value;
    std::string line;
    stream_t input(source);

    while (std::getline(input, line)) {
        for (auto& transform : transforms) {
            line = transform(line);
        }
        return_value.push_back(line);
    }
    return return_value;
}

template <char separator>
std::string
transform_line_directives(const std::string& string)
{
    if (!string.starts_with("#line")) {
        return string;
    }
    if (string.find("\"") == std::string::npos) {
        return string;
    }
    if ((string.find(separator) == std::string::npos)) {
        // Already trimmed.
        return string;
    }

    return string.substr(0, string.find("\"") + 1) + string.substr(string.find_last_of(separator) + 1);
}

// Workaround for: https://github.com/microsoft/ebpf-for-windows/issues/1060
std::string
transform_fix_opcode_comment(const std::string& string)
{
    if (!string.starts_with(INDENT INDENT "// EBPF_OP_")) {
        return string;
    } else {
        return string.substr(sizeof(INDENT) - 1);
    }
}

std::tuple<std::string, std::string, int>
run_test_main(std::vector<const char*> argv)
{
    capture_helper_t capture;
    errno_t error = capture.begin_capture();
    if (error != 0) {
        throw std::runtime_error("capture.begin_capture failed");
    }
    auto return_value = test_main(static_cast<int>(argv.size()), const_cast<char**>(argv.data()));

    return {
        return_value == 0 ? capture.get_stdout_contents() : "",
        return_value != 0 ? capture.get_stderr_contents() : "",
        return_value};
}

enum class _test_mode
{
    Verify,
    VerifyFail,
    UseHash,
    UseHashSHA512,
    UseHashX,
    FileNotFound,
    FileOutput,
};

void
run_test_elf(const std::string& elf_file, _test_mode test_mode, const std::optional<std::string>& type)
{
    std::vector<const char*> argv;
    auto name = elf_file.substr(0, elf_file.find('.'));
    argv.push_back("bpf2c.exe");
    argv.push_back("--bpf");
    argv.push_back(elf_file.c_str());
    if (test_mode == _test_mode::UseHash) {
        argv.push_back("--hash");
        argv.push_back("SHA256");
    } else if (test_mode == _test_mode::UseHashSHA512) {
        argv.push_back("--hash");
        argv.push_back("SHA512");
    } else if (test_mode == _test_mode::UseHashX) {
        argv.push_back("--hash");
        // Invalid hash algorithm.
        argv.push_back("SHAX");
    } else {
        argv.push_back("--hash");
        argv.push_back("none");
    }
    if (type) {
        argv.push_back("--type");
        argv.push_back(type.value().c_str());
    }

    auto test = [&](const char* option, const char* suffix) {
        if (option) {
            argv.push_back(option);
        }
        auto temp_file_path = std::filesystem::temp_directory_path() / std::filesystem::path(name + suffix);
        std::string temp_file_path_string = temp_file_path.string();
        if (test_mode == _test_mode::FileOutput) {
            argv.push_back(temp_file_path_string.c_str());
        }
        auto [out, err, result_value] = run_test_main(argv);
        switch (test_mode) {
        case _test_mode::FileOutput:
        case _test_mode::Verify: {
            std::vector<std::string> expected_output = read_contents<std::ifstream>(
                std::string("expected\\") + name + suffix,
                {transform_line_directives<'\\'>, transform_line_directives<'/'>, transform_fix_opcode_comment});
            std::vector<std::string> actual_output;
            if (test_mode == _test_mode::FileOutput) {
                actual_output = read_contents<std::ifstream>(
                    temp_file_path_string, {transform_line_directives<'\\'>, transform_line_directives<'/'>});
            } else {
                actual_output = read_contents<std::istringstream>(
                    out, {transform_line_directives<'\\'>, transform_line_directives<'/'>});
            }

            // Find the first line that differs.
            if (actual_output.size() != expected_output.size()) {
                for (size_t i = 0; i < min(actual_output.size(), expected_output.size()); i++) {
                    if (actual_output[i] != expected_output[i]) {
                        std::cout << "First difference at line " << i << std::endl;
                        std::cout << "Expected: " << expected_output[i] << std::endl;
                        std::cout << "Actual: " << actual_output[i] << std::endl;
                        break;
                    }
                }
            }
            REQUIRE(actual_output.size() == expected_output.size());
            for (size_t i = 0; i < actual_output.size(); i++) {
                REQUIRE(expected_output[i] == actual_output[i]);
            }
        } break;
        case _test_mode::VerifyFail:
        case _test_mode::FileNotFound: {
            REQUIRE(result_value != 0);
            REQUIRE(err != "");
        } break;
        case _test_mode::UseHashSHA512:
        case _test_mode::UseHash: {
            REQUIRE(result_value == 0);
            REQUIRE(out != "");
        } break;
        case _test_mode::UseHashX: {
            REQUIRE(result_value != 0);
            REQUIRE(err != "");
        }
        }
        if (option) {
            argv.pop_back();
        }
        if (test_mode == _test_mode::FileOutput) {
            argv.pop_back();
        }
    };

    test("--raw", "_raw.c");
    test("--dll", "_dll.c");
    test("--sys", "_sys.c");
}

#define DECLARE_TEST(FILE, MODE) \
    TEST_CASE(FILE " " #MODE, "[elf_bpf_code_gen]") { run_test_elf(FILE ".o", MODE, std::nullopt); }

#define DECLARE_TEST_CUSTOM_PROGRAM_TYPE(FILE, MODE, TYPE) \
    TEST_CASE(FILE "-custom-" #MODE, "[elf_bpf_code_gen]") { run_test_elf(FILE ".o", MODE, TYPE); }

DECLARE_TEST("atomic_instruction_fetch_add", _test_mode::Verify)
DECLARE_TEST("bad_map_name", _test_mode::Verify)
DECLARE_TEST("bindmonitor", _test_mode::Verify)
DECLARE_TEST("bindmonitor_bpf2bpf", _test_mode::Verify)
DECLARE_TEST("bindmonitor_ringbuf", _test_mode::Verify)
DECLARE_TEST("bindmonitor_tailcall", _test_mode::Verify)
DECLARE_TEST("bindmonitor_mt_tailcall", _test_mode::Verify)
DECLARE_TEST_CUSTOM_PROGRAM_TYPE("bpf", _test_mode::Verify, std::string("bind"))
DECLARE_TEST_CUSTOM_PROGRAM_TYPE("bpf", _test_mode::FileOutput, std::string("bind"))
DECLARE_TEST("bpf_call", _test_mode::Verify)
DECLARE_TEST("cgroup_sock_addr", _test_mode::Verify)
DECLARE_TEST("cgroup_sock_addr2", _test_mode::Verify)
DECLARE_TEST("decap_permit_packet", _test_mode::Verify)
DECLARE_TEST("divide_by_zero", _test_mode::Verify)
DECLARE_TEST("droppacket", _test_mode::Verify)
DECLARE_TEST("encap_reflect_packet", _test_mode::Verify)
DECLARE_TEST("hash_of_map", _test_mode::Verify)
DECLARE_TEST("inner_map", _test_mode::Verify)
DECLARE_TEST("map_in_map_btf", _test_mode::Verify)
DECLARE_TEST("map_in_map_legacy_id", _test_mode::Verify)
DECLARE_TEST("map_in_map_legacy_idx", _test_mode::Verify)
DECLARE_TEST("map_reuse", _test_mode::Verify)
DECLARE_TEST("map_reuse_2", _test_mode::Verify)
DECLARE_TEST("pidtgid", _test_mode::Verify)
DECLARE_TEST("printk", _test_mode::Verify)
DECLARE_TEST("printk_legacy", _test_mode::Verify)
DECLARE_TEST("reflect_packet", _test_mode::Verify)
DECLARE_TEST("sockops", _test_mode::Verify)
DECLARE_TEST("tail_call", _test_mode::Verify)
DECLARE_TEST("tail_call_bad", _test_mode::Verify)
DECLARE_TEST("tail_call_map", _test_mode::Verify)
DECLARE_TEST("tail_call_max_exceed", _test_mode::Verify)
DECLARE_TEST("tail_call_multiple", _test_mode::Verify)
DECLARE_TEST("tail_call_recursive", _test_mode::Verify)
DECLARE_TEST("tail_call_sequential", _test_mode::Verify)
DECLARE_TEST("test_sample_ebpf", _test_mode::Verify)
DECLARE_TEST("test_utility_helpers", _test_mode::Verify)
DECLARE_TEST("cgroup_sock_addr", _test_mode::UseHashSHA512)
DECLARE_TEST("cgroup_sock_addr2", _test_mode::UseHashX)

DECLARE_TEST("no_such_file", _test_mode::FileNotFound)
DECLARE_TEST_CUSTOM_PROGRAM_TYPE("bpf", _test_mode::UseHash, std::string("bind"))

DECLARE_TEST("bpf", _test_mode::VerifyFail)
DECLARE_TEST_CUSTOM_PROGRAM_TYPE("bpf", _test_mode::VerifyFail, std::string("invalid"))

TEST_CASE("help", "[bpf2c_cli]")
{
    std::vector<const char*> argv;
    argv.push_back("bpf2c.exe");
    argv.push_back("--help");

    auto [out, err, result_value] = run_test_main(argv);
    REQUIRE(result_value != 0);
    std::vector<std::string> options = {"--sys", "--dll", "--bpf", "--hash", "--help"};
    for (const auto& option : options) {
        REQUIRE(err.find(option) != std::string::npos);
    }
}

TEST_CASE("bad --bpf", "[bpf2c_cli]")
{
    std::vector<const char*> argv;
    argv.push_back("bpf2c.exe");
    argv.push_back("--bpf");

    auto [out, err, result_value] = run_test_main(argv);
    REQUIRE(result_value != 0);
    REQUIRE(!err.empty());
}

TEST_CASE("bad --hash", "[bpf2c_cli]")
{
    std::vector<const char*> argv;
    argv.push_back("bpf2c.exe");
    argv.push_back("--hash");

    auto [out, err, result_value] = run_test_main(argv);
    REQUIRE(result_value != 0);
    REQUIRE(!err.empty());
}

// List of malformed ELF files and the expected error message.
// Files are named after the SHA1 hash of the ELF file to avoid duplicates and merge conflicts.
const std::map<std::string, std::string> _malformed_elf_expected_output{
    {"0BB5D8637905866F80790C88104CFD580258052E",
     "Failed parsing in struct _E_IDENT field SEVEN.refinement reason constraint failed"},
    {"2775DA65BC9DC1B1BD6558C1B456C7532CD1BE02",
     "Failed parsing in struct _SECTION_HEADER_TABLE_ENTRY field none reason constraint failed"},
    {"3688AF1375D9360872B65D0E67F31E5D9AA8166B",
     "error: Illegal operation on symbol bind_tail_call_map at location 27"},
    {"9A0D5CC0FB24BC6AFB0415DC648388B961FE3E38",
     "error: Illegal operation on symbol bind_tail_call_map at location 27"},
};

TEST_CASE("bad malformed ELF", "[bpf2c_cli]")
{
    // For each file in bad\*.o run bpf2c.exe --bpf <file>
    std::filesystem::path bad_path("bad");
    for (const auto& entry : std::filesystem::directory_iterator(bad_path)) {
        std::vector<const char*> argv;
        argv.push_back("bpf2c.exe");
        argv.push_back("--bpf");
        std::string file_path = entry.path().string();

        // Check if we have an expected error for this file.
        auto expected_error_entry = _malformed_elf_expected_output.find(entry.path().filename().stem().string());
        if (expected_error_entry == _malformed_elf_expected_output.end()) {
            // No expected error, fail the test.
            REQUIRE(entry.path().filename().stem().string() == "Update the expected error");
        }

        std::string expected_error = expected_error_entry->second;
        argv.push_back(file_path.c_str());

        // Run bpf2c.exe --bpf <file>
        auto [out, err, result_value] = run_test_main(argv);
        REQUIRE(result_value != 0);
        REQUIRE(!err.empty());
        // Split err on \n and only keep the first line.
        err = err.substr(0, err.find('\n'));
        REQUIRE(err == expected_error);
    }
}

TEST_CASE("Verbose output", "[bpf2c_cli]")
{
    std::string non_verbose_error;
    std::string verbose_error;
    auto test = [&](bool verbose) -> std::string {
        std::vector<const char*> argv;
        argv.push_back("bpf2c.exe");
        argv.push_back("--bpf");
        argv.push_back("droppacket_unsafe.o");
        if (verbose) {
            argv.push_back("--verbose");
        }
        auto [out, err, result_value] = run_test_main(argv);
        REQUIRE(result_value != 0);
        REQUIRE(!err.empty());
        REQUIRE(err.find("Verification failed for DropPacket with error Verification failed") != std::string::npos);
        return err;
    };

    non_verbose_error = test(false);
    verbose_error = test(true);

    REQUIRE(non_verbose_error != verbose_error);
    REQUIRE(non_verbose_error.length() < verbose_error.length());

    // Count Pre-Invariant and Post-Invariant lines in the verbose output.
    int pre_invariant = 0;
    int post_invariant = 0;
    std::istringstream verbose_stream(verbose_error);
    std::string line;
    while (std::getline(verbose_stream, line)) {
        if (line.find("Pre-invariant") != std::string::npos) {
            pre_invariant++;
        }
        if (line.find("Post-invariant") != std::string::npos) {
            post_invariant++;
        }
    }

    REQUIRE(pre_invariant == 34);
    REQUIRE(post_invariant == 34);

    // Check to make sure that the verbose flag doesn't cause verification to fail.
    std::vector<const char*> argv;
    argv.push_back("bpf2c.exe");
    argv.push_back("--bpf");
    argv.push_back("droppacket.o");
    argv.push_back("--verbose");
    auto [out, err, result_value] = run_test_main(argv);
    REQUIRE(result_value == 0);
    REQUIRE(err.empty());
}