// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "catch_wrapper.hpp"

#include <windows.h>
#include <cstddef>
#include <filesystem>
#include <string>

namespace {
static_assert(offsetof(bpf_map_info, id) == 0);
static_assert(offsetof(bpf_prog_info, id) == 0);
static_assert(offsetof(bpf_link_info, id) == 0);

class vm_handle
{
  public:
    explicit vm_handle(HANDLE handle = nullptr) : value(handle) {}
    vm_handle(const vm_handle&) = delete;
    vm_handle&
    operator=(const vm_handle&) = delete;
    ~vm_handle()
    {
        if (value && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
    HANDLE value;
};

std::wstring
vm_quote(const std::wstring& value)
{
    REQUIRE(value.find(L'"') == std::wstring::npos);
    REQUIRE(!value.empty());
    REQUIRE(value.back() != L'\\');
    return L"\"" + value + L"\"";
}

void
run_namespace_vm_fixture(const wchar_t* scenario, const wchar_t* manifest_variable = L"EBPF_NAMESPACE_VM_MANIFEST")
{
    DWORD size = GetEnvironmentVariableW(manifest_variable, nullptr, 0);
    INFO("Explicitly selected VM case requires its manifest environment variable and an approved preprovisioned VM.");
    REQUIRE(size > 1);
    std::wstring manifest(size, L'\0');
    DWORD length = GetEnvironmentVariableW(manifest_variable, manifest.data(), size);
    REQUIRE(length > 0);
    REQUIRE(length < size);
    manifest.resize(length);
    REQUIRE(std::filesystem::is_regular_file(manifest));

    wchar_t executable[32768]{};
    length = GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
    REQUIRE(length > 0);
    REQUIRE(length < ARRAYSIZE(executable));
    auto script = std::filesystem::path(executable).parent_path() / L"execute_namespace_vm_tests.ps1";
    REQUIRE(std::filesystem::is_regular_file(script));

    wchar_t system_directory[MAX_PATH]{};
    length = GetSystemDirectoryW(system_directory, ARRAYSIZE(system_directory));
    REQUIRE(length > 0);
    REQUIRE(length < ARRAYSIZE(system_directory));
    std::wstring powershell = std::wstring(system_directory) + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    std::wstring command = vm_quote(powershell) + L" -NoProfile -NonInteractive -File " + vm_quote(script.wstring()) +
                           L" -Scenario " + scenario + L" -Manifest " + vm_quote(manifest);

    vm_handle job(CreateJobObjectW(nullptr, nullptr));
    REQUIRE(job.value != nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    REQUIRE(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    REQUIRE(CreateProcessW(
        powershell.c_str(),
        command.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        &startup,
        &process));
    vm_handle child(process.hProcess);
    vm_handle thread(process.hThread);
    if (!AssignProcessToJobObject(job.value, child.value)) {
        auto error = GetLastError();
        TerminateProcess(child.value, ERROR_PROCESS_ABORTED);
        FAIL("Cannot assign VM fixture child to an ownership-bounded job: " << error);
    }
    REQUIRE(ResumeThread(thread.value) != static_cast<DWORD>(-1));
    REQUIRE(WaitForSingleObject(child.value, 300000) == WAIT_OBJECT_0);
    DWORD exit_code = 0;
    REQUIRE(GetExitCodeProcess(child.value, &exit_code));
    REQUIRE(exit_code == 0);
}
} // namespace

// ND23 must use the standalone controller, not this statically SDK-linked runner.
TEST_CASE("ND31 actual OLD DLL against NEW driver image", "[.namespace_vm][ND31]")
{
    run_namespace_vm_fixture(L"ND31OldDllNewDriver");
}

TEST_CASE("ND31 actual NEW DLL against OLD driver image", "[.namespace_vm][ND31]")
{
    run_namespace_vm_fixture(L"ND31NewDllOldDriver");
}

TEST_CASE("ND12 actual Administrator namespace fixture", "[.namespace_vm][ND12]")
{
    run_namespace_vm_fixture(L"ND12Admin", L"EBPF_NAMESPACE_VM_IDENTITY_MANIFEST");
}
