// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"

#include <Windows.h>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace {
// Keep the dynamically marshaled Windows map-info layout below tied to the public header.
static_assert(sizeof(bpf_map_info) == 96 && offsetof(bpf_map_info, id) == 0);
static_assert(offsetof(bpf_map_info, name) == 20 && offsetof(bpf_map_info, map_flags) == 84);
static_assert(BPF_MAP_TYPE_HASH == 1 && BPF_ANY == 0);

constexpr char dll_lifetime_script[] = R"ND04(
param(
    [Parameter(Mandatory=$true)][string]$DllPath,
    [Parameter(Mandatory=$true)][string]$NamespaceA,
    [Parameter(Mandatory=$true)][string]$NamespaceB,
    [Parameter(Mandatory=$true)][string]$PinPath
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# CodeDOM compiler artifacts belong to this test's newly created directory, not the machine TEMP directory.
$env:TEMP = $PSScriptRoot
$env:TMP = $PSScriptRoot
$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public static class NamespaceDllLifetime
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string path);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr GetModuleHandleW(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr module);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int SetNamespace([In] ref Guid value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int GetNamespace(out Guid value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int CreateMap(
        int type, [MarshalAs(UnmanagedType.LPStr)] string name,
        uint keySize, uint valueSize, uint maxEntries, IntPtr options);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int MapInfoByFd(int fd, [In, Out] ref MapInfo info, ref uint length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int PinObject(int fd, [MarshalAs(UnmanagedType.LPStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int UnpinObject([MarshalAs(UnmanagedType.LPStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int MapById(uint id);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int CloseFd(int fd);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Update(int fd, ref uint key, ref uint value, ulong flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Lookup(int fd, ref uint key, out uint value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Delete(int fd, ref uint key);

    [StructLayout(LayoutKind.Sequential)]
    private struct MapInfo
    {
        public uint Id, Type, KeySize, ValueSize, MaxEntries;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] Name;
        public uint Flags, InnerMapId, PinnedPathCount;
    }

    public sealed class Report
    {
        public bool Passed;
        public string Stage = "start";
        public string Error;
        public uint OldMapId, NewMapId;
        public bool FirstUnload, ReloadPreservedNamespace, IsolatedIds, RetainedHandleCrud, FinalUnload;
        public List<string> CleanupErrors = new List<string>();
    }

    private sealed class Api
    {
        public readonly SetNamespace Set;
        public readonly GetNamespace Get;
        public readonly CreateMap Create;
        public readonly MapInfoByFd Info;
        public readonly PinObject Pin;
        public readonly UnpinObject Unpin;
        public readonly MapById ById;
        public readonly CloseFd Close;
        public readonly Update Put;
        public readonly Lookup Find;
        public readonly Delete Remove;

        public Api(IntPtr module)
        {
            Set = Bind<SetNamespace>(module, "ebpf_set_namespace");
            Get = Bind<GetNamespace>(module, "ebpf_get_namespace");
            Create = Bind<CreateMap>(module, "bpf_map_create");
            Info = Bind<MapInfoByFd>(module, "bpf_obj_get_info_by_fd");
            Pin = Bind<PinObject>(module, "bpf_obj_pin");
            Unpin = Bind<UnpinObject>(module, "ebpf_object_unpin");
            ById = Bind<MapById>(module, "bpf_map_get_fd_by_id");
            Close = Bind<CloseFd>(module, "ebpf_close_fd");
            Put = Bind<Update>(module, "bpf_map_update_elem");
            Find = Bind<Lookup>(module, "bpf_map_lookup_elem");
            Remove = Bind<Delete>(module, "bpf_map_delete_elem");
        }
    }

    private static T Bind<T>(IntPtr module, string name) where T : class
    {
        IntPtr address = GetProcAddress(module, name);
        Require(address != IntPtr.Zero, "Missing export " + name + ": " + Marshal.GetLastWin32Error());
        return (T)(object)Marshal.GetDelegateForFunctionPointer(address, typeof(T));
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) {
            throw new InvalidOperationException(message);
        }
    }

    private static void Success(int result, string operation)
    {
        Require(result == 0, operation + " returned " + result);
    }

    private static IntPtr Load(string path)
    {
        IntPtr module = LoadLibraryW(path);
        if (module == IntPtr.Zero) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "LoadLibraryW " + path);
        }
        return module;
    }

    private static void Unload(ref IntPtr module, string name)
    {
        Require(FreeLibrary(module), "FreeLibrary failed: " + Marshal.GetLastWin32Error());
        module = IntPtr.Zero;
        Require(GetModuleHandleW(name) == IntPtr.Zero, "ebpfapi.dll still has a loaded module reference");
    }

    private static int Own(int fd, List<int> owned, string operation)
    {
        Require(fd >= 0, operation + " returned " + fd);
        owned.Add(fd);
        return fd;
    }

    private static void Close(Api api, List<int> owned, int fd)
    {
        Success(api.Close(fd), "ebpf_close_fd");
        owned.Remove(fd);
    }

    private static uint Id(Api api, int fd)
    {
        MapInfo info = new MapInfo {
            Id = 0, Type = 0, KeySize = 0, ValueSize = 0, MaxEntries = 0,
            Name = new byte[64], Flags = 0, InnerMapId = 0, PinnedPathCount = 0
        };
        uint length = (uint)Marshal.SizeOf(typeof(MapInfo));
        Success(api.Info(fd, ref info, ref length), "bpf_obj_get_info_by_fd");
        Require(length == 96 && info.Id != 0 && info.Type == 1 &&
            info.KeySize == 4 && info.ValueSize == 4 && info.MaxEntries == 8, "Unexpected public map-info layout");
        return info.Id;
    }

    private static void Marker(Api api, int fd, uint expected)
    {
        uint key = 1, actual;
        Success(api.Find(fd, ref key, out actual), "bpf_map_lookup_elem");
        Require(actual == expected, "Marker mismatch: " + actual + " != " + expected);
    }

    private static void Hidden(Api api, List<int> owned, uint id)
    {
        int fd = api.ById(id);
        if (fd >= 0) {
            owned.Add(fd);
        }
        Require(fd == -2, "Namespace B opened A map ID " + id + " or returned an error other than -ENOENT: " + fd);
    }

    private static void Cleanup(Report report, string operation, Action action)
    {
        try {
            action();
        } catch (Exception exception) {
            report.CleanupErrors.Add(operation + ": " + exception.Message);
        }
    }

    public static Report Run(string path, string namespaceA, string namespaceB, string pinPath)
    {
        Report report = new Report();
        Guid a = Guid.Parse(namespaceA), b = Guid.Parse(namespaceB), empty = Guid.Empty;
        IntPtr module = IntPtr.Zero;
        Api api = null;
        List<int> owned = new List<int>();
        bool pinned = false, completed = false;
        string moduleName = Path.GetFileName(path);
        try {
            report.Stage = "initial-load";
            Require(GetModuleHandleW(moduleName) == IntPtr.Zero, "Child already imported ebpfapi.dll");
            module = Load(path);
            api = new Api(module);
            Guid current;
            Success(api.Get(out current), "initial ebpf_get_namespace");
            Require(current == empty, "New child did not start in the null namespace");
            Success(api.Set(ref a), "select A");
            int oldFd = Own(api.Create(1, "ns_dll_old", 4, 4, 8, IntPtr.Zero), owned, "create old A map");
            uint key = 1, marker = 0x4e443034;
            Success(api.Put(oldFd, ref key, ref marker, 0), "initialize old marker");
            report.OldMapId = Id(api, oldFd);
            Success(api.Pin(oldFd, pinPath), "bpf_obj_pin");
            pinned = true;
            Close(api, owned, oldFd);
            Require(owned.Count == 0, "API descriptors remain before first unload");

            report.Stage = "first-full-unload";
            api = null;
            Unload(ref module, moduleName);
            report.FirstUnload = true;

            report.Stage = "reload-without-SET";
            module = Load(path);
            api = new Api(module);
            Success(api.Get(out current), "ebpf_get_namespace after reload");
            Require(current == a, "Full ebpfapi DLL unload/reload reset process namespace A");
            report.ReloadPreservedNamespace = true;
            int retained = Own(api.ById(report.OldMapId), owned, "reopen old A map ID after reload");
            Require(Id(api, retained) == report.OldMapId, "Reopened map ID changed");
            Marker(api, retained, marker);
            int newFd = Own(api.Create(1, "ns_dll_new", 4, 4, 8, IntPtr.Zero), owned, "create new A map after reload");
            report.NewMapId = Id(api, newFd);
            Require(report.NewMapId != report.OldMapId, "Distinct live maps reused an ID");
            Success(api.Put(newFd, ref key, ref marker, 0), "initialize new marker");

            report.Stage = "B-isolation-and-retained-A-CRUD";
            Success(api.Set(ref b), "select B");
            Hidden(api, owned, report.OldMapId);
            Hidden(api, owned, report.NewMapId);
            report.IsolatedIds = true;
            Require(Id(api, retained) == report.OldMapId, "Retained A handle changed ownership under B");
            Marker(api, retained, marker);
            marker++;
            Success(api.Put(retained, ref key, ref marker, 0), "update retained A handle under B");
            Marker(api, retained, marker);
            Success(api.Remove(retained, ref key), "delete through retained A handle under B");
            uint missing;
            Require(api.Find(retained, ref key, out missing) == -2, "Deleted retained A key was still visible");
            Success(api.Put(retained, ref key, ref marker, 0), "recreate retained A key under B");
            Marker(api, retained, marker);
            report.RetainedHandleCrud = true;

            report.Stage = "owned-cleanup-and-final-unload";
            Success(api.Set(ref a), "restore A");
            Success(api.Unpin(pinPath), "ebpf_object_unpin");
            pinned = false;
            Close(api, owned, retained);
            Close(api, owned, newFd);
            Success(api.Set(ref empty), "reset null namespace");
            api = null;
            Unload(ref module, moduleName);
            report.FinalUnload = true;
            completed = true;
        } catch (Exception exception) {
            report.Error = exception.ToString();
        } finally {
            if (module == IntPtr.Zero && pinned) {
                Cleanup(report, "reload for owned-pin cleanup", delegate {
                    module = Load(path);
                    api = new Api(module);
                });
            }
            if (module != IntPtr.Zero && api != null) {
                if (pinned) {
                    Cleanup(report, "remove owned pin in A", delegate {
                        Success(api.Set(ref a), "cleanup select A");
                        Success(api.Unpin(pinPath), "cleanup unpin");
                        pinned = false;
                    });
                }
                foreach (int fd in new List<int>(owned)) {
                    Cleanup(report, "close owned fd " + fd, delegate { Close(api, owned, fd); });
                }
                Cleanup(report, "reset null", delegate { Success(api.Set(ref empty), "cleanup reset null"); });
            }
            if (module != IntPtr.Zero) {
                api = null;
                Cleanup(report, "unload cleanup module", delegate { Unload(ref module, moduleName); });
            }
        }
        report.Passed = completed && report.CleanupErrors.Count == 0;
        if (report.Passed) {
            report.Stage = "complete";
        }
        return report;
    }
}
'@
try {
    $parameters = New-Object System.CodeDom.Compiler.CompilerParameters
    $parameters.GenerateInMemory = $true
    $parameters.TreatWarningsAsErrors = $true
    $parameters.TempFiles = New-Object System.CodeDom.Compiler.TempFileCollection($PSScriptRoot, $false)
    [void]$parameters.ReferencedAssemblies.Add('System.dll')
    Add-Type -TypeDefinition $source -Language CSharp -CompilerParameters $parameters -ErrorAction Stop
    $report = [NamespaceDllLifetime]::Run($DllPath, $NamespaceA, $NamespaceB, $PinPath)
    Write-Output ('ND04_RESULT=' + ($report | ConvertTo-Json -Compress -Depth 4))
    if (-not $report.Passed) { exit 1 }
    exit 0
} catch {
    $report = [ordered]@{ Passed = $false; Stage = 'PowerShell'; Error = $_.Exception.ToString() }
    Write-Output ('ND04_RESULT=' + ($report | ConvertTo-Json -Compress))
    exit 2
}
)ND04";

struct lifetime_handle
{
    explicit lifetime_handle(HANDLE value = INVALID_HANDLE_VALUE) : value(value) {}
    lifetime_handle(const lifetime_handle&) = delete;
    lifetime_handle&
    operator=(const lifetime_handle&) = delete;
    ~lifetime_handle()
    {
        if (value && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
    HANDLE value;
};

class lifetime_artifacts
{
  public:
    lifetime_artifacts()
    {
        static std::atomic<uint32_t> sequence{};
        auto name =
            std::format(L"namespace_dll_lifetime_{}_{:x}_{}", GetCurrentProcessId(), GetTickCount64(), ++sequence);
        path = std::filesystem::absolute(name);
        REQUIRE(CreateDirectoryW(path.c_str(), nullptr));
        owned = true;
    }
    ~lifetime_artifacts()
    {
        if (owned) {
            std::error_code error;
            std::filesystem::remove_all(path, error);
            CHECK_FALSE(error);
        }
    }
    std::filesystem::path path;

  private:
    bool owned = false;
};

class lifetime_pin_cleanup
{
  public:
    lifetime_pin_cleanup(const GUID& selected, const std::string& path) : selected(selected), path(path) {}
    ~lifetime_pin_cleanup()
    {
        if (!armed) {
            return;
        }
        GUID saved{};
        auto result = ebpf_get_namespace(&saved);
        CHECK(result == EBPF_SUCCESS);
        if (result != EBPF_SUCCESS) {
            return;
        }
        result = ebpf_set_namespace(&selected);
        CHECK(result == EBPF_SUCCESS);
        if (result == EBPF_SUCCESS) {
            result = ebpf_object_unpin(path.c_str());
            CHECK((result == EBPF_SUCCESS || result == EBPF_KEY_NOT_FOUND || result == EBPF_OBJECT_NOT_FOUND));
            CHECK(ebpf_set_namespace(&saved) == EBPF_SUCCESS);
        }
    }
    bool armed = false;

  private:
    GUID selected;
    std::string path;
};

std::wstring
lifetime_quote(const std::wstring& argument)
{
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (auto character : argument) {
        if (character == L'\\') {
            slashes++;
        } else {
            result.append(character == L'"' ? slashes * 2 + 1 : slashes, L'\\');
            result += character;
            slashes = 0;
        }
    }
    result.append(slashes * 2, L'\\');
    return result + L'"';
}

std::wstring
lifetime_guid_text(const GUID& value)
{
    return std::format(
        L"{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value.Data1,
        value.Data2,
        value.Data3,
        value.Data4[0],
        value.Data4[1],
        value.Data4[2],
        value.Data4[3],
        value.Data4[4],
        value.Data4[5],
        value.Data4[6],
        value.Data4[7]);
}

class lifetime_process
{
  public:
    ~lifetime_process()
    {
        if (value.hProcess) {
            if (WaitForSingleObject(value.hProcess, 0) != WAIT_OBJECT_0) {
                CHECK(TerminateProcess(value.hProcess, ERROR_CANCELLED));
                CHECK(WaitForSingleObject(value.hProcess, 10000) == WAIT_OBJECT_0);
            }
            CloseHandle(value.hThread);
            CloseHandle(value.hProcess);
        }
    }
    PROCESS_INFORMATION value{};
};

class lifetime_attributes
{
  public:
    lifetime_attributes()
    {
        SIZE_T size = 0;
        REQUIRE_FALSE(InitializeProcThreadAttributeList(nullptr, 1, 0, &size));
        REQUIRE(GetLastError() == ERROR_INSUFFICIENT_BUFFER);
        storage.resize(size);
        value = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        REQUIRE(InitializeProcThreadAttributeList(value, 1, 0, &size));
        initialized = true;
    }
    ~lifetime_attributes()
    {
        if (initialized) {
            DeleteProcThreadAttributeList(value);
        }
    }
    LPPROC_THREAD_ATTRIBUTE_LIST value = nullptr;

  private:
    std::vector<uint8_t> storage;
    bool initialized = false;
};

struct lifetime_child_result
{
    DWORD wait;
    DWORD exit_code;
    std::string output;
};

lifetime_child_result
run_lifetime_child(
    const lifetime_artifacts& artifacts, const std::vector<std::wstring>& arguments, lifetime_pin_cleanup& pin_cleanup)
{
    std::array<wchar_t, 32768> system_directory{};
    auto length = GetSystemDirectoryW(system_directory.data(), static_cast<UINT>(system_directory.size()));
    REQUIRE(length > 0);
    REQUIRE(length < system_directory.size());
    auto powershell = std::filesystem::path(system_directory.data()) / L"WindowsPowerShell\\v1.0\\powershell.exe";

    lifetime_handle job(CreateJobObjectW(nullptr, nullptr));
    REQUIRE(job.value != nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    REQUIRE(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)));
    auto log = artifacts.path / L"child.log";
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    lifetime_handle output(CreateFileW(
        log.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security,
        CREATE_NEW,
        0,
        nullptr));
    REQUIRE(output.value != INVALID_HANDLE_VALUE);
    lifetime_handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &security, OPEN_EXISTING, 0, nullptr));
    REQUIRE(input.value != INVALID_HANDLE_VALUE);
    std::array<HANDLE, 2> inherited{input.value, output.value};
    lifetime_attributes attributes;
    REQUIRE(UpdateProcThreadAttribute(
        attributes.value, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), sizeof(inherited), nullptr, nullptr));
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.value;
    startup.StartupInfo.hStdOutput = output.value;
    startup.StartupInfo.hStdError = output.value;
    startup.lpAttributeList = attributes.value;
    std::wstring command = lifetime_quote(powershell.wstring());
    for (const auto& argument : arguments) {
        command += L" " + lifetime_quote(argument);
    }
    lifetime_process process;
    auto created = CreateProcessW(
        powershell.c_str(),
        command.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        nullptr,
        &startup.StartupInfo,
        &process.value);
    INFO("PowerShell child creation error: " << (created ? ERROR_SUCCESS : GetLastError()));
    REQUIRE(created);
    REQUIRE(AssignProcessToJobObject(job.value, process.value.hProcess));
    pin_cleanup.armed = true;
    REQUIRE(ResumeThread(process.value.hThread) != static_cast<DWORD>(-1));
    auto wait = WaitForSingleObject(process.value.hProcess, 120000);
    if (wait != WAIT_OBJECT_0) {
        REQUIRE(TerminateJobObject(job.value, ERROR_TIMEOUT));
        REQUIRE(WaitForSingleObject(process.value.hProcess, 10000) == WAIT_OBJECT_0);
    }
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    auto deadline = GetTickCount64() + 10000;
    do {
        REQUIRE(QueryInformationJobObject(
            job.value, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr));
        if (accounting.ActiveProcesses == 0) {
            break;
        }
        Sleep(10);
    } while (GetTickCount64() < deadline);
    REQUIRE(accounting.ActiveProcesses == 0);
    DWORD exit_code = 0;
    REQUIRE(GetExitCodeProcess(process.value.hProcess, &exit_code));
    LARGE_INTEGER log_size{};
    REQUIRE(GetFileSizeEx(output.value, &log_size));
    INFO("ND04 child output length: " << log_size.QuadPart);
    REQUIRE(log_size.QuadPart <= 65536);
    std::ifstream stream(log, std::ios::binary);
    REQUIRE(stream.good());
    return {wait, exit_code, {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()}};
}
} // namespace

TEST_CASE(
    "namespace_ND04_process_selection_survives_full_ebpfapi_DLL_unload_reload", "[namespace][driver][dll_lifetime]")
{
    lifetime_artifacts artifacts;
    static std::atomic<uint16_t> sequence{};
    GUID a{};
    a.Data1 = GetCurrentProcessId();
    a.Data2 = 0xd104;
    a.Data3 = ++sequence;
    auto tick = GetTickCount64();
    memcpy(a.Data4, &tick, sizeof(tick));
    GUID b = a;
    b.Data2 = static_cast<uint16_t>(b.Data2 ^ 0x8000);
    const std::string pin_path = "/namespace/" + artifacts.path.filename().string();
    lifetime_pin_cleanup pin_cleanup(a, pin_path);

    HMODULE imported = GetModuleHandleW(L"ebpfapi.dll");
    REQUIRE(imported != nullptr);
    std::array<wchar_t, 32768> dll_path{};
    auto length = GetModuleFileNameW(imported, dll_path.data(), static_cast<DWORD>(dll_path.size()));
    REQUIRE(length > 0);
    REQUIRE(length < dll_path.size());
    auto script_path = artifacts.path / L"child.ps1";
    {
        std::ofstream script(script_path, std::ios::binary);
        REQUIRE(script.good());
        script << dll_lifetime_script;
        script.close();
        REQUIRE(script.good());
    }

    auto result = run_lifetime_child(
        artifacts,
        {L"-NoLogo",
         L"-NoProfile",
         L"-NonInteractive",
         L"-File",
         script_path.wstring(),
         L"-DllPath",
         dll_path.data(),
         L"-NamespaceA",
         lifetime_guid_text(a),
         L"-NamespaceB",
         lifetime_guid_text(b),
         L"-PinPath",
         std::wstring(pin_path.begin(), pin_path.end())},
        pin_cleanup);
    INFO("ND04 PowerShell wait=" << result.wait << "; exit=" << result.exit_code << "; output=" << result.output);
    REQUIRE(result.wait == WAIT_OBJECT_0);
    REQUIRE(result.exit_code == 0);
    REQUIRE(result.output.find("ND04_RESULT=") != std::string::npos);
    REQUIRE(result.output.find("\"Passed\":true") != std::string::npos);
    for (const char* field :
         {"FirstUnload", "ReloadPreservedNamespace", "IsolatedIds", "RetainedHandleCrud", "FinalUnload"}) {
        REQUIRE(result.output.find(std::format("\"{}\":true", field)) != std::string::npos);
    }
    pin_cleanup.armed = false;
}
