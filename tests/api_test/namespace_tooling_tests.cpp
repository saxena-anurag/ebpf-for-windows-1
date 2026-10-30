// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_test.h"
#include "bpf/bpf.h"
#include "ebpf_protocol.h"

#include <windows.h>
#include <array>
#include <atomic>
#include <filesystem>
#include <format>
#include <fstream>
#include <io.h>
#include <memory>
#include <regex>
#include <sstream>
#include <vector>
#include <winioctl.h>

namespace {
constexpr GUID default_namespace{};
constexpr DWORD tooling_ioctl = CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS);

struct tooling_handle
{
    explicit tooling_handle(HANDLE value = INVALID_HANDLE_VALUE) : value(value) {}
    tooling_handle(const tooling_handle&) = delete;
    tooling_handle&
    operator=(const tooling_handle&) = delete;
    ~tooling_handle() { reset(); }
    void
    reset()
    {
        if (value != nullptr && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
            value = INVALID_HANDLE_VALUE;
        }
    }
    HANDLE value;
};

struct tooling_fd
{
    explicit tooling_fd(fd_t value = ebpf_fd_invalid) : value(value) {}
    tooling_fd(const tooling_fd&) = delete;
    tooling_fd&
    operator=(const tooling_fd&) = delete;
    ~tooling_fd() { reset(); }
    void
    reset()
    {
        if (value >= 0) {
            CHECK(ebpf_close_fd(value) == EBPF_SUCCESS);
            value = ebpf_fd_invalid;
        }
    }
    fd_t value;
};

uint32_t
next_tooling_number()
{
    static std::atomic<uint32_t> number{};
    return ++number;
}

std::string
tooling_suffix()
{
    return std::format("{}_{:x}_{}", GetCurrentProcessId(), GetTickCount64(), next_tooling_number());
}

GUID
tooling_namespace()
{
    GUID value{};
    value.Data1 = GetCurrentProcessId();
    value.Data2 = static_cast<uint16_t>(next_tooling_number());
    value.Data3 = 0xc117;
    auto tick = GetTickCount64();
    memcpy(value.Data4, &tick, sizeof(tick));
    return value;
}

std::string
guid_text(const GUID& value)
{
    return std::format(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
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

std::wstring
wide_ascii(const std::string& value)
{
    std::wstring result;
    result.reserve(value.size());
    for (auto character : value) {
        result += static_cast<wchar_t>(static_cast<unsigned char>(character));
    }
    return result;
}

std::string
hex_u32(uint32_t value, const char* separator = "")
{
    return std::format(
        "{:02x}{}{:02x}{}{:02x}{}{:02x}",
        value & 0xff,
        separator,
        (value >> 8) & 0xff,
        separator,
        (value >> 16) & 0xff,
        separator,
        value >> 24);
}

class tooling_namespace_restore
{
  public:
    tooling_namespace_restore() { REQUIRE(ebpf_get_namespace(&_saved) == EBPF_SUCCESS); }
    ~tooling_namespace_restore() { CHECK(ebpf_set_namespace(&_saved) == EBPF_SUCCESS); }

  private:
    GUID _saved{};
};

class tooling_path
{
  public:
    explicit tooling_path(const wchar_t* extension)
        : path(std::filesystem::absolute(L"namespace_tooling_" + wide_ascii(tooling_suffix()) + extension))
    {
    }
    ~tooling_path()
    {
        if (_owned) {
            DeleteFileW(path.c_str());
        }
    }
    HANDLE
    create(bool inherit)
    {
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, inherit ? TRUE : FALSE};
        auto handle = CreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            _owned = true;
        }
        return handle;
    }
    void
    write(const std::string& text)
    {
        tooling_handle file(create(false));
        REQUIRE(file.value != INVALID_HANDLE_VALUE);
        DWORD written = 0;
        REQUIRE(WriteFile(file.value, text.data(), static_cast<DWORD>(text.size()), &written, nullptr));
        REQUIRE(written == text.size());
    }
    void
    copy_from(const wchar_t* source)
    {
        INFO("Required signed native sample: " << std::filesystem::path(source).string());
        REQUIRE(CopyFileW(source, path.c_str(), TRUE));
        _owned = true;
    }
    const std::filesystem::path path;

  private:
    bool _owned = false;
};

std::wstring
quote_argument(const std::wstring& argument)
{
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (auto character : argument) {
        if (character == L'\\') {
            ++slashes;
        } else {
            result.append(character == L'"' ? slashes * 2 + 1 : slashes, L'\\');
            result += character;
            slashes = 0;
        }
    }
    result.append(slashes * 2, L'\\');
    result += L'"';
    return result;
}

struct tooling_result
{
    DWORD exit_code;
    std::string output;
};

tooling_result
run_tool(const std::filesystem::path& executable, const std::vector<std::wstring>& arguments)
{
    tooling_path output(L".log");
    tooling_handle output_file(output.create(true));
    REQUIRE(output_file.value != INVALID_HANDLE_VALUE);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    tooling_handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &attributes, OPEN_EXISTING, 0, nullptr));
    REQUIRE(input.value != INVALID_HANDLE_VALUE);
    std::wstring command = quote_argument(executable.wstring());
    for (const auto& argument : arguments) {
        command += L" " + quote_argument(argument);
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input.value;
    startup.hStdOutput = output_file.value;
    startup.hStdError = output_file.value;
    PROCESS_INFORMATION process{};
    auto created = CreateProcessW(
        executable.c_str(),
        command.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup,
        &process);
    auto error = GetLastError();
    INFO("Required candidate tool: " << executable.string() << "; CreateProcess error: " << error);
    REQUIRE(created);
    tooling_handle process_handle(process.hProcess);
    tooling_handle thread_handle(process.hThread);
    auto wait = WaitForSingleObject(process_handle.value, 30000);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process_handle.value, ERROR_TIMEOUT);
        WaitForSingleObject(process_handle.value, 30000);
    }
    REQUIRE(wait == WAIT_OBJECT_0);
    DWORD exit_code = 0;
    REQUIRE(GetExitCodeProcess(process_handle.value, &exit_code));
    output_file.reset();
    std::ifstream stream(output.path, std::ios::binary);
    REQUIRE(stream.good());
    return {exit_code, {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()}};
}

std::filesystem::path
netsh_path()
{
    std::array<wchar_t, MAX_PATH> directory{};
    auto length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
    REQUIRE(length > 0);
    REQUIRE(length < directory.size());
    return std::filesystem::path(directory.data()) / L"netsh.exe";
}

std::filesystem::path
bpftool_path()
{
    std::array<wchar_t, 32768> buffer{};
    auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    REQUIRE(length > 0);
    REQUIRE(length < buffer.size());
    auto sibling = std::filesystem::path(buffer.data()).parent_path() / L"bpftool.exe";
    if (GetFileAttributesW(sibling.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return sibling;
    }
    length = SearchPathW(nullptr, L"bpftool.exe", nullptr, static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    INFO("Required candidate bpftool.exe must be beside api_test.exe or on PATH");
    REQUIRE(length > 0);
    REQUIRE(length < buffer.size());
    return buffer.data();
}

tooling_result
netsh_script(const std::string& commands)
{
    tooling_path script(L".netsh");
    script.write("pushd ebpf\r\n" + commands + "\r\npopd\r\n");
    return run_tool(netsh_path(), {L"-f", script.path.wstring()});
}

void
require_tool_success(const tooling_result& result)
{
    INFO("Child exit code: " << result.exit_code << "\n" << result.output);
    REQUIRE(result.exit_code == 0);
    REQUIRE_FALSE(std::regex_search(result.output, std::regex(R"((^|\n)\s*error\b)", std::regex::icase)));
}

std::vector<std::string>
namespace_lines(const std::string& output)
{
    std::vector<std::string> result;
    std::istringstream stream(output);
    std::string line;
    const std::regex guid(R"(^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$)");
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (std::regex_match(line, guid)) {
            result.push_back(line);
        }
    }
    return result;
}

class tooling_pin_cleanup
{
  public:
    tooling_pin_cleanup(HANDLE device, fd_t fd, std::string path) : _device(device), _fd(fd)
    {
        std::array<char, MAX_PATH> canonical{};
        REQUIRE(ebpf_canonicalize_pin_path(canonical.data(), canonical.size(), path.c_str()) == EBPF_SUCCESS);
        _path = canonical.data();
    }
    ~tooling_pin_cleanup()
    {
        if (!_active) {
            return;
        }
        alignas(ebpf_operation_delete_pinning_if_matches_request_t)
            std::array<uint8_t, offsetof(ebpf_operation_delete_pinning_if_matches_request_t, path) + MAX_PATH>
                buffer{};
        auto request = reinterpret_cast<ebpf_operation_delete_pinning_if_matches_request_t*>(buffer.data());
        auto length = offsetof(ebpf_operation_delete_pinning_if_matches_request_t, path) + _path.size();
        request->header = {static_cast<uint16_t>(length), EBPF_OPERATION_DELETE_PINNING_IF_MATCHES};
        request->handle = static_cast<ebpf_handle_t>(_get_osfhandle(_fd));
        memcpy(request->path, _path.data(), _path.size());
        DWORD returned = 0;
        auto success = DeviceIoControl(
            _device, tooling_ioctl, buffer.data(), static_cast<DWORD>(length), nullptr, 0, &returned, nullptr);
        auto error = success ? ERROR_SUCCESS : GetLastError();
        CHECK((error == ERROR_SUCCESS || error == ERROR_NOT_FOUND));
    }
    void
    disarm()
    {
        _active = false;
    }

  private:
    HANDLE _device;
    fd_t _fd;
    std::string _path;
    bool _active = true;
};

class tooling_map
{
  public:
    tooling_map(HANDLE device, const GUID& owner, const std::string& name, const std::string& path, uint32_t marker)
    {
        tooling_namespace_restore restore;
        REQUIRE(ebpf_set_namespace(&owner) == EBPF_SUCCESS);
        _fd.value = bpf_map_create(BPF_MAP_TYPE_HASH, name.c_str(), 4, 4, 4, nullptr);
        REQUIRE(_fd.value >= 0);
        uint32_t key = 1;
        REQUIRE(bpf_map_update_elem(_fd.value, &key, &marker, BPF_ANY) == 0);
        bpf_map_info info{};
        uint32_t size = sizeof(info);
        REQUIRE(bpf_obj_get_info_by_fd(_fd.value, &info, &size) == 0);
        id = info.id;
        _pin = std::make_unique<tooling_pin_cleanup>(device, _fd.value, path);
        REQUIRE(bpf_obj_pin(_fd.value, path.c_str()) == 0);
    }
    uint32_t
    marker() const
    {
        uint32_t key = 1, value = 0;
        REQUIRE(bpf_map_lookup_elem(_fd.value, &key, &value) == 0);
        return value;
    }
    fd_t
    fd() const
    {
        return _fd.value;
    }
    uint32_t id = 0;

  private:
    tooling_fd _fd;
    std::unique_ptr<tooling_pin_cleanup> _pin;
};

class tooling_fixture
{
  public:
    tooling_fixture()
        : control(device.value, default_namespace, default_name, pin_path, 0x11223344),
          selected(device.value, a, selected_name, pin_path, 0xaabbccdd)
    {
        INFO("Requires the approved installed candidate driver/DLL and registered candidate ebpfnetsh helper");
        REQUIRE(device.value != INVALID_HANDLE_VALUE);
        REQUIRE(ebpf_set_namespace(&a) == EBPF_SUCCESS);
        ebpf_operation_get_namespace_request_t request{{sizeof(request), EBPF_OPERATION_GET_NAMESPACE}};
        ebpf_operation_get_namespace_reply_t reply{};
        DWORD returned = 0;
        REQUIRE(DeviceIoControl(
            device.value, tooling_ioctl, &request, sizeof(request), &reply, sizeof(reply), &returned, nullptr));
        REQUIRE(returned == sizeof(reply));
        REQUIRE(reply.header.id == EBPF_OPERATION_GET_NAMESPACE);
        REQUIRE(reply.header.length == sizeof(reply));
        REQUIRE(IsEqualGUID(reply.namespace_id, a));
    }
    void
    require_parent_namespace(const GUID& expected) const
    {
        GUID current{};
        REQUIRE(ebpf_get_namespace(&current) == EBPF_SUCCESS);
        REQUIRE(IsEqualGUID(current, expected));
    }

  private:
    tooling_namespace_restore _restore;

  public:
    tooling_handle device{
        CreateFileW(L"\\\\.\\EbpfIoDevice", GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr)};
    const GUID a = tooling_namespace();
    const std::string suffix = tooling_suffix();
    const std::string default_name = "nd_default_" + suffix;
    const std::string selected_name = "nd_selected_" + suffix;
    const std::string pin_path = "BPF:\\namespace_tooling\\" + suffix;
    tooling_map control;
    tooling_map selected;
};

class tooling_program_link_cleanup
{
  public:
    tooling_program_link_cleanup(const GUID& owner, uint32_t program_id) : _owner(owner), _program_id(program_id) {}
    ~tooling_program_link_cleanup()
    {
        GUID saved{};
        auto result = ebpf_get_namespace(&saved);
        CHECK(result == EBPF_SUCCESS);
        if (result != EBPF_SUCCESS) {
            return;
        }
        result = ebpf_set_namespace(&_owner);
        CHECK(result == EBPF_SUCCESS);
        if (result != EBPF_SUCCESS) {
            return;
        }
        uint32_t id = 0;
        while (bpf_link_get_next_id(id, &id) == 0) {
            tooling_fd fd(bpf_link_get_fd_by_id(id));
            if (fd.value < 0) {
                CHECK(errno == ENOENT);
                continue;
            }
            bpf_link_info info{};
            uint32_t size = sizeof(info);
            auto error = bpf_obj_get_info_by_fd(fd.value, &info, &size);
            CHECK(error == 0);
            if (error == 0 && info.prog_id == _program_id) {
                CHECK(bpf_link_detach(fd.value) == 0);
            }
        }
        CHECK(errno == ENOENT);
        CHECK(ebpf_set_namespace(&saved) == EBPF_SUCCESS);
    }

  private:
    GUID _owner;
    uint32_t _program_id;
};

std::string
select_namespace(const GUID& value)
{
    return "set namespace " + guid_text(value) + "\r\n";
}

void
require_pin_missing(const std::string& path)
{
    tooling_fd fd(bpf_obj_get(path.c_str()));
    REQUIRE(fd.value < 0);
    REQUIRE(errno == ENOENT);
}
} // namespace

TEST_CASE("namespace_ND27_netsh_script_selection_reset_and_fresh_process", "[namespace][driver][tooling]")
{
    tooling_fixture fixture;
    auto result = netsh_script(
        select_namespace(fixture.a) + "show namespace\r\nshow maps\r\n" + select_namespace(default_namespace) +
        "show namespace\r\nshow maps");
    INFO(result.output);
    require_tool_success(result);
    REQUIRE(
        (namespace_lines(result.output) ==
         std::vector<std::string>{guid_text(fixture.a), guid_text(default_namespace)}));
    REQUIRE(result.output.find(fixture.selected_name) != std::string::npos);
    REQUIRE(result.output.find(fixture.default_name) != std::string::npos);
    auto selected_position = result.output.find(fixture.selected_name);
    auto default_position = result.output.find(fixture.default_name);
    REQUIRE(selected_position < default_position);
    auto reset_position = result.output.find(guid_text(default_namespace));
    REQUIRE(reset_position != std::string::npos);
    REQUIRE(result.output.substr(0, reset_position).find(fixture.default_name) == std::string::npos);
    REQUIRE(result.output.substr(reset_position).find(fixture.selected_name) == std::string::npos);
    fixture.require_parent_namespace(fixture.a);

    auto fresh = run_tool(netsh_path(), {L"ebpf", L"show", L"namespace"});
    INFO(fresh.output);
    require_tool_success(fresh);
    REQUIRE(namespace_lines(fresh.output) == std::vector<std::string>{guid_text(default_namespace)});
    auto maps = run_tool(netsh_path(), {L"ebpf", L"show", L"maps"});
    INFO(maps.output);
    require_tool_success(maps);
    REQUIRE(maps.output.find(fixture.default_name) != std::string::npos);
    REQUIRE(maps.output.find(fixture.selected_name) == std::string::npos);
    REQUIRE(fixture.control.marker() == 0x11223344);
    REQUIRE(fixture.selected.marker() == 0xaabbccdd);
    fixture.require_parent_namespace(fixture.a);
}

TEST_CASE("namespace_ND28_netsh_map_management_and_readable_failures", "[namespace][driver][tooling]")
{
    tooling_fixture fixture;
    auto id = std::to_string(fixture.selected.id);
    auto extra_path = fixture.pin_path + "_extra";
    auto created_path = fixture.pin_path + "_created";
    auto created_name = "nd_created_" + fixture.suffix;
    tooling_pin_cleanup extra(fixture.device.value, fixture.selected.fd(), extra_path);
    auto result = netsh_script(
        select_namespace(fixture.a) + "show namespace\r\nshow maps\r\nlookup map " + id +
        " key=01000000\r\nupdate map " + id + " key=01000000 value=2a000000 flags=exist\r\nlookup map " + id +
        " key=01000000\r\ngetnext map " + id + "\r\ndump map " + id + "\r\npin map " + id + " " + extra_path +
        "\r\nshow pins\r\nunpin map " + id + " " + extra_path + "\r\ndelete map " + id +
        " key=01000000\r\nupdate map " + id +
        " key=01000000 value=aabbccdd flags=noexist\r\nadd map type=hash keysize=4 "
        "valuesize=4 maxentries=4 pinpath=" +
        created_path + " name=" + created_name + "\r\nshow maps");
    INFO(result.output);
    require_tool_success(result);
    tooling_fd created(bpf_obj_get(created_path.c_str()));
    REQUIRE(created.value >= 0);
    tooling_pin_cleanup cleanup_created(fixture.device.value, created.value, created_path);
    bpf_map_info info{};
    uint32_t size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(created.value, &info, &size) == 0);
    REQUIRE(std::string(info.name) == created_name);
    REQUIRE(result.output.find("Created with ID " + std::to_string(info.id)) != std::string::npos);
    REQUIRE(result.output.find("value: ddccbbaa") != std::string::npos);
    REQUIRE(result.output.find("value: 2a000000") != std::string::npos);
    REQUIRE(result.output.find("key: 01000000") != std::string::npos);
    REQUIRE(result.output.find(std::format("{:7}      Map  {}", fixture.selected.id, extra_path)) != std::string::npos);
    REQUIRE(result.output.find(fixture.default_name) == std::string::npos);
    REQUIRE(fixture.control.marker() == 0x11223344);
    REQUIRE(fixture.selected.marker() == 0xddccbbaa);
    require_pin_missing(extra_path);
    auto unpin =
        netsh_script(select_namespace(fixture.a) + "unpin map " + std::to_string(info.id) + " " + created_path);
    require_tool_success(unpin);
    require_pin_missing(created_path);

    auto malformed = netsh_script(select_namespace(fixture.a) + "set namespace not-a-guid");
    INFO(malformed.output);
    REQUIRE(malformed.output.find("error: invalid namespace GUID; expected ") != std::string::npos);
    auto bad_key = netsh_script(select_namespace(fixture.a) + "lookup map " + id + " key=01");
    INFO(bad_key.output);
    REQUIRE(
        bad_key.output.find("error: key must contain exactly keysize bytes as hexadecimal pairs") != std::string::npos);
    auto bad_value = netsh_script(select_namespace(fixture.a) + "update map " + id + " key=01000000 value=zz000000");
    INFO(bad_value.output);
    REQUIRE(
        bad_value.output.find("error: value must contain exactly valuesize bytes as hexadecimal pairs") !=
        std::string::npos);
    auto foreign = netsh_script(
        select_namespace(fixture.a) + "lookup map " + std::to_string(fixture.control.id) + " key=01000000");
    INFO(foreign.output);
    REQUIRE(foreign.output.find("error 2: could not open map") != std::string::npos);
    fixture.require_parent_namespace(fixture.a);
}

TEST_CASE("namespace_ND28_netsh_native_program_and_link_management", "[namespace][driver][tooling][native]")
{
    tooling_fixture fixture;
    tooling_path native_program(L".sys");
    native_program.copy_from(L"bindmonitor.sys");
    auto program_path = fixture.pin_path + "_program";
    auto extra_path = fixture.pin_path + "_program_extra";
    auto link_path = fixture.pin_path + "_link";
    auto loaded = netsh_script(
        select_namespace(fixture.a) + "add program filename=\"" + native_program.path.filename().string() +
        "\" type=bind pinpath=" + program_path + "\r\nshow programs\r\nshow links\r\nshow maps\r\nshow pins");
    INFO(loaded.output);
    require_tool_success(loaded);
    tooling_fd program(bpf_obj_get(program_path.c_str()));
    REQUIRE(program.value >= 0);
    tooling_pin_cleanup program_pin(fixture.device.value, program.value, program_path);
    tooling_pin_cleanup extra_pin(fixture.device.value, program.value, extra_path);
    bpf_prog_info info{};
    uint32_t size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(program.value, &info, &size) == 0);
    tooling_program_link_cleanup cleanup_links(fixture.a, info.id);
    REQUIRE(loaded.output.find("Loaded with ID " + std::to_string(info.id)) != std::string::npos);
    REQUIRE(info.link_count == 1);
    REQUIRE(loaded.output.find(std::format("{:7}  Program  {}", info.id, program_path)) != std::string::npos);
    REQUIRE(loaded.output.find(fixture.default_name) == std::string::npos);
    uint32_t link_id = 0;
    tooling_fd link;
    while (bpf_link_get_next_id(link_id, &link_id) == 0) {
        tooling_fd candidate(bpf_link_get_fd_by_id(link_id));
        REQUIRE(candidate.value >= 0);
        bpf_link_info link_info{};
        size = sizeof(link_info);
        REQUIRE(bpf_obj_get_info_by_fd(candidate.value, &link_info, &size) == 0);
        if (link_info.prog_id == info.id) {
            link.value = candidate.value;
            candidate.value = ebpf_fd_invalid;
            break;
        }
    }
    REQUIRE(link.value >= 0);
    tooling_pin_cleanup link_pin(fixture.device.value, link.value, link_path);
    auto id = std::to_string(info.id);
    auto link_text = std::to_string(link_id);
    auto managed = netsh_script(
        select_namespace(fixture.a) + "pin program " + id + " " + extra_path + "\r\nshow pins\r\nunpin program " + id +
        " " + extra_path + "\r\npin link " + link_text + " " + link_path + "\r\nshow pins\r\ndelete link " + link_text +
        "\r\nunpin link " + link_text + " " + link_path);
    INFO(managed.output);
    require_tool_success(managed);
    REQUIRE(managed.output.find(std::format("{:7}  Program  {}", info.id, extra_path)) != std::string::npos);
    REQUIRE(managed.output.find(std::format("{:7}     Link  {}", link_id, link_path)) != std::string::npos);
    require_pin_missing(extra_path);
    require_pin_missing(link_path);
    link_pin.disarm();
    link.reset();
    auto changed = netsh_script(
        select_namespace(fixture.a) + "set program " + id + " attached=bind\r\nset program " + id +
        " attached=\"\"\r\nset program " + id + " attached=bind\r\nshow links\r\ndelete program " + id);
    INFO(changed.output);
    require_tool_success(changed);
    size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(program.value, &info, &size) == 0);
    REQUIRE(info.link_count == 0);
    require_pin_missing(program_path);
    fixture.require_parent_namespace(fixture.a);
}

TEST_CASE("namespace_ND29_separate_bpftool_remains_in_default_namespace", "[namespace][driver][tooling]")
{
    tooling_fixture fixture;
    auto executable = bpftool_path();
    auto listed = run_tool(executable, {L"map", L"show"});
    INFO(listed.output);
    require_tool_success(listed);
    REQUIRE(listed.output.find(fixture.default_name) != std::string::npos);
    REQUIRE(listed.output.find(fixture.selected_name) == std::string::npos);
    auto control = run_tool(executable, {L"map", L"dump", L"pinned", wide_ascii(fixture.pin_path)});
    INFO(control.output);
    require_tool_success(control);
    REQUIRE(control.output.find("value: " + hex_u32(0x11223344, " ")) != std::string::npos);
    REQUIRE(control.output.find(hex_u32(0xaabbccdd, " ")) == std::string::npos);
    auto foreign = run_tool(executable, {L"map", L"show", L"id", std::to_wstring(fixture.selected.id)});
    INFO(foreign.output);
    REQUIRE(foreign.exit_code != 0);
    REQUIRE(foreign.output.find("No such file or directory") != std::string::npos);
    fixture.require_parent_namespace(fixture.a);
    REQUIRE(fixture.selected.marker() == 0xaabbccdd);
}

TEST_CASE("namespace_ND30_process_diagnostics_are_explicitly_host_wide", "[namespace][driver][tooling]")
{
    tooling_fixture fixture;
    auto parent_namespace = tooling_namespace();
    REQUIRE(ebpf_set_namespace(&parent_namespace) == EBPF_SUCCESS);
    auto result =
        netsh_script(select_namespace(fixture.a) + "show maps\r\nshow processes\r\nshow namespace\r\nshow maps");
    INFO(result.output);
    require_tool_success(result);
    REQUIRE(result.output.find(fixture.selected_name) != std::string::npos);
    REQUIRE(result.output.find(fixture.default_name) == std::string::npos);
    auto diagnostic = result.output.find("Host-wide process handle diagnostics (not namespace-scoped)");
    REQUIRE(diagnostic != std::string::npos);
    REQUIRE(namespace_lines(result.output) == std::vector<std::string>{guid_text(fixture.a)});
    auto diagnostic_end = result.output.find(guid_text(fixture.a), diagnostic);
    REQUIRE(diagnostic_end != std::string::npos);
    auto diagnostic_output = result.output.substr(diagnostic, diagnostic_end - diagnostic);
    REQUIRE(std::regex_search(
        diagnostic_output, std::regex("(^|\\n)\\s*" + std::to_string(GetCurrentProcessId()) + "\\s+")));
    const std::regex guid(R"(\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?)", std::regex::icase);
    REQUIRE_FALSE(std::regex_search(diagnostic_output, guid));
    fixture.require_parent_namespace(parent_namespace);

    auto all = run_tool(netsh_path(), {L"ebpf", L"show", L"namespace", L"all"});
    INFO(all.output);
    REQUIRE(namespace_lines(all.output).empty());
    REQUIRE(all.output.find("Usage:") != std::string::npos);
}
