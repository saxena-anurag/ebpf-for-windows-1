# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs ND23, ND31, or the privileged ND12 identity fixtures on a preprovisioned,
explicitly approved dedicated VM. Never provisions/replaces core or extension
drivers, service fixtures, or DLLs.
.DESCRIPTION
ND23 is deliberately standalone: api_test.exe imports ebpfapi.dll and therefore
holds a device reference. This controller never loads that DLL. SDK operations
run in fresh PowerShell children using the exact manifest DLL and Cdecl exports.
See docs\NamespaceVmTests.md for the manifest and evidence contract.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ND23', 'ND31OldDllNewDriver', 'ND31NewDllOldDriver',
        'ND12Admin', 'ND12System', 'ND12Service', 'ND12LocalService')]
    [string] $Scenario,
    [Parameter(Mandatory = $true)][string] $Manifest,
    [switch] $AllowDriverRestart,
    [ValidateSet('', 'Populate', 'Verify', 'Cleanup', 'Compatibility')][string] $ChildPhase = '',
    [string] $StatePath,
    [string] $RunDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Condition([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Artifact($Artifact, [string] $Name, [switch] $RequireVersion) {
    Assert-Condition ([IO.Path]::IsPathRooted($Artifact.path)) "$Name.path must be absolute."
    Assert-Condition (Test-Path -LiteralPath $Artifact.path -PathType Leaf) "Required $Name fixture missing: $($Artifact.path)"
    Assert-Condition ($Artifact.sha256 -match '^[0-9a-fA-F]{64}$') "$Name.sha256 must be the approved artifact SHA256."
    if ($RequireVersion) {
        Assert-Condition (-not [string]::IsNullOrWhiteSpace($Artifact.version)) "$Name.version must be the exact approved file version."
    }
    $hash = (Get-FileHash -LiteralPath $Artifact.path -Algorithm SHA256).Hash
    Assert-Condition ($hash -eq $Artifact.sha256) "$Name SHA256 mismatch: actual $hash"
    $version = [string][Diagnostics.FileVersionInfo]::GetVersionInfo($Artifact.path).FileVersion
    Assert-Condition ($version -eq $Artifact.version) "$Name version mismatch: actual '$version', expected '$($Artifact.version)'."
    Write-Host "$Name path=$($Artifact.path) SHA256=$hash version=$version"
}

$Manifest = (Resolve-Path -LiteralPath $Manifest).Path
$fixture = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
Assert-Condition ($fixture.approvedDedicatedVM -is [bool] -and $fixture.approvedDedicatedVM) `
    'Blocked: manifest must explicitly approve this dedicated VM (approvedDedicatedVM: true).'
Assert-Condition ($fixture.dll.namespaceSupport -is [bool] -and $fixture.driver.namespaceSupport -is [bool]) `
    'DLL/driver namespaceSupport must be explicit JSON booleans (OLD=false, NEW=true).'
Assert-Artifact $fixture.dll 'dll' -RequireVersion
Assert-Artifact $fixture.driver 'driver' -RequireVersion
Assert-Condition ([IO.Path]::IsPathRooted($fixture.powershellPath) -and
    (Test-Path -LiteralPath $fixture.powershellPath -PathType Leaf)) 'Required absolute powershellPath is missing.'

if ($Scenario -eq 'ND31OldDllNewDriver') {
    Assert-Condition (-not $fixture.dll.namespaceSupport -and $fixture.driver.namespaceSupport) `
        'ND31OldDllNewDriver requires a genuine OLD DLL and NEW driver image.'
} elseif ($Scenario -eq 'ND31NewDllOldDriver') {
    Assert-Condition ($fixture.dll.namespaceSupport -and -not $fixture.driver.namespaceSupport) `
        'ND31NewDllOldDriver requires a genuine NEW DLL and OLD driver image.'
} else {
    Assert-Condition ($fixture.dll.namespaceSupport -and $fixture.driver.namespaceSupport) `
        "$Scenario requires a NEW DLL and NEW driver image."
}
if ($Scenario -eq 'ND23') {
    Assert-Condition $AllowDriverRestart.IsPresent 'ND23 requires the additional -AllowDriverRestart opt-in.'
    Assert-Artifact $fixture.nativeProgram 'nativeProgram'
}

$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class NamespaceVmNative
{
    public static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] input, int inputSize,
        byte[] output, int outputSize, out int returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    public static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetModuleFileName(IntPtr module, System.Text.StringBuilder path, int size);

    public static SafeFileHandle OpenDevice()
    {
        var device = CreateFile(@"\\.\EbpfIoDevice", 0xc0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (device.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open management device");
        return device;
    }
    // Native protocol header is uint16 length, two padding bytes, uint32 operation.
    public static byte[] Request(uint operation, int length)
    {
        var bytes = new byte[length];
        Array.Copy(BitConverter.GetBytes((ushort)length), 0, bytes, 0, 2);
        Array.Copy(BitConverter.GetBytes(operation), 0, bytes, 4, 4);
        return bytes;
    }
    public static int Ioctl(SafeFileHandle device, byte[] input, byte[] output, out int returned)
    {
        bool success = DeviceIoControl(device, 0x00122400, input, input.Length, output,
            output == null ? 0 : output.Length, out returned, IntPtr.Zero);
        return success ? 0 : Marshal.GetLastWin32Error();
    }
    public static int Set(SafeFileHandle device, Guid value)
    {
        var request = Request(46, 24);
        Array.Copy(value.ToByteArray(), 0, request, 8, 16);
        int returned;
        return Ioctl(device, request, null, out returned);
    }
    public static int Get(SafeFileHandle device, out Guid value)
    {
        byte[] reply = new byte[24];
        int returned;
        int error = Ioctl(device, Request(47, 8), reply, out returned);
        value = Guid.Empty;
        if (error == 0) {
            Require(returned == 24 && BitConverter.ToUInt16(reply, 0) == 24 &&
                BitConverter.ToUInt32(reply, 4) == 47, "Malformed raw GET reply");
            byte[] guid = new byte[16];
            Array.Copy(reply, 8, guid, 0, 16);
            value = new Guid(guid);
        }
        return error;
    }
    public static Guid GetSelection()
    {
        using (var device = OpenDevice()) {
            Guid value;
            Require(Get(device, out value) == 0, "Raw GET must succeed");
            return value;
        }
    }
    public static void Select(Guid value)
    {
        using (var device = OpenDevice()) {
            Require(Set(device, value) == 0, "Raw SET must succeed");
            Guid actual;
            Require(Get(device, out actual) == 0 && actual == value, "Raw selection mismatch");
        }
    }
    public static void RemovePinIfMatches(NamespaceVmPin pin)
    {
        // Test-owned paths are already canonical BPF:\ paths. Open the expected
        // object by ID, then let opcode 48 compare and delete atomically.
        Require(pin.Path.StartsWith(@"BPF:\namespace_vm\", StringComparison.Ordinal),
            "Refuse conditional cleanup outside canonical test-owned path family");
        using (var device = OpenDevice()) {
            uint operation = pin.Kind == "map" ? 20U : 19U;
            byte[] request = Request(operation, 12), reply = new byte[16];
            Array.Copy(BitConverter.GetBytes(pin.Id), 0, request, 8, 4);
            int returned;
            Require(Ioctl(device, request, reply, out returned) == 0 && returned == 16 &&
                BitConverter.ToUInt16(reply, 0) == 16 && BitConverter.ToUInt32(reply, 4) == operation,
                "Open exact expected object ID for conditional cleanup");
            byte[] handle = new byte[8];
            Array.Copy(reply, 8, handle, 0, 8);
            try {
                byte[] path = System.Text.Encoding.ASCII.GetBytes(pin.Path);
                request = Request(48, 16 + path.Length);
                Array.Copy(handle, 0, request, 8, 8);
                Array.Copy(path, 0, request, 16, path.Length);
                Require(Ioctl(device, request, null, out returned) == 0,
                    "Conditional unpin failed; replacement pins are never removed");
            } finally {
                request = Request(15, 16);
                Array.Copy(handle, 0, request, 8, 8);
                Require(Ioctl(device, request, null, out returned) == 0, "Close conditional-cleanup raw object handle");
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ServiceStatusProcess
    {
        public uint type, state, controls, win32Exit, serviceExit, checkpoint, waitHint, pid, flags;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ServiceStatus
    {
        public uint type, state, controls, win32Exit, serviceExit, checkpoint, waitHint;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatusProcess status,
        int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ControlService(IntPtr service, uint control, out ServiceStatus status);
    [DllImport("advapi32.dll")]
    static extern bool CloseServiceHandle(IntPtr service);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr source, uint access, IntPtr attributes, int level,
        int type, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int type, IntPtr data, int size, out int needed);

    public static void StopExistingService(string name)
    {
        // Match restart_test_controller's SCM STOP. ServiceController.Stop() on
        // some runtimes recursively stops dependents; that is not allowed here.
        IntPtr scm = OpenSCManager(null, null, 1);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open SCM");
        try {
            IntPtr service = OpenService(scm, name, 0x24);
            if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open " + name);
            try {
                ServiceStatus status;
                if (!ControlService(service, 1, out status))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Non-forced STOP " + name);
            } finally { CloseServiceHandle(service); }
        } finally { CloseServiceHandle(scm); }
    }

    static bool HasGroup(IntPtr token, SecurityIdentifier sid, bool enabledOnly)
    {
        int size;
        GetTokenInformation(token, 2, IntPtr.Zero, 0, out size);
        IntPtr data = Marshal.AllocHGlobal(size);
        try {
            Require(GetTokenInformation(token, 2, data, size, out size), "Query actual token groups");
            int count = Marshal.ReadInt32(data);
            int first = IntPtr.Size == 8 ? 8 : 4;
            int stride = IntPtr.Size == 8 ? 16 : 8;
            for (int i = 0; i < count; ++i) {
                IntPtr entry = IntPtr.Add(data, first + i * stride);
                var actual = new SecurityIdentifier(Marshal.ReadIntPtr(entry));
                uint attributes = (uint)Marshal.ReadInt32(entry, IntPtr.Size);
                if (actual == sid && (!enabledOnly || ((attributes & 4) != 0 && (attributes & 0x10) == 0)))
                    return true;
            }
            return false;
        } finally { Marshal.FreeHGlobal(data); }
    }
    static void CheckIdentity(WindowsIdentity identity, string lane, string serviceName)
    {
        SecurityIdentifier serviceSid = null;
        if (lane == "ND12Service" || lane == "ND12LocalService")
            serviceSid = (SecurityIdentifier)new NTAccount(@"NT SERVICE\ebpfsvc").Translate(typeof(SecurityIdentifier));
        var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        if (lane == "ND12Admin")
            Require(identity.User.Value != "S-1-5-18" && identity.User.Value != "S-1-5-19" &&
                identity.User.Value != "S-1-5-20" && HasGroup(identity.Token, admin, true),
                "Requires actual enabled local Administrator user token, not SYSTEM/a service account");
        else if (lane == "ND12System")
            Require(identity.User.Value == "S-1-5-18", "Requires actual SYSTEM primary user");
        else if (lane == "ND12Service")
            Require(String.Equals(serviceName, "ebpfsvc", StringComparison.OrdinalIgnoreCase) &&
                identity.User.Value == "S-1-5-19" && !HasGroup(identity.Token, admin, true) &&
                HasGroup(identity.Token, serviceSid, true), "Actual LocalService ebpfsvc enabled service SID required");
        else {
            Require(identity.User.Value == "S-1-5-19", "Negative service token primary user must be LocalService");
            Require(!HasGroup(identity.Token, serviceSid, false), "Unrelated service must not contain ebpfsvc SID");
            Require(!HasGroup(identity.Token, admin, true), "Negative service must not be Administrator");
        }
        Console.WriteLine("ND12 lane={0} user={1} service={2} token={3}", lane, identity.User, serviceName, identity.Name);
    }
    public static void IdentityLane(string lane, string serviceName)
    {
        // Open as the actual elevated caller, BEFORE service-token impersonation.
        using (var device = OpenDevice()) {
            Guid original;
            Require(Get(device, out original) == 0, "Preopened device GET positive control");
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            bool impersonating = false;
            try {
                if (lane == "ND12Service" || lane == "ND12LocalService") {
                    IntPtr scm = OpenSCManager(null, null, 1);
                    Require(scm != IntPtr.Zero, "Open SCM");
                    try {
                        IntPtr service = OpenService(scm, serviceName, 4);
                        Require(service != IntPtr.Zero, "Required pre-running service unavailable: " + serviceName);
                        try {
                            ServiceStatusProcess status;
                            int needed;
                            Require(QueryServiceStatusEx(service, 0, out status, Marshal.SizeOf(typeof(ServiceStatusProcess)),
                                out needed) && status.state == 4 && status.pid != 0 && (status.type & 0x10) != 0,
                                "Required dedicated own-process service is not running");
                            using (var observed = Process.GetProcessById((int)status.pid))
                                Console.WriteLine("Actual service PID={0} startUTC={1:O}", status.pid, observed.StartTime.ToUniversalTime());
                            IntPtr process = OpenProcess(0x1000, false, status.pid);
                            if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open service process");
                            try {
                                Require(OpenProcessToken(process, 0x000a, out token), "Open actual service process token");
                            } finally { CloseHandle(process); }
                            ServiceStatusProcess recheck;
                            Require(QueryServiceStatusEx(service, 0, out recheck, Marshal.SizeOf(typeof(ServiceStatusProcess)),
                                out needed) && recheck.state == 4 && recheck.pid == status.pid, "Service PID changed during token capture");
                        } finally { CloseServiceHandle(service); }
                    } finally { CloseServiceHandle(scm); }
                    Require(DuplicateTokenEx(token, 0x000e, IntPtr.Zero, 2, 2, out duplicate),
                        "Duplicate actual token (requires caller privilege; no privilege changes are made)");
                    using (var identity = new WindowsIdentity(duplicate)) { CheckIdentity(identity, lane, serviceName); }
                    Require(ImpersonateLoggedOnUser(duplicate), "Impersonate actual service token");
                    impersonating = true;
                } else {
                    using (var identity = WindowsIdentity.GetCurrent()) { CheckIdentity(identity, lane, ""); }
                }
                bool denied = lane == "ND12LocalService";
                Guid selected = Guid.NewGuid(), actual;
                int set = Set(device, selected);
                int get = Get(device, out actual);
                Console.WriteLine("Per-request SET Win32={0}; GET Win32={1}", set, get);
                Require(set == (denied ? 5 : 0), "SET authorization result mismatch");
                Require(get == (denied ? 5 : 0), "GET authorization result mismatch");
                if (!denied) Require(actual == selected, "Authorized selection must be effective");
                if (impersonating) {
                    Require(RevertToSelf(), "Revert actual service token");
                    impersonating = false;
                }
                Require(Get(device, out actual) == 0 && actual == (denied ? original : selected),
                    "Authorization must not silently mutate selection on denied request");
            } finally {
                if (impersonating) Require(RevertToSelf(), "Revert service identity during failure cleanup");
                if (duplicate != IntPtr.Zero) CloseHandle(duplicate);
                if (token != IntPtr.Zero) CloseHandle(token);
                Require(Set(device, original) == 0, "Restore original selection after identity fixture");
            }
        }
    }
}

public sealed class NamespaceVmPin
{
    public string Namespace;
    public string Path;
    public uint Id;
    public uint Marker;
    public string Kind;
    public uint ProgramId;
    public uint[] NativeMapIds;
}

public sealed class NamespaceVmSdk : IDisposable
{
    IntPtr module;
    readonly bool supported;
    readonly string dllPath;
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int MapCreate(uint type, [MarshalAs(UnmanagedType.LPStr)] string name, uint keySize,
        uint valueSize, uint count, IntPtr options);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Update(int fd, ref uint key, ref uint value, ulong flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Lookup(int fd, ref uint key, out uint value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Delete(int fd, ref uint key);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Info(int fd, [Out] byte[] data, ref uint length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Close(int fd);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Pin(int fd, [MarshalAs(UnmanagedType.LPStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int OpenPin([MarshalAs(UnmanagedType.LPStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Unpin([MarshalAs(UnmanagedType.LPStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int OpenId(uint id);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int NamespaceCall(ref Guid value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate IntPtr ObjectOpen([MarshalAs(UnmanagedType.LPStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int ObjectLoad(IntPtr obj);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void ObjectClose(IntPtr obj);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Execution(IntPtr obj, int type);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate IntPtr NextProgram(IntPtr obj, IntPtr previous);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Attach(int programFd, IntPtr attachType, byte[] parameters, UIntPtr parameterSize, out IntPtr link);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int LinkPin(IntPtr link, [MarshalAs(UnmanagedType.LPStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void LinkDisconnect(IntPtr link);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int LinkDestroy(IntPtr link);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int ObjectFd(IntPtr obj);

    T Bind<T>(string name) where T : class
    {
        IntPtr address = NamespaceVmNative.GetProcAddress(module, name);
        NamespaceVmNative.Require(address != IntPtr.Zero, "Required public Cdecl export missing: " + name);
        return Marshal.GetDelegateForFunctionPointer(address, typeof(T)) as T;
    }
    public NamespaceVmSdk(string path, bool namespaceSupport)
    {
        dllPath = Path.GetFullPath(path);
        supported = namespaceSupport;
        NamespaceVmNative.Require(NamespaceVmNative.GetModuleHandle("ebpfapi.dll") == IntPtr.Zero,
            "SDK child must not already have an imported ebpfapi.dll");
        module = NamespaceVmNative.LoadLibraryEx(dllPath, IntPtr.Zero, 0x1100);
        if (module == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Load exact fixture DLL (check bitness/dependencies)");
        try {
            var actual = new System.Text.StringBuilder(32768);
            NamespaceVmNative.Require(NamespaceVmNative.GetModuleFileName(module, actual, actual.Capacity) > 0 &&
                String.Equals(Path.GetFullPath(actual.ToString()), dllPath, StringComparison.OrdinalIgnoreCase),
                "Loaded DLL is not the manifest DLL");
            bool set = NamespaceVmNative.GetProcAddress(module, "ebpf_set_namespace") != IntPtr.Zero;
            bool get = NamespaceVmNative.GetProcAddress(module, "ebpf_get_namespace") != IntPtr.Zero;
            NamespaceVmNative.Require(set == supported && get == supported,
                "OLD must lack namespace exports; NEW must expose both (not fake old APIs in a new DLL)");
            Console.WriteLine("Loaded exact DLL={0}; namespace exports={1}; process bitness={2}", dllPath, supported, IntPtr.Size * 8);
        } catch { Dispose(); throw; }
    }
    public void Dispose()
    {
        if (module == IntPtr.Zero) return;
        IntPtr value = module;
        module = IntPtr.Zero;
        NamespaceVmNative.Require(NamespaceVmNative.FreeLibrary(value), "Free complete fixture SDK DLL");
        NamespaceVmNative.Require(NamespaceVmNative.GetModuleHandle(dllPath) == IntPtr.Zero,
            "SDK DLL remained loaded; child process exit is not accepted as DLL unload evidence");
        Console.WriteLine("All SDK handles closed and complete DLL unloaded before child exit");
    }
    void Select(Guid value)
    {
        NamespaceVmNative.Require(supported, "Selected namespace requires NEW DLL");
        NamespaceVmNative.Require(Bind<NamespaceCall>("ebpf_set_namespace")(ref value) == 0, "Public SET");
        Guid actual = Guid.NewGuid();
        NamespaceVmNative.Require(Bind<NamespaceCall>("ebpf_get_namespace")(ref actual) == 0 && actual == value, "Public GET selection");
    }
    void CloseFd(int fd)
    {
        if (fd >= 0) NamespaceVmNative.Require(Bind<Close>("ebpf_close_fd")(fd) == 0, "Close fixture fd");
    }
    public uint Id(int fd)
    {
        byte[] data = new byte[1024];
        uint length = (uint)data.Length;
        NamespaceVmNative.Require(Bind<Info>("bpf_obj_get_info_by_fd")(fd, data, ref length) == 0 &&
            length >= 8, "Public object metadata");
        // The public bpf_map_info/bpf_link_info ID is at offset 4, not an internal SDK layout.
        // Windows SDK bpf_*_info structs begin with id, unlike Linux syscall layouts.
        uint id = BitConverter.ToUInt32(data, 0);
        NamespaceVmNative.Require(id != 0, "Object ID must be nonzero");
        return id;
    }
    public NamespaceVmPin CreateMap(Guid ns, string path, uint marker, bool select)
    {
        if (select) Select(ns);
        int fd = Bind<MapCreate>("bpf_map_create")(1, "namespace_vm", 4, 4, 4, IntPtr.Zero);
        NamespaceVmNative.Require(fd >= 0, "Create legacy-compatible HASH map");
        try {
            Crud(fd, marker);
            uint key = 0;
            NamespaceVmNative.Require(Bind<Update>("bpf_map_update_elem")(fd, ref key, ref marker, 0) == 0, "Persist map marker");
            uint id = Id(fd);
            NamespaceVmNative.Require(Bind<Pin>("bpf_obj_pin")(fd, path) == 0, "Pin test-owned map");
            Console.WriteLine("Map namespace={0} path={1} id={2} marker={3}", ns, path, id, marker);
            return new NamespaceVmPin { Namespace = ns.ToString(), Path = path, Id = id, Marker = marker, Kind = "map" };
        } finally { CloseFd(fd); }
    }
    void Crud(int fd, uint marker)
    {
        uint key = 0, value;
        NamespaceVmNative.Require(Bind<Update>("bpf_map_update_elem")(fd, ref key, ref marker, 0) == 0, "Legacy map update");
        NamespaceVmNative.Require(Bind<Lookup>("bpf_map_lookup_elem")(fd, ref key, out value) == 0 && value == marker, "Legacy map lookup marker");
        NamespaceVmNative.Require(Bind<Delete>("bpf_map_delete_elem")(fd, ref key) == 0, "Legacy map delete");
        NamespaceVmNative.Require(Bind<Lookup>("bpf_map_lookup_elem")(fd, ref key, out value) == -2, "Deleted HASH key must be ENOENT");
    }
    public NamespaceVmPin CreateLink(Guid ns, string path, string nativeProgram)
    {
        Select(ns);
        IntPtr obj = Bind<ObjectOpen>("bpf_object__open")(nativeProgram);
        NamespaceVmNative.Require(obj.ToInt64() > 0, "Open required signed native sample fixture");
        IntPtr link = IntPtr.Zero;
        bool pinned = false;
        try {
            NamespaceVmNative.Require(Bind<Execution>("ebpf_object_set_execution_type")(obj, 3) == 0, "Select native execution");
            NamespaceVmNative.Require(Bind<ObjectLoad>("bpf_object__load")(obj) == 0, "Load required native sample (sample extension must be running)");
            IntPtr program = Bind<NextProgram>("bpf_object__next_program")(obj, IntPtr.Zero);
            NamespaceVmNative.Require(program != IntPtr.Zero, "Native sample must have a program");
            uint programId = Id(Bind<ObjectFd>("bpf_program__fd")(program));
            var mapIds = new List<uint>();
            IntPtr map = IntPtr.Zero;
            while ((map = Bind<NextProgram>("bpf_object__next_map")(obj, map)) != IntPtr.Zero)
                mapIds.Add(Id(Bind<ObjectFd>("bpf_map__fd")(map)));
            byte[] attachParameters = Guid.NewGuid().ToByteArray();
            NamespaceVmNative.Require(Bind<Attach>("ebpf_program_attach_by_fd")(
                Bind<ObjectFd>("bpf_program__fd")(program), IntPtr.Zero, attachParameters,
                new UIntPtr((uint)attachParameters.Length), out link) == 0 && link != IntPtr.Zero,
                "Attach native sample with a unique provider-supported attach parameter");
            uint id = Id(Bind<ObjectFd>("bpf_link__fd")(link));
            NamespaceVmNative.Require(Bind<LinkPin>("bpf_link__pin")(link, path) == 0, "Pin test-owned link");
            pinned = true;
            // Preserve pinned link, but release the SDK descriptor/structure and the native object.
            Bind<LinkDisconnect>("bpf_link__disconnect")(link);
            Console.WriteLine("Link namespace={0} path={1} id={2} programId={3} nativeMapIds={4}",
                ns, path, id, programId, String.Join(",", mapIds));
            return new NamespaceVmPin { Namespace = ns.ToString(), Path = path, Id = id, Kind = "link",
                ProgramId = programId, NativeMapIds = mapIds.ToArray() };
        } finally {
            if (link != IntPtr.Zero)
                NamespaceVmNative.Require(Bind<LinkDestroy>("bpf_link__destroy")(link) == 0, "Release link SDK reference");
            Bind<ObjectClose>("bpf_object__close")(obj);
            if (!pinned) Console.WriteLine("Link fixture failed before a pin was retained");
        }
    }
    public void VerifyPin(NamespaceVmPin pin)
    {
        if (supported) Select(new Guid(pin.Namespace));
        VerifyPinDefault(pin);
    }
    void VerifyPinDefault(NamespaceVmPin pin)
    {
        int fd = Bind<OpenPin>("bpf_obj_get")(pin.Path);
        NamespaceVmNative.Require(fd >= 0, "Pin must survive child DLL unload: " + pin.Path);
        try {
            NamespaceVmNative.Require(Id(fd) == pin.Id, "Pinned object ID changed");
            if (pin.Kind == "map") {
                uint key = 0, value;
                NamespaceVmNative.Require(Bind<Lookup>("bpf_map_lookup_elem")(fd, ref key, out value) == 0 &&
                    value == pin.Marker, "Pinned map marker changed");
            }
        } finally { CloseFd(fd); }
    }
    public void VerifyAbsent(NamespaceVmPin pin)
    {
        Select(new Guid(pin.Namespace));
        int fd = Bind<OpenPin>("bpf_obj_get")(pin.Path);
        if (fd >= 0) { CloseFd(fd); throw new InvalidOperationException("Old pin survived actual driver unload: " + pin.Path); }
        NamespaceVmNative.Require(fd == -2, "Missing old pin must report ENOENT, not access denied/another failure");
        RequireIdAbsent(pin.Kind, pin.Id);
        if (pin.Kind == "link") {
            RequireIdAbsent("program", pin.ProgramId);
            foreach (uint mapId in pin.NativeMapIds) RequireIdAbsent("map", mapId);
        }
    }
    void RequireIdAbsent(string kind, uint id)
    {
        string export = kind == "map" ? "bpf_map_get_fd_by_id" :
            kind == "link" ? "bpf_link_get_fd_by_id" : "bpf_prog_get_fd_by_id";
        int fd = Bind<OpenId>(export)(id);
        if (fd >= 0) { CloseFd(fd); throw new InvalidOperationException("Old object ID survived actual driver unload"); }
        NamespaceVmNative.Require(fd == -2, "Old object ID must report ENOENT");
    }
    public void RemoveOwned(NamespaceVmPin pin)
    {
        if (supported) Select(new Guid(pin.Namespace));
        int fd = Bind<OpenPin>("bpf_obj_get")(pin.Path);
        if (fd == -2) return;
        NamespaceVmNative.Require(fd >= 0, "Open pin for ownership-safe cleanup");
        try {
            NamespaceVmNative.Require(Id(fd) == pin.Id, "Refuse cleanup: path is no longer owned by this test");
            NamespaceVmNative.RemovePinIfMatches(pin);
        } finally { CloseFd(fd); }
    }
    public void Compatibility(bool driverSupportsNamespace, string path)
    {
        Guid requested = Guid.NewGuid();
        NamespaceVmPin map = null;
        try {
            if (driverSupportsNamespace)
                NamespaceVmNative.Require(NamespaceVmNative.GetSelection() == Guid.Empty, "OLD DLL starts in real driver default scope");
            map = CreateMap(Guid.Empty, path, 0x31c0ffee, false);
            VerifyPinDefault(map);
            if (driverSupportsNamespace) {
                // Probe the actual NEW driver's scope without loading a NEW SDK into this OLD-DLL child.
                NamespaceVmNative.Require(NamespaceVmNative.GetSelection() == Guid.Empty, "OLD APIs must not change selection");
                NamespaceVmNative.Select(requested);
                int hidden = Bind<OpenPin>("bpf_obj_get")(path);
                if (hidden >= 0) { CloseFd(hidden); throw new InvalidOperationException("OLD-DLL default pin leaked into namespace A"); }
                NamespaceVmNative.Require(hidden == -2, "Foreign default pin must be ENOENT");
                hidden = Bind<OpenId>("bpf_map_get_fd_by_id")(map.Id);
                if (hidden >= 0) { CloseFd(hidden); throw new InvalidOperationException("OLD-DLL default ID leaked into A"); }
                NamespaceVmNative.Require(hidden == -2, "Foreign default ID must be ENOENT");
                NamespaceVmNative.Select(Guid.Empty);
                VerifyPinDefault(map);
            } else {
                var set = Bind<NamespaceCall>("ebpf_set_namespace");
                var get = Bind<NamespaceCall>("ebpf_get_namespace");
                Guid output = Guid.NewGuid();
                int getResult = get(ref output), setResult = set(ref requested);
                Console.WriteLine("NEW DLL/OLD driver public GET={0}, SET={1} (expected EBPF_OPERATION_NOT_SUPPORTED=18)", getResult, setResult);
                NamespaceVmNative.Require(getResult == 18 && setResult == 18,
                    "OLD driver must explicitly return unsupported, never namespace success/access-denied conversion");
                Guid empty = Guid.Empty;
                NamespaceVmNative.Require(set(ref empty) == 18 && get(ref output) == 18,
                    "Even default SET must not silently succeed on OLD driver");
                VerifyPinDefault(map);
                int fd = Bind<OpenPin>("bpf_obj_get")(path);
                NamespaceVmNative.Require(fd >= 0, "Default pin remains usable after unsupported namespace requests");
                try { Crud(fd, 0x31abcdef); } finally { CloseFd(fd); }
            }
        } finally {
            if (driverSupportsNamespace) NamespaceVmNative.Select(Guid.Empty);
            if (map != null) {
                // The OLD-driver lane cannot issue SET, including during cleanup.
                int fd = Bind<OpenPin>("bpf_obj_get")(map.Path);
                NamespaceVmNative.Require(fd >= 0, "Compatibility cleanup must reopen its owned pin");
                try {
                    NamespaceVmNative.Require(Id(fd) == map.Id, "Refuse to unpin a replacement object");
                    if (driverSupportsNamespace) NamespaceVmNative.RemovePinIfMatches(map);
                    else NamespaceVmNative.Require(Bind<Unpin>("ebpf_object_unpin")(map.Path) == 0,
                        "OLD-driver compatibility owned unpin (isolated random path, no conditional opcode on OLD)");
                } finally { CloseFd(fd); }
            }
        }
    }
}
'@

# CodeDOM on Windows PowerShell must also keep compiler scratch files in our
# owned working directory, not the machine's shared TEMP directory.
if (-not $RunDirectory) {
    $RunDirectory = Join-Path (Get-Location).Path ('namespace_vm_' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $RunDirectory -ErrorAction Stop
} else {
    Assert-Condition ([IO.Path]::IsPathRooted($RunDirectory) -and
        (Test-Path -LiteralPath $RunDirectory -PathType Container)) 'Child RunDirectory must exist.'
}
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$env:TEMP = $RunDirectory
$env:TMP = $RunDirectory
try {
    Add-Type -TypeDefinition $source -ErrorAction Stop
} finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
}

function Assert-InstalledDriver {
    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='ebpfcore'"
    Assert-Condition ($null -ne $driver -and $driver.State -eq 'Running') 'Required preinstalled ebpfcore driver must be running.'
    $installed = [Environment]::ExpandEnvironmentVariables($driver.PathName.Trim('"'))
    if ($installed.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $installed = Join-Path $env:SystemRoot $installed.Substring(12)
    }
    if ($installed.StartsWith('\??\')) { $installed = $installed.Substring(4) }
    Assert-Condition ([IO.Path]::GetFullPath($installed) -eq [IO.Path]::GetFullPath($fixture.driver.path)) `
        "Running ebpfcore image path '$installed' does not match manifest '$($fixture.driver.path)'."
    Write-Host "Preprovisioned running driver: $installed"
}

function Read-Pins {
    $pins = @(Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json)
    foreach ($entry in $pins) {
        $pin = New-Object NamespaceVmPin
        $pin.Namespace = $entry.Namespace
        $pin.Path = $entry.Path
        $pin.Id = $entry.Id
        $pin.Marker = $entry.Marker
        $pin.Kind = $entry.Kind
        $pin.ProgramId = $entry.ProgramId
        $pin.NativeMapIds = $entry.NativeMapIds
        $pin
    }
}

Assert-InstalledDriver
if ($ChildPhase) {
    $sdk = $null
    try {
        $sdk = [NamespaceVmSdk]::new($fixture.dll.path, $fixture.dll.namespaceSupport)
        if ($ChildPhase -eq 'Compatibility') {
            $sdk.Compatibility($fixture.driver.namespaceSupport, ('BPF:\namespace_vm\' + [guid]::NewGuid().ToString('N')))
        } elseif ($ChildPhase -eq 'Populate') {
            Assert-Condition (-not (Test-Path -LiteralPath $StatePath)) 'Refuse to overwrite fixture state.'
            $pins = @()
            $namespaces = @([guid]::Empty, [guid]::NewGuid(), [guid]::NewGuid())
            $path = 'BPF:\namespace_vm\' + [guid]::NewGuid().ToString('N')
            for ($index = 0; $index -lt $namespaces.Count; $index++) {
                $pins += $sdk.CreateMap($namespaces[$index], $path, [uint32](2300 + $index), $true)
                $pins | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatePath
                # Unique native image names avoid collisions with other loaded module instances.
                $sample = Join-Path $RunDirectory ("$([IO.Path]::GetFileName($RunDirectory))_$index.sys")
                [IO.File]::Copy($fixture.nativeProgram.path, $sample, $false)
                $pins += $sdk.CreateLink($namespaces[$index], ($path + '-link'), $sample)
                $pins | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatePath
            }
            foreach ($pin in $pins) { $sdk.VerifyPin($pin) }
        } elseif ($ChildPhase -eq 'Verify') {
            $pins = @(Read-Pins)
            Assert-Condition ($pins.Count -eq 6) 'ND23 requires all A/B/default map and link fixtures.'
            # Check every old ID before creating new objects: IDs may legitimately be reused after reload.
            foreach ($pin in $pins) { $sdk.VerifyAbsent($pin) }
            foreach ($pin in @($pins | Where-Object Kind -eq 'map')) {
                $fresh = $sdk.CreateMap([guid]$pin.Namespace, $pin.Path, [uint32]2399, $true)
                try { $sdk.VerifyPin($fresh) } finally { $sdk.RemoveOwned($fresh) }
            }
            $index = 0
            foreach ($pin in @($pins | Where-Object Kind -eq 'link')) {
                $sample = Join-Path $RunDirectory ("$([IO.Path]::GetFileName($RunDirectory))_restart_$index.sys")
                [IO.File]::Copy($fixture.nativeProgram.path, $sample, $false)
                $fresh = $sdk.CreateLink([guid]$pin.Namespace, $pin.Path, $sample)
                try { $sdk.VerifyPin($fresh) } finally { $sdk.RemoveOwned($fresh) }
                $index++
            }
        } elseif ($ChildPhase -eq 'Cleanup') {
            foreach ($pin in @(Read-Pins)) { $sdk.RemoveOwned($pin) }
        }
    } finally {
        if ($null -ne $sdk) { $sdk.Dispose() }
    }
    $completion = [ordered]@{
        scenario = $Scenario
        phase = $ChildPhase
        pid = $PID
        processStartUtc = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString('O')
        principal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        dllPath = $fixture.dll.path
        dllSha256 = $fixture.dll.sha256
        driverPath = $fixture.driver.path
        driverSha256 = $fixture.driver.sha256
        dllUnloaded = $true
    }
    $completionPath = Join-Path $RunDirectory ($ChildPhase + '.completed.json')
    $file = [IO.File]::Open($completionPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    $writer = [IO.StreamWriter]::new($file)
    try { $writer.Write(($completion | ConvertTo-Json -Depth 4)) } finally { $writer.Dispose() }
    exit 0
}

function Invoke-SdkChild([string] $Phase) {
    $arguments = @('-NoProfile', '-NonInteractive', '-File', $PSCommandPath, '-Scenario', $Scenario,
        '-Manifest', $Manifest, '-ChildPhase', $Phase, '-RunDirectory', $RunDirectory)
    if ($StatePath) { $arguments += @('-StatePath', $StatePath) }
    if ($AllowDriverRestart) { $arguments += '-AllowDriverRestart' }
    # Windows PowerShell's Start-Process joins arguments without quoting them.
    $quoted = @($arguments | ForEach-Object {
        Assert-Condition (-not $_.Contains('"') -and -not $_.EndsWith('\')) 'Unsupported quote/trailing slash in child argument.'
        '"' + $_ + '"'
    })
    $stdout = Join-Path $RunDirectory ($Phase + '.stdout.log')
    $stderr = Join-Path $RunDirectory ($Phase + '.stderr.log')
    $child = Start-Process -FilePath $fixture.powershellPath -ArgumentList $quoted -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    try {
        $null = $child.Handle
        if (-not $child.WaitForExit(180000)) {
            Stop-Process -Id $child.Id -ErrorAction Stop
            throw "SDK child $Phase PID=$($child.Id) timed out after 180 seconds; no driver stop will follow."
        }
        $child.WaitForExit()
        Get-Content -LiteralPath $stdout | Write-Host
        Get-Content -LiteralPath $stderr | Write-Host
        Assert-Condition ($child.ExitCode -eq 0) "SDK child $Phase failed (exit $($child.ExitCode)); evidence: $RunDirectory"
        $completion = Get-Content -LiteralPath (Join-Path $RunDirectory ($Phase + '.completed.json')) -Raw | ConvertFrom-Json
        Assert-Condition ($completion.scenario -eq $Scenario -and $completion.phase -eq $Phase -and
            $completion.pid -eq $child.Id -and $completion.dllSha256 -eq $fixture.dll.sha256 -and
            $completion.driverSha256 -eq $fixture.driver.sha256 -and $completion.dllUnloaded -eq $true) `
            "Missing or incorrect SDK child completion evidence for $Phase."
    } finally { $child.Dispose() }
}

$null = Start-Transcript -Path (Join-Path $RunDirectory 'controller.log') -NoClobber
try {
Write-Host "Scenario=$Scenario principal=$([Security.Principal.WindowsIdentity]::GetCurrent().Name) PID=$PID startUTC=$([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString('O')) evidence=$RunDirectory"
if ($Scenario.StartsWith('ND31')) {
    Invoke-SdkChild 'Compatibility'
} elseif ($Scenario.StartsWith('ND12')) {
    $serviceName = ''
    if ($Scenario -eq 'ND12Service') { $serviceName = $fixture.services.ebpfService }
    if ($Scenario -eq 'ND12LocalService') { $serviceName = $fixture.services.unrelatedLocalService }
    [NamespaceVmNative]::IdentityLane($Scenario, $serviceName)
} else {
    Assert-Condition ([NamespaceVmNative]::GetModuleHandle('ebpfapi.dll') -eq [IntPtr]::Zero) `
        'ND23 controller must not load ebpfapi.dll or inherit an API device reference.'
    Assert-Condition ([NamespaceVmNative]::GetSelection() -eq [guid]::Empty) 'Fresh ND23 controller must start in default namespace.'
    $StatePath = Join-Path $RunDirectory 'pins.json'
    $stopped = New-Object 'Collections.Generic.List[string]'
    $coreStopped = $false
    $completed = $false
    try {
        Invoke-SdkChild 'Populate'
        $pins = @(Read-Pins)
        $selected = [guid]$pins[2].Namespace
        # This SAME controller survives unload. Selection is not "verified" by a fresh process.
        [NamespaceVmNative]::Select($selected)
        # Same supported ordering as install_ebpf / restart controller: service first,
        # extension providers before core; SCM STOP only, never Force or live-handle unload.
        foreach ($name in @('ebpfsvc', 'SampleEbpfExt', 'NetEbpfExt', 'EbpfCore')) {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -eq $service) {
                Assert-Condition ($name -eq 'ebpfsvc') "Required ND23 driver service '$name' is missing."
                continue
            }
            if ($service.Status -ne 'Running') {
                Assert-Condition ($name -eq 'ebpfsvc') "Required ND23 driver '$name' must initially be running."
                continue
            }
            Write-Host "Supported non-forced SCM stop: $name (all child DLL/device/object references released)"
            [NamespaceVmNative]::StopExistingService($name)
            $stopped.Add($name)
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
            if ($name -eq 'EbpfCore') { $coreStopped = $true }
            $service.Dispose()
        }
        Assert-Condition $coreStopped 'ND23 requires actual EbpfCore SERVICE_STOPPED, not child process exit.'
        try {
            $unexpected = [NamespaceVmNative]::OpenDevice()
            $unexpected.Dispose()
            throw 'Device remained openable after actual EbpfCore stop.'
        } catch [ComponentModel.Win32Exception] {
            Assert-Condition ($_.Exception.NativeErrorCode -in @(2, 3, 55)) `
                "Unexpected stopped-device error: $($_.Exception.NativeErrorCode)"
        }
        for ($index = $stopped.Count - 1; $index -ge 0; $index--) {
            $name = $stopped[$index]
            $service = Get-Service -Name $name
            $service.Start()
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
            $service.Dispose()
            $stopped.RemoveAt($index)
        }
        Assert-InstalledDriver
        Assert-Condition ([NamespaceVmNative]::GetSelection() -eq [guid]::Empty) `
            'Old selection survived actual unload/reload in the same controller process.'
        Invoke-SdkChild 'Verify'
        $completed = $true
    } finally {
        # Restore only services this invocation successfully requested to stop, never install/force.
        for ($index = $stopped.Count - 1; $index -ge 0; $index--) {
            $name = $stopped[$index]
            try {
                $service = Get-Service -Name $name
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
                $service.Start()
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
                $service.Dispose()
            } catch { Write-Warning "Failed to restore owned service $name : $_" }
        }
        if (-not $coreStopped -and (Test-Path -LiteralPath $StatePath)) {
            # Before a successful unload the exact IDs still identify our own pins.
            Invoke-SdkChild 'Cleanup'
        }
        if (-not $completed) { Write-Warning "ND23 FAILED; retain evidence in $RunDirectory. No forced unload was attempted." }
        if ((Get-Service -Name EbpfCore).Status -eq 'Running') { [NamespaceVmNative]::Select([guid]::Empty) }
    }
}
Write-Host "PASS $Scenario (actual execution); evidence=$RunDirectory"
} finally {
    $null = Stop-Transcript
}
