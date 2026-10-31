# Dedicated VM namespace fixtures (ND12, ND23, ND31)

These tests **must not run on a shared development host**. They require an
administrator-approved, preprovisioned dedicated kernel-test VM. No script
provisions/replaces core or extension drivers, DLLs, service identity fixtures,
or a VM; downloads binaries; changes security policy; or enables privileges.
ND23 alone stops/restarts existing infrastructure services, with an additional
explicit switch. Its native program loads use the repository's ordinary native
loader (including transient native-module driver services), not a new helper
service. The ND12 token lanes never create/start/stop services.
Missing fixtures and incorrect results fail;
there is no skip/pass fallback.

## Manifest and artifact provenance

Copy `scripts\namespace_vm_fixture.example.json` to an operator-owned manifest,
replace every example field, and explicitly approve the dedicated VM.
`scripts\namespace_vm_fixture.schema.json` documents its shape. The example is
deliberately **not runnable**. Review paths/hashes against trusted release/build
artifacts before setting `approvedDedicatedVM` to `true`; do not generate an
approval by hashing whichever binary happens to be installed. Artifact file
versions and SHA256 hashes must match exactly. `namespaceSupport: false` means
a genuine OLD binary predating namespaces; `true` means NEW. The DLL must have
the same bitness as `powershellPath`, with its matching runtime dependencies
available. The DLL is loaded by full path with DLL-load-directory/default search
flags and verified by `GetModuleFileName`; no static SDK import is used by children.
The native sample may legitimately lack a version resource; use `version: ""`
to require that absence. DLL and core-driver versions must be nonempty.

Provision and boot **separate clean images** for OLD-driver/NEW-DLL and
NEW-driver/OLD-DLL. Never swap an on-disk driver while it is loaded. The script
checks the running SCM driver path and the expected on-disk hash/version, not a
cryptographic hash of kernel memory; immutable-image provenance is an operator
prerequisite. No command below performs provisioning or live binary replacement.

Run from a writable build output directory. The deployed script, schema, and
example are in the driver-test package. Every execution creates a unique,
test-owned `namespace_vm_<GUID>` directory under the current directory. Retain
the child stdout/stderr logs, ND23 `pins.json` (GUIDs, paths, IDs, markers), and
the controller transcript and per-child completion JSON with the CI run. Child
completion records include PID/start time, principal, and checked artifact hashes.
PowerShell compiler scratch is
also confined to that directory. Child waits are bounded at 180 seconds and
SCM state waits at 30 seconds. Failures are not evidence of coverage passing.

## ND31: actual cross-version images

On the clean **NEW-driver/OLD-DLL** image, set driver support `true` and DLL
support `false`, and use the approved legacy `ebpfapi.dll` path:

```powershell
.\execute_namespace_vm_tests.ps1 -Scenario ND31OldDllNewDriver -Manifest .\old-dll-new-driver.json
```

On the separate clean **OLD-driver/NEW-DLL** image, set driver support `false`
and DLL support `true`, and use the candidate DLL path:

```powershell
.\execute_namespace_vm_tests.ps1 -Scenario ND31NewDllOldDriver -Manifest .\new-dll-old-driver.json
```

Alternatively select exactly one hidden Catch case on its corresponding image:

```powershell
$env:EBPF_NAMESPACE_VM_MANIFEST = (Resolve-Path .\old-dll-new-driver.json).Path
.\api_test.exe 'ND31 actual OLD DLL against NEW driver image'
# On the OTHER image, with its corresponding manifest:
$env:EBPF_NAMESPACE_VM_MANIFEST = (Resolve-Path .\new-dll-old-driver.json).Path
.\api_test.exe 'ND31 actual NEW DLL against OLD driver image'
```

The `[.namespace_vm][ND31]` cases are intentionally not ordinary namespace-driver
CI cases. Running both on one image is incorrect and fails the manifest checks.
Both lanes dynamically bind the actual fixture DLL's public Cdecl map creation,
lookup/update/delete, pin/open, metadata, and close exports. Metadata uses the
Windows SDK object ID at offset 0, not the Linux syscall layout. The OLD DLL must
lack both namespace exports; using
old function names in a NEW DLL cannot satisfy this test. A real raw SET/GET
probe of the NEW driver proves default selection, pin/ID absence after selecting
A, and default visibility after restoring null. The NEW-DLL/OLD-driver lane
requires public SET/GET to return `EBPF_OPERATION_NOT_SUPPORTED` (18), including
SET(null); default map/pin CRUD must work before and after unsupported requests.
Access denied is never treated as success or unsupported. Owned pins are removed,
descriptors closed, and the complete DLL explicitly unloaded before child exit.

## ND23: actual unload/restart cleanup

Use a **NEW/NEW** manifest with a signed `test_sample_ebpf.sys` native sample,
running `SampleEbpfExt` and `NetEbpfExt`, and the normally installed optional
`ebpfsvc`. Each sample attachment uses its own provider-supported opaque attach
parameter, rather than assuming the provider permits duplicate default attaches.
Run only when the approved VM is idle and no other clients hold device references:

```powershell
.\execute_namespace_vm_tests.ps1 -Scenario ND23 -Manifest .\new-new.json -AllowDriverRestart
```

Do **not** launch ND23 from `api_test.exe`: its imported SDK initializes a device
handle. The standalone controller never loads an SDK. Its SDK child populates
default/A/B with distinct HASH-map markers and native pinned links at the same
namespace-relative paths, verifies all six pins, closes every fd/object/link SDK
reference, and explicitly unloads the entire DLL. Native copies have unique,
test-owned names; original binaries are never modified.

The same controller selects A via a raw request, closes its management handle,
then survives the actual stop/restart. It follows the existing supported SCM
ordering: user service first, extension providers, then core; startup is reversed.
It uses ordinary SCM STOP, **never Force**, never closes another process's handles,
and fails if supported stop preconditions are not satisfied. SERVICE_STOPPED and
an unavailable device are required, rather than treating child exit as unload.
After restart, the *same controller* must read null selection. A fresh SDK child
must find all old pins and IDs (including linked programs and their native maps)
absent in their original scopes **before any new
ID allocations**, then successfully create/use/unpin clean maps and native links
in all scopes.
The script restores only services it stopped. Before successful core unload,
failure cleanup checks pin IDs and uses conditional-unpin opcode 48 before
removing test-owned pins. On the OLD-driver lane, where that opcode does not
exist, cleanup checks its UUID-private path's ID before the legacy unpin; that
clean image must not have another process sharing those test-generated paths. Retain failed
fixture state for diagnosis; do not force unload to make a failing test pass.

## ND12: real privileged identities

Use NEW/NEW fixtures. These lanes make no service state changes. Admin and SYSTEM
must run as those **actual** identities, using the existing ordinary/SYSTEM
driver-test job routing (not a synthetic token or a new service):

```powershell
.\execute_namespace_vm_tests.ps1 -Scenario ND12Admin -Manifest .\new-new.json
# Run this command from the existing SYSTEM test lane:
.\execute_namespace_vm_tests.ps1 -Scenario ND12System -Manifest .\new-new.json
```

For service identity lanes, the fixture must name the actual, already-running
`ebpfsvc` and a dedicated own-process unrelated LocalService service. The caller
must already have access to query and duplicate the process token; absence of
that access explicitly fails (no privilege elevation/enablement is attempted):

```powershell
.\execute_namespace_vm_tests.ps1 -Scenario ND12Service -Manifest .\new-new.json
.\execute_namespace_vm_tests.ps1 -Scenario ND12LocalService -Manifest .\new-new.json
```

The helper queries SCM `QueryServiceStatusEx`, opens that running PID, duplicates
its **actual** token with `DuplicateTokenEx`, verifies identity/groups, and
impersonates only after opening the management device as the caller. PID/state
are rechecked during capture. The positive token must be LocalService with an
enabled, non-deny-only `NT SERVICE\ebpfsvc` SID. The unrelated service token must
have LocalService as primary user, no ebpfsvc SID, and no enabled Administrator
membership. Raw SET/GET on the **preopened handle** must respectively succeed
or both return `ERROR_ACCESS_DENIED` (5); device-open denial cannot satisfy the
negative case. Reversion verifies no denied mutation and restores selection.
No fake allow-DACL, service SID, RPC endpoint, or driver test knob is created.

To include all four identities in the existing `Invoke-CICDTests` routing, set
`EBPF_NAMESPACE_VM_IDENTITY_MANIFEST` to the absolute approved NEW/NEW manifest
path in the dedicated VM's test job and enable `ExecuteSystemTests`. This adds
the hidden `ND12 actual Administrator namespace fixture` to the ordinary lane
and explicitly launches ND12System/ND12Service/ND12LocalService through the
existing SYSTEM PsExec path. The manifest is passed explicitly across the
identity boundary. Opt-in with the SYSTEM lane disabled fails, rather than
silently omitting privileged coverage. The variable is distinct from ND31's
manifest, so cross-version images do not accidentally select identity tests.
