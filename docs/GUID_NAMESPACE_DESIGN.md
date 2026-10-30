# GUID-based BPF object namespaces: implementation design

**Status:** Implementation design, not an approved security boundary.
Prepared 2026-10-19; local GUID implementation was subsequently requested and
added in October 2026. See `IMPLEMENTATION_RUNBOOK.md` section 9 for current
code, executed validation, and outstanding driver/toolchain gates. The
original design-research session itself made no feature-code changes.

**Repository revision:** 2026-10-28, following independent design review.
This copy includes required corrections to async request ownership, pin rollback,
broker synchronization, and protocol/build prerequisites. These corrections are
design requirements, not claims that the existing implementation or tests already
satisfy them. Section 16 records the remaining implementation gates.

The original design, companion `ACL_OBJECT_ACCESS_DESIGN.md`, and
`IMPLEMENTATION_RUNBOOK.md` remain in `D:\projects\namespace_isolation`.
References to the runbook below mean that external artifact, not a file shipped
alongside this repository copy. Only this GUID design is being copied/revised.

## 1. Decision summary

Implement the behavior in
[microsoft/ebpf-for-windows#4424](https://github.com/microsoft/ebpf-for-windows/pull/4424):
an immutable namespace GUID on every map, program, and link; process-wide current
namespace state; namespace-filtered ID discovery; and pin keys consisting of
`(namespace GUID, canonical pin path)`. Keep the existing global numeric ID
allocator. Do not namespace-check ordinary operations on an already acquired
handle.

This is logical partitioning, not authorization. A sufficiently privileged
application that knows another application's GUID can select it. GUID secrecy is
an application policy, not a platform isolation guarantee. Implement the
independent ACL design in `ACL_OBJECT_ACCESS_DESIGN.md` for delegated,
low-privilege map access.

**Important design choice:** Use a kernel process-state registry to meet the
literal per-process contract. A GUID stored only on one control `FILE_OBJECT`
does not meet it in this checkout: synchronous control handles are thread-local,
and there is a separate asynchronous handle. Section 5 explains the tradeoff
with the meeting's lighter-weight file-object idea.

## 2. Source baseline and precedence

| Source | Pinned reference |
|---|---|
| Proposal | `docs/Namespaces.md` at PR head `99ea23f06209025a5cfdc657c0ce20a24a2d94ec`; 94 added lines; PR was open when inspected |
| Proposal URL | <https://github.com/microsoft/ebpf-for-windows/blob/99ea23f06209025a5cfdc657c0ce20a24a2d94ec/docs/Namespaces.md> |
| Repository examined | `D:\git\github\ebpf-for-windows-1-2\ebpf-for-windows-1` |
| Code revision | `c859a626356b0fee939c0c7cfe4b462edd3d694a`, local branch `main` |
| Meeting | `D:\projects\namespace_isolation\eBPF & Cilium for Windows - Office Hours.vtt` |
| Transcript SHA-256 | `B22AC004882E76827FA7E67621A09AECDEF0E159494C7C8F1114DD31D7789D5B` |

The latest PR text is the normative feature contract for this design. Review
comments and meeting suggestions explain intent but are not all accepted
requirements. This matters because some comments suggest mutually incompatible
pinning behavior.

### 2.1 Meeting findings that affect the implementation

Times below refer to the local VTT, not wall-clock meeting dates. The transcript
contains transcription errors: references to "good/grid" generally mean GUID,
"actor/actual" generally mean IOCTL, and "SDK" often means security descriptor.
The explanations here are interpretations supported by the code, not literal
technical quotations.

| Time | Relevant discussion | Design treatment |
|---|---|---|
| 06:54-09:42 | Same-privilege applications, GUID secrecy, possible all-namespace diagnostics | No claim of protection from hostile administrators. All-namespace discovery is deferred, not silently implemented. |
| 09:43-13:01 | A service wants non-admin map lookup/update; object-handle delegation is suggested | Orthogonal ACL/capability work, not solved by selecting a GUID. |
| 23:19-27:46 | Real filesystem and BFE object/container security are alternatives | Neither is required to implement the PR. |
| 27:45-29:14 | Avoid throwing namespace work away when per-object security arrives; namespaces are discovery filtering | Pass an explicit internal request context reusable by the ACL work. |
| 32:02-38:22; 40:25-43:31 | Per-process setting, possibly stored on the file object obtained from a WDF request | Preserve the behavioral goal, but fix the multiple-control-handle gap described in section 5. |
| 43:34-45:05 | A shared namespace SD would need a defined shared lifetime | Do not introduce namespace SDs or first-creator ownership in this design. |
| 48:26-50:33 | User SID cannot distinguish different vendors running under the same identity; both direct and brokered callers exist | GUID selection is not token authorization. Cover both calling arrangements in tests and integration guidance. |
| 52:12-53:10 | Namespaces first, security later; clarify consumer requirements | Preserve the separation; unresolved product requirements are listed in section 15. |
| 53:10-56:41 | Old FDs continue to work; filtering at open/enumeration time, not each map operation | Preserve R6. Do not add a current-namespace check to generic handle resolution. |
| 54:23-54:48 | A pin path alone is insufficient across namespaces | Composite pin key for lookup, deletion, insertion, and enumeration. |
| 57:26-59:31 | Many file objects can reference one BPF object; requirements are behavioral | Store namespace ownership on the core object, not independently on each handle. |

### 2.2 Material PR discussion

- Pin partitioning and the "enumerate says absent, insert says collision" problem:
  [discussion_r2114785527](https://github.com/microsoft/ebpf-for-windows/pull/4424#discussion_r2114785527),
  [discussion_r2114886593](https://github.com/microsoft/ebpf-for-windows/pull/4424#discussion_r2114886593).
- Cross-namespace map reuse was questioned and the author favored disallowing it:
  [discussion_r2114877829](https://github.com/microsoft/ebpf-for-windows/pull/4424#discussion_r2114877829).
  Section 8 makes this a proposed additional graph invariant, not a new reading
  of R6.
- Namespace discovery and netsh usability:
  [discussion_r2175442000](https://github.com/microsoft/ebpf-for-windows/pull/4424#discussion_r2175442000),
  [discussion_r2190478246](https://github.com/microsoft/ebpf-for-windows/pull/4424#discussion_r2190478246).
- netsh/bpftool parity:
  [discussion_r2175443919](https://github.com/microsoft/ebpf-for-windows/pull/4424#discussion_r2175443919).
- A later automated suggestion permits pinning a foreign handle in the current
  namespace:
  [discussion_r2755840313](https://github.com/microsoft/ebpf-for-windows/pull/4424#discussion_r2755840313).
  Do not adopt that suggestion without changing the contract: a pin lookup in B
  would otherwise return an object whose immutable namespace is A, contradicting
  R4. This design rejects cross-namespace pin insertion.

## 3. Requirements and acceptance traceability

| PR requirement | Implementation rule | Required evidence |
|---|---|---|
| R1: Exactly one namespace GUID per BPF object at creation | Initialize `ebpf_core_object_t.namespace_id` before publishing the object in the ID table; immutable afterward | G01, G02, G10 |
| R2: Default is `GUID_NULL` | A process with no entry reads as the null GUID; setting null explicitly resets selection | G01, G03 |
| R3: ID lookups return only matching namespace | Filter referenced ID lookup, next-object discovery, and sorted next-ID enumeration | G04 |
| R4: Pin lookups return only matching namespace | Resolve composite key; require object namespace to equal pin namespace | G05 |
| R5: Same path may exist in multiple namespaces | Namespace is part of hash identity, not merely an after-lookup filter | G05, G06 |
| R6: Existing handles remain valid after a switch | Handle-to-object resolution does not compare current namespace; object remains unchanged | G07 |
| R7: Switching changes subsequent operations, not objects | Publish one atomic process selection; snapshot once per kernel request | G02, G08 |
| R8: Management requires existing management privileges | SET uses the driver's current privileged-subject policy in addition to the device DACL | G09 |
| R9: Unmodified applications use default namespace | Old request layouts/opcodes remain unchanged; missing selection means null | G01, G12 |

| PR acceptance criterion | Test mapping |
|---|---|
| AC1: A cannot enumerate/open B's IDs | G04 |
| AC2: A cannot resolve B's pin | G05 |
| AC3: Identical paths can coexist | G05, G06 |
| AC4: New objects inherit new selection | G02, G10 |
| AC5: Existing handles continue working | G07, G11 |
| AC6: No namespace calls preserves old behavior | G01, G12 |
| AC7: Unprivileged SET fails with access denied | G09, including a duplicated control handle |

## 4. Current implementation: exact seams

All code paths in this document are relative to the repository root. Line
numbers describe the pinned code baseline; locate symbols again after rebasing.

| Surface | Existing location and behavior | Required change |
|---|---|---|
| Transport caching | `libs\api_common\device_helper.cpp:29-31,94-112`: TLS sync handle, global async handle | Do not treat either cached handle as authoritative process selection |
| IOCTL transport | `libs\api_common\device_helper.hpp:88-186`: `invoke_ioctl` selects sync/async device and sends one buffered IOCTL | Add public SET/GET and internal rollback-aware transport; ordinary discovery requests need no GUID field |
| Device creation | `ebpfcore\ebpf_drv.c:653-725`: `WdfControlDeviceInitAllocate`, no create callback, file-close callback | Capture caller state before queueing; give pending requests a real WDF queue association and owned context; preserve file-close semantics |
| Authorization | `ebpfcore\ebpf_drv.c:32-46,840-865,936-942` | Reuse actual Admin/SYSTEM/ebpfsvc policy for SET; not a check for a token-elevation boolean |
| Dispatch | `libs\execution_context\ebpf_core.c:2760-2815,2932-3006,3076-3250` | Thread explicit request context through dispatch and affected handlers |
| Wire schema | `libs\execution_context\ebpf_protocol.h:10-59`; `libs\ioctl_spec\EbpfProtocol.3d:40-67` | Append SET/GET opcodes; update both schema and C layout assertions |
| Object publication | `libs\runtime\ebpf_object.h:154-174`; `libs\runtime\ebpf_object.c:194-259` | Add immutable GUID and supply it before ID table insertion |
| ID discovery | `libs\runtime\ebpf_object.c:368-507` | Extend filters with namespace; retain existing epoch/refcount rules |
| Pin identity | `libs\runtime\ebpf_pinning_table.c:25-88,116-225,229-335,338-429` | Composite key and namespace-aware filtering/cursors |
| Pin entry points | `libs\execution_context\ebpf_core.c:1317-1405` | Pass caller snapshot; foreign insert fails; unpin is path-only |
| IDs and pin enumeration | `libs\execution_context\ebpf_core.c:1768-1999` | Scope old and new enumeration paths, including bulk pinned-map information |
| Handle creation/reference | `libs\runtime\kernel\ebpf_handle_kernel.c:25-148` | Retain object namespace; do not add namespace gates on existing handles |
| Handle close | `ebpfcore\ebpf_drv.c:815-820`; `libs\execution_context\ebpf_core.c:3285-3298` | `FsContext2` is already the BPF/base-object pointer; do not overwrite it with a GUID allocation |
| Object creation | `libs\execution_context\ebpf_maps.c:3775-3905`; `ebpf_program.c:1346-1516`; `ebpf_link.c:254-330` | Propagate creation attributes to every object constructor |
| Native loading | `libs\execution_context\ebpf_core.c:602-739`; `ebpf_native.c:95-104,1384-1420,2460-2650` | Snapshot the object-creation load request; preserve namespace through map reuse and rollback |
| JIT/interpreter | `libs\execution_context\ebpf_core_jit.c`; `libs\service\api_service.cpp`; `rpc_interface\rpc_interface.idl:19-63` | Use already created object's namespace on service-side operations; system-handle RPC is not the original caller's current process |
| Implicit link discovery | `libs\execution_context\ebpf_core.c:1461-1588` | Filter attach-data/program-matching detach by caller namespace |
| Shutdown | `libs\execution_context\ebpf_link.c:664-695` | Explicit internal all-object traversal, not namespace-filtered user discovery |
| User pin caches | `libs\api\api_internal.h:62-71`; `ebpf_api.cpp:1702-1780,3640-3745`; `libbpf_link.cpp:23-81` | Qualify pin bookkeeping by namespace; no path-only rollback after a switch |
| Tools | `tools\netsh\dllmain.c:34-244`; `libs\ebpfnetsh\*.cpp` | SET/GET namespace commands, resource help, command registration and parity work |

The source has a stale comment mentioning LocalService near device initialization.
The actual SDDL grants ebpfsvc's service SID, Builtin Administrators, and SYSTEM,
not arbitrary LocalService processes. Do not broaden it while implementing this
feature.

## 5. Namespace selection: process state versus file-object state

### 5.1 Why file-object-only state is insufficient here

The meeting suggests `WdfRequestGetFileObject` followed by a GUID in file context.
That is a useful request-plumbing technique, but not a complete implementation
of the current contract:

1. Thread T1 and T2 obtain independent synchronous file objects today.
2. The async file object is a third independent open.
3. Updating T1's GUID leaves T2 and async work in a different namespace.
4. A direct `CreateFile` creates another file object not known to the DLL.
5. `DuplicateHandle` shares a file object across processes; its GUID would
   otherwise accidentally become another process's "current namespace."
6. Closing/reopening a transport handle would reset selection before process
   exit, contrary to the specified persistence.

If the project chooses strictly per-open/session semantics instead, it can avoid
the process registry, but that requires an explicit PR contract change. Do not
quietly label that implementation per-process.

### 5.2 Recommended process-state registry

Add a small runtime module, provisionally `libs\runtime\ebpf_namespace.{h,c}`,
and a Windows-specific process-identity/lifetime adapter. This module is for
process selection, not a registry of namespace objects.

Conceptual private structures:

```c
typedef struct _ebpf_namespace_process_state
{
    // Private refcount, referenced process identity, lock and teardown state.
    GUID current_namespace;
    uint64_t generation;
} ebpf_namespace_process_state_t;

typedef struct _ebpf_request_context
{
    GUID namespace_id;          // Immutable snapshot for this request.
    uint64_t namespace_generation;
    // Referenced requestor and validated caller/security context as needed.
    // Future ACL work can add an authorized endpoint/object reference.
} ebpf_request_context_t;
```

These are proposed internal types, not public/wire layouts. Use repository
reference/rundown and lock primitives rather than copying this sketch verbatim.

Registry rules:

- Key entries by a referenced process identity, or a process-start-key plus an
  appropriate referenced process object. Never key only by a reusable PID.
- Reads for processes with no selection return `GUID_NULL` without allocating.
  SET creates or updates an entry. Allocation failure returns `EBPF_NO_MEMORY`;
  it must not report success or silently reset to null.
- Use a registry lock for membership and a short entry lock for a coherent
  16-byte GUID copy and generation. Do not assume a GUID write is atomic.
- Register supported Windows process-exit notification before accepting
  requests. At exit, mark/remove the entry under synchronization, prevent late
  insertion for an exiting requestor, then drop the registry reference.
  Requests already holding a state/reference may finish with their snapshot.
- The capture path and exit callback must share the membership synchronization
  and check exiting state; a deferred request must not recreate a removed entry.
  Requests hold captured identity, never rediscover state by a stale PID.
- Keeping a reference to `EPROCESS` alone does not provide the required cleanup:
  it can keep an exited object alive. Explicit exit removal is required.
- Register/unregister callbacks and drain request rundown during driver
  initialization/unload failure handling. Callback registration failure fails
  feature/driver initialization, not fallback to weaker session semantics.
- Process exit removes selection only. It does not delete pins, detach links, or
  destroy objects still referenced by other owners.
- New child processes start at null; do not infer namespace inheritance from a
  duplicated transport handle. Explicitly selecting the GUID is supported.
- A namespace itself has no create/delete API, refcount, owner, or SD. Empty
  selection entries are process state, not evidence that a namespace "exists."

The kernel adapter uses `PsSetCreateProcessNotifyRoutineEx`. The image containing
the callback must have `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`, set by the
linker's `/INTEGRITYCHECK` option. Otherwise registration returns
`STATUS_ACCESS_DENIED`; because registration is mandatory, core initialization
must fail and unwind, not silently disable process cleanup. Apply the linker
option in every supported driver configuration. Verify the actual built PE
header, not just a project property, and run initialization with the signed
candidate on the supported kernel-test images. This flag does not replace normal
driver-signing/deployment requirements. See the
[Windows registration contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex).

### 5.3 Request capture and execution context

Use `WdfDeviceInitSetIoInCallerContextCallback` / `EvtIoInCallerContext`, or an
equivalent proven caller-context path, to obtain the real requestor process.
Validate requests at PASSIVE_LEVEL where Windows handle/security work requires
it. Do not use whatever process happens to be current on a queue worker.

Separate requests that complete synchronously from operations that can pend:

- Synchronous requests may execute and complete in caller context. Resolve input
  handles and create returned handles in that original process.
- For pending-capable requests, perform validation, effective-subject
  authorization, namespace capture, and input-handle referencing in caller
  context. Store the immutable snapshot, referenced objects, and completion/
  cancellation state in owned WDF request context, then call
  `WdfDeviceEnqueueRequest`. The queue handler consumes this prepared context;
  it must not recapture the worker's namespace/token or resolve numeric handles
  in the worker's handle table. Fully initialize the context before enqueueing:
  delivery may occur inline, so the caller callback must not access the request
  or its context after a successful ownership handoff.
- Do not dispatch an async handler that enables cancellation directly from
  `EvtIoInCallerContext` before enqueueing. At that point the request has no
  queue association. KMDF rejects `WdfRequestMarkCancelable`,
  `WdfRequestMarkCancelableEx`, and `WdfRequestUnmarkCancelable` on such requests;
  switching to the Ex API alone does not solve this.
- A queued operation that returns newly created user handles needs an explicit
  original-process handle-delivery mechanism before it is moved off caller
  context. Initially keep such creation operations synchronous; do not rely on
  a queue handler happening to run inline in the submitter's thread.

Use the shared validated dispatch logic without retaining assumptions that a
queue worker is the original caller. Pending paths need prepared, referenced
objects rather than the old raw-handle lookup path. Queue configuration must not
permit an unprepared namespace-sensitive request to bypass capture. If future
guaranteed-forward-progress settings bypass the caller callback under memory
pressure, explicitly reject an unprepared request or provide a separately proven
capture path; never substitute worker state.

Pass `const ebpf_request_context_t*` through
`ebpf_core_invoke_protocol_handler`, its dispatch function signatures, and
namespace-dependent helpers. No ambient TLS GUID in core code. A request's GUID
is copied by value; async operations retain any needed references until complete
or cancel, not pointers into a dispatch stack.

Pending-request ownership follows these transitions:

1. **Captured:** the caller callback owns prepared context. Validation/capture or
   enqueue failure completes the request and releases each acquired reference.
2. **Queued:** KMDF owns cancellation. Register `EvtIoCanceledOnQueue` where
   needed to release captured resources and complete a canceled queued request.
3. **Driver-owned:** after dequeue, initialize and publish the cancellation
   context before arming `WdfRequestMarkCancelableEx`. Synchronize registration,
   cancel, and normal completion. Handle `STATUS_CANCELLED` explicitly; a
   successful reference alone is not proof cancellation registration succeeded.
4. **Terminal:** exactly one completion/cancellation path completes the request
   and releases its context/object references. Handle
   `WdfRequestUnmarkCancelable` returning `STATUS_CANCELLED` by deferring to the
   established cancellation owner, not double-completing. No callback may run
   after its context is freed.

Define these transitions for each pending protocol handler, including
notification subscription and test-run paths. A request queued before process
exit may finish/cancel using its captured values; it must not recreate registry
membership for the exited process. Prove cancellation before enqueue, while
queued, during registration, while pending, and racing completion on real KMDF
with framework verification enabled. Usersim's synchronous queue and simplified
cancel implementation are not proof of KMDF request ownership.

Authoritative contracts:
[caller-context callback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfdevice/nc-wdfdevice-evt_wdf_io_in_caller_context),
[cancel registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nf-wdfrequest-wdfrequestmarkcancelableex),
and [framework queue checks](https://github.com/microsoft/Windows-Driver-Frameworks/blob/b6191d9543441329154da32f7ab9bdd97228dd3c/src/framework/shared/core/fxrequestapi.cpp#L3448-L3453).

Read/set linearization:

- SET publishes `(GUID, generation)` under the process-entry lock.
- Each other namespace-sensitive IOCTL snapshots under that lock exactly once.
- An overlapping operation uses entirely the old or entirely the new value.
  SET does not retroactively change a pending request.
- Requests initiated after a successful SET returns see the new selection,
  including on other threads and through the async transport.
- Trusted kernel teardown has a distinct internal API, not a user-provided
  `all_namespaces` flag or a null context interpreted as an authorization bypass.

## 6. Public API and wire contract

Keep the PR signature and add a query needed by tooling:

```c
ebpf_result_t ebpf_set_namespace(_In_ const GUID* namespace_guid);
ebpf_result_t ebpf_get_namespace(_Out_ GUID* namespace_guid);
```

Both names here are proposed additions. Declare them in `include\ebpf_api.h`,
export in `ebpfapi\Source.def`, and implement in `libs\api\ebpf_api.cpp`.
Null pointer arguments are invalid; `GUID_NULL` is a value, not a null pointer.
The getter returns only the calling process's GUID.

Never renumber existing operations or insert entries in the middle. The local
implementation has already appended operations 46-49. Their layouts below
describe that implementation, not the additional pin-incarnation protection
required by this revision:

```text
46 SET_NAMESPACE request: header, GUID namespace_id; no reply
47 GET_NAMESPACE request: header; reply: header, GUID namespace_id
48 DELETE_PINNING_IF_MATCHES request: header, expected HANDLE, path bytes; no reply
49 LOAD_NATIVE_PROGRAMS_EX request: header, module GUID
   reply: legacy native prefix, map HANDLEs, program HANDLEs,
          one ownership byte per map, captured namespace GUID
```

Use compiler-checked C layouts, not a presumed packed 18-byte GUID message.
Headers are currently 8 bytes on x64 MSVC; their ID enum is 4 bytes. Preserve
`uint16_t` message-length limits.

### 6.1 Native ownership metadata and compatibility

The legacy operation 32 (`LOAD_NATIVE_PROGRAMS`) uses a 24-byte x64 request
(header plus module GUID). Its reply has a 24-byte prefix: header at offset 0,
`size_t program_handle_count` at offset 8, `size_t map_handle_count` at offset 16,
then map HANDLEs followed by program HANDLEs. Keep that contract unchanged.

Operation 49 uses the same request/prefix. For M maps and P programs, the x64
reply is exactly `40 + 9*M + 8*P` bytes: the prefix and handles, M ownership
bytes (`NONE=0`, `CREATED=1`, `REUSED=2`), then the captured 16-byte creation GUID.
Validate the header ID/length, transport byte count, expected counts, ownership
values, and checked size arithmetic before using metadata. The GUID is the
creating request's snapshot, never a later GET or client-supplied override.

This metadata allows a client to distinguish created pins from reused pins
after kernel success, including failure to wrap an fd or query map metadata.
However, operation 49 has no insertion cookies: it cannot satisfy the revised
same-object re-pin guarantee in section 7.3. Operation 48 is likewise only an
object-identity comparison. Neither may be presented as incarnation-safe.

### 6.2 Incarnation-safe internal protocol additions

Append these new internal operations after the current 0-49 range. Values 50-52
are the assignments for this design revision; check the enum at implementation
time before allocating them if another change has extended it. Do not silently
change the layout of 48 or 49 to require clients to guess which version ran.

| Opcode / name | Request | Reply / rules |
|---|---|---|
| 50 `UPDATE_PINNING_EX` | Existing pin-insert layout: header, object HANDLE, canonical path bytes | Header plus a nonzero `uint64_t pin_cookie`; x64 reply length 16. Insert only; invalid-handle unpin sentinel is rejected. Validate reply capacity before mutation. |
| 51 `DELETE_PINNING_IF_MATCHES_EX` | Header, expected HANDLE, `uint64_t pin_cookie`, canonical path bytes | No reply. On x64 the path begins at offset 24. Cookie zero is invalid. Under the pin lock compare namespace, path, expected object, and cookie before removing. |
| 52 `LOAD_NATIVE_PROGRAMS_EX2` | Header plus module GUID; x64 request length 24 | Native prefix, map HANDLEs, program HANDLEs, M ownership bytes, M `uint64_t` cookies, captured creation GUID. Exact x64 length `40 + 17*M + 8*P`. |

Operation 52 returns a nonzero cookie only for `CREATED`; `NONE` and `REUSED`
must have zero cookies and never authorize rollback deletion. Variable-length
cookie bytes may be unaligned: copy/decode them with schema-safe access, not
unchecked `uint64_t*` casts. All length calculations use checked arithmetic.
Use schema/layout assertions on every supported architecture rather than
assuming the x64 prefix/count widths elsewhere.

Mark 50/51 as all-modes privileged operations, like internal conditional cleanup;
52 is native-mode privileged. These operations do not expose an arbitrary
namespace selector. Derive conditional deletion's namespace from the held
expected object's immutable ownership. Reject malformed or short requests/
replies explicitly. Validate native reply capacity and allocate all kernel
reply/ownership storage before creating or transferring objects.

Allocate user-mode handle arrays and rollback records before dispatch. On a
complete, validated success reply, retain all returned raw HANDLEs and receipts
until wrapping/metadata initialization succeeds. If a later step fails, delete
only `CREATED` receipts with operation 51, then close every still-owned raw
HANDLE/fd exactly once. Reused pins and later pin incarnations survive. If a
malformed reply makes ownership unverifiable, report the protocol/cleanup
failure explicitly; do not guess ownership or claim rollback succeeded.

Compatibility and fallback:

- Old DLL/new driver keeps unchanged operation 32/default workflows.
- New DLL on a pre-namespace driver may use the legacy default-only path only
  when the new operation and GET_NAMESPACE both return unsupported. Retain the
  historical legacy reply handling: old operation-32 servers may leave
  `reply.header.length` at 24 while returning the complete handle payload.
  Validate transport byte count/counts for that legacy path; do not impose the
  extended header contract on it. This preserves legacy behavior, not the new
  incarnation-safe rollback guarantee.
- If GET_NAMESPACE succeeds but 50 or 52 is unsupported, fail the affected
  rollback-requiring high-level sequence as unsupported before its first pin
  insertion or native-program object creation. Unwind any preliminary native
  module/authorization resources normally. Do not silently use 48/49 and claim
  the stronger guarantee, even when the current selection happens to be null.
- Implement/publish 50-52 together as one internal protocol capability. Do not
  partially deploy a creator that returns receipts without their deletion path.
  Capability checks, if added, must be side-effect-free.
- Never fall back on access denied, blocked-by-policy, invalid lengths, malformed
  metadata, or another operational failure. Unsupported probing is not
  authorization.

### 6.3 Authorization, generation, and public compatibility

Mark SET `PROTOCOL_ALL_MODES | PROTOCOL_PRIVILEGED_OPERATION`. Gate GET with
the same management policy initially for consistency and to avoid adding
unprivileged transport access; this is stricter than a future low-privilege
self-query might require. The effective policy is the existing `SeAccessCheck`
against the driver's privileged SD, not "is LocalSystem only" or an invented
privilege name. Run it for each management request, including a duplicated
control handle.

Update together:

- `ebpf_protocol.h` and `_ebpf_protocol_handlers`, including dispatch bounds.
- `libs\ioctl_spec\EbpfProtocol.3d`: maximum opcode and exact body constraints.
- `ebpf_protocol_layout_check.h`: sizes/offsets and opcode assertions.
- Regenerated committed `libs\ioctl_spec\generated\*` via existing tooling.
- User-mode mocks, usersim request capture, direct core-call tests, and fuzzer
  inputs for every new opcode. The original baseline validator ended at 45;
  extend its bounds for the implemented protocol revision, not just SET/GET.

Old DLL/new driver uses null until a namespace is explicitly selected in that
process. New DLL/old driver returns `EBPF_OPERATION_NOT_SUPPORTED` for SET/GET;
do not turn that into apparent success. Ordinary old operations remain usable
in the default namespace. Version probing is not authorization.

## 7. Core algorithms

### 7.1 Object creation and immutability

Add `GUID namespace_id` to `ebpf_core_object_t`, not `ebpf_base_object_t`.
The latter also represents native-module and other reference-counted entities
that are not BPF maps/programs/links. Do not use the C++ keyword `namespace` as
the member name.

Introduce an internal creation-attributes argument containing the namespace.
Thread it through map, program, and link constructors to
`EBPF_OBJECT_INITIALIZE` / `ebpf_object_initialize`. Initialize the GUID before
the ID table publication at `ebpf_object.c:234-239`. Assigning it after a
constructor returns creates an enumeration race.

Every constructor must specify attributes explicitly. Unit-test-only helpers
may construct null attributes; production code must not silently default an
omitted context to null. A link created by a request inherits that request's
namespace; a map template synthesized during a load inherits the same captured
creation context.

Keep object IDs globally unique using the current allocator. An ID does not
become a pair exposed to libbpf. Filtering is sufficient for R3; reusing numeric
IDs independently per namespace would needlessly change references, info
structures, map contents, and Linux compatibility.

### 7.2 ID lookup and enumeration

Extend the namespace-sensitive internal APIs with an explicit GUID argument:

```text
ebpf_object_reference_by_id(id, type, namespace, ...)
ebpf_object_reference_next_object(previous, type, namespace, ...)
ebpf_object_get_next_id(start_id, type, namespace, ...)
```

The public-facing API remains implicit from the request snapshot as required
by the proposal; explicit parameters are an internal implementation detail.

Algorithm for reference-by-ID:

1. Enter the existing epoch-protected path and find the ID entry.
2. Check live object, expected type, and GUID equality.
3. Use the existing try-acquire-reference operation before returning the
   object. A concurrently dying entry behaves as absent.
4. A namespace mismatch returns the same `EBPF_KEY_NOT_FOUND` result as a missing
   candidate. Do not return the foreign GUID.

For sorted next-ID, add GUID to the existing type filter context. Start IDs
need not exist, so do not first resolve the cursor through a scoped lookup.
Skip hidden/dead entries and continue; do not stop at the first foreign entry.
Return `EBPF_NO_MORE_KEYS` only when no matching candidate remains, retaining
existing NTSTATUS/Win32 enumeration-end mapping.

`ebpf_object_reference_next_object` is also used for global shutdown. Split out
a clearly named, private unscoped traversal for teardown. Do not let a scoped
default leave links in other namespaces attached during unload.

`ebpf_object_pointer_by_id` is a non-owning internal API. Audit its actual
callers/function-pointer exposure at implementation time. Keep trusted
already-bound data-plane references independent of the current process; never
route user ID discovery through an unscoped pointer helper.

### 7.3 Pin key representation

Filtering the result of today's path-only table cannot satisfy R5. Store a
contiguous, owned internal key:

```text
internal key bytes = binary GUID (16 bytes) || canonical path bytes
logical key length = 16 + path byte length
```

Use an explicit byte sequence; do not hash a structure containing a GUID,
padding, length, and a pointer. The pin table already has an extract callback,
so extend the private pin entry/key representation to provide these bytes.
The extract callback reports length in bits, as it does today. Check
addition/multiplication overflow.

Keep the displayed/returned `path` separate from the namespace prefix. It may
alias the owned key's path tail if freeing and snapshot-copy ownership are
unambiguous. Enumerated output entries still own their duplicated visible
path and referenced object. Do not expose binary prefixes as pin strings.

Rules:

- Validate/canonicalize visible paths exactly as today. Apply
  `EBPF_MAX_PIN_PATH_LENGTH` to the path, not the larger internal key.
- Insert requires `object.namespace_id == request.namespace_id`; otherwise
  `EBPF_INVALID_ARGUMENT`. This does not invalidate the old handle.
- Insert-only conflict is per composite key and returns the existing
  already-exists error.
- Assign every successful insertion a nonzero `uint64_t pin_cookie` under the
  table lock. Allocate it from a driver-lifetime monotonic counter, not an
  object ID, pointer, or per-path counter that resets after deletion. Reject
  counter exhaustion explicitly before publication; do not wrap/reuse a cookie.
  The cookie is separate from the key, namespace generation, and public object
  metadata. Preserve it until this specific entry is deleted.
- Internal creation paths record a receipt `(namespace, canonical path,
  referenced expected object, pin_cookie)`. Rollback compares all four under
  the same table lock. A deleted entry reinserted with the same object receives
  a different cookie, so old cleanup cannot delete it. Object comparison alone
  prevents replacement-object deletion but does not prevent this same-object
  remove/reinsert (ABA) race.
- Every user-mode insertion that may need later rollback uses operation 50 from
  the start. Never insert with the old operation and then query the current pin
  to reconstruct a receipt: replacement may already have occurred. Ordinary
  pin insertion without later rollback may retain the legacy request layout.
- Find and delete construct the composite key from the request snapshot.
  Unpin of A's path while in B deletes B's entry if B has one, or returns
  missing. It cannot delete A's entry.
- Enumerate and bulk map-info snapshot paths filter namespace before counting
  and allocating visible output. Do not use a global key count truncated to
  `uint16_t` as the visible namespace count; bound/report overflow explicitly.
- Sorted path iteration compares namespace first and path bytes second, with
  a filter for the requested namespace/type. The input cursor is an arbitrary
  path in that same namespace, including a path that has since been deleted.
- Free/unload walks all entries with an internal unscoped deletion path. It
  must not depend on the unloading thread's selected namespace.
- Preserve reference counts and `pinned_path_count`: increment once after a
  successful insertion, decrement once after a successful deletion.

The same visible path in A and B is therefore independent for insertion,
lookup, unpin, map-info enumeration, and sorted next-path iteration.

Retain object-only compare-and-delete for callers that intentionally mean
"remove the current pin if it names this object"; it is not a creation receipt.
Public path-only unpin retains its existing current-namespace semantics.
Driver unload clears pins and invalidates their object handles, so cookies need
not persist across driver lifetimes. No namespace-wide cookie-discovery API is
introduced.

### 7.4 Handles and name-based mutation

Keep `EBPF_OBJECT_REFERENCE_BY_HANDLE` namespace-neutral. A valid fd/HANDLE
still permits its existing operations subject to existing privileges (and,
when implemented, ACL grants). Obtaining object info through an old handle
also continues to work. This is not an accidental hole; it is R6.

Path-based unpin and attach-data-based detach are not direct-handle
capabilities and must be scoped. Specifically filter
`_ebpf_core_find_matching_link`. Explicit link-handle detach continues working
after a switch.

Do not overwrite `FILE_OBJECT.FsContext2`: it currently holds a base-object
pointer that `_ebpf_driver_file_close` passes to `ebpf_core_close_context`.
A future typed file context should use an additional owned field/context and
preserve exactly-once object release.

## 8. Cross-object relationships and map reuse

**Proposed additional policy, requiring maintainer signoff:** Newly created
object relationships must join objects in the same immutable namespace. This
follows the author's map-reuse discussion but is not explicitly enumerated in
R1-R9. It is preferable to silently allowing a new B program to obtain A maps.

Apply comparisons at relationship establishment, not on every data-plane
operation:

| Relationship | Enforcement seam |
|---|---|
| Program's resolved maps, including JIT service operations | `ebpf_program_associate_maps`, `ebpf_map_associate_program`, resolve-map path |
| Additional bound map | `ebpf_program_associate_additional_map` / BIND_MAP |
| Map-in-map template | `_associate_inner_map` before accepting a template handle |
| Outer-map entry containing another map/program | Array/hash `*_update_*_with_handle` before committing the value object |
| Link to program | `ebpf_link_attach_program`, after link creation attributes are set |
| Native auto-reuse and nested template validation | Namespace-aware pin/ID helpers using the native load snapshot |

For two valid supplied handles with mismatching namespaces return
`EBPF_INVALID_ARGUMENT`; there is no need to reveal any GUID. Reject before
committing references or partially changing association state.

Old A map read/update/delete via an A handle while current selection is B
still succeeds. A-to-A association using held objects can remain valid where
no new B object is created. Creating a B link to an A program or binding an A
map to a B program fails. Explicitly test this distinction so R6 is not
mistaken for permission to create arbitrary cross-namespace graphs.

For auto-pinned map reuse, identical visible paths in A and B independently
create/reuse their own maps. A missing pin is the only condition that permits
create-new fallback. Propagate access, memory, and validation errors instead
of treating every failure as absence. The current user-mode
`_ebpf_object_reuse_map` treats all get failures as success
(`ebpf_api.cpp:3640-3653`); tighten this as part of namespace/ACL-aware reuse.

## 9. Multi-step loading, rollback, and service calls

### 9.1 Native loading

The native module is a reference-counted code container, not itself a map,
program, or link. Snapshot namespace on the native-program creation request that
actually creates maps/programs. Pass it through
`ebpf_native_module_instance_t`, map/program creation, template lookup,
automatic pinning, and error cleanup.
Use operation 52 for the revised rollback guarantee; retain operations 32/49
only with their explicit compatibility limitations in section 6.

Keep the shared module's authorization/hash and module GUID separate from the
BPF namespace GUID. Do not assume a module GUID is a namespace or that native
module discovery is a libbpf object-ID lookup.

Preserve the current module loading state machine. This design does not promise
simultaneous repeated loads of a single initialized native module in several
namespaces; the baseline can reject an already loaded/loading module. Independent
module instances supported by the existing loader must nevertheless receive the
correct namespace for every object they actually create.

Native rollback must delete precisely `(captured namespace, recorded path,
expected object, pin_cookie)`, not a path in the thread's current namespace.
Track every newly created automatic pin in the native instance, and carry its
receipt through both in-kernel unwind and the operation-52 reply. Reused maps
have no rollback-owned cookie. If a pin is removed and replaced by Y, or removed
and reinserted with the same X, cleanup must preserve the newer insertion.
Retain the expected object and receipt until cleanup finishes.

Both failure boundaries require this ownership: partial failure inside the
kernel load, and kernel success followed by user-mode wrapping/metadata failure.
Do not reconstruct ownership by looking up the current path or inspecting a
later selected namespace. Update the native cleanup helper itself as well as
the user-mode transport; changing only the IOCTL wrapper would miss kernel
unwind. The original baseline's path-only cleanup and the local implementation's
object-only conditional cleanup do not satisfy the revised ABA guarantee.

### 9.2 JIT/interpreter and RPC

Program creation occurs in the original process; service-side resolution and
code load operate on marshaled handles. `rpc_interface.idl` uses
`system_handle(sh_file)` for file handles. `ebpfsvc` is a different process,
and its TLS/global control handles must not redefine an existing program's
namespace.

Use the program/map objects' immutable namespaces for association checks.
Do not set ebpfsvc's process-wide namespace temporarily to serve a client:
concurrent RPC calls would race. If a future service operation creates new
objects, pass a trusted, kernel-validated creation context, not an unchecked
client GUID or ebpfsvc's default selection.

### 9.3 High-level API synchronization and pin caches

A kernel IOCTL is the namespace snapshot boundary. A high-level
`bpf_object__load` comprises several IOCTLs, not a transaction.

Add one library-level shared/exclusive namespace-operation guard:
high-level namespace-dependent loads/pin sequences hold shared ownership;
SET holds exclusive ownership. Acquire it once in outer entry points and
pass context to internal helpers to avoid recursive-lock deadlocks.
This prevents SET through the same library instance from switching mid-load.
It does not cover the interval between a caller's SET and entry to that load:
`T1 SET(A); T2 SET(B); T1 load` consistently creates B objects. Same-namespace
graph checks cannot detect a load assigned wholly to the wrong intended tenant.
Nor is a module-local lock process-global across independently loaded SDK copies,
static API-library copies, or raw IOCTL callers.

A broker that switches selection must choose one of these supported patterns:

- Prefer one worker process per tenant, selecting once before tenant work.
- Otherwise every participating caller uses one application-owned process-wide
  mutex spanning **save selection -> SET tenant -> all dependent work and
  rollback -> restore selection**. Acquire that mutex before library entry,
  retain it across the separate SET and load calls, and restore on every exit.
  Every SDK instance, raw SET path, callback, and vendor wrapper must cooperate;
  an uncooperative component makes this pattern unsupported. A tenant task must
  not queue dependent work that outlives the mutex and then restore selection.

Lock order is application transaction mutex first, then the library's internal
shared/exclusive guard. Never try to upgrade a held shared library guard to SET;
reentrant SET from a guarded operation must fail explicitly rather than
deadlock. Restore failure is an error: stop serving tenant work until selection
is re-established, not a successful cleanup fallback. Shared brokers must not
advertise arbitrary concurrent tenant execution under this process-scoped API.

Raw SET outside these rules has only per-request snapshot consistency, not a
high-level transaction guarantee. Tests must distinguish the documented
unsupported interleaving from the application's serialized positive control.

Record namespace with auto-pin ownership and rollback records in user-mode
map/link bookkeeping. A cached `pinned` bit and path from A cannot mean "already
pinned in B." A public unpin invoked in B remains B-relative; internal cleanup
must use its captured creation namespace, expected object, and insertion cookie.
Use the receipt-returning pin/native operations and cookie-aware conditional
delete from section 6. Do not infer receipt ownership from a cached `pinned` bit.
Derive the key's namespace from that object's immutable ownership; do not accept
an arbitrary GUID as a general cross-namespace lookup escape. Do not mutate
process selection around rollback or accidentally cross namespace through a
general public pin lookup.

## 10. Tooling and administrator experience

### 10.1 netsh namespace commands

Implement the PR's `set namespace {GUID}` and `show namespace` in the eBPF
context. Registration belongs in `tools\netsh\dllmain.c`; implementations can
live in a new `libs\ebpfnetsh\namespaces.{h,cpp}`. Add project entries,
`tokens.h`, resource IDs and localized/help text in `tools\netsh` resources.
Update normal, original, and long command-table variants because this checkout
contains a netsh ABI-workaround path.

Accept canonical brace/hyphen GUIDs using Windows parsing and return explicit
invalid-GUID errors. Show only the current process's selection. Null is a valid
reset. State is not written to the registry, installed product configuration,
or the parent shell.

Example in ONE interactive process, once the feature is implemented:

```text
netsh
netsh> ebpf
netsh ebpf> set namespace {12345678-1234-4234-8234-123456789abc}
netsh ebpf> show namespace
netsh ebpf> show maps
netsh ebpf> show programs
```

An equivalent `netsh -f` script must perform selection and subsequent commands
inside the same invocation. Two independent `netsh ebpf ...` processes do not
share selection.

There is no platform-wide namespace-list API in this increment. Products
document/configure their application-to-GUID mapping. Do not claim namespaces
are secret while recommending a publicly documented GUID as an authorization
mechanism. An optional vendor subcontext can set/execute/restore using a guard
on every exit path; command inheritance alone supplies no enter/exit callback.
Because selection is process-wide, the wrapper must participate in the same
application transaction mutex across save/SET/execute/restore described in
section 9.3. Serializing only individual SET calls is insufficient. Wrappers
are not thread-local tenant contexts.

### 10.2 bpftool and feature parity

Keep bpftool's CLI unchanged and in `GUID_NULL`, as specified by the PR.
A separately launched bpftool process does not inherit a netsh process's
namespace. Do not add a hidden environment-variable override.

The current netsh command registration and `maps.h` show that namespace selection
alone would not replace all useful bpftool operations:

| Operation | Current netsh evidence | Namespace release treatment |
|---|---|---|
| Program list/load/delete | `programs.cpp` handlers | Make existing commands use scoped APIs |
| Program attach/detach/change attach options | `handle_ebpf_set_program` exists | Exercise supported set/add paths; compare attach-type coverage rather than assuming absent |
| Map list and pin/unpin | `maps.cpp` / `maps.h` | Scope existing commands |
| Map create, lookup, update, delete, next key, dump | No corresponding commands in `maps.h` or command table | Add namespace-aware commands for supported map types; implement dump with checked iteration |
| Link list | `links.cpp` | Scope existing command; add pin/unpin/detach coverage where supported |
| Pin list | `pins.cpp` | Scope both legacy and current enumeration protocols |
| Program test-run and additional bpftool commands | Not established as netsh commands by this inspection | Inventory supported Windows bpftool operations; implement namespace-relevant management gaps or explicitly defer with approval |
| BTF/feature/perf/profiling facilities | Presence upstream does not prove Windows API support | Do not promise unsupported Linux functionality |

Complete a checked command-by-command inventory against
`external\bpftool\src\{map,prog,link,main}.c` at the implementation baseline.
The inspected bpftool submodule commit was
`ee9e72612eef8f53e959ee4c646befcf47892a77`.

`netsh ebpf show processes` is special: `libs\ebpfnetsh\processes.cpp:68-166`
walks Windows process handles and duplicates them rather than using BPF object
enumeration. Label it as host-wide handle diagnostics, not namespace-scoped BPF
discovery. Do not print namespace GUIDs or present this output as evidence of
AC1 filtering. Restrict any future object-detail expansion to explicitly
scoped discovery; OS-level administrator inspection remains outside the
logical-partitioning guarantee.

## 11. Errors, compatibility, and observability

| Condition | Result |
|---|---|
| Foreign/missing ID or pin candidate | Existing missing-object/key result for that entry point; same outward mapping as a genuinely missing candidate |
| Enumeration exhausted | `EBPF_NO_MORE_KEYS` and existing enumeration-end translation |
| Same namespace, duplicate path | Existing already-exists result |
| Valid handle, foreign pin insertion or new cross-namespace relationship | `EBPF_INVALID_ARGUMENT` |
| SET denied | `EBPF_ACCESS_DENIED` / access denied, not unsupported or not found |
| Unsupported new opcode on old driver | `EBPF_OPERATION_NOT_SUPPORTED` |
| Malformed/truncated GUID message, bad length or pointer | Invalid argument; no state change |
| Allocation/overflow/cleanup failure | Explicit existing error, propagated and logged; no successful default fallback |
| Stale rollback cookie after deletion/reinsertion, including the same object | Missing-entry result; preserve the later insertion |
| Namespace-aware driver lacks required incarnation-safe operations | Unsupported before starting the affected rollback-requiring sequence; no unsafe extended-to-legacy fallback |
| Broker cannot restore its saved selection | Explicit failure; block subsequent tenant work until recovered |

Do not change public `bpf_*` signatures or append GUIDs to Linux-compatible
object-info structures. Namespace ownership is internal. Existing default
workloads preserve behavior; adding non-default objects intentionally removes
them from default discovery.

Use existing TraceLogging for operation/result and lifecycle failures.
Do not emit every namespace GUID on a public diagnostic channel or introduce
all-namespace counters as a discovery API. Log GUIDs only under an explicit
privileged diagnostic policy if later approved. A getter reveals the caller's
own selected GUID, not a foreign object's GUID.

No namespace checks are added to helper/data-plane map access. Object lookup
adds a GUID comparison; pinning adds 16 internal key bytes. Enumeration still
has the existing sorted-table scan costs, with extra filtering. Do not claim
measured zero overhead. Measure management lookup/enumeration and memory under
many namespaces; optimize only if justified.

## 12. Implementation slices and completion conditions

| Slice | Concrete work | Done when |
|---|---|---|
| N0: Contract lock | Confirm section 15 decisions; add failing behavioral tests | Tests distinguish process, thread, handle, and object scope |
| N1: Request/process state | Process identity/exit adapter, registry, request capture, SET/GET, schema regeneration, mocks, queue-associated pending-request lifecycle and integrity flag | Cross-thread and sync/async switching works; real KMDF cancellation and exit/driver-unload/fault tests pass; built PE flags verified |
| N2: Object creation | Creation attributes through all constructors before publication | Maps/programs/links and native/JIT paths have correct immutable GUIDs |
| N3: ID discovery | Scoped ID and next-object APIs, private teardown traversal, legacy detach | All ID types hidden across namespaces; global cleanup still sees all |
| N4: Pinning | Composite hash keys, insertion cookies/receipts, sorted iteration, bulk info, scoped deletion, refcounts | Same paths coexist; foreign unpin and stale receipts cannot delete another insertion, even of the same object; no leaks on failures |
| N5: Integration | Native ownership/cookie wire contracts, reuse/rollback, library guards and outer broker transaction mutex, caches, relationship invariants | No mixed/wrong-tenant load under supported synchronization, no incorrect rollback, and explicit old-driver compatibility limits |
| N6: Tools/ship | netsh commands/resources/parity, compatibility docs, real-kernel tests | Administrators can manage non-default objects without bpftool |

N2-N5 may be developed in a branch independently but must not ship partially
enforced discovery. In particular, filtering IDs without partitioning pins is
not an acceptable implementation of the PR.

## 13. Test specification

Add tags `[namespace]` and `[namespace_kernel]` as appropriate; these are new
tags, not claims about tests already present.

### 13.1 Behavioral coverage groups

G01-G18 are stable coverage groups. The detailed NU/ND cases below expand these
groups into unit and real-driver work items; a single test named after a group
does not establish all of its coverage.

| ID | Test and assertions |
|---|---|
| G01 | Null default: unmodified API app creates/enumerates/opens/pins all three object types exactly as before. Compare old APIs and raw IOCTLs. |
| G02 | Select A, create map/program/link; switch B; verify new objects B and original objects still A. No GUID mutation after publication. |
| G03 | Set null explicitly; independent process and child start null. Close/reopen sync/async transports and unload/reload DLL without resetting process selection. |
| G04 | A/B/default objects interleaved in global IDs. Test open-by-ID and next-ID for all types, foreign/nonexistent/deleted cursors and wrong type. Stop only after visible objects exhausted. |
| G05 | A and B pin `/same/path`; each resolves its own object. B cannot find/delete A-only path. Test all five pin helpers and both old/new next-path opcodes. |
| G06 | Duplicate path in A fails; A/B identical paths succeed concurrently. Exercise max path length, embedded NUL, canonical aliases, arbitrary/deleted cursor, bulk map-info counts and short buffers. |
| G07 | Open A object, switch B, continue map lookup/update/delete, object-info query, program query and explicit link-handle detach; object stays A. Cross-namespace pin insertion is rejected without invalidating the handle. |
| G08 | T1 SET while T2 uses its existing TLS handle, T3 opens a new handle, T4 uses global async. Test raw independent opens too. Barrier-controlled requests have one coherent snapshot; no torn GUIDs. Separately prove the broker's outer save/SET/work/restore mutex; per-load locking alone is not a tenant transaction. |
| G09 | Admin/SYSTEM/ebpfsvc policy positive cases; normal user and non-elevated/deny-only admin negative cases. Duplicate a management handle to a low-privilege process and verify SET still denies. Cover caller impersonation and requestor versus queue-worker context. |
| G10 | Native map/template/program auto-pin and reuse scoped to load namespace; JIT/interpreter service operations preserve caller-created objects. Test independent clients served concurrently; do not switch ebpfsvc global state. |
| G11 | Duplicate/inherit an object HANDLE into another process, wrap in a local CRT fd, and use it. Namespace does not change; passing a numeric fd alone is not handle transfer. Name/ID discovery stays scoped. |
| G12 | Existing `[platform]`, `[execution_context]`, libbpf, native, netsh and bpftool regressions in null namespace; Debug and NativeOnly configurations. |
| G13 | Reject cross-namespace program-map binding, inner templates, map-in-map/prog-array insertion and new link attachment. Old-handle CRUD still succeeds. Test races before edge publication. |
| G14 | Pin then exit all selecting processes: another process selecting same GUID can reopen pinned object. Close last reference/unpin and verify deferred free/refcount balance. |
| G15 | Unload detaches links and frees pins from A/B/default. Process exit, PID reuse, real queue-associated pending cancellation, driver-init rollback and allocation failure do not leak process/namespace state. Check FORCE_INTEGRITY and signed-candidate callback registration in each driver configuration. |
| G16 | Malformed SET/GET messages, unknown enum, exact/truncated/oversized input, header/actual-length mismatch, fuzzing and generated validator consistency. |
| G17 | Failed native/user load rollback only unpins insertion receipts it created; concurrent path replacement or same-object removal/reinsertion is not removed. Switching selection never makes rollback target another namespace's same path. Cover kernel failure and post-kernel-success user-mode failure. |
| G18 | netsh interactive/script persistence, new invocation reset, invalid GUID, null reset, normal/original/long command tables; bpftool remains default-only. |

### 13.2 Harness placement and fixtures to add

**Unit versus driver is determined by what is linked/executed, not directory
names.** `tests\unit\test.vcxproj:216-228` compiles the runtime/core tests,
`tests\end_to_end\end_to_end*.cpp`, and `netsh_test.cpp` into `unit_tests.exe`.
`_test_helper_end_to_end` installs mock transport/handle functions and starts
the user-mode execution context (`test_helper.cpp:672-750`). These are unit/
simulated integration tests, not evidence from `ebpfcore.sys`.

| Fixture code | Placement / runner | New fixture responsibilities |
|---|---|---|
| U-R | `libs\runtime\unit\platform_unit_test.cpp`, `unit_tests.exe` | Extend `pinning_test`; create referenced test objects, explicit GUID attributes, process-identity adapter, allocation/refcount counters and deterministic scheduling latches |
| U-C | `libs\execution_context\unit\execution_context_unit_test*.cpp`, `unit_tests.exe` | Use `_ebpf_core_initializer`, real core dispatcher/validator, map/program/link constructors and existing hook providers; inject request context explicitly |
| U-A | `tests\unit\libbpf_test*.cpp` and `tests\end_to_end\end_to_end*.cpp`, `unit_tests.exe` | Extend `_test_helper_libbpf` / `_test_helper_end_to_end`; model separate process identities, independent sync/async opens, and pin bookkeeping rather than one magic global namespace |
| U-W | `tests\unit\ebpfcore_test.cpp`, `unit_tests.exe` | Model captured versus queued versus driver-owned requests, queue association, cancellation registration outcomes, subject checks and exactly-once cleanup; real KMDF verification remains mandatory |
| U-T | `tests\end_to_end\netsh_test.cpp`, `unit_tests.exe` | Command parsing, resource/command registration variants, state restore and namespace-aware command dispatch |
| D-K | `tests\api_test\api_test.cpp` / `api_test_jit.cpp`, `api_test.exe` | Real DLL/device/driver; add separate namespace test source files to this project if needed; no mock core initializer in driver cases |
| D-P | Child mode in `api_test.exe`, shared support in `tests\libs\util` | Actual processes/tokens, HANDLE transfer, bounded authenticated control pipe, synchronization and per-process result records |
| D-T | `api_test.exe` launching netsh/bpftool on the approved VM | Real command process lifetime and installed DLL/resources; do not reuse U-T as proof |

Reuse `tests\libs\common\common_tests.{h,cpp}` for environment-neutral assertions
where appropriate. Do not put mock transport into the real-driver fixture.
`tests\libs\util\ioctl_helper.cpp` currently sends through `invoke_ioctl`;
add explicit-HANDLE helpers so raw tests do not accidentally use a cached
handle different from the one under test.

For D-P, extend the existing child-mode pattern in
`api_test.cpp:793-869,4517-4522`. Dispatch worker commands before Catch starts;
workers must not run privileged suite setup. Pass only intended IPC/HANDLE
capabilities, check every child launch/exit status, use bounded waits, and
return structured observations, not only an exit code. A worker protocol needs
commands for SET/GET, open/close control, create objects, pin/unpin, enumerate,
operate on imported handles, wait at a barrier, and exit without cleanup.
Use `native_module_helper_t` for independent native module instances rather
than requiring unsupported concurrent reload of the identical module.

The process-registry unit adapter must model process identity and start key,
effective subject, exit notification and request references separately.
Giving every test thread a different fake process would hide the TLS bug.
An exit/refcount test must observe registry membership and outstanding
references through private test seams, not add a public all-namespace API.

### 13.3 Common test data, oracles, and cleanup

- Use null, A, B, and C GUIDs, plus GUIDs differing in only one byte in each
  GUID field. Make identity comparisons binary; include a valid non-RFC-format
  GUID value because the API contract is a GUID value, not a UUID-version rule.
  Different processes selecting the same A are a required positive control.
- Create map/program/link triplets with distinct names and stored marker
  values. Obtain actual IDs from created handles; never assume ID 1, consecutive
  allocation, or an empty host. A controlled run records its own expected set.
- For each path family, include the same canonical path in A/B/default,
  A-only/B-only paths, lexical prefixes, case/separator aliases according to the
  existing canonicalizer, maximum valid length, and invalid paths. Determine
  canonical equality with existing path rules, not a new test-specific rule.
- Exercise direct internal helpers, ebpfapi, libbpf and valid raw IOCTLs where
  specified. Missing candidates map to the same error as genuinely absent
  candidates. At the baseline, `api_common.hpp:174-203` maps missing/end to
  ENOENT, access denied to EPERM, already-exists to EEXIST; freeze the exact
  native/Win32/libbpf mapping in assertions, not `result != success` alone.
- For every rejected mutation, compare before/after data, pins, associations,
  references, selection and visible IDs using an independent authorized
  observer. A denied call that also changed data is a failure.
- Hold explicit references when testing retained handles; separately test
  final-reference destruction. Drain deferred epoch work before checking
  allocations/final destruction, with bounded waits rather than arbitrary
  sleeps. Never dereference an object after releasing its final reference.
- Save and explicitly restore the test runner's namespace; track every created
  pin by namespace/path/object identity and every child/HANDLE/fd/module.
  Cleanup must work after a failed assertion and report restoration failure.
  Do not clean up by enumerating/detaching unrelated host objects.
- API-call consistency is per kernel request. Without the documented high-level
  guard, an enumeration or load made of several requests is not a global
  snapshot. Do not write tests that demand transactional behavior the design
  does not promise.

### 13.4 Detailed unit test matrix

Each row is a mandatory scenario family. Parameterize by object type, execution
mode, public entry point and transport where stated; report each parameter
combination separately. NU IDs can be carried in Catch names, for example
`namespace_NU09_snapshot_is_coherent`.

#### 13.4.1 Process state, request capture, and switching

| ID / fixture / group | Setup and execution | Required assertions |
|---|---|---|
| NU01 / U-R / G01,G03 | Query an unseen process, set A twice, reset null, query again | Unseen read is null without allocation; SET/GET round-trip exactly; idempotent SET does not leak; reset does not change object ownership |
| NU02 / U-R / G02,G08 | Same fake process, two threads with independent sync opens and one async open; SET only through thread 1 | All later snapshots use A, including an open created after SET; no per-thread/per-open namespace fork |
| NU03 / U-R / G03,G11 | Process P selects A; independent Q and child R use independent opens and a duplicate of P's control file | Q/R remain null; their SET does not change P; file-object sharing does not replace requestor process identity |
| NU04 / U-R / G15 | Remove exiting P; model another process with same numeric PID but different identity/start key | New process is null; no stale A state or references; key lookup uses identity, not PID alone |
| NU05 / U-R / G15 | Pause SET before registry insertion; deliver exit notification, then release SET | No new live entry for the exiting identity; result is explicit failure or previously captured completion as specified, never leaked resurrection |
| NU06 / U-R / G15 | Hold request/state reference, exit process and remove registry membership, then finish/cancel request | State remains valid until request release, is freed exactly once, and is not found by new requests |
| NU07 / U-R / G03,G15 | Close all transports while P remains alive; reopen; terminate/reinitialize API state without process exit | Selection persists until process exit; close/API cleanup does not delete registry state |
| NU08 / U-W / G09 | Caller P/low subject submits request; queue/current worker is SYSTEM with another identity; repeat with admin caller on low worker model | Captured requestor/subject determines namespace and SET authorization, not worker identity; all captured refs release |
| NU09 / U-R,U-C / G08 | Race writers alternating GUIDs that differ in all 16 bytes against readers at a deterministic publication latch | Every snapshot is a complete published GUID/generation pair; never torn bytes or a mismatched generation |
| NU10 / U-C / G07,G08 | Capture A for a request, publish B before inner helper dispatch, then execute multiple dependent lookups/creates | All work in that request uses A; a request captured after SET uses B; no late ambient lookup |
| NU11 / U-W / G09 | Allowed Admin/SYSTEM/ebpfsvc and denied ordinary/deny-only-admin effective subjects issue valid SET/GET | Exact success/denial per management policy; denied SET leaves current selection unchanged; duplicated control file does not bypass check |
| NU12 / U-R,U-W / G15,G16 | Fail registry allocation, process reference/callback registration, request capture and initialization at each supported failure point; simulate callback-registration access denied | Explicit error, no successful null fallback, no partial publication; callback unregister/rundown exactly once on failure/unload; pair with real PE-flag/registration gate |

#### 13.4.2 Object creation, IDs, and discovery

| ID / fixture / group | Setup and execution | Required assertions |
|---|---|---|
| NU13 / U-C / G01,G02 | Construct map/program/link in null, A and B through each enabled constructor path | Correct immutable ownership on all objects before visibility; base/native-module objects are not miscast as core objects |
| NU14 / U-R,U-C / G02 | Pause immediately before ID publication while another observer enumerates/opens | Object is either absent or fully initialized with correct GUID; no temporary null-namespace exposure |
| NU15 / U-R / G04 | Interleave A/B/default objects of all types; scoped reference-by-ID with matching, foreign, wrong type and absent IDs | Only matching live type succeeds; foreign and absent yield identical missing result; references balance |
| NU16 / U-R / G04 | Enumerate sorted IDs with hidden IDs between visible ones; cursors zero, live/foreign/deleted IDs, arbitrary gaps and maximum ebpf_id_t | Visible IDs only, strictly after cursor; skip hidden entries without premature end; no cursor resolution prerequisite |
| NU17 / U-R / G04,G15 | Delete a candidate during lookup/next-object try-reference and at epoch transition | Either valid referenced object or absent/end; no resurrection, stale returned object or leaked reference |
| NU18 / U-R / G04 | Exercise next-object traversal independently from sorted next-ID with previous matching/foreign referenced objects | Scoped traversal skips foreign types/namespaces and advances correctly; previous-object lifetime retained correctly |
| NU19 / U-C / G04,G16 | Execute all three GET_*_HANDLE_BY_ID and GET_NEXT_*_ID opcodes through validated dispatch | Uniform scope and exact reply lengths/headers; expected end is not misreported as access denied or generic error |
| NU20 / U-C / G07 | Hold A handles, switch B; query object info/program metadata and perform supported map CRUD | Handle operations still target A; returned related IDs are metadata, not cross-namespace name/ID opens |
| NU21 / U-C / G07,G13 | Explicitly detach A link via handle in B, then attempt attach-data/program-discovery detach from B | Direct handle detaches A; discovery-based detach cannot affect A; same-namespace positive control detaches intended links only |
| NU22 / U-R,U-C / G15 | Invoke unscoped internal teardown with A/B/default links and pins while selected C | Every owned object is processed; no dependence on unloading thread namespace; user dispatcher cannot invoke unrestricted traversal |

#### 13.4.3 Composite pin table and enumeration

| ID / fixture / group | Setup and execution | Required assertions |
|---|---|---|
| NU23 / U-R / G05 | Insert identical canonical path with A/B/default objects; find each with explicit namespace | Three independent entries and correct objects; GUID bytes participate in hashing/equality |
| NU24 / U-R / G05,G06 | Insert an existing composite key again with same and different object | Existing already-exists result; original entry intact; rejected insert adds no pinned/user reference |
| NU25 / U-R,U-C / G05,G07 | Attempt pin of held A object in B; then normal A CRUD | Invalid argument; no B alias, no path-count increment, retained handle still works |
| NU26 / U-R,U-C / G05 | Delete path from B when only A owns it, then when both namespaces own it | First is missing; second removes only B; A survives with unchanged ownership/reference count |
| NU27 / U-R / G06 | Paths at zero, maximum-valid, first-invalid lengths; embedded NUL; internal-key length overflow in injected boundary model | Existing path validation retained; GUID prefix does not reduce user path capacity; no out-of-bounds key extraction |
| NU28 / U-A,U-C / G06 | Canonical alias/case/separator and prefix pairs in same versus different namespaces | Existing canonical aliases collide only within a namespace; byte-prefix paths remain distinct when canonicalizer says so |
| NU29 / U-R / G05,G06 | Enumerate pin snapshots by map/program/link type with many hidden pins and no visible pins | Only matching visible entries copied/referenced; counts reflect visible set; no hidden path/count/required-size disclosure |
| NU30 / U-R,U-C / G06 | Visible counts near uint16_t bounds using a synthetic table/count adapter; small/exact/large output buffers | Checked size arithmetic and explicit overflow/short-buffer result; no truncated visible count or global-count allocation bug |
| NU31 / U-R / G06 | Sorted next-path over shared path names and lexical prefixes; absent/deleted/foreign cursor, empty start and type filter | Lexical next visible path only; no pointer-address ordering; no entry skipped because another namespace shares cursor text |
| NU32 / U-C / G05,G16 | Run deprecated program-only and current object next-path opcodes, plus pinned-map-info, with short/exact replies | Both protocol generations scope identically and preserve type/header/size/end conventions |
| NU33 / U-R / G06,G15 | Fail key allocation, path duplication, table insert, snapshot array and each copied snapshot path | No partially inserted entry or leaked output references; exactly-once unwind; original table unchanged on failed mutation |
| NU34 / U-R / G05,G15 | Pin one object under multiple names; delete/reinsert; close handle before final unpin | Path/user-reference counts track successful entries; final destruction occurs only after final owning reference drains |
| NU35 / U-R,U-C / G17 | Record A/path/X/cookie c1; delete and reinsert either Y or the same X with cookie c2; change selection B, then retry c1 cleanup | Cleanup never deletes either c2 insertion or B's path; only the original object-and-cookie match can be removed; include invalid zero cookie and counter-exhaustion atomicity |
| NU36 / U-R / G06,G15 | Barrier-race same-key insert/delete/find and snapshot release across A/B | At most one winner per composite insertion; cross-namespace independence; referenced snapshots remain valid after delete |

#### 13.4.4 Loading, relationships, public API, and teardown

| ID / fixture / group | Setup and execution | Required assertions |
|---|---|---|
| NU37 / U-C,U-A / G10 | Native load in A creates maps, inner templates and programs; capture load request then switch selection | Entire creating request uses captured A, including pins and cleanup; no objects leak into B/default |
| NU38 / U-C,U-A / G10,G13 | Auto-reuse with matching and incompatible definitions; same path populated independently in A/B | Reuses only same-namespace compatible map; mismatch fails; foreign pin behaves absent and creates local map without altering foreign one |
| NU39 / U-A / G10,G17 | Inject get-pin outcomes not-found, access denied, no-memory, bad-definition and transport error | Only not-found permits create-new fallback; every other failure propagates without creating or unpinning another object |
| NU40 / U-C / G10,G15 | Existing module already loaded/loading/unloading; independent supported instances loaded in A/B | Preserve module state machine errors and reference counts; namespace feature does not imply unsupported repeated module loading |
| NU41 / U-C,U-A / G10 | Two simulated RPC clients with A/B objects use marshaled handles while service process selects C/default | Existing objects keep A/B; service does not SET its process namespace for a client; concurrent clients do not cross-contaminate |
| NU42 / U-C / G13 | Parameterize program-map resolution/bind, inner template, map-in-map/prog-array entry and link-program edges with same/foreign GUID pairs | Same-namespace valid graph succeeds; foreign edge rejects before partial reference/association publication, per approved graph policy |
| NU43 / U-C / G07,G13 | Current B with retained A handles: A-to-A association where supported, A map CRUD, and creation of new B link/graph referencing A | Distinguish allowed old-object operations from rejected new cross-namespace edges; do not add global handle-lookup namespace gate |
| NU44 / U-A / G08,G10 | Hold shared load/pin guard while SET waits; separately force SET(A), SET(B), then load, and run the same broker tasks under the outer save/SET/work/restore mutex | Per-load guard prevents mid-load SET only; unsupported unguarded sequence demonstrates B selection; cooperative broker tasks create only intended tenant objects, restore on success/failure/exception, and stop on restore failure; lock-order/reentry tests do not deadlock |
| NU45 / U-A / G07,G17 | Cache pin state for A, switch B, pin/unpin same text via map/link/object wrappers | Cached A `pinned` state never falsely describes B; public unpin is current-relative; internal rollback uses captured ownership |
| NU46 / U-C,U-A / G10,G17 | Fail at each map/template/program/link creation, native initial-value/association/pin, fd-wrap and metadata-query stage; replace pins with Y and re-pin the same X before cleanup | Receipts survive kernel-to-client handoff; only CREATED object-and-cookie matches are removed; reused pins, foreign pins and later same-object incarnations survive; every raw HANDLE/fd closes once |
| NU47 / U-W,U-C / G16 | SET/GET and operations 48-52 valid bytes; sweep truncation, header/count/size mismatch, invalid ownership/cookie combinations, oversize > UINT16_MAX, unknown/negative opcode and null API arguments | Exact API/transport/structural error; invalid requests do not mutate; extended reply lengths and unaligned cookie arrays decode correctly; new maximum opcode/schema/layout checks agree |
| NU48 / U-A / G12,G16 | Simulate pre-namespace driver, namespace driver with only 46-49, and full 50-52 support; old DLL unchanged requests on new driver; legacy op32 short header but full payload | Only unsupported-plus-unsupported permits default-only legacy fallback; namespace-aware missing receipt support fails before mutation; denied/policy/malformed results never trigger fallback; legacy header compatibility preserved |
| NU49 / U-A,U-W / G08,G15 | Capture A, enqueue, SET B; force cancellation before enqueue, while queued, during cancel registration, pending, and racing normal completion/close | No cancellation registration before queue association; original caller subject/objects/snapshot retained; enqueue and MarkCancelableEx failure unwind; exactly one terminal owner and reference release; later requests use B |
| NU50 / U-T / G18 | Parse valid/null/malformed GUIDs; register normal/original/long tables; execute vendor wrapper with success/failure/exception | Exact selection/reset/parse result; wrapper restores previous state on every exit; no global persistence or list-all API |
| NU51 / U-A,U-T / G12,G18 | Existing list/load/pin/map CRUD/dump/attach/detach handlers under A versus null; bpftool entry stays null | All intended management commands use scoped APIs; no hidden environment override; host-wide process diagnostics labeled separately |
| NU52 / U-R,U-W / G15 | Core init failure/unload with callbacks, open requests, process entries, pins and graph references in all namespaces | Correct callback unregister/rundown ordering; all owned refs drain; reinitialize starts clean without leaked prior selections |

### 13.5 Detailed real-driver test matrix

Run ND cases with the installed candidate `ebpfapi.dll`, `ebpfcore.sys`,
appropriate sample/network extensions and, for JIT, `ebpfsvc`. The D-K fixture
must prove the device/driver path is live. Observing the same behavior in a
mocked process is not a replacement.

| ID / group | Setup and execution on the driver VM | Required assertions |
|---|---|---|
| ND01 / G01,G12 | Fresh worker never calls namespace API; create/open/enumerate/pin map/program/link with old public APIs | Null/default behavior and exact legacy errors preserved; compare with isolated baseline behavior and owned IDs |
| ND02 / G02,G07 | Worker creates triplet in A, saves handles/IDs, SET B, creates second triplet, resets null | Each triplet discovered only by its owning namespace; saved handles still operate; no object ownership mutation |
| ND03 / G08 | Pre-open sync handles on T1/T2, global async on T3 and a raw independent file; SET on T1, release barrier for other threads and late opener | Every post-SET create/lookup uses A; catches updating only one TLS/file handle |
| ND04 / G03 | Close/reopen control transports and unload/reload DLL while the same worker process stays alive | GET and newly created objects remain A; no implicit process reset |
| ND05 / G03,G11 | Independent P/Q and a child: P selects A, gives Q a duplicate control HANDLE; Q/child create before their own SET | Q/child start null despite shared file object/inheritance; P unchanged after Q SET B |
| ND06 / G04 | Coordinated A/B/default workers create interleaved IDs of all types and enumerate using public and raw opcodes | Each exact owned visible set only; hidden cursors do not end enumeration early; direct foreign IDs look missing |
| ND07 / G05,G06 | A/B/default pin different markers at same canonical path; resolve and unpin in alternating processes | All three coexist; read marker confirms correct object, not merely successful open; unpin affects only selected namespace |
| ND08 / G05,G06 | Enumerate old/new next-path and bulk pinned-map info with hidden path prefixes/collisions and varying reply sizes | Correct visible counts, ordering, type/end mapping and no hidden strings/required-size leakage |
| ND09 / G07 | In B, use A map/program/link HANDLEs acquired before switch; exercise supported CRUD/query/batch/explicit detach | Allowed operations succeed on A and do not modify B; new foreign pin fails without invalidating A handle |
| ND10 / G11 | Real DuplicateHandle and explicit inheritance of A object into Q in B/default; convert recipient HANDLE to local fd | Object stays A; holder can perform currently authorized old-handle operations; Q cannot open A by ID/path without selecting A |
| ND11 / G09 | Low-privilege child attempts direct management open, SET/GET, then valid SET/GET on an intentionally duplicated management HANDLE | Direct device gate and per-request policy enforced independently; valid SET denies and leaves child/parent selection unchanged |
| ND12 / G09 | Run permitted elevated-admin, SYSTEM and actual ebpfsvc-service-SID subject cases; ordinary, filtered/deny-only-admin and unrelated LocalService negative cases | Actual configured policy, not "admin name"/worker token, determines result; lack of a token fixture is a recorded blocked subcase |
| ND13 / G09 | Reuse same process/control HANDLE while alternately impersonating allowed and denied clients and reverting | Effective subject used on each SET; requestor process selection changes only on authorized calls; no cached privilege after revert |
| ND14 / G08 | SET A completes before barrier release of another thread's create; separately race rapid A/B SET against creates | Ordered call always A; overlap yields complete A or B ownership per request, never mixed GUID or unrelated namespace |
| ND15 / G10 | Load independent native modules in A/B, including auto-pinned maps and inner templates | Native maps/programs inherit creating request; independent pins/reuse work; already-loaded module behavior remains unchanged |
| ND16 / G10 | Load JIT/interpreter programs in A/B while service itself is default; have two clients load concurrently | No service-default objects or cross-client map binding; runtime-disabled modes return policy/unsupported rather than silently taking another mode |
| ND17 / G10,G13 | Same visible auto-pin name in A/B; reload within each; incompatible same-namespace map definition | Same-namespace compatible reuse only; incompatible definition errors; foreign objects unchanged |
| ND18 / G13 | Raw/API bind, inner template, map/prog entry and link attachment using same versus foreign handles | Positive control succeeds; foreign graph rejected under approved policy; no partial edge; ordinary old-handle CRUD still succeeds |
| ND19 / G07,G13 | Two namespaces attach compatible programs at same attach-data when provider permits; invoke legacy detach by context/program and explicit link detach | Context-based route affects only caller namespace; explicit held link remains usable across switch; unrelated attachment still functional |
| ND20 / G14 | P pins A object and exits; all A-selecting processes exit; Q later selects same A | Pin is still resolvable, correct ID/marker preserved; process-state cleanup is not namespace-object destruction |
| ND21 / G03,G15 | Worker selects A then exits gracefully and abnormally; launch many fresh workers | Every new process starts null; no stale selections; deterministic PID/start-key aliasing remains NU04's unit obligation, not an unreliable OS PID-reuse assertion |
| ND22 / G08,G15 | On real KMDF with framework verification, exercise pending notifications/test-run operations through SDK/raw transports; cancel before enqueue, queued, during registration, pending, at completion, and during worker exit | Every cancelable request has queue association; explicit MarkCancelableEx/enqueue outcomes and one terminal completion; no verifier violation/hang/double free; caller snapshot survives worker context and later SET; post-SET requests see B |
| ND23 / G15 | Approved dedicated VM: validate candidate PE FORCE_INTEGRITY/signing and successful process callback registration; populate A/B/default, then supported stop/unload/restart | Missing integrity flag is a failed build/deployment gate, never namespace fallback; expected stop preconditions honored; unload cleans every namespace and reload has no old objects/selections; no force unload with live refs |
| ND24 / G16 | Valid raw SET/GET positive control, then systematic malformed headers/bodies/output sizes and unknown opcodes | Exact native/Win32 failures, no mutated selection or object visibility; process remains responsive after every malformed request |
| ND25 / G17 | Fail load after auto-pin creation and after native kernel success before client initialization completes; replace with Y or remove/re-pin X before rollback where black-box scheduling permits | No stale owned insertion; reused/replacement/same-object later insertion remains; B's same text never removed; deterministic receipt race proven by NU35/NU46 |
| ND26 / G08,G10 | Race load against SET; separately interleave broker SET and load before entry, then serialize full save/SET/work/restore transactions; cover cooperating SDK/raw paths | Per-load versus outer transaction guarantees are distinct; serialized broker operations create only intended tenant objects and restore selection; unsupported unguarded sequence is not asserted tenant-safe |
| ND27 / G18 | One interactive netsh or `netsh -f` invocation SETs A then queries/manages; second fresh netsh invocation queries | First stays A throughout; second null; parent shell/service process unaffected |
| ND28 / G18 | In selected netsh, exercise every approved namespace management command, error paths and null/invalid GUID | Correct objects/data/attachments and readable failures; resource/command registration works on both supported netsh ABI variants available in the test matrix |
| ND29 / G12,G18 | Launch bpftool separately after A objects exist and default control objects are created | Default controls visible, A fixtures absent; launching from a namespace-selected parent does not change bpftool scope |
| ND30 / G12,G18 | Run host-wide `show processes` diagnostic alongside namespace-scoped lists | No foreign GUID-discovery API introduced; host-wide handle diagnostics not falsely asserted to be scoped or treated as AC1 failure |
| ND31 / G12,G16 | Separate clean images for old DLL/new driver, new DLL/pre-namespace driver, and new DLL/namespace-aware 46-49-only driver; not live replacement | Default legacy workflows remain explicit; SET/GET unsupported on old driver; 50-52-dependent sequences reject the intermediate driver before mutation; access denied never becomes fallback success |
| ND32 / G05,G06,G15 | Many independent A/B/C workers insert/find/enumerate/unpin same path families, while others exit/reopen handles | No foreign marker reads/deletions, crashes, deadlocks or monotonic test-owned resource leaks; capture seed/operations for replay |
| ND33 / G12 | Existing unit/API/native/netsh/bpftool/socket/sample-extension regressions with all new selection restored | No default behavior or data-plane regression; suites do not inherit A from a previous test |
| ND34 / G01,G02 | Two independent authorized processes intentionally select the same A GUID | Both discover/access the same objects as existing privileges allow; GUID feature is not mistakenly implemented as PID ownership or secret-namespace ACL |
| ND35 / G02,G04 | Call API with valid GUID values differing in each byte and valid non-versioned GUID representation; compare API/CLI parsing boundaries | Binary GUID ownership correct; CLI accepts documented syntax and rejects malformed text without imposing new binary API UUID restrictions |
| ND36 / G15 | Hold duplicated object/pin references across graceful/abnormal creator exit and final observer cleanup | Remaining references preserve object; final close/unpin eventually removes owned ID with no crash; unit refcount proof paired with real handle behavior |

### 13.6 Forced concurrency schedules and failure injection

Avoid sleep-based proof. Implement these unit schedules with an injected private
adapter/latch, then run the corresponding driver invariant under real overlap:

| Schedule | Exact ordering | Evidence |
|---|---|---|
| S-N1 | T1 captures A and pauses; T2 completes SET B; T1 resumes inner create/pin/lookup; T3 starts a fresh request | NU10/NU49 prove per-request capture; ND03/ND14/ND22 prove ordered/overlap behavior with real transport |
| S-N2 | Reference entry P and pause; exit removes P; start same-PID different-start-key Q; resume P and release | NU04-NU06 prove membership/ref lifetime; ND20/ND21/ND36 validate actual rundown without requiring deterministic OS PID reuse |
| S-N3 | Cleanup retains A/path/X/c1; another actor removes the pin and inserts Y or the same X with c2; selection changes B; c1 cleanup resumes | NU35/NU46 prove insertion-cookie comparison, not pointer identity alone; ND25 validates available black-box failure paths |
| S-N4 | Enumerate/acquire pin snapshot; delete table entry; release snapshot after epoch progression | NU17/NU29/NU36 prove reference ownership; ND08/ND32 validate real concurrent enumeration safety |
| S-N5 | User/API load holds shared guard; SET waits; load fails and conditionally cleans up; guard releases | NU44-NU46 prove ordering and no deadlock; ND26 covers supported API serialization |
| S-N6 | Without an outer mutex T1 SET(A), T2 SET(B), then T1 enters load; repeat with each tenant's complete save/SET/work/restore protected by the same mutex | NU44/ND26 distinguish consistent-but-wrong-tenant unguarded behavior from supported broker isolation; include restore failure and module-local lock limits |
| S-N7 | Capture caller A/subject/objects; pause before enqueue, on queue, before cancel registration, and before completion while another actor cancels/closes/exits and SETs B | NU49 models ownership outcomes; ND22 must prove actual queue association and cancellation behavior under KMDF verification |

Add failure-at-each-step cases using existing cxplat fault-injection
infrastructure for registry/key/path/snapshot/object/fd/native cleanup paths.
After each injected failure, disable injection for verification/cleanup, drain
epochs, compare owned resource baselines, then retry the same operation without
injection and require success. A failed GET/SET/load must not poison later use.
If a kernel allocation-failure mechanism is available and approved, replay
these driver-reachable recovery paths there too; do not invent a public
fault-control IOCTL or count usersim injection as kernel execution.

Structural fuzz seeds must include SET/GET and old/new pin/ID operations in
each namespace context, not just random bytes starting in null. Extend
`tests\libfuzzer\execution_context\libfuzz_harness.cpp`; assert post-input
state invariants and retain minimized failures. That harness currently defines
a local `REQUIRE` macro that evaluates/discards its boolean, so new invariant
oracles need actual failure signaling rather than relying on that macro.
Raw structural rejection alone does not establish namespace authorization.

### 13.7 Traceability and required execution matrix

| Group / requirements | Unit obligations | Driver obligations |
|---|---|---|
| G01,G02 / R1,R2,R7,R9 / AC4,AC6 | NU01,NU13,NU14,NU20 | ND01,ND02,ND34,ND35 |
| G03 / R2,R7,R9 | NU03,NU04,NU07 | ND04,ND05,ND21 |
| G04 / R3 / AC1 | NU15-NU19 | ND06 |
| G05,G06 / R4,R5 / AC2,AC3 | NU23-NU34,NU36 | ND07,ND08,ND32 |
| G07,G11 / R6 / AC5 | NU03,NU20,NU21,NU25,NU43,NU45 | ND09,ND10,ND19,ND36 |
| G08 / process-wide R7 | NU02,NU08-NU10,NU44,NU49 | ND03,ND14,ND22,ND26 |
| G09 / R8 / AC7 | NU08,NU11,NU12 | ND11-ND13 |
| G10 / all creation/load routes | NU37-NU41,NU44,NU46 | ND15-ND17,ND26 |
| G12 / backward compatibility | NU48,NU51 | ND01,ND29,ND31,ND33 |
| G13 / proposed graph invariant | NU21,NU25,NU38,NU42,NU43 | ND17-ND19 |
| G14,G15 / lifecycle | NU04-NU07,NU12,NU17,NU22,NU33,NU34,NU40,NU49,NU52 | ND20-ND23,ND32,ND36 |
| G16 / wire/error behavior | NU19,NU30,NU32,NU47,NU48 | ND24,ND31 |
| G17 / rollback | NU35,NU39,NU45,NU46 | ND25 |
| G18 / tooling | NU50,NU51 | ND27-ND30 |

All listed cases are required unless explicitly conditional on an enabled
execution mode, an approved additional graph rule, or an unavailable privileged
test fixture. Mark a missing fixture as blocked with the exact missing evidence,
not passed/skipped without explanation. If the graph policy changes, revise the
NU/ND expected results rather than silently weakening the tests.

| Lane | Required coverage / acceptance |
|---|---|
| Per-change unit | All NU cases, real validator and usersim dispatch, new `[namespace]` tag; nonzero case count plus existing platform/core/libbpf/netsh regressions |
| Per-change driver | ND01-ND22, ND24-ND30, ND34-ND36 on an approved kernel-test VM; identity/service subcases routed to their required principal fixtures |
| Native-only | Unit and driver native cases in NativeOnlyDebug and NativeOnlyRelease; all-modes operations remain available and native 52 remains enabled while JIT/interpreter slots remain disabled |
| Debug/full modes | Native plus JIT when platform/HVCI allows and interpreter when compiled in; disabled/blocked modes have explicit negative results |
| Release/OS/architecture | Driver-test NativeOnlyRelease closure; oldest supported and current Windows test images; x64 and any other architecture claimed by the feature/release, or an explicit unvalidated-architecture blocker |
| Nightly / isolated | ND23 driver restart, ND31 cross-version images, ND32 seeded stress; existing kernel stress framework, permitted Driver Verifier/pool/handle checks and fault/fuzz lanes |
| Composition | Namespace-only behavior first; with ACLs enabled, add ACL plan AD35 and retain all namespace outcomes subject to legitimate rights |

Each driver build lane must inspect the core image's FORCE_INTEGRITY bit. Kernel
lanes must confirm actual callback registration and exercise ND22's queue/
cancel lifecycle with framework verification. No amount of usersim success
replaces these gates. Driver-test results from the earlier implementation are
not evidence that the revised cookie protocol, broker schedules, or pending
request lifecycle have passed.

`api_test.exe` is already in the driver-test aggregate. Prefer child modes to
an unnecessary helper binary. If a helper executable is added, update its
project, `tools\driver-test\driver-test.vcxproj`, solution dependencies,
`scripts\check_driver_test_closure.ps1`, and deployment/copy lists. Verify
driver tests actually discover new cases: `scripts\run_driver_tests.psm1`
has separate ordinary and SYSTEM API-test runs and excludes some historical
tests. Do not hide all new security/namespace cases behind a filter never run
in CI.

Record test ID/parameters, principal, actual process/start-key observations,
namespace, transport, execution mode, driver/API version, exact result,
before/after marker/ID/pin sets, seed and failure artifact for each run.
Runbook commands/environment gates are in `IMPLEMENTATION_RUNBOOK.md`.
This section specifies required tests, not execution evidence. The original
design phase added no test code. Current implementation and actual results
are recorded separately in `IMPLEMENTATION_RUNBOOK.md` section 9.

## 14. Composition with ACLs

The namespace design contributes immutable ownership GUIDs, scoped discovery,
and explicit request/creation contexts. The ACL design contributes SDs and
granted capabilities on object opens. They compose as:

```text
new discovery/open:
  namespace filter -> object candidate -> ACL desired-access check -> handle

existing handle operation:
  valid object handle -> granted-operation check -> operation
  (no comparison against the process's current namespace)
```

Do not put SDs on every namespace just to implement object ACLs. That creates
an additional policy/lifetime model not required by either the PR or the
delegated-map scenario. If namespace ACLs are later required, define explicit
namespace ownership and shared lifetime rather than first-writer GUID claims.

## 15. Decisions to confirm, without blocking design handoff

These are review gates before implementation/ship, not questions already
resolved by the meeting:

| Decision | Recommended baseline | Consequence of choosing otherwise |
|---|---|---|
| Literal process semantics versus per-open sessions | Honor PR: kernel process registry | Per-open requires revising scope/persistence and acceptance tests |
| Cross-namespace relationship policy | Reject new cross-namespace graphs and pin insertion | Relaxing graph rules needs explicit sharing semantics; foreign pin insertion conflicts with R4 |
| Meaning of isolation for same-account privileged vendors | Logical partitioning only | Real hostile-admin isolation is outside this feature; service identity/OS controls needed |
| All-namespace diagnostics | Deferred; no wildcard GUID | Adding it changes secrecy/discovery expectations and requires a separate authorization contract |
| Tool parity release minimum | Scoped existing management plus map CRUD/dump and a reviewed remaining-gap inventory | Shipping SET alone strands non-default-namespace administration |
| Multi-tenant broker in one process | Prefer one worker per tenant; otherwise every participant shares an outer mutex across save/SET/work/rollback/restore, in addition to the library guard | Per-load locking alone does not select the intended tenant; uncooperative SDK/raw callers make shared-process switching unsupported |
| GET privilege | Same management gate initially | Low-privilege self-query requires a narrow transport path, not broad device access |

The original request was design-only. The subsequent implementation request
selected GUID namespaces and followed the original design's recommended
baselines. That selection does not imply maintainer approval, stronger security
guarantees, or completion of the later review corrections. Historical execution
evidence is recorded in the external `IMPLEMENTATION_RUNBOOK.md`; section 16
identifies what must still change for this revision.

## 16. Independent-review corrections and implementation gates

This repository revision incorporates the 2026-10-28 review. It changes the
required design and test oracles; it does not modify production code or certify
earlier binaries against the revised design.

| Finding | Required design resolution | Completion evidence still required |
|---|---|---|
| High: caller-context async dispatch lacks queue association | Section 5.3 captures caller state, queues pending-capable requests, then registers cancellation with exactly-once ownership | Implement prepared async dispatch and failure cleanup; NU49/S-N7 plus real ND22 under KMDF verification |
| Medium: same-object pin removal/reinsertion defeats expected-object rollback | Sections 7.3/9.1 require a unique insertion cookie and retained receipt, compared atomically with the object | Implement receipt creation/transport/deletion and counter exhaustion; NU35/NU46/S-N3 and ND25 |
| Medium: SET followed by load is not an atomic tenant transaction | Section 9.3 requires an application-wide save/SET/work/restore mutex or separate worker processes | NU44/S-N6/ND26 demonstrate unsupported interleaving and serialized positive controls, restore errors and participating SDK/raw paths |
| Medium: native ownership wire contract incomplete | Section 6 defines existing 48/49, appended 50-52, exact x64 layouts, receipt ownership and explicit legacy/intermediate-driver behavior | Update schema/layout/dispatch/client together; NU47/NU48 and genuine compatibility images in ND31 |
| Low: process-notify image prerequisite absent | Section 5.2 requires `/INTEGRITYCHECK`, actual PE flag checks and signed-candidate registration | Preserve the existing linker correction in every configuration and retain per-lane build/kernel evidence |

The local implementation already contains object-only conditional delete (48),
native ownership metadata (49), and `/INTEGRITYCHECK`. It does not follow from
those additions that it implements the new insertion-cookie operations 50-52
or the corrected async queue lifecycle. Reconcile implementation and existing
test fixtures explicitly before marking this revised design complete. The
external runbook records historical validation of the earlier implementation,
not automatic validation of these review corrections.
