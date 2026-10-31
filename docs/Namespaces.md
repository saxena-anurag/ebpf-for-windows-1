# Namespace-aware management

An eBPF namespace is a GUID selected for a **process**, not a thread, parent shell,
Windows network compartment, or persistent machine setting. New processes start
in `GUID_NULL`, including separately launched netsh and bpftool processes. Object
IDs and pin paths are discovered in the selected namespace through the existing
APIs. Objects retain their creation namespace after selection changes.

Namespace selection and queries require an authorized effective caller, such as
an elevated administrator or LocalSystem; existing device and operation access
checks still apply. A GUID is not a secret or a per-object ACL. Privileged
applications can intentionally select the same GUID. Previously acquired object
handles remain capabilities after selection changes. Namespace selection does not
add filtering to eBPF helpers or isolate data-plane hook execution.

## netsh

Use **one interactive netsh process** or one `netsh -f <script>` invocation:

```text
pushd ebpf
set namespace {12345678-1234-4234-8234-123456789abc}
show namespace
show maps
show programs
show links
show pins
set namespace {00000000-0000-0000-0000-000000000000}
show namespace
popd
```

The example can be saved as a netsh script. Two independent `netsh ebpf ...`
invocations do not share selection. Selection is not written to the registry,
inherited by child processes, or installed as product configuration. Do not use
process-wide selection as a thread-local tenant context; serialize selection and
management when embedding the APIs.

Supported DLL high-level load/pin sequences serialize with `ebpf_set_namespace`.
Direct raw SET IOCTLs bypass that user-mode guard; do not race them with those
sequences. A driver request captures its selection, but a raw multi-request
sequence is not an atomic tenant context. With the matching namespace-aware DLL
and driver, native-load rollback conditionally removes only pins created by that
load, preserving reused pins and later replacements even if selection changes.

`set namespace [namespace=]{GUID}` accepts the canonical brace/hyphen spelling,
case-insensitively. The all-zero GUID resets selection; the literal word `null`
is not a GUID. Malformed text produces an explicit error without changing
selection. `show namespace` prints only the current process's GUID. There is no
all-namespace enumeration command or public namespace-discovery API.

Existing program load/list/pin/unpin/delete, supported program attach/detach
through `set program`, and map/link/pin lists use the selected namespace
implicitly. Existing handle and privilege rules still apply.

### Map commands

| Command in the eBPF context | Behavior |
|---|---|
| `add map <type> <keysize> <valuesize> <maxentries> <pinpath> [name] [innerid]` | Creates and pins a map; prints its ID. |
| `lookup map <id> [key]` | Prints the value for a key; omit key for a queue or stack. |
| `update map <id> [key] value=<bytes> [flags=any\|noexist\|exist]` | Inserts or updates a value. |
| `delete map <id> [key]` | Deletes an element, not the map. With no key, removes the next queue/stack value. |
| `getnext map <id> [key]` | Prints the first key when omitted, or the next key; exhaustion is an explicit error. |
| `dump map <id>` | Prints keys and values using checked, nondestructive iteration. |
| `pin map <id> [pinpath]` / `unpin map <id> [pinpath]` | Adds or removes a pin. |

Arguments also accept their help-documented tags, such as `type=hash`,
`keysize=4`, `valuesize=4`, `maxentries=8`, `pinpath=BPF:\example`, and `innerid=7`.
Map type names match `show maps`. `innerid` is required only for `array_of_maps`
and `hash_of_maps`; the referenced template must be discoverable in the selected
namespace. The create pin keeps a map alive after the command returns. To release
a map, remove its pins and other references.

Keys and values are **contiguous hexadecimal byte pairs in memory order**, with
exact byte counts and no `0x` prefix or separators. For example, the Windows
four-byte integer 42 is `2a000000`. Per-CPU values contain an eight-byte-rounded
slot for every possible CPU. For program arrays and map-in-map updates, the value
is a four-byte little-endian **object ID**, resolved in the selected namespace,
not a process-local file descriptor.

```text
add map type=hash keysize=4 valuesize=4 maxentries=8 pinpath=BPF:\example name=example
show maps
# Replace 7 with the ID printed by add map.
update map id=7 key=01000000 value=2a000000 flags=any
lookup map id=7 key=01000000
getnext map id=7
dump map id=7
delete map id=7 key=01000000
unpin map id=7 pinpath=BPF:\example
```

Map-type restrictions are enforced by the existing APIs and failures are
reported, not silently treated as success. An empty iterable map dumps
successfully. Queue/stack and other keyless maps have no nondestructive key
iterator and cannot be dumped. Dump is not an atomic snapshot: concurrent
changes can produce partial output and an explicit iteration failure.

### Links and diagnostics

`pin link <id> <pinpath>`, `unpin link <id> <pinpath>`, and `delete link <id>`
operate on links discovered in the selected namespace. Unpin requires the path
to refer to that link. Delete detaches the link; it does not remove pins or
other references. Existing `set program <id> attached=<type>` and
`set program <id> attached=""` attach and detach programs using the supported
Windows attach types and parameters.

**`show processes` is host-wide OS handle diagnostics, not namespace-scoped
object discovery.** Its output is labeled accordingly. It does not list
namespaces or disclose object-owner namespace GUIDs.

## bpftool and scope of parity

bpftool's CLI is unchanged and a separate bpftool process starts in `GUID_NULL`,
even when launched by a process that selected another namespace. There is no
namespace command-line or environment-variable override. Use namespace-selected
netsh for the management operations above.

The inventory at bpftool commit
`ee9e72612eef8f53e959ee4c646befcf47892a77` includes map list/create/pin,
lookup/update/delete/getnext/dump and queue/stack aliases; program list/load/
loadall/pin/run; and link list/pin/detach. The namespace tooling supplies the
listed map operations, existing program management/attach paths, and link
pin/unpin/detach. Queue/stack peek/push/removal use lookup/update/delete rather
than adding bpftool aliases. Program test-run, JSON/BTF formatting, and additional
upstream inspection/profiling facilities are not added by this tooling change.
No unsupported Linux functionality is implied.

## Driver CLI validation

`api_test.exe "[namespace][driver][tooling]"` contains ND27–ND30 tests against
the actual device and separately launched netsh/bpftool processes. Run only on
the approved kernel-test setup with the matching installed `ebpfcore.sys` and
`ebpfapi.dll`, registered candidate `ebpfnetsh.dll`, available candidate
`bpftool.exe`, network extension, and signed `bindmonitor.sys` sample.
The tests do not install helpers, change security policy, or skip missing
fixtures; missing prerequisites fail explicitly. They restore selection and
conditionally remove only their own pins. Their script/output files are created
in the working directory, not a temporary directory.

Unit command coverage is in `unit_tests.exe "[netsh][namespace]"`. Passing it is
not evidence that the installed netsh helper, OS ABI variant, real-driver
authorization, or independent-process behavior passed. Run driver CLI cases on
each supported OS/ABI variant in the test matrix.

ND23 actual driver unload/restart, ND31 genuine cross-version images, and the
privileged ND12 identity fixtures use the explicit dedicated-VM harness described
in [NamespaceVmTests.md](NamespaceVmTests.md). They never run implicitly on a
shared development host.
