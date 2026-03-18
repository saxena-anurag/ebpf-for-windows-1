# Inline Array Map Lookup — Forward R1 Register Tracking Approach

> **Status**: Superseded by the [Verifier-Assisted approach](VerifierAssistedMapOptimization.md).
> This document is retained as a reference for the simpler alternative design.

## 1. Problem Statement

Same as the verifier-assisted approach — eliminate indirect helper function
calls for `bpf_map_lookup_elem` on `BPF_MAP_TYPE_ARRAY` maps by inlining the
bounds check and array index at compile time.

## 2. Approach: Forward Register Tracking in bpf2c

Instead of relying on the PREVAIL verifier's abstract domain, this approach
tracks register `r1` during bpf2c's own instruction encoding pass.

### How it works

During `encode_instructions()`, a `const map_info_t* r1_map` pointer tracks
the map currently loaded in register `r1`:

1. **Set** when processing `LDDW r1, MAP_FD` — points to the map's
   `map_info_t` from bpf2c's own `map_definitions`.

2. **Invalidated** when:
   - The current instruction is a **jump target** (another path may have
     loaded a different map).
   - Any instruction writes to `r1` (ALU, MOV, LDX, etc.) that is not a
     `LDDW MAP_FD` to r1.
   - A **CALL instruction** is executed (calls clobber r0–r5 per BPF ABI).

3. **Used** at `BPF_FUNC_map_lookup_elem` CALL instructions: if `r1_map` is
   set and the map type is `BPF_MAP_TYPE_ARRAY`, emit inline code instead of
   the helper call.

### Advantages

- **Simple**: No verifier changes, no API plumbing, no external dependencies.
- **No numbering mismatch**: Uses bpf2c's own `map_definitions` indices
  directly — the same indices used in generated `map_data[]` accesses.
- **Conservative**: Invalidates at jump targets and register overwrites,
  so it never produces incorrect inlining.

### Limitations

- **Misses maps loaded across branches**: If `r1` is loaded with different
  maps on different control-flow paths that merge before the call, the tracker
  is invalidated at the join point (jump target) and falls back to a helper
  call. The verifier could prove the map is the same on all paths.

- **Fragile to instruction reordering**: If future BPF compiler optimizations
  reorder instructions such that `r1` is loaded earlier or through a different
  pattern, the tracker may not recognize it.

## 3. Implementation

### Encoding loop changes

```cpp
// At the top of encode_instructions():
const map_info_t* r1_map = nullptr;

// At the start of each instruction:
if (output.jump_target) {
    r1_map = nullptr;
}
if (inst.dst == 1) {
    bool is_map_fd_load = (inst.opcode == INST_OP_LDDW_IMM &&
                           inst.src == INST_LD_MODE_MAP_FD);
    if (!is_map_fd_load) {
        r1_map = nullptr;
    }
}

// In the LDDW MAP_FD handler, after generating the load:
if (inst.dst == 1) {
    r1_map = &map_definition->second;
}

// At the CALL handler for BPF_FUNC_map_lookup_elem:
if (helper_id == BPF_FUNC_map_lookup_elem && r1_map != nullptr &&
    r1_map->definition.type == BPF_MAP_TYPE_ARRAY) {
    // Emit inline array lookup using r1_map->index,
    // r1_map->definition.value_size, r1_map->definition.max_entries
    inlined = true;
}
// After any CALL:
r1_map = nullptr;  // Calls clobber r0-r5
```

### Generated code

```c
{
    uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
    if (_array_key < 64) {  // max_entries
        r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data +
             (uint64_t)_array_key * 8);  // value_size
    } else {
        r0 = 0;
    }
}
```

## 4. Correctness Analysis

| Concern | Status |
|---------|--------|
| **Map numbering** | Correct — uses bpf2c's own `map_definitions[name].index` |
| **Control flow** | Conservative — invalidates at jump targets, so conditional map loads produce no inlining |
| **Register clobber** | Correct — `r1_map` cleared on any non-MAP_FD write to r1 |
| **Value size** | Correct — uses ELF definition, same as kernel allocation |
| **Fallback** | Correct — if `r1_map` is NULL, standard helper call emitted |
| **Cross-branch maps** | Not handled — falls back to helper call even if verifier could prove safety |

## 5. Changes Required

| File | Change |
|------|--------|
| `tools/bpf2c/bpf_code_generator.cpp` | Forward r1 tracking + inline array lookup emission |
| `include/bpf2c.h` | `array_data` field in `map_data_t`, version bump |
| `libs/shared/shared_common.c` | Version table entry for new map_data size |
| `libs/execution_context/ebpf_native.c` | Populate `array_data` via `ebpf_map_get_value_address()` |

No verifier, API, or export changes needed.

## 6. Why This Was Superseded

The verifier-assisted approach provides strictly stronger guarantees:

- It handles maps loaded across branches (the verifier's abstract domain
  proves singleton identity across all control-flow paths).
- It eliminates the r1 tracking logic entirely — the verifier has already
  done the analysis more thoroughly.
- The map identity is proven, not heuristically tracked.

The cost is additional complexity (PREVAIL API changes, map name bridging,
annotation plumbing), but the correctness properties are worth it for
production use.
