# Proposal: Extend Map Annotations to BPF-to-BPF Subprograms

## Problem Statement

The bpf2c array-data inline optimization currently does **not** apply to `bpf_map_lookup_elem` calls inside BPF-to-BPF subprograms. Only entry programs get annotations. This means subprogram map lookups always go through the helper call path, even when the verifier has enough information to prove they are safe for inlining.

## Why It Doesn't Work Today

1. The verifier (`ebpf_verify_program`) is called once per *entry program* section. It does verify subprogram code (following BPF-to-BPF calls), so the analysis covers those instructions — the invariants exist.
2. `api_common.cpp` extracts annotations using `label.from` as the instruction offset. For subprograms, these offsets are relative to the entry program's flattened instruction stream (the verifier sees a flattened CFG with subprograms appended after the entry).
3. In bpf2c, `extract_program()` splits subprograms into separate `bpf_code_generator_program` objects with offsets restarting at 0. So verifier offsets for subprogram instructions don't match bpf2c's local offsets.
4. `bpf2c.cpp` currently skips `.text` subprograms when calling `set_map_annotations`, so subprograms are never present in `_program_map_annotations`.

## Proposed Fix (Two-Part)

### Part A: Verifier/api_common side — emit scoped annotations

In `api_common.cpp`, when extracting annotations from the verifier's invariant list:

1. Track which instruction ranges correspond to which subprogram (the verifier's CFG already has this info via subprogram start offsets or by detecting label gaps).
2. Emit each annotation as `(subprogram_name, local_offset_within_subprogram, map_info)` rather than just `(global_offset, map_info)`.

Concretely, change `ebpf_get_map_annotations_from_verifier` to return a structure like:

```c
typedef struct _ebpf_verifier_map_annotation {
    const char* program_name;       // NULL for entry, or subprogram name (e.g., "lookup_hash_value")
    uint32_t instruction_offset;    // local offset within that program/subprogram
    ebpf_verifier_map_info_t info;
} ebpf_verifier_map_annotation_t;
```

The verifier already knows subprogram boundaries (it uses `call <relative_offset>` to enter them and tracks return). The flattened offset → subprogram name mapping can be derived from the ELF symbol table or from the verifier's internal `subprogram_info`.

### Part B: bpf2c side — store and lookup per-subprogram annotations

In bpf2c:

1. After verifying each entry program, call `set_map_annotations(subprogram_name, annotations, count)` for each subprogram that had annotations extracted.
2. In `encode_instructions()`, when encoding a subprogram, look up `_program_map_annotations[subprogram_name]` — the infrastructure already supports this since the map is keyed by program name.

## Complexity and Tradeoffs

| Aspect | Difficulty | Notes |
|--------|-----------|-------|
| Verifier knows subprogram boundaries | Low | Already tracked for call validation |
| Mapping flattened offset → local offset | Low | `local_offset = global_offset - subprogram_start_offset` |
| New annotation API shape | Medium | Breaking change to `ebpf_get_map_annotations_from_verifier` |
| bpf2c storage | Already done | `_program_map_annotations` is keyed by name, works for subprograms too |
| Correctness for recursive/shared subprograms | Medium | Same subprogram called from multiple entries may have different annotations depending on call context — would need to use the annotation from the first (or any) verified context |

## Key Insight

The PREVAIL verifier already analyzes subprogram code in the context of its caller. If a subprogram calls `bpf_map_lookup_elem` on an ARRAY map with a bounded key, the verifier's abstract state at that point contains the same information needed for annotation. The gap is purely in the **extraction/plumbing layer**, not in the analysis.

## Related Files

- `libs/api_common/api_common.cpp` — annotation extraction from verifier invariants
- `tools/bpf2c/bpf2c.cpp` — per-program annotation storage call site
- `tools/bpf2c/bpf_code_generator.h` — `_program_map_annotations` declaration
- `tools/bpf2c/bpf_code_generator.cpp` — `set_map_annotations()` and `encode_instructions()` lookup
- `tests/sample/undocked/map_annotation_collision.c` — existing test for annotation scoping
