# Verifier Regression Runbook: assign_valid_ptr stale svalue and map lookup annotation loss

## Objective
Capture the full workflow used in this session to:
- Diagnose asymmetric bpf2c inlining for sequential map lookups.
- Identify and fix the PREVAIL verifier root cause.
- Add regression coverage in ebpf-for-windows sample and bpf2c tests.

## Symptom
In generated bpf2c output for `map_synchronized_update`, the first `failure_stats` lookup was inlined but the second one was not.

Observed behavior:
- First lookup site had verifier map annotation and inlined direct array access.
- Second lookup site had no annotation and remained helper call path.

## Root Cause
File: `external/ebpf-verifier/src/crab/ebpf_transformer.cpp`
Function: `EbpfTransformer::assign_valid_ptr`

Bug:
- `uvalue` was havoced and constrained, but `svalue` was not reset.
- A stale non-null `svalue` range could survive across helper-return pointer assignments.
- Later `assume r0 == 0` on a truly reachable null branch became contradictory, producing bottom (unreachable) for that path.

Impact:
- Missing verifier invariants/annotations on pruned path.
- bpf2c missed inlining for valid callsites.
- Potential soundness issue: verifier can skip checks on a reachable path if it is incorrectly marked bottom.

## Fix Applied
File: `external/ebpf-verifier/src/crab/ebpf_transformer.cpp`

Updated `assign_valid_ptr` logic to:
1. Havoc both `reg.svalue` and `reg.uvalue`.
2. Apply pointer-range constraints on `reg.svalue`.
3. Assign `reg.uvalue = reg.svalue` to keep signed/unsigned domains aligned.

Result:
- Null branch after subsequent map lookup remains reachable when appropriate.
- Annotation extraction sees non-bottom pre-state and emits map annotations.
- bpf2c can inline both eligible map lookup callsites.

## Supporting Verifier/BPF Pipeline Notes
- Annotation extraction path involved `libs/api_common/api_common.cpp` using analysis invariants.
- Temporary tracing was used during investigation and then cleaned up.
- A guard to skip bottom pre-states was retained in annotation extraction.

## Code and Test Changes Added in This Session

### 1) Safe regression sample (inlining behavior)
- `tests/sample/undocked/map_sequential_lookup.c`

Purpose:
- Two sequential array-map lookups on the same path with null checks.
- Valid program expected to verify and produce inlined lookups in bpf2c output.

### 2) Unsafe regression sample (soundness behavior)
- `tests/sample/unsafe/map_sequential_lookup_unsafe.c`

Purpose:
- Intentionally unsafe pattern where second lookup result is dereferenced without null check.
- Must be rejected by verifier.
- Detects regression where an incorrectly pruned branch could hide unsafe code.

### 3) bpf2c test declarations
- `tests/bpf2c_tests/elf_bpf.cpp`

Added:
- `DECLARE_TEST("map_sequential_lookup", _test_mode::Verify)`
- `DECLARE_TEST("map_sequential_lookup_unsafe", _test_mode::VerifyFail)`

### 4) Golden output files for safe sample
- `tests/bpf2c_tests/expected/map_sequential_lookup_dll.c`
- `tests/bpf2c_tests/expected/map_sequential_lookup_raw.c`
- `tests/bpf2c_tests/expected/map_sequential_lookup_sys.c`

Expected property:
- Two inlined lookup sites (direct `runtime_context->map_data[...]` access) in generated output.

## Build and Validation Commands
Run from repo root unless noted.

### A. Build sample artifacts
- `msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-for-windows.sln /t:tests\sample`

### B. Regenerate expected bpf2c outputs (safe sample)
- `.\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\`

Note:
- This script can touch many expected files and may fail transiently on file locks.
- Verify required outputs exist for the target sample.

### C. Build bpf2c tests directly with SolutionDir set
- `msbuild /m /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir="<repo-root>\\" tests\bpf2c_tests\bpf2c_tests.vcxproj`

### D. Run targeted safe test
- `x64\Debug\bpf2c_tests.exe "map_sequential_lookup _test_mode::Verify" -r compact`

Expected:
- Pass.

### E. Run targeted unsafe test
- `x64\Debug\bpf2c_tests.exe "map_sequential_lookup_unsafe _test_mode::VerifyFail" -r compact`

Expected:
- Pass (meaning verification fails as intended).

## Troubleshooting

### 1) Building bpf2c_tests.vcxproj fails with missing wdk.props
Cause:
- `$(SolutionDir)` not set when building project file directly.

Fix:
- Pass `/p:SolutionDir="<repo-root>\\"`.

### 2) `tests\sample` build fails when unsafe program is placed in `tests/sample/undocked`
Cause:
- Undocked wildcard build invokes conversion/native generation for each file.
- Unsafe program intentionally fails verification and breaks custom build.

Fix:
- Place intentionally failing programs in `tests/sample/unsafe/` so they compile to `.o` only.

### 3) Full `[elf_bpf_code_gen]` suite has unrelated failures
Observed in session:
- `cgroup_sock_addr _test_mode::UseHashSHA512`
- `bpf-custom-_test_mode::UseHash`

Action:
- Treat as pre-existing unless proven related.
- Use targeted runs for session regression checks.

## Suggested Review Checklist
- Confirm fix exists in `assign_valid_ptr` and signed/unsigned values are aligned.
- Confirm safe sample compiles and expected outputs include both inlined callsites.
- Confirm unsafe sample is compiled from `tests/sample/unsafe` and VerifyFail test passes.
- Confirm no temporary debug instrumentation remains.

## Session Outcome
- Root cause identified and fixed in verifier.
- Regression coverage added for both behavior and safety dimensions.
- Targeted safe and unsafe bpf2c tests pass with current fix.