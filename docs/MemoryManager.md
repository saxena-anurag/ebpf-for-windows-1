# eBPF Memory Manager – Architecture & Design

## 1. Motivation

Today, `ebpf_epoch_allocate()` / `ebpf_epoch_free()` delegate directly to `cxplat_allocate()` (i.e., `ExAllocatePool2`) for every allocation and prepend an `ebpf_epoch_allocation_header_t` for deferred reclamation. This works correctly but incurs pool allocator overhead on every call, which is significant for hot paths like hash-table insert/delete where the value size is known and fixed.

The memory manager introduces a **pre-allocated, per-CPU block pool** that eliminates pool allocator calls on the fast path while remaining transparent to existing callers of `ebpf_epoch_allocate` / `ebpf_epoch_free`.

### Goals

| # | Goal |
|---|------|
| G1 | Zero pool-allocator calls on the fast-path alloc/free. |
| G2 | Lock-free per-CPU fast path (DISPATCH_LEVEL exclusion only). |
| G3 | Transparent integration with the existing epoch reclamation system. |
| G4 | Automatic load balancing when per-CPU lists become empty or full. |
| G5 | Clean separation: new module in `ebpf_memory.c` / `ebpf_memory.h`. |

### Non-Goals

- General-purpose variable-size allocator.  Each memory manager instance handles a single fixed block size.
- NUMA-aware placement (future enhancement).

---

## 2. Public API

```c
// Opaque handle returned by initialize.
typedef struct _ebpf_memory_manager ebpf_memory_manager_t;

// 1. Initialize – allocates N blocks of size S.
_Must_inspect_result_ ebpf_result_t
ebpf_memory_manager_initialize(
    _Out_ ebpf_memory_manager_t** context,
    uint32_t block_count,   // N – total number of pre-allocated blocks
    size_t   block_size);   // S – usable size of each block (bytes)

// 2. Allocate – returns one block from the pool.
//    If per-CPU and global pools are empty, triggers a synchronous rebalance
//    to scavenge blocks from other CPUs before returning NULL.
_Must_inspect_result_
_Ret_writes_maybenull_(block_size) void*
ebpf_memory_manager_allocate(_Inout_ ebpf_memory_manager_t* context);

// 2b. Try Allocate – non-blocking variant.
//     Checks per-CPU list and global pool only. Returns NULL immediately if
//     no block is available, without triggering a synchronous rebalance.
//     Use this when the caller can fall back to another allocator (e.g., the
//     hash table falls back to ebpf_epoch_allocate_with_tag when the pool
//     is temporarily exhausted due to in-flight epoch-deferred frees).
_Must_inspect_result_
_Ret_writes_maybenull_(block_size) void*
ebpf_memory_manager_try_allocate(_Inout_ ebpf_memory_manager_t* context);

// 3. Free – returns one block to the pool.
void
ebpf_memory_manager_free(
    _Inout_ ebpf_memory_manager_t* context,
    _Frees_ptr_ void* block);

// 4. Uninitialize – tears down the pool.
void
ebpf_memory_manager_uninitialize(_Frees_ptr_ ebpf_memory_manager_t* context);

// 5. Ownership check – returns true if the block belongs to this manager's pool.
bool
ebpf_memory_manager_owns_block(
    _In_ const ebpf_memory_manager_t* context,
    _In_ const void* block);
```

All functions follow existing eBPF naming conventions (`lower_snake_case`, `ebpf_` prefix, SAL annotations, `ebpf_result_t` return).

### 2.1 Why `try_allocate` Exists

When the memory manager is integrated with epoch-deferred reclamation, blocks freed
via `ebpf_epoch_free_to_manager` remain in the epoch free list until the epoch advances.
These blocks are invisible to the memory manager — they are neither in per-CPU lists
nor in the global pool. The synchronous rebalance in `allocate` attempts to redistribute
blocks across CPUs, but it cannot reclaim epoch-held blocks. In environments where the
rebalance work item runs on a separate thread (e.g., usersim), the calling thread's
spin-wait deadlocks because the work item thread cannot be scheduled.

`try_allocate` avoids this by returning NULL immediately when per-CPU and global pools
are empty, allowing the caller to fall back to the regular pool allocator
(`ebpf_epoch_allocate_with_tag`). The fallback allocation is slower but always succeeds.

---

## 3. Internal Data Structures

### 3.1 Top-Level Context

```
┌─────────────────────────────────────────────────┐
│              ebpf_memory_manager_t              │
│                                                 │
│  block_size          : size_t                   │
│  total_block_count   : uint32_t       (= N)     │
│  cpu_count           : uint32_t                 │
│  raw_allocation      : void*  ─── single        │
│  │                              contiguous      │
│  │                              allocation for  │
│  │                              all N blocks    │
│  per_cpu_entries     : ─────► [per_cpu_entry[0]]│
│                               [per_cpu_entry[1]]│
│                               [       ...      ]│
│                               [per_cpu_entry[P]]│
│  global_pool         : ─────► global_pool_t     │
│  rebalance_work_item : cxplat_preemptible_      │
│                          work_item_t*           │
│  rebalance_pending   : volatile long (0/1)      │
│  global_only         : bool                     │
│     // true if N < EBPF_MEMORY_MIN_BLOCKS_PER_CPU│
│     // * cpu_count. All blocks in global pool,  │
│     // no per-CPU entries or rebalancing.        │
└─────────────────────────────────────────────────┘
```

**Global-only mode:** When the total block count is too small to meaningfully distribute
across CPUs (fewer than `EBPF_MEMORY_MIN_BLOCKS_PER_CPU` (8) blocks per CPU), the manager
uses a single global spin-locked pool with no per-CPU arrays or rebalancing. This avoids
pathological rebalancing behavior with very few blocks.

### 3.2 Per-CPU Entry (cache-line aligned, no locks)

```c
__declspec(align(EBPF_CACHE_LINE_SIZE))
typedef struct _ebpf_memory_per_cpu_entry
{
    void**   slots;        // Array of pointers to free blocks.
    uint32_t capacity;     // Total slots in this array.
    uint32_t head;         // Index of next block to allocate (top of stack).
                           // slots[0..head-1] contain available blocks.
                           // head == 0  → empty
                           // head == capacity → full
} ebpf_memory_per_cpu_entry_t;
```

The per-CPU array operates as a **LIFO stack** (push/pop at `head`):

- **Allocate:** `block = slots[--head]`
- **Free:** `slots[head++] = block`

No locks needed because the caller raises IRQL to DISPATCH_LEVEL before accessing the per-CPU entry, which pins the thread to the current CPU.

### 3.3 Global Pool (protected by a spin lock)

```c
typedef struct _ebpf_memory_global_pool
{
    void**         slots;       // Array of pointers to free blocks.
    uint32_t       capacity;    // = N (100% to handle worst case).
    uint32_t       count;       // Number of blocks currently in the global pool.
    KSPIN_LOCK     lock;        // Protects slots[] and count.
} ebpf_memory_global_pool_t;
```

The global pool is the **overflow / underflow reservoir**.  It is accessed:
- During initialization (no contention).
- On the slow path when a per-CPU list is empty or full.
- During asynchronous load-balancing.

A spin lock is acceptable here because the critical section is O(1) for single-block operations and O(K) for batch transfers during rebalancing (K is small, ~tens of blocks).

---

## 4. Algorithms

### 4.1 Initialize (`ebpf_memory_manager_initialize`)

```
Input:  N (block_count), S (block_size)
Output: context C

1.  cpu_count = ebpf_get_cpu_count();

2.  Allocate the context structure C.

3.  Allocate the raw memory for all N blocks in a single contiguous allocation:
       raw = cxplat_allocate(N * S)
    Each block_i starts at raw + i * S.

4.  Allocate global_pool.slots with capacity = N.

5.  For each CPU i in [0, cpu_count):
        a. per_cpu_capacity = ceil(0.80 * N / cpu_count)
           // Ensure sum of per-cpu capacities >= 80% of N.
           // Each per-CPU array has room for its share of blocks.
        b. Allocate per_cpu_entries[i].slots with capacity = per_cpu_capacity.

6.  Distribute blocks:
        a. global_blocks = floor(0.20 * N)
        b. per_cpu_blocks = N - global_blocks
        c. blocks_per_cpu = per_cpu_blocks / cpu_count
           remainder      = per_cpu_blocks % cpu_count

        d. block_index = 0
        e. For each CPU i:
              count_i = blocks_per_cpu + (i < remainder ? 1 : 0)
              For j in [0, count_i):
                  per_cpu_entries[i].slots[j] = raw + block_index * S
                  block_index++
              per_cpu_entries[i].head = count_i   // Stack has count_i items.

        f. For j in [0, global_blocks):
              global_pool.slots[j] = raw + block_index * S
              block_index++
           global_pool.count = global_blocks

7.  Pre-allocate the rebalance work item (cxplat_preemptible_work_item).

8.  Return C.
```

**Capacity sizing rationale:**
- Global pool capacity = N (100%) so it can absorb all blocks in the worst case where every per-CPU list is drained to global.
- Per-CPU capacity is sized to hold its fair share; during rebalancing, blocks are redistributed up to this capacity.

### 4.2 Allocate (`ebpf_memory_manager_allocate`)

```
1.  old_irql = ebpf_raise_irql_to_dispatch_if_needed()
2.  cpu_id = ebpf_get_current_cpu()
3.  entry = context->per_cpu_entries[cpu_id]

4.  IF entry->head > 0:                        // ── Fast Path ──
        block = entry->slots[--entry->head]
        ebpf_lower_irql_from_dispatch_if_needed(old_irql)
        return block

5.  // ── Slow Path 1: per-CPU list is empty, try global pool ──
    KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock)
    IF context->global_pool.count > 0:
        block = context->global_pool.slots[--context->global_pool.count]
        KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock)
        _ebpf_memory_trigger_rebalance(context)     // Async refill
        ebpf_lower_irql_from_dispatch_if_needed(old_irql)
        return block
    KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock)

6.  // ── Slow Path 2: global pool also empty, scavenge from other CPUs ──
    //
    // Blocks may still exist in other CPUs' per-CPU lists due to cross-CPU
    // free patterns (allocated on CPU A, freed on CPU B → block sits in B's
    // list). Without this step the allocation would falsely return NULL even
    // though the system has available blocks.
    //
    // Trigger a *synchronous* rebalance (or inline scavenge) before giving up.
    // Two options are discussed below; Option 6a is recommended.
    //
    // ── Option 6a: Synchronous targeted scavenge (recommended) ──
    //   Lower IRQL, send a synchronous rebalance request via targeted DPCs
    //   to all CPUs (same mechanism as the async rebalance but waited on).
    //   After the rebalance completes, retry from step 1.
    //
    //   ebpf_lower_irql_from_dispatch_if_needed(old_irql)
    //   _ebpf_memory_synchronous_rebalance(context)   // blocks until done
    //   // Retry allocation (go back to step 1).
    //   // If retry also fails → all N blocks are genuinely in use → return NULL.
    //
    // ── Option 6b: Inline steal from a neighbor ──
    //   While still at DISPATCH_LEVEL, peek at other CPUs' head counts via
    //   a volatile read (safe because head is only modified at DISPATCH on
    //   the owning CPU — the read is racy but conservative: we might see a
    //   stale value, never an invalid one).  If a neighbor has blocks, send
    //   a targeted DPC to that specific CPU to transfer K blocks into the
    //   global pool, then retry.
    //
    //   This avoids the cost of touching all CPUs but requires more complex
    //   code and has the race caveat above.
    //
    // After either option, if the retry still fails:

7.  // All N blocks are genuinely in use – allocation fails.
    ebpf_lower_irql_from_dispatch_if_needed(old_irql)
    return NULL
```

#### 4.2.1 Why the Global Pool Can Be Empty While Blocks Exist

Consider an 8-CPU system with 1000 blocks:

```
Initial distribution:
  Per-CPU: 100 blocks each (800 total)
  Global:  200 blocks

Workload: All allocations happen on CPU 0, all frees happen on CPUs 1–7.

After 300 allocations on CPU 0:
  CPU 0:  0 blocks  (exhausted its 100, then drew 200 from global)
  Global: 0 blocks  (drained by CPU 0)
  CPU 1:  140 blocks (original 100 + 40 freed here)
  CPU 2:  130 blocks ...
  ...
  Total available: 700 blocks, but CPU 0 sees 0 locally and 0 in global.
```

Without step 6, the 301st allocation on CPU 0 returns NULL despite 700 free blocks
existing system-wide. The synchronous rebalance in step 6 corrects this by
redistributing blocks before declaring failure.

#### 4.2.2 Synchronous Rebalance Design

```c
static void
_ebpf_memory_synchronous_rebalance(_Inout_ ebpf_memory_manager_t* context)
{
    // 1. Set rebalance_pending to prevent concurrent async rebalances.
    InterlockedExchange(&context->rebalance_pending, 1);

    // 2. Phase 1 – Drain: For each CPU, queue a targeted DPC that moves
    //    excess blocks (head > target) into the global pool.
    //    Wait for all DPCs to complete via KEVENT.

    // 3. Phase 2 – Fill: For each CPU, queue a targeted DPC that pulls
    //    blocks from the global pool to reach target level.
    //    Wait for all DPCs to complete via KEVENT.

    // 4. Clear rebalance_pending.
    InterlockedExchange(&context->rebalance_pending, 0);
}
```

This is called **at most once per allocation** and only on the rare path where both
per-CPU and global are empty. The cost (~16 μs for 8 CPUs) is acceptable because
the alternative is a false allocation failure.

#### 4.2.3 Retry Limit

To avoid an infinite retry loop if all blocks are genuinely in use, the allocate
function retries **exactly once** after the synchronous rebalance:

```
6.  _ebpf_memory_synchronous_rebalance(context)
    // Retry steps 1–5 exactly once.
    old_irql = ebpf_raise_irql_to_dispatch_if_needed()
    entry = context->per_cpu_entries[ebpf_get_current_cpu()]
    IF entry->head > 0:
        block = entry->slots[--entry->head]
        ebpf_lower_irql_from_dispatch_if_needed(old_irql)
        return block
    // Per-CPU still empty after rebalance → check global one more time.
    KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock)
    IF context->global_pool.count > 0:
        block = context->global_pool.slots[--context->global_pool.count]
        KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock)
        ebpf_lower_irql_from_dispatch_if_needed(old_irql)
        return block
    KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock)
7.  // All N blocks are genuinely in use.
    ebpf_lower_irql_from_dispatch_if_needed(old_irql)
    return NULL
```

### 4.3 Free (`ebpf_memory_manager_free`)

```
1.  old_irql = ebpf_raise_irql_to_dispatch_if_needed()
2.  cpu_id = ebpf_get_current_cpu()
3.  entry = context->per_cpu_entries[cpu_id]

4.  IF entry->head < entry->capacity:          // ── Fast Path ──
        entry->slots[entry->head++] = block
        ebpf_lower_irql_from_dispatch_if_needed(old_irql)
        return

5.  // ── Slow Path: per-CPU list is full ──
    KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock)
    ASSERT(context->global_pool.count < context->global_pool.capacity)
    context->global_pool.slots[context->global_pool.count++] = block
    KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock)
    _ebpf_memory_trigger_rebalance(context)         // Async rebalance
    ebpf_lower_irql_from_dispatch_if_needed(old_irql)
```

### 4.4 Uninitialize (`ebpf_memory_manager_uninitialize`)

```
1.  total_returned = global_pool.count
    For each CPU i:
        total_returned += per_cpu_entries[i].head
    ASSERT(total_returned == total_block_count)  // All blocks returned.

2.  Cancel / free the rebalance work item.
3.  cxplat_free(raw_allocation)                  // Single free for all blocks.
4.  Free per_cpu_entries[i].slots for each CPU.
5.  Free global_pool.slots.
6.  Free the context C.
```

---

## 5. Load Balancing

### 5.1 Trigger Conditions

A rebalance is triggered (asynchronously) when either of the following occurs during alloc or free:
1. A per-CPU list becomes **empty** (alloc had to fall back to global pool).
2. A per-CPU list becomes **full** (free had to push to global pool).

### 5.2 Trigger Mechanism

```c
static void
_ebpf_memory_trigger_rebalance(_Inout_ ebpf_memory_manager_t* context)
{
    // Use InterlockedCompareExchange to ensure only one rebalance is in-flight.
    if (InterlockedCompareExchange(&context->rebalance_pending, 1, 0) == 0) {
        cxplat_queue_preemptible_work_item(context->rebalance_work_item);
    }
}
```

The work item runs at PASSIVE_LEVEL on an arbitrary thread.

### 5.3 Load Balancing Proposals

Below are three proposals for the rebalancing algorithm, in increasing order of complexity.

#### Proposal A: Simple Fair-Share Redistribution (Recommended for v1)

**Algorithm:**
```
1.  Compute target = total_available_blocks / cpu_count
    (total_available = global_pool.count + Σ per_cpu[i].head)

2.  Phase 1 – Drain excess from each CPU into the global pool:
    For each CPU i:
        Raise IRQL and set affinity to CPU i (or send a DPC to CPU i).
        excess = per_cpu[i].head - target
        IF excess > 0:
            Transfer min(excess, global_can_absorb) blocks:
                global_pool.slots[count++] = per_cpu[i].slots[--head]
            (Per-CPU side is lock-free; global side under spin lock.)

3.  Phase 2 – Fill deficient CPUs from the global pool:
    For each CPU i:
        Raise IRQL and set affinity to CPU i (or send a DPC to CPU i).
        deficit = target - per_cpu[i].head
        IF deficit > 0:
            Transfer min(deficit, global_pool.count) blocks:
                per_cpu[i].slots[head++] = global_pool.slots[--count]

4.  InterlockedExchange(&context->rebalance_pending, 0)
```

**Per-CPU access without locks:**
Since per-CPU arrays can only be safely modified on their owning CPU, the rebalance worker must execute on each CPU. Two approaches:

- **Option 1 – Targeted DPCs:** Queue a KDPC targeted to each CPU. The DPC runs at DISPATCH_LEVEL on that CPU and performs the transfer. This is the recommended approach because it matches the existing pattern in the epoch module (inter-CPU messaging via `ebpf_timed_work_queue`).

- **Option 2 – Rebalance via the existing epoch messaging system:** Send a custom message type through the `ebpf_timed_work_queue` on each CPU, similar to how `EBPF_EPOCH_CPU_MESSAGE_TYPE_PROPOSE_RELEASE_EPOCH` propagates.

**Pros:** Simple, deterministic, O(cpu_count) messages.  
**Cons:** May over-correct if workload is asymmetric.

#### Proposal B: Watermark-Based Rebalancing

**Algorithm:**
```
Define two watermarks per CPU:
    low_watermark  = 0.25 * per_cpu_capacity
    high_watermark = 0.75 * per_cpu_capacity

1.  For each CPU i (via targeted DPC):
        IF per_cpu[i].head < low_watermark:
            // Refill from global pool.
            refill_count = target_fill - per_cpu[i].head
            // where target_fill = 0.50 * per_cpu_capacity
            Lock global pool.
            Transfer min(refill_count, global_pool.count) blocks to per_cpu[i].
            Unlock global pool.

        ELSE IF per_cpu[i].head > high_watermark:
            // Drain to global pool.
            drain_count = per_cpu[i].head - target_fill
            Lock global pool.
            Transfer drain_count blocks from per_cpu[i] to global pool.
            Unlock global pool.

2.  InterlockedExchange(&context->rebalance_pending, 0)
```

**Pros:** Only moves blocks that are clearly in excess/deficit; avoids thrashing.  
**Cons:** Slightly more complex; watermarks need tuning.

#### Proposal C: Work-Stealing (Most Complex)

**Concept:** Instead of a central rebalance, an empty CPU directly steals from a neighbor.

```
On alloc slow path (per-CPU empty, global also empty):
    For neighbor in [cpu_id+1, cpu_id+2, ..., wrapping]:
        IF per_cpu[neighbor].head > threshold:
            // Send a targeted DPC to neighbor to transfer K blocks.
            break
```

**Pros:** Minimal latency for refill; no global coordination.  
**Cons:** Requires inter-CPU communication for every steal; complex correctness argument around concurrent modification; potential cache-line bouncing on the neighbor's per-CPU entry. Not recommended for v1.

### 5.4 Recommendation

**Proposal B (watermark-based)** was selected for the implementation. It provides better behavior
for asymmetric workloads by only moving blocks that are clearly in excess/deficit, avoiding
thrashing under skewed access patterns. The implementation uses watermarks at 25% (low), 50%
(target), and 75% (high) of per-CPU capacity.

*Note: The original design recommended Proposal A for v1. During implementation, Proposal B was
adopted directly due to its modest additional complexity and better suitability for real workloads.*

---

## 6. Epoch Integration

### 6.1 Current Flow

```
Hash table insert
  └─► ebpf_epoch_allocate_with_tag(value_size, tag)
        └─► cxplat_allocate(value_size + header_size, tag)   // Pool alloc
              └─► Return ptr past header

Hash table delete
  └─► ebpf_epoch_free(value_ptr)
        └─► Stamp freed_epoch on header
        └─► Insert into per-CPU epoch free list
              └─► (later) _ebpf_epoch_release_free_list → cxplat_free(header)
```

### 6.2 Implemented Flow with Memory Manager

```
LRU Hash table create
  └─► Compute value_data_size = value_size + supplemental_value_size
  └─► block_size = ebpf_epoch_memory_manager_block_size(value_data_size)
  └─► block_count = max_entries * 2   // 2x for in-flight deferred frees
  └─► ebpf_memory_manager_initialize(&mgr, block_count, block_size)
  └─► Pass mgr via hash_table_creation_options.memory_manager

Hash table insert (value allocation)
  └─► _ebpf_hash_table_allocate_value(hash_table)
        ├─► ebpf_epoch_try_allocate_from_manager(mgr)  // Non-blocking
        │     └─► ebpf_memory_manager_try_allocate(mgr) // Pool-free fast path
        │           └─► Return pre-allocated block (or NULL if exhausted)
        └─► If NULL: fallback to hash_table->allocate() // Regular epoch alloc

Hash table delete/update (value free, deferred)
  └─► _ebpf_hash_table_free_value(hash_table, ptr)
        ├─► Check ebpf_epoch_managed_block_belongs_to_manager(mgr, ptr)
        ├─► If owned: ebpf_epoch_free_to_manager(mgr, ptr)  // Deferred
        │     └─► (later) _ebpf_epoch_release_free_list
        │           └─► ebpf_memory_manager_free(mgr, block) // Return to pool
        └─► If not owned: hash_table->free(ptr)  // Regular epoch free

Hash table destroy (immediate free, no concurrent readers)
  └─► _ebpf_hash_table_free_value_immediate(hash_table, ptr)
        ├─► If owned: ebpf_epoch_free_to_manager_immediate(mgr, ptr)
        │     └─► ebpf_memory_manager_free(mgr, block) // Direct return
        └─► If not owned: hash_table->free(ptr)

LRU Hash table destroy
  └─► ebpf_hash_table_destroy()   // Immediate frees for remaining entries
  └─► Schedule epoch work item: _ebpf_memory_manager_deferred_uninitialize
        └─► (later, after all epoch-deferred frees complete)
              └─► ebpf_memory_manager_uninitialize(mgr)
```

**Key design decisions:**

1. **Non-blocking allocation (`try_allocate`):** The hash table uses `ebpf_epoch_try_allocate_from_manager`
   which never triggers a synchronous rebalance. If the pool is temporarily exhausted (blocks held by
   epoch-deferred frees), the hash table falls back to `ebpf_epoch_allocate_with_tag`.

2. **Ownership-based free routing:** Since fallback allocations come from the regular pool allocator,
   the free path must determine whether a block belongs to the memory manager or was allocated via
   fallback. `ebpf_epoch_managed_block_belongs_to_manager` checks if the block's raw pointer falls
   within the memory manager's contiguous allocation range.

3. **Immediate free during destroy:** `ebpf_hash_table_destroy` uses `_ebpf_hash_table_free_value_immediate`
   which returns blocks directly to the memory manager (bypassing epoch deferral). This is safe because
   there are no concurrent readers during destroy.

4. **Deferred memory manager teardown:** The memory manager cannot be uninitialized immediately in the
   map's delete path because previously-deleted entries may still be in the epoch free list. The map
   delete is itself called from an epoch work item, so calling `ebpf_epoch_synchronize()` would deadlock.
   Instead, an epoch work item is scheduled to uninitialize the memory manager after all pending
   epoch-deferred frees have been processed.

### 6.3 Epoch Allocation Header Extension

A new allocation type is added:

```c
typedef enum _ebpf_epoch_allocation_type
{
    EBPF_EPOCH_ALLOCATION_MEMORY,
    EBPF_EPOCH_ALLOCATION_WORK_ITEM,
    EBPF_EPOCH_ALLOCATION_SYNCHRONIZATION,
    EBPF_EPOCH_ALLOCATION_MEMORY_CACHE_ALIGNED,
    EBPF_EPOCH_ALLOCATION_MANAGED,               // NEW
} ebpf_epoch_allocation_type_t;
```

The `ebpf_epoch_allocation_header_t` is **not** prepended by the memory manager itself (the blocks are pre-allocated without headers). Instead, the **epoch layer** allocates a small header wrapper or embeds the header at the start of each managed block.

**Design option (recommended):** Reserve `sizeof(ebpf_epoch_allocation_header_t)` at the **beginning of each pre-allocated block**. The block size passed to `ebpf_memory_manager_initialize` is `user_size + sizeof(ebpf_epoch_allocation_header_t)`. The epoch layer then:
- On allocate: gets a block from the manager, initializes the header, returns `block + sizeof(header)` to the caller.
- On free: receives `ptr`, backs up to header, stamps `freed_epoch`, inserts into the epoch free list.
- On epoch release: recognizes `EBPF_EPOCH_ALLOCATION_MANAGED`, calls `ebpf_memory_manager_free(mgr, block)` instead of `cxplat_free`.

This keeps the managed header inline with the block, preserving cache locality and avoiding a separate header allocation.

### 6.4 New Epoch APIs

```c
// Stored in the epoch header for managed allocations.
// Allows the release path to call back into the correct manager.
typedef struct _ebpf_epoch_managed_allocation_header
{
    ebpf_epoch_allocation_header_t base;
    ebpf_memory_manager_t* manager;         // Back-pointer to owning manager.
} ebpf_epoch_managed_allocation_header_t;

// Allocate a block from a memory manager, under epoch control.
// Uses ebpf_memory_manager_allocate (may trigger synchronous rebalance).
_Must_inspect_result_
_Ret_writes_maybenull_(block_size) void*
ebpf_epoch_allocate_from_manager(_Inout_ ebpf_memory_manager_t* manager);

// Non-blocking variant — uses ebpf_memory_manager_try_allocate.
// Returns NULL immediately if pool is exhausted, without synchronous rebalance.
_Must_inspect_result_
_Ret_writes_maybenull_(block_size) void*
ebpf_epoch_try_allocate_from_manager(_Inout_ ebpf_memory_manager_t* manager);

// Free a block back to a memory manager, under epoch control (deferred).
void
ebpf_epoch_free_to_manager(
    _Inout_ ebpf_memory_manager_t* manager,
    _Frees_ptr_ void* block);

// Free a block back to a memory manager immediately (non-deferred).
// Use only when there are no concurrent readers (e.g., during hash table destroy).
void
ebpf_epoch_free_to_manager_immediate(
    _Inout_ ebpf_memory_manager_t* manager,
    _Frees_ptr_ void* block);

// Compute the memory manager block size needed for a given usable payload size.
// Includes the internal epoch managed allocation header.
size_t
ebpf_epoch_memory_manager_block_size(size_t usable_size);

// Check if a user-visible block (as returned by ebpf_epoch_allocate_from_manager)
// belongs to the given memory manager's pool.
bool
ebpf_epoch_managed_block_belongs_to_manager(
    _In_ const ebpf_memory_manager_t* manager,
    _In_ const void* block);
```

### 6.5 Changes to `_ebpf_epoch_release_free_list`

Add a case for the new type:

```c
case EBPF_EPOCH_ALLOCATION_MANAGED: {
    ebpf_epoch_managed_allocation_header_t* managed_header =
        CONTAINING_RECORD(header, ebpf_epoch_managed_allocation_header_t, base);
    ebpf_memory_manager_free(managed_header->manager, managed_header);
    break;
}
```

### 6.6 Hash Table Integration

The hash table natively supports an optional memory manager for value data allocations.

**Changes to `ebpf_hash_table_creation_options_t`:**

```c
typedef struct _ebpf_hash_table_creation_options
{
    // ... existing fields ...
    ebpf_memory_manager_t* memory_manager; // Optional memory manager for value data.
                                           // When set, value allocations use the pool.
                                           // Bucket allocations always use the regular allocator.
} ebpf_hash_table_creation_options_t;
```

**Changes to `ebpf_hash_table_t` (internal):**

A `memory_manager` pointer is stored in the hash table struct. Three internal helpers route
value allocations and frees:

```c
// Allocate value data: try memory manager first, fall back to regular allocator.
static void* _ebpf_hash_table_allocate_value(const ebpf_hash_table_t* hash_table)
{
    if (hash_table->memory_manager) {
        void* block = ebpf_epoch_try_allocate_from_manager(hash_table->memory_manager);
        if (block != NULL) return block;
        // Pool exhausted — fall back to regular allocator.
    }
    return hash_table->allocate(hash_table->value_size + hash_table->supplemental_value_size,
                                hash_table->allocation_tag);
}

// Free value data: check ownership to route correctly.
static void _ebpf_hash_table_free_value(const ebpf_hash_table_t* hash_table, void* value)
{
    if (hash_table->memory_manager &&
        ebpf_epoch_managed_block_belongs_to_manager(hash_table->memory_manager, value))
        ebpf_epoch_free_to_manager(hash_table->memory_manager, value);
    else
        hash_table->free(value);
}

// Immediate free for use during ebpf_hash_table_destroy (no concurrent readers).
static void _ebpf_hash_table_free_value_immediate(const ebpf_hash_table_t* hash_table, void* value)
{
    if (hash_table->memory_manager &&
        ebpf_epoch_managed_block_belongs_to_manager(hash_table->memory_manager, value))
        ebpf_epoch_free_to_manager_immediate(hash_table->memory_manager, value);
    else
        hash_table->free(value);
}
```

**Ownership check rationale:** When the memory manager pool is temporarily exhausted (blocks held by
epoch-deferred frees), the allocator falls back to `ebpf_epoch_allocate_with_tag`. These fallback blocks
live outside the memory manager's contiguous allocation. The free path must check ownership to route
each block to the correct free function. `ebpf_epoch_managed_block_belongs_to_manager` performs this
check by verifying the block's raw pointer falls within `[raw_allocation, raw_allocation + N * block_size)`.

### 6.7 LRU Hash Table Integration

The LRU hash table (`BPF_MAP_TYPE_LRU_HASH` and `BPF_MAP_TYPE_LRU_PERCPU_HASH`) is the first
consumer of the memory manager. Regular `BPF_MAP_TYPE_HASH` maps are unchanged.

**Creation (`_create_lru_hash_map`):**

```c
// Compute the block size: epoch managed header + value + supplemental (LRU metadata).
size_t value_data_size = map_definition->value_size + supplemental_value_size;
size_t block_size = ebpf_epoch_memory_manager_block_size(value_data_size);

// Allocate 2x max_entries to handle in-flight deferred frees during update operations.
uint32_t block_count = map_definition->max_entries * 2;
ebpf_memory_manager_initialize(&memory_manager, block_count, block_size);

// Pass to hash table via options.
options.memory_manager = memory_manager;
```

**Why 2x `max_entries`:** When a value is updated, the new value is allocated before the old value
is freed (deferred via epoch). Both temporarily consume a block. Under rapid updates, multiple old
values can accumulate in the epoch free list. The 2x factor provides headroom for this transient
state. If the pool is still exhausted, the fallback allocator handles the overflow.

**Deletion (`_delete_lru_hash_map`):**

```c
static void _delete_lru_hash_map(ebpf_core_map_t* map)
{
    ebpf_core_lru_map_t* lru_map = ...;
    ebpf_memory_manager_t* memory_manager = lru_map->memory_manager;

    // Destroy hash table — remaining entries freed immediately (non-deferred).
    ebpf_hash_table_destroy(lru_map->core_map.data);
    ebpf_epoch_free_cache_aligned(map);

    // Schedule deferred memory manager teardown via epoch work item.
    // This ensures all prior epoch-deferred frees have been processed
    // before the memory manager is uninitialized.
    if (memory_manager) {
        ebpf_epoch_work_item_t* work_item = ebpf_epoch_allocate_work_item(
            memory_manager, _ebpf_memory_manager_deferred_uninitialize);
        ebpf_epoch_schedule_work_item(work_item);
    }
}
```

**Why deferred teardown:** The map's delete function is called from an epoch work item (the object's
ref-count-zeroed callback). Calling `ebpf_epoch_synchronize()` from this context would deadlock.
Previously-deleted entries may still be in the epoch free list as deferred frees. Scheduling the
memory manager uninitialize as an epoch work item ensures it runs after those deferred frees complete.

---

## 7. Concurrency Model

| Operation | IRQL | Synchronization |
|-----------|------|-----------------|
| Per-CPU alloc/free (fast path) | DISPATCH_LEVEL | None needed – CPU affinity at DISPATCH prevents preemption and migration. |
| Global pool access (slow path) | DISPATCH_LEVEL | `KSPIN_LOCK` (`KeAcquireSpinLockAtDpcLevel`). |
| Rebalance trigger | DISPATCH_LEVEL | `InterlockedCompareExchange` on `rebalance_pending` flag. |
| Rebalance execution | DISPATCH_LEVEL (DPC per CPU) | Per-CPU portion is lock-free (runs on owning CPU). Global portion under spin lock. |
| Initialize / Uninitialize | PASSIVE_LEVEL | Single-threaded by contract (startup/shutdown). |

### 7.1 Why No Locks on Per-CPU Data

The pattern mirrors the existing epoch module:

1. Caller raises IRQL to DISPATCH_LEVEL via `ebpf_raise_irql_to_dispatch_if_needed()`.
2. At DISPATCH_LEVEL, the thread is pinned to the current CPU and cannot be preempted by another thread on the same CPU.
3. The per-CPU `slots[]` array and `head` index are only ever accessed by code running on that CPU at DISPATCH_LEVEL.
4. The rebalance worker accesses each CPU's data by running a targeted DPC on that specific CPU.

Therefore, no locks or atomics are needed for per-CPU state.

---

## 8. Memory Layout

All N blocks are allocated in a single contiguous region for cache-friendliness and to minimize fragmentation:

```
┌─────────────────────────────────────────────────────────┐
│                    raw_allocation                       │
│                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐    ┌──────────┐│
│  │ Block  0 │ │ Block  1 │ │ Block  2 │ ...│ Block N-1││
│  │ (S bytes)│ │ (S bytes)│ │ (S bytes)│    │ (S bytes)││
│  └──────────┘ └──────────┘ └──────────┘    └──────────┘│
│                                                         │
│  S includes epoch header + usable payload               │
└─────────────────────────────────────────────────────────┘
```

Within each block (when used with epoch integration):

```
┌───────────────────────────────────────────────┐
│     ebpf_epoch_managed_allocation_header_t    │
│  ┌──────────────────────────────────────────┐ │
│  │ list_entry  | freed_epoch | entry_type   │ │
│  │ manager*                                 │ │
│  └──────────────────────────────────────────┘ │
│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│            Usable payload                     │
│        (returned to caller)                   │
└───────────────────────────────────────────────┘
```

---

## 9. Per-CPU Array as LIFO Stack

The per-CPU array operates as a simple index-based stack:

```
slots:  [ ptr3 | ptr7 | ptr1 | ---- | ---- ]
                        ^head=3

Allocate: head-- → return slots[2] (ptr1)
          [ ptr3 | ptr7 | ---- | ---- | ---- ]
                   ^head=2

Free(ptrX): slots[head] = ptrX → head++
          [ ptr3 | ptr7 | ptrX | ---- | ---- ]
                          ^head=3
```

This gives O(1) alloc and free with excellent cache behavior (sequential access near the top of the stack).

---

## 10. Failure Modes & Edge Cases

| Scenario | Behavior |
|----------|----------|
| All N blocks in use | `ebpf_memory_manager_allocate` returns `NULL`. Caller handles as out-of-memory. Before returning NULL, a synchronous rebalance is attempted to scavenge blocks from other CPUs (see Section 4.2 step 6). NULL is only returned when all N blocks are genuinely in use system-wide. |
| Per-CPU and global empty, but blocks on other CPUs | Synchronous rebalance (Section 4.2.2) redistributes blocks from full CPUs into the requesting CPU's list and global pool. Allocation is retried once after rebalance. This prevents false allocation failures caused by cross-CPU free patterns. |
| Free called on wrong manager | Undefined behavior. Debug builds can validate by checking if the block address falls within `[raw_allocation, raw_allocation + N*S)`. |
| Uninitialize with outstanding blocks | `ASSERT` fires. All blocks must be returned before teardown. With epoch integration, caller must call `ebpf_epoch_synchronize()` first to drain deferred frees. |
| Rebalance fails to run | Alloc/free still work via global pool fallback. Next alloc/free will re-trigger rebalance. The `rebalance_pending` flag prevents queue flooding. |
| Single-CPU system | `cpu_count = 1`. Per-CPU array gets 80% of blocks, global gets 20%. Rebalancing is a no-op (only one CPU). |

---

## 11. File Structure

```
libs/runtime/
├── ebpf_memory.h       // Public API: initialize, allocate, try_allocate, free, uninitialize, owns_block
├── ebpf_memory.c       // Implementation: per-CPU arrays, global pool, watermark-based rebalancing
├── ebpf_epoch.h        // Extended with epoch-managed allocation APIs
├── ebpf_epoch.c        // Extended _ebpf_epoch_release_free_list with MANAGED case
├── ebpf_hash_table.h   // Extended with optional memory_manager field in creation options
├── ebpf_hash_table.c   // Value alloc/free routed through memory manager when set

libs/execution_context/
├── ebpf_maps.c         // LRU hash map creation/deletion uses memory manager
```

---

## 12. Testing Strategy

| Test | Description |
|------|-------------|
| Basic alloc/free | Initialize(N=100, S=64). Allocate 100 blocks, free 100 blocks, uninitialize. |
| Over-allocation | Allocate N+1 blocks; verify N+1th returns NULL. |
| Cross-CPU free | Allocate on CPU 0, free on CPU 1. Verify block lands in CPU 1's per-CPU list or global pool. |
| Rebalance trigger | Allocate all blocks from CPU 0 (draining its per-CPU list), verify rebalance runs and refills. |
| Epoch integration | Use `ebpf_epoch_allocate_from_manager` / `ebpf_epoch_free_to_manager`. Verify deferred reclamation works (block not returned to pool until epoch advances). |
| Stress test | Multi-threaded alloc/free storm across all CPUs. Verify no corruption, no leaks. |
| Uninitialize assertion | Free only N-1 blocks, then uninitialize. Verify assertion fires. |

### 12.1 Unit Tests

All unit tests run under usersim (user-mode simulation of kernel APIs) and use Catch2. Each test initializes and uninitializes its own `ebpf_memory_manager_t` instance. Tests use `ebpf_set_current_thread_affinity()` to pin threads to specific CPUs.

#### 12.1.1 Single Thread – All Allocations on a Single CPU

**Test:** `memory_manager_single_cpu_alloc_free`

```
1. Initialize manager with N=100, S=64 on a system with P CPUs.
2. Pin thread to CPU 0.
3. Allocate N blocks, storing each returned pointer.
4. Verify all N pointers are non-NULL and unique.
5. Verify allocation N+1 returns NULL (pool exhausted).
6. Free all N blocks (still pinned to CPU 0).
7. Allocate N blocks again – verify all succeed (blocks recycled).
8. Free all N blocks.
9. Uninitialize – verify assertion passes (all blocks returned).
```

**Validates:** Fast-path alloc/free on a single per-CPU list; LIFO stack correctness; exhaustion returns NULL; blocks are reusable after free.

#### 12.1.2 Single Thread – Allocate on CPU 0, Free on CPU 1

**Test:** `memory_manager_cross_cpu_free`

```
1. Initialize manager with N=100, S=64.
2. Pin thread to CPU 0.
3. Allocate 2 blocks (block_a, block_b) on CPU 0.
4. Re-pin thread to CPU 1.
5. Free block_a on CPU 1.
6. Free block_b on CPU 1.
7. Verify: block_a and block_b are now in CPU 1's per-CPU list
   (or in the global pool if CPU 1's list was full).
8. Re-pin thread to CPU 1. Allocate 2 blocks – verify one or both
   of {block_a, block_b} are returned (LIFO recycling on CPU 1).
9. Free all outstanding blocks, uninitialize.
```

**Validates:** Cross-CPU free path; blocks migrate to the freeing CPU's per-CPU list; freed blocks are allocatable from the new CPU.

#### 12.1.3 Single Thread – Alloc-Alloc-Free Loop on a Single CPU

**Test:** `memory_manager_alloc_alloc_free_loop`

```
1. Initialize manager with N=100, S=64.
2. Pin thread to CPU 0.
3. Repeat 1000 iterations:
     a. Allocate block_a.
     b. Allocate block_b.
     c. Free block_a.
     d. Verify block_b is still valid (write + read a known pattern).
4. Free all remaining outstanding blocks.
5. Uninitialize – verify all N blocks returned.
```

**Validates:** Interleaved alloc/free does not corrupt the LIFO stack; partial free does not affect other live blocks; head index stays consistent across mixed operations; no leaks after many iterations.

#### 12.1.4 Multiple Threads – Parallel Allocations on Different CPUs

**Test:** `memory_manager_parallel_alloc_different_cpus`

```
1. Initialize manager with N=800, S=64 on P=4 CPUs.
   (Per-CPU capacity ≈ 160 each, global ≈ 160.)
2. Launch P threads, one per CPU (thread i pinned to CPU i).
3. Each thread allocates 100 blocks, stores pointers in a thread-local array.
4. Barrier – wait for all threads to complete allocation phase.
5. Verify: total of P×100 allocations succeeded (no NULLs).
6. Verify: no pointer appears in more than one thread's array (no duplicates
   across CPUs).
7. Each thread frees its 100 blocks (still pinned to its CPU).
8. Barrier – wait for all threads to complete free phase.
9. Uninitialize – verify all N blocks returned.
```

**Validates:** Per-CPU fast paths operate independently without contention; no cross-CPU corruption under parallel load; each CPU's LIFO stack is isolated.

#### 12.1.5 Multiple Threads – Parallel Allocs and Frees on Multiple CPUs

**Test:** `memory_manager_parallel_alloc_free_stress`

```
1. Initialize manager with N=1000, S=64 on P=4 CPUs.
2. Launch P threads, each pinned to a different CPU.
3. Each thread runs 10,000 iterations:
     a. Allocate a block. If NULL, skip to (c).
     b. Write a per-thread marker pattern into the block.
     c. With 50% probability, pick a random previously allocated block
        (from this thread's list) and free it.
4. After the loop, each thread frees all remaining blocks it holds.
5. Barrier – wait for all threads.
6. Uninitialize – verify all N blocks returned.
7. Verify: no block ever contained a corrupted marker (i.e., no block was
   handed out to two threads simultaneously).
```

**Validates:** Concurrent alloc/free across CPUs under contention; global pool spin lock correctness; rebalance triggers function correctly; no double-allocation, no use-after-free, no leaks.

#### 12.1.6 Additional Corner-Case Unit Tests

| Test Name | Description |
|-----------|-------------|
| `memory_manager_zero_blocks` | Initialize with N=0. Verify allocate immediately returns NULL. Uninitialize succeeds. |
| `memory_manager_single_block` | Initialize with N=1. Allocate succeeds, second allocate returns NULL, free, re-allocate succeeds. |
| `memory_manager_single_cpu_system` | Initialize on a 1-CPU system (or mock `ebpf_get_cpu_count()=1`). Verify all alloc/free works without rebalance issues. Global pool has 20% of blocks, per-CPU has 80%. |
| `memory_manager_exhaust_and_rebalance` | Pin to CPU 0, allocate until per-CPU list and global pool are empty (blocks exist on other CPUs from prior cross-CPU frees). Verify synchronous rebalance fires and allocation succeeds. |
| `memory_manager_free_wrong_block` | (Debug build only) Free a pointer not within `[raw_allocation, raw_allocation + N*S)`. Verify assertion fires or error is returned. |
| `memory_manager_uninitialize_outstanding` | Allocate N blocks, free only N-1, call uninitialize. Verify assertion fires (debug) indicating a leak. |
| `memory_manager_double_free` | (Debug build only) Free the same block twice. Verify assertion fires or corruption is detected. |
| `memory_manager_alloc_after_uninitialize` | Uninitialize the manager, then attempt allocate. Verify crash or assertion (use-after-free detection in debug builds). |
| `memory_manager_rebalance_no_op_single_cpu` | On a 1-CPU system, trigger a rebalance. Verify it completes without error and block distribution is unchanged. |
| `memory_manager_cross_cpu_free_triggers_rebalance` | Allocate all blocks on CPU 0, free all on CPU 1 (filling CPU 1's list). Allocate on CPU 0 – per-CPU empty, global empty. Verify synchronous rebalance scavenges blocks from CPU 1 and allocation succeeds. |
| `memory_manager_epoch_integration_deferred_free` | Use `ebpf_epoch_allocate_from_manager` to allocate a block. Call `ebpf_epoch_free_to_manager` to free it. Verify the block is NOT returned to the pool until the epoch advances. Advance epoch, verify block is back in the pool. |
| `memory_manager_epoch_integration_multiple_epochs` | Allocate and free blocks across multiple epoch generations. Verify blocks are reclaimed in the correct epoch order and all are eventually returned. |
| `memory_manager_large_block_size` | Initialize with S=4096 (page-sized blocks) and N=16. Run basic alloc/free cycle. Verify correctness with large block sizes. |
| `memory_manager_contiguous_allocation_check` | After initialize, verify all N block pointers are contiguous (each at offset `i * S` from `raw_allocation`). Confirms single contiguous allocation layout. |

### 12.2 Performance Tests

Performance tests measure allocation and free latencies under controlled conditions, compute percentile distributions, and compare against the baseline on-demand allocator (`cxplat_allocate`/`cxplat_free`). These tests run using the `ebpf_performance` test infrastructure.

#### 12.2.1 Methodology

```
For each test scenario:
  1. Initialize the memory manager (excluded from timing).
  2. Warm up: run 1,000 alloc/free cycles (excluded from timing).
  3. Measurement phase: run M iterations (M=100,000 or more).
     - Record the timestamp (via QueryPerformanceCounter or KeQueryPerformanceCounter)
       before and after each allocate and each free call.
     - Store per-operation latencies in a pre-allocated array.
  4. Compute statistics from the latency array:
       - p50, p90, p99, p99.9, p99.99 percentiles
       - min, max, mean, standard deviation
  5. Run the same scenario using cxplat_allocate/cxplat_free as baseline.
  6. Report results as a comparison table.
```

**Timer requirements:**
- Use high-resolution performance counter (`QueryPerformanceCounter` in user-mode, `KeQueryPerformanceCounter` in kernel-mode).
- Ensure timer granularity is ≤ 100 ns. If not, batch multiple operations and divide.

#### 12.2.2 Test Scenarios

##### Scenario P1: Single-CPU Sequential Alloc/Free

```
Setup: N=10,000, S=64, pin thread to CPU 0.
Loop M times:
    t0 = now()
    block = ebpf_memory_manager_allocate(mgr)
    t1 = now()
    ebpf_memory_manager_free(mgr, block)
    t2 = now()
    alloc_latencies[i] = t1 - t0
    free_latencies[i]  = t2 - t1

Baseline: Same loop with cxplat_allocate / cxplat_free.
Report: Percentile table for alloc and free latencies (MM vs baseline).
```

##### Scenario P2: Single-CPU Burst Allocation Then Burst Free

```
Setup: N=10,000, S=64, pin thread to CPU 0.
Phase 1 – Allocate burst:
    For i in [0, N):
        t0 = now()
        blocks[i] = ebpf_memory_manager_allocate(mgr)
        t1 = now()
        alloc_latencies[i] = t1 - t0
Phase 2 – Free burst:
    For i in [0, N):
        t0 = now()
        ebpf_memory_manager_free(mgr, blocks[i])
        t1 = now()
        free_latencies[i] = t1 - t0

Baseline: Same with cxplat_allocate / cxplat_free.
Report: Percentile table. Note latency changes as per-CPU list drains
        and global pool fallback kicks in.
```

##### Scenario P3: Multi-CPU Parallel Alloc/Free Throughput

```
Setup: N=10,000, S=64, P threads each pinned to a different CPU.
Each thread runs M/P iterations:
    t0 = now()
    block = ebpf_memory_manager_allocate(mgr)
    t1 = now()
    ebpf_memory_manager_free(mgr, block)
    t2 = now()
    alloc_latencies[thread][i] = t1 - t0
    free_latencies[thread][i]  = t2 - t1

Baseline: Same with cxplat_allocate / cxplat_free.
Report: Per-thread and aggregate percentile tables.
        Measure total wall-clock time for aggregate throughput (ops/sec).
```

##### Scenario P4: Cross-CPU Alloc/Free (Asymmetric Workload)

```
Setup: N=10,000, S=64, 2 threads.
Thread A (pinned to CPU 0): Allocates blocks, pushes to shared queue.
Thread B (pinned to CPU 1): Pops blocks from shared queue, frees them.

Thread A loop (M iterations):
    t0 = now()
    block = ebpf_memory_manager_allocate(mgr)
    t1 = now()
    alloc_latencies[i] = t1 - t0
    enqueue(block)

Thread B loop (M iterations):
    block = dequeue()  // wait if empty
    t0 = now()
    ebpf_memory_manager_free(mgr, block)
    t1 = now()
    free_latencies[i] = t1 - t0

Baseline: Same with cxplat_allocate / cxplat_free.
Report: Separate alloc/free percentile tables.
        Track how often slow path (global pool fallback) is hit.
        Track rebalance trigger count during the test.
```

##### Scenario P5: Multi-CPU Contended Alloc/Free (Near Exhaustion)

```
Setup: N=P*10 (just enough blocks per CPU), S=64, P threads.
Each thread runs M iterations:
    block = ebpf_memory_manager_allocate(mgr)
    if block != NULL:
        // Hold block for a random short duration.
        ebpf_memory_manager_free(mgr, block)
    Record alloc latency and whether NULL was returned.

Report: Percentile table for alloc latency.
        Count of NULL returns (allocation failures).
        Count of global pool fallbacks and rebalance triggers.
```

#### 12.2.3 Reporting Format

Each scenario produces a table like:

```
Scenario: P1 – Single-CPU Sequential Alloc/Free (M=100,000, N=10,000, S=64)

                  Memory Manager          cxplat_allocate         Speedup
             ┌────────────────────┬────────────────────┬──────────────────┐
  Allocate   │                    │                    │                  │
    min      │            X ns    │            X ns    │       X.Xx       │
    p50      │            X ns    │            X ns    │       X.Xx       │
    p90      │            X ns    │            X ns    │       X.Xx       │
    p99      │            X ns    │            X ns    │       X.Xx       │
    p99.9    │            X ns    │            X ns    │       X.Xx       │
    p99.99   │            X ns    │            X ns    │       X.Xx       │
    max      │            X ns    │            X ns    │       X.Xx       │
    mean     │            X ns    │            X ns    │       X.Xx       │
    stddev   │            X ns    │            X ns    │                  │
  ───────────┼────────────────────┼────────────────────┼──────────────────┤
  Free       │                    │                    │                  │
    min      │            X ns    │            X ns    │       X.Xx       │
    p50      │            X ns    │            X ns    │       X.Xx       │
    ...      │                    │                    │                  │
             └────────────────────┴────────────────────┴──────────────────┘

  Throughput:  MM: X,XXX,XXX ops/sec    Baseline: X,XXX,XXX ops/sec
  Slow-path hits:  global fallback: X    rebalance triggers: X
```

#### 12.2.4 Success Criteria

| Metric | Target |
|--------|--------|
| Fast-path alloc p50 | ≤ 50 ns |
| Fast-path free p50 | ≤ 50 ns |
| Fast-path alloc p99 | ≤ 200 ns |
| Speedup vs `cxplat_allocate` at p50 | ≥ 5x |
| Slow-path (global fallback) frequency | ≤ 5% of total allocations |
| Synchronous rebalance frequency | ≤ 0.1% of total allocations |
| Zero allocation failures | When total outstanding blocks < N |

---

## 13. Summary of Changes

| Component | Change |
|-----------|--------|
| **New: `ebpf_memory.h`** | Public API for memory manager (initialize, allocate, try_allocate, free, uninitialize, owns_block). |
| **New: `ebpf_memory.c`** | Full implementation including per-CPU arrays, global pool, watermark-based load balancing (Proposal B), global-only mode for small block counts. |
| **`ebpf_epoch.c`** | Add `EBPF_EPOCH_ALLOCATION_MANAGED` case in `_ebpf_epoch_release_free_list`. Add `ebpf_epoch_allocate_from_manager`, `ebpf_epoch_try_allocate_from_manager`, `ebpf_epoch_free_to_manager`, `ebpf_epoch_free_to_manager_immediate`, `ebpf_epoch_memory_manager_block_size`, `ebpf_epoch_managed_block_belongs_to_manager`. |
| **`ebpf_epoch.h`** | Declare new epoch APIs. Extend `ebpf_epoch_allocation_type_t` enum. |
| **`ebpf_hash_table.h`** | Add optional `memory_manager` field to `ebpf_hash_table_creation_options_t`. |
| **`ebpf_hash_table.c`** | Add `memory_manager` to hash table struct. Route value allocations through memory manager with fallback. Ownership-based free routing. Immediate free during destroy. |
| **`ebpf_maps.c`** | LRU hash map (`BPF_MAP_TYPE_LRU_HASH`, `BPF_MAP_TYPE_LRU_PERCPU_HASH`) creates memory manager with 2x `max_entries` blocks. `_delete_lru_hash_map` uses deferred epoch work item for memory manager teardown. `ebpf_core_lru_map_t` gains `memory_manager` field. Regular `BPF_MAP_TYPE_HASH` is unchanged. |

---

## Appendix A: Rebalance Sequence Diagram (Proposal A)

```
Alloc on CPU 2 finds per-CPU list empty
  │
  ▼
  Takes one block from global pool (under spin lock)
  │
  ▼
  Calls _ebpf_memory_trigger_rebalance()
  │   InterlockedCompareExchange(&rebalance_pending, 1, 0) == 0  → queue work item
  │
  ▼
  Work item runs at PASSIVE_LEVEL
  │
  ├── Compute target = total_available / cpu_count
  │
  ├── Phase 1: For each CPU i (via targeted DPC on CPU i):
  │     IF per_cpu[i].head > target:
  │       excess = head - target
  │       Lock global pool
  │       Move 'excess' blocks: per_cpu → global
  │       Unlock global pool
  │
  ├── Phase 2: For each CPU i (via targeted DPC on CPU i):
  │     IF per_cpu[i].head < target:
  │       deficit = target - head
  │       Lock global pool
  │       Move 'deficit' blocks: global → per_cpu
  │       Unlock global pool
  │
  └── InterlockedExchange(&rebalance_pending, 0)
```

## Appendix B: Comparison with Existing Patterns

| Aspect | Epoch Free List | Memory Manager |
|--------|----------------|----------------|
| Allocation source | `cxplat_allocate` (pool) every time | Pre-allocated pool; zero pool calls on fast path |
| Per-CPU structure | Linked list (`ebpf_list_entry_t`) | Index-based array (LIFO stack) |
| Synchronization | DISPATCH_LEVEL exclusion | Same for per-CPU; spin lock for global pool |
| Block size | Variable | Fixed (per manager instance) |
| Reclamation | Epoch-based deferred free | Immediate return to pool (epoch defers the return) |
| Inter-CPU messaging | `ebpf_timed_work_queue` | Targeted DPCs (or reuse `ebpf_timed_work_queue`) |

## Appendix C: Performance Analysis

This section compares the memory manager (pool-based) approach against the current on-demand allocation (`cxplat_allocate` / `ExAllocatePool2`) across steady-state and corner-case scenarios.

### C.1 Cost Model: Per-Operation Breakdown

| Operation | On-Demand (`cxplat_allocate`) | MM – Fast Path | MM – Slow Path 1 (global fallback) | MM – Slow Path 1 + Async Rebalance | MM – Slow Path 2 (sync rebalance) |
|-----------|-------------------------------|----------------|-------------------------------------|-------------------------------------|------------------------------------|
| **Allocate** | ~200–800 ns | ~10–20 ns (index decrement + pointer load at DISPATCH) | ~50–100 ns (spin lock on global pool) | ~50–100 ns + async DPC cost amortized | ~16–30 μs (synchronous DPC to all CPUs + retry). Rare: only when both per-CPU and global are empty but blocks exist on other CPUs. |
| **Free** | ~150–500 ns | ~10–20 ns (index increment + pointer store at DISPATCH) | ~50–100 ns (spin lock on global pool) | ~50–100 ns + async DPC cost amortized | N/A (free never triggers sync rebalance) |

The allocate path has **four tiers**, each progressively more expensive but also progressively rarer:

| Tier | Path | Estimated Latency | Expected Frequency |
|------|------|-------------------|--------------------|
| 1 | Per-CPU fast path | ~10–20 ns | ~98–99% of allocations |
| 2 | Global pool fallback + async rebalance | ~50–100 ns | ~1–2% of allocations |
| 3 | Synchronous rebalance + retry | ~16–30 μs | <0.01% of allocations (only under severe cross-CPU imbalance) |
| 4 | All N blocks in use → return NULL | ~16–30 μs (sync rebalance ran, confirmed nothing available) | Depends on sizing of N |

**Key takeaway:** The fast path is **10–40x faster** than on-demand allocation because it avoids the kernel pool allocator entirely — no spin locks, no free-list traversal, no page-table manipulation. Even the rare synchronous rebalance path (~16 μs) compares favorably when amortized: if it fires once per 10,000 allocations, the amortized impact is ~1.6 ns per allocation.

### C.2 Steady-State Performance

**Scenario:** Hash table with uniform insert/delete rate across all CPUs.

```
On-Demand:
  Insert: raise IRQL → pool lock → scan free list → allocate → lower IRQL
  Delete: epoch_free stamps header → (later) raise IRQL → pool lock → return to pool → lower IRQL
  Total per insert+delete cycle: ~400–1300 ns

Memory Manager:
  Insert: raise IRQL → slots[--head] → lower IRQL
  Delete: epoch_free stamps header → (later) slots[head++] = block
  Total per insert+delete cycle: ~20–40 ns
```

**With 100K ops/sec across 8 CPUs:**

| Metric | On-Demand | Memory Manager |
|--------|-----------|----------------|
| CPU cycles per op (est.) | 600–2400 | 30–60 |
| Pool lock contention | High (global pool lock per alloc/free) | None on fast path |
| Cache behavior | Poor (pool metadata scattered) | Excellent (LIFO stack → hot cache line) |

### C.3 Corner Case Analysis

#### Corner Case 1: Asymmetric Workload — One CPU Allocates, All CPUs Free

**Scenario:** CPU 0 performs all allocations (e.g., packet receive path), but packets are processed and freed on different CPUs after distribution.

```
Timeline:
  t=0: CPU 0 has 80% of blocks. Other CPUs have their shares.
  t=1: CPU 0 rapidly allocates, draining its per-CPU list.
  t=2: CPU 0 falls back to global pool → triggers rebalance.
  Meanwhile: CPUs 1–7 free blocks, filling their per-CPU lists.
  t=3: CPUs 1–7 per-CPU lists fill up → some frees go to global pool.
```

| Metric | On-Demand | Memory Manager |
|--------|-----------|----------------|
| Alloc latency (CPU 0) | ~200–800 ns (constant) | ~10–20 ns until per-CPU exhausted; then ~50–100 ns (global fallback); stable after async rebalance |
| Async rebalance overhead | N/A | One-time: ~2–10 μs (DPC to each CPU, O(cpu_count) messages, O(K) block transfers per CPU) |
| Async rebalance frequency | N/A | Low — once per full drain/fill cycle. With 1000 blocks and 8 CPUs (~100 per CPU), rebalance triggers every ~100 allocs without corresponding frees on that CPU. |
| Worst-case single alloc (global has blocks) | ~800 ns | ~100 ns (global pool fallback while async rebalance is pending) |
| Worst-case single alloc (global also empty) | ~800 ns | ~16–30 μs (synchronous rebalance: DPCs to all CPUs to scavenge blocks from their per-CPU lists, then retry). This only occurs when cross-CPU free patterns have drained both the local per-CPU list and the global pool while blocks sit on other CPUs. |
| **Net throughput impact** | Baseline | **Still faster.** Even with every 100th alloc hitting slow path 1, amortized cost ≈ 20 + (100/100) ≈ 21 ns. If 1 in 10,000 hits synchronous rebalance, add ≈ 2 ns amortized. Total ~23 ns vs 500 ns on-demand. |

**Proposal A vs B comparison for this case:**
- **Proposal A (fair-share):** Redistributes evenly — CPU 0 gets refilled, CPUs 1–7 get drained. Effective but may over-drain CPUs 1–7 if they also need blocks for new allocations.
- **Proposal B (watermark):** Only drains CPUs above high_watermark and refills CPUs below low_watermark. Better fit for asymmetric workloads because it preserves a working buffer on all CPUs.

#### Corner Case 2: Burst Allocation — All CPUs Allocate Simultaneously

**Scenario:** Burst of network traffic causes all CPUs to allocate blocks concurrently.

```
Timeline:
  t=0: All CPUs simultaneously allocate from their per-CPU lists.
  t=1: Multiple CPUs exhaust their per-CPU lists at ~the same time.
  t=2: Multiple CPUs contend on the global pool spin lock.
  t=3: Multiple CPUs trigger async rebalance, but InterlockedCmpXchg ensures only one runs.
  t=4: If global pool is also empty (extreme burst), first CPU to find it empty triggers
       synchronous rebalance. Other CPUs that reach step 6 concurrently will block on the
       rebalance_pending flag and retry after it completes.
```

| Metric | On-Demand | Memory Manager |
|--------|-----------|----------------|
| Contention point | Pool allocator lock (every alloc) | Global pool spin lock (only when per-CPU exhausted) |
| Contention frequency | Every operation | Only on slow path (~1 in 100 ops) |
| Spin lock hold time | Varies (pool allocator internals) | O(1) — single array index + pointer copy |
| Async rebalance storm risk | N/A | No risk — `InterlockedCompareExchange` coalesces concurrent triggers into one work item. |
| Sync rebalance storm risk | N/A | No risk — `InterlockedCompareExchange` on `rebalance_pending` ensures only one synchronous rebalance executes. Other CPUs that enter step 6 concurrently will see `rebalance_pending == 1` and can either spin-wait for it to complete or proceed directly to the retry (the rebalance running on another thread will redistribute blocks that the retrying CPU can then pick up). |
| **Worst case latency (global has blocks)** | ~800 ns + queued spin waits | ~100 ns + brief spin on global lock. On a fully contended 8-CPU system with all CPUs hitting slow path simultaneously, worst-case serialization ≈ 8 × 50 ns = 400 ns for the last CPU. Still better than on-demand. |
| **Worst case latency (global also empty)** | ~800 ns + queued spin waits | ~16–30 μs for the CPU that triggers synchronous rebalance. Other CPUs retry after it completes (~50–100 ns for the retry). Total worst-case for a single allocation in this scenario: ~30 μs. This is worse than on-demand for that single allocation, but (a) it is extremely rare, and (b) it prevents a false NULL return that would otherwise have failed the operation entirely. |

#### Corner Case 3: Rebalance During High-Frequency Alloc/Free

**Scenario:** Continuous high-rate alloc/free while rebalance DPCs are executing.

```
Concern: Rebalance DPC runs on CPU i at DISPATCH_LEVEL, modifying per_cpu[i].slots[].
         Meanwhile, normal alloc/free also wants to touch per_cpu[i] at DISPATCH_LEVEL.

Resolution: No conflict — the DPC runs on CPU i, and alloc/free also runs on CPU i.
            At DISPATCH_LEVEL, only one piece of code executes at a time on a given CPU.
            The DPC is the code that's running; no other alloc/free can execute concurrently.
```

| Metric | On-Demand | Memory Manager |
|--------|-----------|----------------|
| Interference | None (no rebalance concept) | None — DPC exclusion guarantees serialization on owning CPU. |
| Alloc/free latency during rebalance | Baseline | Normal alloc/free on other CPUs proceeds unaffected. On the CPU where the DPC is running, alloc/free is deferred until the DPC completes (microseconds). |
| DPC time per CPU | N/A | ~0.5–2 μs (move ~tens of blocks between per-CPU slots and global pool; each move is a pointer copy). |
| Total rebalance wall-clock | N/A | ~P × 2 μs serialized across P CPUs ≈ 16 μs for 8 CPUs. |

#### Corner Case 4: Nearly Full Pool — Allocation Pressure

**Scenario:** N-1 of N blocks are in use. Only 1 block remains.

| Metric | On-Demand | Memory Manager |
|--------|-----------|----------------|
| Behavior | Pool allocator may still succeed (OS has large pool) | Only 1 block available — whichever CPU gets it wins; others return NULL. |
| Fairness | OS pool is first-come-first-served | Same. The one remaining block is in either a per-CPU list or global pool. First allocator at DISPATCH wins. |
| Failure mode | OS pool exhaustion → BSOD risk or NULL return depending on flags | Clean NULL return; no OS pool impact. Pool is bounded. |
| **Advantage** | Elastic — can allocate beyond N | Bounded — hard cap at N blocks. This is by design (predictable memory footprint). |

**Important:** The memory manager trades elasticity for predictability. The caller must size N appropriately for the expected workload. If the workload exceeds N, allocations fail gracefully (return NULL).

**Note on false failures:** In an earlier version of this design, allocation could falsely return NULL when the local per-CPU list and global pool were both empty, even though blocks existed on other CPUs' per-CPU lists (due to cross-CPU free patterns). This is addressed in Section 4.2 (step 6) by performing a synchronous rebalance before declaring failure. The allocation now only returns NULL when all N blocks are genuinely in use across the entire system.

#### Corner Case 5: Free on Different CPU Than Allocate (Cross-CPU Free)

**Scenario:** Block allocated on CPU 0, freed on CPU 3.

```
On-Demand:
  Free goes through epoch deferred list on CPU 3.
  When epoch releases, cxplat_free() returns to the global pool allocator.
  Cost: ~150–500 ns at release time.

Memory Manager:
  Epoch deferred free goes to CPU 3's epoch free list.
  When epoch releases, ebpf_memory_manager_free() pushes the block into CPU 3's per-CPU slots.
  Block now lives on CPU 3 instead of CPU 0.
  Over time, this causes natural migration of blocks toward freeing CPUs.
  If imbalance exceeds thresholds, rebalance corrects.
  Cost: ~10–20 ns at release time.
```

This is the primary driver of rebalance triggers in real workloads. The async rebalance cost (~16 μs amortized over hundreds of operations) is negligible compared to the per-operation savings.

In extreme cases where cross-CPU free patterns drain both the allocating CPU's per-CPU list **and** the global pool, the synchronous rebalance (Section 4.2, step 6) kicks in. This costs ~16–30 μs for that one allocation but prevents a false NULL return. The key insight: without the synchronous scavenge, this scenario would have been a **failed allocation**; with it, the allocation succeeds at the cost of one DPC round-trip to all CPUs. Even in the worst case, this is far preferable to returning NULL when blocks are available.

### C.4 Rebalance Cost Summary by Proposal

| Metric | Proposal A (Fair-Share) | Proposal B (Watermark) | Proposal C (Work-Steal) |
|--------|------------------------|------------------------|-------------------------|
| **Async trigger frequency** | On any empty/full per-CPU list | On any empty/full per-CPU list | On alloc miss only (no trigger on full) |
| **Sync trigger frequency** | Only when per-CPU AND global are both empty (very rare) | Same | Same |
| **DPC count per async rebalance** | 2 × cpu_count (drain pass + fill pass) | cpu_count (single pass) | 1–2 (steal from neighbor only) |
| **DPC count per sync rebalance** | Same as async (but waited on) | Same as async (but waited on) | 1–2 (but waited on) |
| **Blocks moved per rebalance** | O(total_available) worst case | O(blocks beyond watermark) | O(K) where K is steal batch size |
| **Async rebalance wall-clock** | ~16 μs (8 CPUs) | ~8 μs (8 CPUs) | ~2 μs (1 DPC) |
| **Sync rebalance wall-clock** | ~16–30 μs (8 CPUs, includes wait) | ~8–16 μs (8 CPUs) | ~2–4 μs (1 DPC) |
| **Global lock hold time** | O(blocks_moved) × ~50 ns | Same | Same |
| **Steady-state overhead** | Near zero (rebalance rare) | Near zero | Near zero |
| **Worst-case async rebalance/sec** | ~1000 (if allocation rate per CPU ≈ per-CPU capacity/s) | ~1000 | ~1000 per CPU |
| **Worst-case sync rebalance/sec** | ≪100 (requires per-CPU AND global to be empty simultaneously) | ≪100 | ≪100 |
| **CPU overhead at 1000 async rebalance/sec** | ~16 ms/s = 1.6% of one CPU | ~8 ms/s = 0.8% | ~2 ms/s = 0.2% |
| **CPU overhead at 100 sync rebalance/sec** | ~3 ms/s = 0.3% of one CPU (blocking the caller) | ~1.6 ms/s = 0.16% | ~0.4 ms/s = 0.04% |
| **Recommended for** | General workloads, simplicity | Asymmetric workloads | Ultra-low-latency (not recommended v1) |

**Note on sync vs async rebalance trade-off:** The synchronous rebalance is the "last resort" before returning NULL. Its higher latency (~16–30 μs) is the price of correctness — without it, the allocator would falsely fail. Proposal C (work-stealing) minimizes this cost to ~2–4 μs by stealing from a single neighbor, but is more complex to implement correctly. For v1, Proposal A's synchronous rebalance latency is acceptable given its rarity (<0.01% of allocations).

### C.5 Memory Overhead Comparison

| Component | On-Demand | Memory Manager |
|-----------|-----------|----------------|
| Per-block overhead | `ebpf_epoch_allocation_header_t` (32 bytes) prepended on each alloc | `ebpf_epoch_managed_allocation_header_t` (~40 bytes) embedded in pre-allocated block |
| Pool metadata | OS pool allocator adds ~16–32 bytes per allocation (internal bookkeeping) | None — blocks pre-allocated in contiguous array |
| Per-CPU data structures | None (epoch has its own per-CPU free list) | `slots[]` array: `cpu_count × per_cpu_capacity × sizeof(void*)` ≈ 8 CPUs × 100 slots × 8 bytes = 6.4 KB |
| Global pool | None | `N × sizeof(void*)` ≈ 1000 × 8 = 8 KB |
| **Total overhead for 1000 blocks of 64 bytes** | ~48 KB pool metadata (estimated) + no upfront cost | ~14.4 KB data structures + 104 KB pre-allocated blocks (all upfront) |
| **Trade-off** | Pay-as-you-go; no upfront cost | Fixed upfront cost; zero per-operation overhead |

### C.6 Latency Distribution (Expected)

```
             On-Demand Allocation          Memory Manager Allocation
             ┌────────────────────┐        ┌────────────────────┐
             │                    │        │██████████████      │
    p50      │     ████           │        │██████████████ 15ns │
             │     ████  400ns    │        │██████████████      │
             │     ████           │        │                    │
    p99      │         ████       │        │                    │
             │         ████ 700ns │        │    █               │
             │         ████       │        │    █  80ns         │
    p99.9    │            ██      │        │    █               │
             │            ██ 1μs+ │        │      █  100ns      │
             │                    │        │                    │
   p99.99   │            ██      │        │        ▪  ~20μs    │
             │            ██ 2μs+ │        │   (sync rebalance) │
             └────────────────────┘        └────────────────────┘
                 Flat, high cost              Trimodal:
                 distribution                 fast path (98%),
                                              global fallback (1.99%),
                                              sync rebalance (<0.01%)
```

**Tail latency analysis:**
- **p50–p99:** The memory manager is **10–40x faster** than on-demand (~15 ns vs ~400–700 ns).
- **p99.9** (~100 ns, global pool fallback): Still lower than the on-demand allocator's **p50** (~400 ns).
- **p99.99** (~16–30 μs, synchronous rebalance): This is the only case where the memory manager is slower than on-demand for a single allocation. However, this path only triggers under severe cross-CPU imbalance where both the local per-CPU list and global pool are empty. Without the sync rebalance, this allocation would have **falsely returned NULL** — so the ~20 μs cost buys correctness, not just performance.
- **Amortized impact of p99.99:** At 1 sync rebalance per 10,000 allocations, the amortized cost is ~2 ns/alloc — negligible.

### C.7 When NOT to Use the Memory Manager

| Scenario | Recommendation |
|----------|----------------|
| Variable-size allocations | Use on-demand. Memory manager handles fixed-size blocks only. |
| Very low allocation rate (< 100/sec) | On-demand is fine; pool overhead is negligible at low rates. |
| Unknown or unbounded N | On-demand is elastic; memory manager requires a bounded N upfront. |
| Short-lived contexts | Setup/teardown cost of the manager (~N allocations) may not amortize. |
| Block size > 4 KB | Pool allocator handles large allocations efficiently; contiguous pre-allocation of many large blocks wastes physical memory. |
