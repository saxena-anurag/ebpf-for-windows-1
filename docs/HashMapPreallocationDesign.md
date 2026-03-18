# Hash Map Pre-allocation Design

## 1. Motivation

On Linux, eBPF hash maps (and LRU hash maps) pre-allocate all entries by default.
Only when the map is created with the `BPF_F_NO_PREALLOC` flag are entries allocated
on demand. Pre-allocation provides two key benefits:

1. **Deterministic performance**: No memory allocation in the hot path (insert/update).
   Allocations call into the memory manager, which can contend across CPUs and trigger
   page-faults or pool expansion under pressure.
2. **Bounded memory usage**: The map's memory footprint is fixed at creation time, so
   eBPF programs running at DISPATCH_LEVEL cannot cause unbounded non-paged pool growth.

On Windows, eBPF hash maps currently allocate entries on demand. This document proposes
adding pre-allocation support that is highly performant and scalable under concurrent
access from multiple CPUs.

---

## 2. Current Architecture

### 2.1 Hash Table Internals (ebpf_hash_table.c)

The hash table uses **immutable-bucket RCU** (read-copy-update) semantics:

- Buckets are arrays of entries. Each entry holds a `data` pointer and an
  inline `key`.
- **Reads are lock-free**: `ebpf_hash_table_find` reads the bucket pointer with
  acquire semantics (`ReadSizeTAcquire`), then linearly scans the immutable
  bucket entries.
- **Writes take a per-bucket spinlock** (`ebpf_lock_t` — kernel spinlock,
  raises IRQL to `DISPATCH_LEVEL`), build a new immutable bucket, and
  atomically publish it with release semantics (`WriteSizeTRelease`).
- The old bucket and old data are freed (via `ebpf_epoch_free`) after the lock
  is released.

### 2.2 Allocations Per Insert

A single INSERT into a hash table performs **2–3 epoch allocations**:

| # | What | Size |
|---|------|------|
| 1 | `new_data` — value copy | `value_size + supplemental_value_size` |
| 2 | `local_new_bucket` — replacement bucket | `header + entry_size × (old_count + 1)` |
| 3 | `backup_bucket` — pre-allocated for future delete | `header + entry_size × old_count` (only if bucket was non-empty) |

These all go through `hash_table->allocate` (currently `ebpf_epoch_allocate_with_tag`).

### 2.3 Allocations Per Delete

A DELETE performs **zero allocations** — it reuses the `backup_bucket` that was
pre-allocated during the most recent INSERT into the same bucket. Old data is
freed via `hash_table->free`.

### 2.4 Current Map Creation Path

```
_create_hash_map()
  → _create_hash_map_internal(fixed_size_map=false, ...)
    → _initialize_hash_map_internal()
      → ebpf_hash_table_create(&options)
```

Key observations:
- `fixed_size_map = false` → `max_entries = EBPF_HASH_TABLE_NO_LIMIT` (no entry limit).
- No notification callbacks for plain hash maps.
- `ebpf_map_definition_in_memory_t` has **no `map_flags` field**.

### 2.5 Existing Patterns

| Pattern | Where | Relevance |
|---------|-------|-----------|
| Notification callbacks | LRU hash maps | `ALLOCATE`/`FREE`/`USE` callbacks manage LRU metadata |
| Custom allocators | `ebpf_hash_table_creation_options_t` | `allocate`/`free` function pointers let the hash table use custom memory |
| Epoch-based reclamation | `ebpf_epoch.c` | Per-CPU free lists with deferred reclamation — items are freed only after all readers have exited |
| Backup buckets | `_bucket_insert` | Pre-allocate a delete-sized bucket at INSERT time to guarantee deletion never fails due to OOM |

---

## 3. Design Goals

1. **Pre-allocate `max_entries` data blocks** during map creation.
2. Pre-allocated entries are **not inserted** into the hash table — they are
   maintained in a free pool.
3. On **insert**, a free entry is popped from the pool (zero allocation in hot
   path).
4. On **delete**, the released entry is pushed back to the pool (zero
   deallocation in hot path).
5. On **map destroy**, all pre-allocated entries are freed.
6. The pool must be **highly concurrent** — multiple CPUs inserting into the
   same map in parallel must not contend on a single lock.

### Non-Goals (for initial implementation)

- Pre-allocating bucket headers. Bucket allocation is harder to pre-allocate
  because bucket sizes are variable (they grow/shrink as entries are
  added/removed from a given bucket). Bucket allocations can be addressed in
  a future iteration.
- Changing the `BPF_F_NO_PREALLOC` flag to be the default. Initially, this
  feature will be opt-in via the flag, and we can flip the default later.

---

## 4. Proposed Design

### 4.1 Flag Plumbing

#### 4.1.1 Define `BPF_F_NO_PREALLOC`

In `include/linux/bpf.h`:

```c
#define BPF_F_NO_PREALLOC (1U << 0)
```

This matches the Linux definition.

#### 4.1.2 Add `map_flags` to `ebpf_map_definition_in_memory_t`

```c
typedef struct _ebpf_map_definition_in_memory
{
    ebpf_map_type_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    ebpf_id_t inner_map_id;
    ebpf_pin_type_t pinning;
    uint32_t map_flags;            // NEW
} ebpf_map_definition_in_memory_t;
```

#### 4.1.3 Accept `map_flags` in `ebpf_map_create()`

Currently `ebpf_map_create()` rejects non-zero `map_flags`. Change it to allow
`BPF_F_NO_PREALLOC` and propagate the value into `ebpf_map_definition_in_memory_t`.

All other unknown flags are rejected with `EBPF_INVALID_ARGUMENT`.

#### 4.1.4 Default Behavior

| Condition | Behavior |
|-----------|----------|
| Hash/LRU hash map, `map_flags` does **not** contain `BPF_F_NO_PREALLOC` | Pre-allocate entries (new behavior) |
| Hash/LRU hash map, `map_flags` **contains** `BPF_F_NO_PREALLOC` | Allocate on demand (current behavior) |
| All other map types | Ignore `BPF_F_NO_PREALLOC`, allocate on demand |

This matches Linux semantics where pre-allocation is the default for hash maps.

---

### 4.2 Pre-allocation Pool Design

#### 4.2.1 Requirements

The pool must support:
- `pop` (get a free entry) — called inside a per-bucket spinlock at
  DISPATCH_LEVEL.
- `push` (return a freed entry) — called after the per-bucket spinlock is
  released but still inside epoch protection, also at DISPATCH_LEVEL or below.
- Must scale well across many CPUs contending on the same map.
- Must not introduce a global lock that serializes all inserts.

#### 4.2.2 Design: Per-CPU Partitioned Free Lists

Use a partitioned pool where entries are distributed across `N` partitions
(where `N` = number of CPUs or a config-tuned value). Each partition is a
lock-free singly-linked list (SLIST).

```
ebpf_hash_table_t
└── prealloc_pool (NEW)
    ├── partition[0]   →  SLIST_HEADER  →  entry → entry → entry → ...
    ├── partition[1]   →  SLIST_HEADER  →  entry → entry → entry → ...
    ├── ...
    └── partition[N-1] →  SLIST_HEADER  →  entry → entry → entry → ...
```

**Why per-CPU partitions?**

- A single global SLIST would become a contention bottleneck — the
  `LOCK CMPXCHG16B` that backs SLIST push/pop contends on the same cache line
  across all CPUs.
- Per-CPU partitions eliminate cross-CPU contention in the common case. Each CPU
  primarily operates on its own partition.
- When a partition is empty, the CPU steals from another partition (work-stealing
  pattern).

**Why SLIST?**

- Windows kernel provides `SLIST_HEADER` / `SLIST_ENTRY` with
  `InterlockedPushEntrySList` / `InterlockedPopEntrySList` — lock-free
  push/pop using the CPU's `CMPXCHG16B` (on x64) or `CMPXCHG8B` (on x86).
- Safe to call at any IRQL including DISPATCH_LEVEL.
- No ABA problem — the 16-byte compare-and-swap includes a sequence counter.
- The codebase currently uses `ebpf_lock_t` (spinlocks) for synchronization but
  SLIST provides better scalability for this use case since push/pop are the
  only required operations.

#### 4.2.3 Data Structures

```c
// In ebpf_hash_table.c (internal)

/**
 * @brief Entry in the pre-allocation free list.
 * The SLIST_ENTRY is placed at the start of a pre-allocated data buffer.
 * When the entry is in the free list, the first sizeof(SLIST_ENTRY) bytes
 * are used for the SLIST linkage. When the entry is in use, the full buffer
 * holds the value (the SLIST_ENTRY is overwritten by value data).
 *
 * This overlay is safe because an entry is either in the free list OR in
 * the hash table — never both simultaneously.
 */
typedef struct _ebpf_prealloc_entry
{
    SLIST_ENTRY list_entry;     // Free list linkage (overlays value data)
} ebpf_prealloc_entry_t;

/**
 * @brief A single partition of the pre-allocation pool.
 * Each partition is cache-line aligned to prevent false sharing.
 */
typedef __declspec(align(EBPF_CACHE_LINE_SIZE)) struct _ebpf_prealloc_partition
{
    SLIST_HEADER free_list;     // Lock-free SLIST of free entries.
} ebpf_prealloc_partition_t;

/**
 * @brief Pre-allocation pool for hash table data entries.
 */
typedef struct _ebpf_prealloc_pool
{
    uint32_t partition_count;                       // Number of partitions (= CPU count).
    size_t entry_size;                              // Size of each pre-allocated data buffer.
    uint8_t* backing_allocation;                    // Single contiguous allocation for all entries.
    size_t backing_allocation_size;                 // Size of backing allocation.
    _Field_size_(partition_count)
    ebpf_prealloc_partition_t partitions[1];        // Flexible array of partitions.
} ebpf_prealloc_pool_t;
```

**Add to `ebpf_hash_table_t`:**

```c
struct _ebpf_hash_table
{
    // ... existing fields ...
    ebpf_prealloc_pool_t* prealloc_pool;  // NULL if pre-allocation is disabled.
};
```

#### 4.2.4 Initialization

During `ebpf_hash_table_create`, if pre-allocation is requested:

```
1. Compute entry_size = value_size + supplemental_value_size.
   Assert entry_size >= sizeof(SLIST_ENTRY) (16 bytes on x64).

2. Compute partition_count = ebpf_get_cpu_count().

3. Allocate the pool struct with partition_count partitions.

4. Allocate a single contiguous block for all max_entries data buffers:
   backing_allocation = allocate(max_entries * entry_size)

5. Distribute entries across partitions round-robin:
   for i in 0..max_entries:
       partition = i % partition_count
       entry = backing_allocation + i * entry_size
       InterlockedPushEntrySList(&partitions[partition].free_list, entry)

6. Store pool pointer in hash_table->prealloc_pool.
```

**Entry size constraint**: `value_size + supplemental_value_size` must be
≥ `sizeof(SLIST_ENTRY)` (16 bytes on x64). If the value is smaller, pad to
16 bytes. In practice, most map values are ≥ 16 bytes. For tiny values
(e.g., a 4-byte counter), the padding cost is acceptable for the performance
benefit.

#### 4.2.5 Allocation (Pop) — Hot Path

Replace `hash_table->allocate(value_size + supplemental_value_size, ...)`
in `_ebpf_hash_table_replace_bucket` with a pool-aware allocation:

```c
static uint8_t*
_ebpf_prealloc_pool_pop(_In_ ebpf_prealloc_pool_t* pool)
{
    uint32_t cpu = ebpf_get_current_cpu();
    uint32_t start_partition = cpu % pool->partition_count;

    // Try our own partition first (fast path - no cross-CPU contention).
    SLIST_ENTRY* entry = InterlockedPopEntrySList(
        &pool->partitions[start_partition].free_list);
    if (entry) {
        return (uint8_t*)entry;
    }

    // Work-stealing: try other partitions.
    for (uint32_t i = 1; i < pool->partition_count; i++) {
        uint32_t partition = (start_partition + i) % pool->partition_count;
        entry = InterlockedPopEntrySList(
            &pool->partitions[partition].free_list);
        if (entry) {
            return (uint8_t*)entry;
        }
    }

    // All partitions exhausted — map is full.
    return NULL;
}
```

**Complexity**: O(1) in the common case (local partition hit). O(N) worst case
where N = partition count (work-stealing). The work-stealing cost only occurs
when the local partition is empty, which happens when the map is nearly full
or when load is highly skewed.

#### 4.2.6 Deallocation (Push) — Hot Path

When an entry is removed from the hash table (delete or update-replace),
return it to the pool instead of calling `hash_table->free`:

```c
static void
_ebpf_prealloc_pool_push(_In_ ebpf_prealloc_pool_t* pool, _In_ uint8_t* data)
{
    uint32_t cpu = ebpf_get_current_cpu();
    uint32_t partition = cpu % pool->partition_count;

    // Zero the memory before returning to the free list.
    memset(data, 0, pool->entry_size);

    // Push to the local CPU's partition.
    InterlockedPushEntrySList(
        &pool->partitions[partition].free_list,
        (SLIST_ENTRY*)data);
}
```

**Note on epoch interaction**: Currently, `old_data` is freed via
`hash_table->free` (which calls `ebpf_epoch_free`) **after** the bucket lock
is released. This means a concurrent reader in `ebpf_hash_table_find` may
still be reading `old_data` when it is freed. Safety is guaranteed by the epoch
system — the memory is not actually reclaimed until all readers exit the epoch.

With pre-allocation, we **cannot** push the entry directly back to the free
list upon eviction — a concurrent reader might still be referencing it. The
entry must go through epoch-based deferred reclamation first. This is addressed
in Section 4.3.

#### 4.2.7 Destruction

On `ebpf_hash_table_destroy`:

```
1. Destroy all buckets (and their entries) as currently done.
   For pre-allocated entries, do NOT call hash_table->free(entry->data).
   Instead, just unlink them.

2. Drain all SLIST partitions (entries already in the free list).

3. Free the backing allocation.

4. Free the pool struct.
```

---

### 4.3 Epoch Integration — Deferred Return to Pool

The key challenge: when an entry is evicted (via delete or update-replace), a
concurrent lock-free reader may still be referencing the old data. We cannot
push the entry back into the free list until the reader has exited the epoch.

#### 4.3.1 Option A: Epoch Work Item (Recommended)

Use `ebpf_epoch_schedule_work_item` to schedule a callback that pushes the
entry back to the pool when the epoch has advanced sufficiently.

```
Delete/Update path:
  1. Build new bucket (no allocation for data — pop from pool or reuse).
  2. Publish new bucket.
  3. old_data is now unreachable from the hash table.
  4. Schedule an epoch work item:
     ebpf_epoch_schedule_work_item(work_item)
     → callback: _ebpf_prealloc_pool_push(pool, old_data)
  5. When epoch advances past the current epoch:
     → callback fires → old_data is pushed back to the free list.
```

**Advantage**: Fully safe. No entry is reused while any reader could
reference it.

**Cost**: Each eviction allocates an `ebpf_epoch_work_item_t` (not from the
pool — this is a small fixed-size allocation). This partially defeats the
"zero allocation in hot path" goal.

#### 4.3.2 Option B: Embedded Epoch Header in Pre-allocated Entries

Pre-allocate entries with an `ebpf_epoch_allocation_header_t` prefix, so they
can be directly inserted into the epoch free list without any additional
allocation.

```
Pre-allocated entry layout:
┌─────────────────────────────────────┬─────────────────────────────┐
│ ebpf_epoch_allocation_header_t     │ value data (overlays        │
│ (used for epoch free list linkage  │  SLIST_ENTRY when in pool)  │
│  when awaiting epoch expiry)       │                             │
└─────────────────────────────────────┴─────────────────────────────┘
```

When an entry is evicted:
1. The epoch header is filled in (set `freed_epoch`, `entry_type`).
2. The entry is inserted into the per-CPU epoch free list via
   `_ebpf_epoch_insert_in_free_list`.
3. When the epoch advances, instead of calling `ebpf_free`, a custom
   reclamation callback pushes the entry back to the pre-alloc pool.

**Advantage**: Zero additional allocations on the eviction path.

**Disadvantage**: Requires a new epoch allocation type
(`EBPF_EPOCH_ALLOCATION_PREALLOC_RETURN`) and custom reclamation logic in
`_ebpf_epoch_release_free_list`. This couples the pre-alloc pool to the epoch
internals.

#### 4.3.3 Option C: Shadow Free List With Epoch Barrier (Recommended)

Instead of returning entries to the SLIST immediately, place evicted entries on
a **shadow deferred list** (per-partition, protected by the same SLIST mechanism).
A background reclamation step moves entries from the shadow list to the free
list once the epoch has advanced.

```
Partition layout:
  partition[i]:
    free_list:   SLIST_HEADER   (immediately reusable entries)
    deferred_list: SLIST_HEADER (entries awaiting epoch expiry)
    deferred_epoch: int64       (epoch when entries were last deferred)
```

Eviction path:
1. Push evicted entry into `deferred_list` (lock-free, no allocation).
2. Record `deferred_epoch` = current epoch.

Allocation path (pop):
1. Try `free_list`.
2. If empty, check if `deferred_epoch` < `released_epoch`:
   - If so, move all entries from `deferred_list` to `free_list` (flush).
   - Then pop from `free_list`.
3. If still empty, steal from other partitions.

**Advantage**: No additional allocations at all. Fully lock-free. The deferred
entries naturally become available as the epoch advances.

**Disadvantage**: Under high insert/delete churn, the effective map capacity
is temporarily reduced because some entries are "in limbo" between eviction and
epoch advancement. This is bounded by the number of entries evicted during one
epoch interval (typically milliseconds).

---

### 4.4 Recommended Approach: Option C (Shadow Deferred List)

Option C best meets the design goals:
- **Zero allocation/deallocation in the hot path** (both pop and push are
  lock-free SLIST operations).
- **Fully safe** — entries are not reused until the epoch guarantees no readers
  reference them.
- **No coupling to epoch internals** — the pool manages its own deferred list.
- **Scalable** — per-CPU partitioned SLISTs eliminate cross-CPU contention.

#### 4.4.1 Revised Data Structures

```c
typedef __declspec(align(EBPF_CACHE_LINE_SIZE)) struct _ebpf_prealloc_partition
{
    SLIST_HEADER free_list;         // Immediately reusable entries.
    SLIST_HEADER deferred_list;     // Entries awaiting epoch expiry.
    volatile int64_t deferred_epoch; // Epoch of the last deferred entry.
} ebpf_prealloc_partition_t;
```

#### 4.4.2 Pop Operation (Revised)

```c
static uint8_t*
_ebpf_prealloc_pool_pop(_In_ ebpf_prealloc_pool_t* pool, int64_t released_epoch)
{
    uint32_t cpu = ebpf_get_current_cpu();
    uint32_t start = cpu % pool->partition_count;

    for (uint32_t i = 0; i < pool->partition_count; i++) {
        uint32_t p = (start + i) % pool->partition_count;
        ebpf_prealloc_partition_t* part = &pool->partitions[p];

        // 1. Try the free list.
        SLIST_ENTRY* entry = InterlockedPopEntrySList(&part->free_list);
        if (entry) {
            return (uint8_t*)entry;
        }

        // 2. Try to flush the deferred list if epoch has advanced.
        if (ReadAcquire64(&part->deferred_epoch) <= released_epoch) {
            // Atomically steal the entire deferred list.
            SLIST_ENTRY* deferred = InterlockedFlushSList(&part->deferred_list);
            if (deferred) {
                // Push all but the first back to the free list.
                SLIST_ENTRY* rest = deferred->Next;
                while (rest) {
                    SLIST_ENTRY* next = rest->Next;
                    InterlockedPushEntrySList(&part->free_list, rest);
                    rest = next;
                }
                // Return the first one directly.
                return (uint8_t*)deferred;
            }
        }
    }

    return NULL;  // Map is full.
}
```

#### 4.4.3 Push (Defer) Operation

```c
static void
_ebpf_prealloc_pool_defer(
    _In_ ebpf_prealloc_pool_t* pool,
    _In_ uint8_t* data,
    int64_t current_epoch)
{
    uint32_t cpu = ebpf_get_current_cpu();
    uint32_t p = cpu % pool->partition_count;
    ebpf_prealloc_partition_t* part = &pool->partitions[p];

    // Zero the value data for security (prevent information leaks to
    // the next user of this entry).
    memset(data, 0, pool->entry_size);

    // Update the deferred epoch for this partition.
    // Use release semantics so the zero-fill is visible before
    // the epoch tag.
    WriteRelease64(&part->deferred_epoch, current_epoch);

    InterlockedPushEntrySList(&part->deferred_list, (SLIST_ENTRY*)data);
}
```

#### 4.4.4 Integration Points in ebpf_hash_table.c

The changes to the hash table are localized to `_ebpf_hash_table_replace_bucket`
and `ebpf_hash_table_create` / `ebpf_hash_table_destroy`:

**In `_ebpf_hash_table_replace_bucket`, allocation of `new_data`:**

```c
// Before (current):
new_data = hash_table->allocate(
    hash_table->value_size + hash_table->supplemental_value_size,
    hash_table->allocation_tag);

// After (with pre-allocation):
if (hash_table->prealloc_pool) {
    new_data = _ebpf_prealloc_pool_pop(
        hash_table->prealloc_pool, /* released_epoch */);
    if (!new_data) {
        result = EBPF_OUT_OF_SPACE;
        goto Done;
    }
} else {
    new_data = hash_table->allocate(
        hash_table->value_size + hash_table->supplemental_value_size,
        hash_table->allocation_tag);
    if (!new_data) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
}
```

**In `_ebpf_hash_table_replace_bucket`, freeing of `old_data` and failed
`new_data`:**

```c
// Before (current):
hash_table->free(old_data);
hash_table->free(new_data);

// After:
if (hash_table->prealloc_pool) {
    if (old_data) {
        _ebpf_prealloc_pool_defer(
            hash_table->prealloc_pool, old_data, current_epoch);
    }
    if (new_data) {
        // Allocation failure cleanup — return directly to free list
        // (no concurrent readers can see it since it was never published).
        _ebpf_prealloc_pool_push_immediate(
            hash_table->prealloc_pool, new_data);
    }
} else {
    hash_table->free(old_data);
    hash_table->free(new_data);
}
```

**Note**: `_ebpf_prealloc_pool_push_immediate` pushes directly to the
`free_list` (not the `deferred_list`) because the entry was never published to
readers.

---

### 4.5 Integration in ebpf_maps.c

**In `_create_hash_map`:**

```c
static ebpf_result_t
_create_hash_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    bool prealloc = !(map_definition->map_flags & BPF_F_NO_PREALLOC);

    return _create_hash_map_internal(
        sizeof(ebpf_core_map_t),
        map_definition,
        0,                          // extra_options
        0,                          // supplemental_value_size
        prealloc,                   // fixed_size_map (enforces max_entries)
        NULL,                       // extract function
        NULL,                       // notification callback
        EBPF_HASH_TABLE_NOTIFICATION_TYPE_NONE,
        prealloc,                   // NEW: enable pre-allocation
        map);
}
```

**In `ebpf_hash_table_creation_options_t`, add:**

```c
typedef struct _ebpf_hash_table_creation_options
{
    // ... existing fields ...
    bool pre_allocate;  // If true, pre-allocate max_entries data buffers.
} ebpf_hash_table_creation_options_t;
```

---

### 4.6 Getting `released_epoch` In the Pop Path

The pop path needs to know the current `released_epoch` to decide whether
deferred entries can be flushed. Two approaches:

#### 4.6.1 Per-CPU Published Released Epoch (Preferred)

The epoch system already maintains `released_epoch` per CPU in
`ebpf_epoch_cpu_entry_t`. Expose it via a new API:

```c
// In ebpf_epoch.h:
int64_t ebpf_epoch_get_released_epoch(uint32_t cpu_id);
```

The pop path reads the local CPU's `released_epoch`. This is a single memory
read with no contention.

#### 4.6.2 Global Released Epoch

Alternatively, maintain a global minimum released epoch (already implicitly
computed during epoch advancement). This is simpler but slightly less precise.

---

## 5. Handling Edge Cases

### 5.1 Value Size < sizeof(SLIST_ENTRY)

`SLIST_ENTRY` is 16 bytes on x64. If `value_size + supplemental_value_size < 16`:
- Pad each pre-allocated entry to 16 bytes.
- Store the padded size in the pool as `entry_size`.
- No impact on the hash table — it always reads/writes exactly `value_size`
  bytes.

### 5.2 Map Full During Pre-allocation

If `max_entries` is excessively large, the initial pre-allocation could fail.
- `ebpf_hash_table_create` returns `EBPF_NO_MEMORY`.
- The map is not created.
- This is analogous to Linux where pre-allocation can fail if the system is
  low on memory.

### 5.3 max_entries = 0 or EBPF_HASH_TABLE_NO_LIMIT

Pre-allocation requires a finite `max_entries`:
- If `max_entries == 0` or `max_entries == EBPF_HASH_TABLE_NO_LIMIT`, reject
  pre-allocation with `EBPF_INVALID_ARGUMENT`.
- This matches Linux where hash maps always require `max_entries > 0`.

### 5.4 Concurrent Insert + Delete Pressure

Under heavy churn, many entries may be in the `deferred_list` waiting for
epoch advancement. This reduces the effective capacity of the map:

- **Worst case**: If all entries are deferred and the epoch hasn't advanced,
  the map appears full even though it logically has space.
- **Mitigation**: The epoch flush interval is 1ms (`EBPF_EPOCH_FLUSH_DELAY_IN_NANOSECONDS`).
  In practice, deferred entries become available within 1–2 epoch intervals.
- **Fallback**: If the user cannot tolerate this behavior, they can use
  `BPF_F_NO_PREALLOC` to get the current on-demand allocation behavior.

### 5.5 LRU Hash Maps

LRU hash maps can also use pre-allocation. The `supplemental_value_size` is
already accounted for in the entry layout. The only change is to pre-allocate
entries with size `value_size + supplemental_value_size`.

LRU eviction (reaping the oldest entry) already calls
`_update_hash_map_entry_operation_context` → `_ebpf_hash_table_replace_bucket`,
which will use the pool naturally.

---

## 6. Testing Strategy

| Test | Description |
|------|-------------|
| Basic insert/find/delete | Hash map with pre-allocation, verify all operations work |
| Fill to capacity | Insert `max_entries` entries, verify `EBPF_OUT_OF_SPACE` on the next insert |
| Delete and reuse | Fill map, delete entries, verify inserts succeed (entries recycled) |
| Concurrent insert/delete | Multiple threads hammering the same map, verify no crashes or data corruption |
| Pre-alloc failure | Set `max_entries` very large, verify map creation returns `EBPF_NO_MEMORY` |
| BPF_F_NO_PREALLOC | Verify on-demand allocation still works when the flag is set |
| Epoch safety | Concurrent readers during delete, verify no use-after-free (via epoch validation) |
| Value size edge cases | Test with `value_size` < 16 bytes, verify padding works correctly |
| LRU + pre-alloc | LRU hash map with pre-allocation, verify LRU eviction reuses entries from pool |

---

## 7. Performance Expectations

| Operation | Current (on-demand) | With Pre-allocation |
|-----------|--------------------|--------------------|
| Insert (data alloc) | `ebpf_epoch_allocate` → pool alloc, ~100-500ns | `InterlockedPopEntrySList` → ~10-30ns |
| Delete (data free) | `ebpf_epoch_free` → insert in epoch free list, ~50-100ns | `InterlockedPushEntrySList` → ~10-30ns |
| Insert contention (N CPUs) | N CPUs contend on global pool allocator | Each CPU hits its own partition — near-zero contention |
| Map creation | Fast | Slower (pre-allocates all entries) — one-time cost |

**Expected improvement**: 5–10x reduction in per-entry allocation latency.
Under high concurrency (many CPUs inserting into the same map), the improvement
could be larger due to elimination of allocator contention.

---

## 8. Implementation Plan

### Phase 1: Core Pool Implementation
1. Implement `ebpf_prealloc_pool_t` with per-CPU partitioned SLISTs.
2. Add pool initialization/destruction to `ebpf_hash_table_create/destroy`.
3. Wire pool pop/push into `_ebpf_hash_table_replace_bucket` for data
   allocation.
4. Add deferred list logic for epoch-safe recycling.

### Phase 2: Flag Plumbing
1. Add `map_flags` to `ebpf_map_definition_in_memory_t`.
2. Accept `BPF_F_NO_PREALLOC` in `ebpf_map_create`.
3. Propagate flag through to hash table creation.
4. Default hash maps to pre-allocate.

### Phase 3: Testing
1. Unit tests for pool operations.
2. Functional tests for pre-allocated hash maps.
3. Concurrency stress tests.
4. Performance benchmarks comparing pre-alloc vs. on-demand.

### Phase 4: LRU Hash Map Integration
1. Enable pre-allocation for LRU hash maps.
2. Verify LRU eviction works correctly with pooled entries.

---

## 9. Alternatives Considered

### 9.1 Windows Lookaside Lists (`NPAGED_LOOKASIDE_LIST`)

The Windows kernel provides built-in object pools via lookaside lists. However:
- Lookaside lists have a fixed depth limit and spill to the general pool when
  full — this doesn't provide bounded memory guarantees.
- They are per-processor but not configurable in partition count.
- The API (`ExAllocateFromNPagedLookasideList`) adds overhead vs. a raw SLIST.
- They don't support a deferred-reuse model needed for epoch integration.

**Verdict**: Not suitable for this use case.

### 9.2 Single Global SLIST (No Partitioning)

Simpler but creates a single contention point. On a 64-CPU system, all CPUs
would contend on the same 16-byte SLIST header. The `LOCK CMPXCHG16B`
instruction would bounce the cache line across all CPUs.

**Verdict**: Acceptable for small CPU counts (≤4) but does not scale.

### 9.3 Modify Epoch System to Support Object Recycling

Extend `ebpf_epoch_free` to call a custom recycler instead of freeing memory.
This would deeply integrate pre-allocation into the epoch system.

**Verdict**: Too invasive. The epoch system is complex and well-tested — adding
recycling logic increases risk. The shadow deferred list (Option C) achieves
the same safety without modifying epoch internals.

---

## 10. Open Questions

1. **Partition count**: Should it be equal to CPU count, or a smaller fixed
   value (e.g., 16)? Benchmarking will determine the optimal value. CPU count
   is the safe default.

2. **Should `BPF_F_NO_PREALLOC` be the default initially?** For backward
   compatibility, we could start with pre-allocation as opt-in
   (default = no pre-alloc, `BPF_F_PREALLOC` to enable), then flip the default
   later. This is the opposite of Linux semantics but reduces risk during
   rollout.

3. **Bucket pre-allocation**: Should we also pre-allocate bucket headers?
   This is more complex because bucket sizes are variable. A future iteration
   could explore a slab allocator for common bucket sizes (1-entry, 2-entry,
   4-entry buckets).

4. **SLIST platform abstraction**: The codebase currently has no SLIST
   wrappers. Should we add platform-abstracted SLIST functions to
   `ebpf_platform.h`, or use the Windows SLIST API directly in the hash
   table implementation? The hash table is Windows-specific kernel code,
   so direct SLIST usage is reasonable.
