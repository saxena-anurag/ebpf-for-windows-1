// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_memory.h"

#include <ebpf_shared_framework.h>

// Pool tag for memory manager allocations.
#define EBPF_POOL_TAG_MEMORY_MANAGER 'mmbe'

// Minimum blocks per CPU for per-CPU mode. If total_block_count < this * cpu_count,
// fall back to global-only mode where all blocks live in a single spin-locked pool.
// This avoids pathological rebalancing when there are too few blocks per CPU.
#define EBPF_MEMORY_MIN_BLOCKS_PER_CPU 8

// ──────────────────────────────────────────────────────────────────────
// Internal data structures
// ──────────────────────────────────────────────────────────────────────

/**
 * @brief Per-CPU entry for the memory manager.
 * Cache-line aligned to avoid false sharing between CPUs.
 * Operates as a LIFO stack: slots[0..head-1] contain available blocks.
 */
#pragma warning(push)
#pragma warning(disable : 4324) // structure was padded due to alignment specifier
__declspec(align(EBPF_CACHE_LINE_SIZE)) typedef struct _ebpf_memory_per_cpu_entry
{
    void** slots;      ///< Array of pointers to free blocks.
    uint32_t capacity; ///< Total slots in this array.
    uint32_t head;     ///< Index of next block to allocate (top of stack).
                       ///< head == 0 → empty, head == capacity → full.
} ebpf_memory_per_cpu_entry_t;
#pragma warning(pop)

/**
 * @brief Global overflow/underflow pool protected by a spin lock.
 */
typedef struct _ebpf_memory_global_pool
{
    void** slots;      ///< Array of pointers to free blocks.
    uint32_t capacity; ///< = N (100% to handle worst case).
    uint32_t count;    ///< Number of blocks currently in the global pool.
    KSPIN_LOCK lock;   ///< Protects slots[] and count.
} ebpf_memory_global_pool_t;

/**
 * @brief Top-level memory manager context.
 */
typedef struct _ebpf_memory_manager
{
    size_t block_size;                                   ///< Usable size of each block (S).
    uint32_t total_block_count;                          ///< Total number of pre-allocated blocks (N).
    uint32_t cpu_count;                                  ///< Number of CPUs.
    void* raw_allocation;                                ///< Single contiguous allocation for all N blocks.
    ebpf_memory_per_cpu_entry_t* per_cpu_entries;        ///< Array of per-CPU entries (NULL if global_only).
    ebpf_memory_global_pool_t global_pool;               ///< Global overflow/underflow pool.
    cxplat_preemptible_work_item_t* rebalance_work_item; ///< Pre-allocated work item for async rebalance.
    volatile long rebalance_pending;                     ///< 0/1 flag to prevent concurrent rebalances.
    bool global_only;                                    ///< true if all blocks in global pool (no per-CPU).
} ebpf_memory_manager_t;

// ──────────────────────────────────────────────────────────────────────
// Forward declarations
// ──────────────────────────────────────────────────────────────────────

static void
_ebpf_memory_trigger_rebalance(_Inout_ ebpf_memory_manager_t* context);

static void
_ebpf_memory_rebalance_worker(_In_ cxplat_preemptible_work_item_t* work_item, _In_opt_ void* work_item_context);

static void
_ebpf_memory_synchronous_rebalance(_Inout_ ebpf_memory_manager_t* context);

// ──────────────────────────────────────────────────────────────────────
// Watermark constants for Proposal B
// ──────────────────────────────────────────────────────────────────────

// Low watermark: 25% of per-CPU capacity. Below this, refill from global.
#define EBPF_MEMORY_LOW_WATERMARK_PERCENT 25

// High watermark: 75% of per-CPU capacity. Above this, drain to global.
#define EBPF_MEMORY_HIGH_WATERMARK_PERCENT 75

// Target fill level: 50% of per-CPU capacity.
#define EBPF_MEMORY_TARGET_FILL_PERCENT 50

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

/**
 * @brief Check if the per-CPU entry has crossed a watermark and trigger
 * an async rebalance if so. Called after alloc (head decreased) or
 * free (head increased) on the fast path.
 */
static inline void
_ebpf_memory_check_watermark(_Inout_ ebpf_memory_manager_t* context, _In_ const ebpf_memory_per_cpu_entry_t* entry)
{
    uint32_t low_watermark = (entry->capacity * EBPF_MEMORY_LOW_WATERMARK_PERCENT) / 100;
    uint32_t high_watermark = (entry->capacity * EBPF_MEMORY_HIGH_WATERMARK_PERCENT) / 100;

    if (entry->head <= low_watermark || entry->head >= high_watermark) {
        _ebpf_memory_trigger_rebalance(context);
    }
}

/**
 * @brief Validate that a block pointer belongs to this memory manager.
 * Debug-only check.
 */
#ifdef DBG
static bool
_ebpf_memory_block_belongs_to_manager(_In_ const ebpf_memory_manager_t* context, _In_ const void* block)
{
    const uint8_t* raw = (const uint8_t*)context->raw_allocation;
    const uint8_t* ptr = (const uint8_t*)block;
    if (ptr < raw || ptr >= raw + (size_t)context->total_block_count * context->block_size) {
        return false;
    }
    // Check alignment to block boundaries.
    size_t offset = (size_t)(ptr - raw);
    return (offset % context->block_size) == 0;
}
#endif

// ──────────────────────────────────────────────────────────────────────
// Initialize
// ──────────────────────────────────────────────────────────────────────

bool
ebpf_memory_manager_owns_block(_In_ const ebpf_memory_manager_t* context, _In_ const void* block)
{
    if (context == NULL || context->raw_allocation == NULL || context->total_block_count == 0) {
        return false;
    }
    const uint8_t* raw = (const uint8_t*)context->raw_allocation;
    const uint8_t* ptr = (const uint8_t*)block;
    return (ptr >= raw && ptr < raw + (size_t)context->total_block_count * context->block_size);
}

_Must_inspect_result_ ebpf_result_t
ebpf_memory_manager_initialize(_Out_ ebpf_memory_manager_t** context, uint32_t block_count, size_t block_size)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_memory_manager_t* mgr = NULL;
    uint32_t cpu_count;
    uint32_t i;

    *context = NULL;

    // Allow block_count == 0; allocate will always return NULL.
    if (block_count > 0 && block_size == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    cpu_count = ebpf_get_cpu_count();

    // Step 1: Allocate the context structure.
    mgr = (ebpf_memory_manager_t*)cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED, sizeof(ebpf_memory_manager_t), EBPF_POOL_TAG_MEMORY_MANAGER);
    if (mgr == NULL) {
        return EBPF_NO_MEMORY;
    }
    memset(mgr, 0, sizeof(*mgr));

    mgr->block_size = block_size;
    mgr->total_block_count = block_count;
    mgr->cpu_count = cpu_count;
    mgr->rebalance_pending = 0;

    if (block_count == 0) {
        // No blocks to allocate; still a valid (empty) manager.
        mgr->global_only = true;
        *context = mgr;
        return EBPF_SUCCESS;
    }

    // Decide whether to use per-CPU distribution or global-only mode.
    // If there aren't enough blocks to meaningfully distribute across CPUs,
    // use a single global pool to avoid pathological rebalancing.
    mgr->global_only = (block_count < (uint64_t)cpu_count * EBPF_MEMORY_MIN_BLOCKS_PER_CPU);

    // Step 2: Allocate contiguous raw memory for all N blocks.
    mgr->raw_allocation =
        cxplat_allocate(CXPLAT_POOL_FLAG_NON_PAGED, (size_t)block_count * block_size, EBPF_POOL_TAG_MEMORY_MANAGER);
    if (mgr->raw_allocation == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    // Step 3: Allocate global pool slots with capacity = N.
    mgr->global_pool.capacity = block_count;
    mgr->global_pool.count = 0;
    KeInitializeSpinLock(&mgr->global_pool.lock);
    mgr->global_pool.slots = (void**)cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED, (size_t)block_count * sizeof(void*), EBPF_POOL_TAG_MEMORY_MANAGER);
    if (mgr->global_pool.slots == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    memset(mgr->global_pool.slots, 0, (size_t)block_count * sizeof(void*));

    if (mgr->global_only) {
        // Global-only mode: all blocks go to the global pool.
        for (i = 0; i < block_count; i++) {
            mgr->global_pool.slots[i] = (uint8_t*)mgr->raw_allocation + (size_t)i * block_size;
        }
        mgr->global_pool.count = block_count;
        // No per-CPU entries or rebalance work item needed.
        *context = mgr;
        return EBPF_SUCCESS;
    }

    // Per-CPU mode: distribute blocks across per-CPU arrays and global pool.

    // Step 4: Allocate per-CPU entries (cache-line aligned).
    mgr->per_cpu_entries = (ebpf_memory_per_cpu_entry_t*)cxplat_allocate(
        (cxplat_pool_flags_t)(CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED),
        (size_t)cpu_count * sizeof(ebpf_memory_per_cpu_entry_t),
        EBPF_POOL_TAG_MEMORY_MANAGER);
    if (mgr->per_cpu_entries == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    memset(mgr->per_cpu_entries, 0, (size_t)cpu_count * sizeof(ebpf_memory_per_cpu_entry_t));

    // Step 5: Allocate per-CPU slots arrays.
#pragma warning(push)
#pragma warning(disable : 6385) // per_cpu_entries array is properly sized for cpu_count elements.
    for (i = 0; i < cpu_count; i++) {
        // per_cpu_capacity = ceil(0.80 * N / cpu_count)
        uint32_t per_cpu_capacity =
            (uint32_t)(((uint64_t)block_count * 80 + (uint64_t)cpu_count * 100 - 1) / ((uint64_t)cpu_count * 100));
        // Ensure at least 1 slot per CPU if there are blocks.
        if (per_cpu_capacity == 0) {
            per_cpu_capacity = 1;
        }

        mgr->per_cpu_entries[i].capacity = per_cpu_capacity;
        mgr->per_cpu_entries[i].head = 0;
        mgr->per_cpu_entries[i].slots = (void**)cxplat_allocate(
            CXPLAT_POOL_FLAG_NON_PAGED, (size_t)per_cpu_capacity * sizeof(void*), EBPF_POOL_TAG_MEMORY_MANAGER);
        if (mgr->per_cpu_entries[i].slots == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
        memset(mgr->per_cpu_entries[i].slots, 0, (size_t)per_cpu_capacity * sizeof(void*));
    }
#pragma warning(pop)

    // Step 6: Distribute blocks.
    {
        uint32_t global_blocks = block_count / 5; // floor(0.20 * N)
        uint32_t per_cpu_blocks = block_count - global_blocks;
        uint32_t blocks_per_cpu = per_cpu_blocks / cpu_count;
        uint32_t remainder = per_cpu_blocks % cpu_count;
        uint32_t block_index = 0;

        // Distribute to per-CPU arrays.
        for (i = 0; i < cpu_count; i++) {
            uint32_t count_i = blocks_per_cpu + (i < remainder ? 1 : 0);
            // Clamp to per-CPU capacity.
            if (count_i > mgr->per_cpu_entries[i].capacity) {
                count_i = mgr->per_cpu_entries[i].capacity;
            }
            for (uint32_t j = 0; j < count_i; j++) {
                mgr->per_cpu_entries[i].slots[j] = (uint8_t*)mgr->raw_allocation + (size_t)block_index * block_size;
                block_index++;
            }
            mgr->per_cpu_entries[i].head = count_i;
        }

        // Remaining blocks go to the global pool.
        uint32_t remaining = block_count - block_index;
        for (uint32_t j = 0; j < remaining; j++) {
            mgr->global_pool.slots[j] = (uint8_t*)mgr->raw_allocation + (size_t)block_index * block_size;
            block_index++;
        }
        mgr->global_pool.count = remaining;
    }

    // Step 7: Pre-allocate the rebalance work item.
    {
        cxplat_status_t status =
            cxplat_allocate_preemptible_work_item(NULL, &mgr->rebalance_work_item, _ebpf_memory_rebalance_worker, mgr);
        if (!CXPLAT_SUCCEEDED(status)) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
    }

    *context = mgr;
    return EBPF_SUCCESS;

Done:
    if (mgr != NULL) {
        // Clean up partial initialization.
        if (mgr->rebalance_work_item != NULL) {
            cxplat_free_preemptible_work_item(mgr->rebalance_work_item);
        }
        if (mgr->per_cpu_entries != NULL) {
            for (i = 0; i < cpu_count; i++) {
                if (mgr->per_cpu_entries[i].slots != NULL) {
                    cxplat_free(
                        mgr->per_cpu_entries[i].slots, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_MEMORY_MANAGER);
                }
            }
            cxplat_free(
                mgr->per_cpu_entries,
                (cxplat_pool_flags_t)(CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED),
                EBPF_POOL_TAG_MEMORY_MANAGER);
        }
        if (mgr->global_pool.slots != NULL) {
            cxplat_free(mgr->global_pool.slots, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_MEMORY_MANAGER);
        }
        if (mgr->raw_allocation != NULL) {
            cxplat_free(mgr->raw_allocation, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_MEMORY_MANAGER);
        }
        cxplat_free(mgr, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_MEMORY_MANAGER);
    }
    return result;
}

// ──────────────────────────────────────────────────────────────────────
// Allocate
// ──────────────────────────────────────────────────────────────────────

_Must_inspect_result_ _Ret_maybenull_ void*
ebpf_memory_manager_allocate(_Inout_ ebpf_memory_manager_t* context)
{
    void* block = NULL;

    if (context->total_block_count == 0) {
        return NULL;
    }

    // Global-only mode: just use the global pool with a spin lock.
    if (context->global_only) {
        KIRQL old_irql;
        KeAcquireSpinLock(&context->global_pool.lock, &old_irql);
        if (context->global_pool.count > 0) {
            block = context->global_pool.slots[--context->global_pool.count];
        }
        KeReleaseSpinLock(&context->global_pool.lock, old_irql);
        return block;
    }

    // Per-CPU mode:

    // Step 1-3: Raise IRQL, get current CPU, get per-CPU entry.
    KIRQL old_irql = ebpf_raise_irql_to_dispatch_if_needed();
    uint32_t cpu_id = ebpf_get_current_cpu();
    ebpf_memory_per_cpu_entry_t* entry = &context->per_cpu_entries[cpu_id];

    // Step 4: Fast path - per-CPU list has blocks.
    if (entry->head > 0) {
        block = entry->slots[--entry->head];
        _ebpf_memory_check_watermark(context, entry);
        ebpf_lower_irql_from_dispatch_if_needed(old_irql);
        return block;
    }

    // Step 5: Slow path 1 - per-CPU list is empty, try global pool.
    KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock);
    if (context->global_pool.count > 0) {
        block = context->global_pool.slots[--context->global_pool.count];
        KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);
        _ebpf_memory_trigger_rebalance(context); // Async refill.
        ebpf_lower_irql_from_dispatch_if_needed(old_irql);
        return block;
    }
    KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);

    // Step 6: Slow path 2 - global pool also empty, synchronous rebalance.
    ebpf_lower_irql_from_dispatch_if_needed(old_irql);
    _ebpf_memory_synchronous_rebalance(context);

    // Retry exactly once after rebalance.
    old_irql = ebpf_raise_irql_to_dispatch_if_needed();
    // Re-read cpu_id after lowering/raising IRQL (thread may have migrated).
    cpu_id = ebpf_get_current_cpu();
    entry = &context->per_cpu_entries[cpu_id];

    if (entry->head > 0) {
        block = entry->slots[--entry->head];
        ebpf_lower_irql_from_dispatch_if_needed(old_irql);
        return block;
    }

    // Per-CPU still empty after rebalance - check global one more time.
    KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock);
    if (context->global_pool.count > 0) {
        block = context->global_pool.slots[--context->global_pool.count];
        KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);
        ebpf_lower_irql_from_dispatch_if_needed(old_irql);
        return block;
    }
    KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);

    // Step 7: All N blocks are genuinely in use.
    ebpf_lower_irql_from_dispatch_if_needed(old_irql);
    return NULL;
}

// ──────────────────────────────────────────────────────────────────────
// Try Allocate (non-blocking)
// ──────────────────────────────────────────────────────────────────────

_Must_inspect_result_ _Ret_maybenull_ void*
ebpf_memory_manager_try_allocate(_Inout_ ebpf_memory_manager_t* context)
{
    void* block = NULL;

    if (context->total_block_count == 0) {
        return NULL;
    }

    // Global-only mode: just use the global pool with a spin lock.
    if (context->global_only) {
        KIRQL old_irql;
        KeAcquireSpinLock(&context->global_pool.lock, &old_irql);
        if (context->global_pool.count > 0) {
            block = context->global_pool.slots[--context->global_pool.count];
        }
        KeReleaseSpinLock(&context->global_pool.lock, old_irql);
        return block;
    }

    // Per-CPU mode:
    KIRQL old_irql = ebpf_raise_irql_to_dispatch_if_needed();
    uint32_t cpu_id = ebpf_get_current_cpu();
    ebpf_memory_per_cpu_entry_t* entry = &context->per_cpu_entries[cpu_id];

    // Fast path - per-CPU list has blocks.
    if (entry->head > 0) {
        block = entry->slots[--entry->head];
        _ebpf_memory_check_watermark(context, entry);
        ebpf_lower_irql_from_dispatch_if_needed(old_irql);
        return block;
    }

    // Slow path - per-CPU list is empty, try global pool.
    KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock);
    if (context->global_pool.count > 0) {
        block = context->global_pool.slots[--context->global_pool.count];
        KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);
        _ebpf_memory_trigger_rebalance(context);
        ebpf_lower_irql_from_dispatch_if_needed(old_irql);
        return block;
    }
    KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);

    // No blocks available - return NULL without synchronous rebalance.
    ebpf_lower_irql_from_dispatch_if_needed(old_irql);
    return NULL;
}

// ──────────────────────────────────────────────────────────────────────
// Free
// ──────────────────────────────────────────────────────────────────────

void
ebpf_memory_manager_free(_Inout_ ebpf_memory_manager_t* context, _Frees_ptr_ void* block)
{
    ebpf_assert(block != NULL);

#ifdef DBG
    ebpf_assert(_ebpf_memory_block_belongs_to_manager(context, block));
#endif

    // Global-only mode: just push to the global pool with a spin lock.
    if (context->global_only) {
        KIRQL old_irql;
        KeAcquireSpinLock(&context->global_pool.lock, &old_irql);
        ebpf_assert(context->global_pool.count < context->global_pool.capacity);
        context->global_pool.slots[context->global_pool.count++] = block;
        KeReleaseSpinLock(&context->global_pool.lock, old_irql);
        return;
    }

    // Per-CPU mode:

    // Step 1-3: Raise IRQL, get current CPU, get per-CPU entry.
    KIRQL old_irql = ebpf_raise_irql_to_dispatch_if_needed();
    uint32_t cpu_id = ebpf_get_current_cpu();
    ebpf_memory_per_cpu_entry_t* entry = &context->per_cpu_entries[cpu_id];

    // Step 4: Fast path - per-CPU list has room.
    if (entry->head < entry->capacity) {
        entry->slots[entry->head++] = block;
        _ebpf_memory_check_watermark(context, entry);
        ebpf_lower_irql_from_dispatch_if_needed(old_irql);
        return;
    }

    // Step 5: Slow path - per-CPU list is full, push to global pool.
    KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock);
    ebpf_assert(context->global_pool.count < context->global_pool.capacity);
    context->global_pool.slots[context->global_pool.count++] = block;
    KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);
    _ebpf_memory_trigger_rebalance(context); // Async rebalance.
    ebpf_lower_irql_from_dispatch_if_needed(old_irql);
}

// ──────────────────────────────────────────────────────────────────────
// Uninitialize
// ──────────────────────────────────────────────────────────────────────

void
ebpf_memory_manager_uninitialize(_Frees_ptr_ ebpf_memory_manager_t* context)
{
    uint32_t i;

    if (context == NULL) {
        return;
    }

    // Wait for any pending async rebalance to complete before tearing down.
    // This prevents a use-after-free where the async worker accesses the
    // context after it has been freed.
    while (ReadAcquire(&context->rebalance_pending) != 0) {
        YieldProcessor();
    }

    // Verify all blocks have been returned.
#pragma warning(push)
#pragma warning(disable : 6001) // context is fully initialized by ebpf_memory_manager_initialize.
    if (context->total_block_count > 0) {
        uint32_t total_returned = context->global_pool.count;
        if (!context->global_only) {
            for (i = 0; i < context->cpu_count; i++) {
                total_returned += context->per_cpu_entries[i].head;
            }
        }
        ebpf_assert(total_returned == context->total_block_count);
    }

    // Free the rebalance work item.
    if (context->rebalance_work_item != NULL) {
        cxplat_free_preemptible_work_item(context->rebalance_work_item);
    }

    // Free per-CPU slots arrays.
    if (context->per_cpu_entries != NULL) {
        for (i = 0; i < context->cpu_count; i++) {
            if (context->per_cpu_entries[i].slots != NULL) {
                cxplat_free(
                    context->per_cpu_entries[i].slots, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_MEMORY_MANAGER);
            }
        }
#pragma warning(pop)
        cxplat_free(
            context->per_cpu_entries,
            (cxplat_pool_flags_t)(CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED),
            EBPF_POOL_TAG_MEMORY_MANAGER);
    }

    // Free global pool slots.
    if (context->global_pool.slots != NULL) {
        cxplat_free(context->global_pool.slots, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_MEMORY_MANAGER);
    }

    // Free the contiguous raw allocation (single free for all blocks).
    if (context->raw_allocation != NULL) {
        cxplat_free(context->raw_allocation, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_MEMORY_MANAGER);
    }

    // Free the context itself.
    cxplat_free(context, CXPLAT_POOL_FLAG_NON_PAGED, EBPF_POOL_TAG_MEMORY_MANAGER);
}

// ──────────────────────────────────────────────────────────────────────
// Load Balancing – Proposal B: Watermark-Based Rebalancing
// ──────────────────────────────────────────────────────────────────────

/**
 * @brief Trigger an asynchronous rebalance if one is not already pending.
 */
static void
_ebpf_memory_trigger_rebalance(_Inout_ ebpf_memory_manager_t* context)
{
    // Use InterlockedCompareExchange to ensure only one rebalance is in-flight.
    if (InterlockedCompareExchange(&context->rebalance_pending, 1, 0) == 0) {
        cxplat_queue_preemptible_work_item(context->rebalance_work_item);
    }
}

/**
 * @brief Perform watermark-based rebalancing for a single CPU.
 * Must be called at DISPATCH_LEVEL on the owning CPU.
 *
 * @param[in,out] context The memory manager context.
 * @param[in] cpu_id The CPU to rebalance.
 */
static void
_ebpf_memory_rebalance_cpu(_Inout_ ebpf_memory_manager_t* context, uint32_t cpu_id)
{
    ebpf_memory_per_cpu_entry_t* entry = &context->per_cpu_entries[cpu_id];

    uint32_t low_watermark = (entry->capacity * EBPF_MEMORY_LOW_WATERMARK_PERCENT) / 100;
    uint32_t high_watermark = (entry->capacity * EBPF_MEMORY_HIGH_WATERMARK_PERCENT) / 100;
    uint32_t target_fill = (entry->capacity * EBPF_MEMORY_TARGET_FILL_PERCENT) / 100;

    // Ensure target_fill is at least 1 if capacity > 0.
    if (entry->capacity > 0 && target_fill == 0) {
        target_fill = 1;
    }

    if (entry->head < low_watermark) {
        // Refill from global pool.
        uint32_t refill_count = target_fill - entry->head;

        KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock);
        uint32_t transfer = refill_count;
        if (transfer > context->global_pool.count) {
            transfer = context->global_pool.count;
        }
        for (uint32_t j = 0; j < transfer; j++) {
            entry->slots[entry->head++] = context->global_pool.slots[--context->global_pool.count];
        }
        KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);

    } else if (entry->head > high_watermark) {
        // Drain to global pool.
        uint32_t drain_count = entry->head - target_fill;

        KeAcquireSpinLockAtDpcLevel(&context->global_pool.lock);
        for (uint32_t j = 0; j < drain_count; j++) {
            ebpf_assert(context->global_pool.count < context->global_pool.capacity);
            context->global_pool.slots[context->global_pool.count++] = entry->slots[--entry->head];
        }
        KeReleaseSpinLockFromDpcLevel(&context->global_pool.lock);
    }
}

/**
 * @brief Asynchronous rebalance worker.
 * Runs at PASSIVE_LEVEL on an arbitrary thread.
 * Uses thread affinity to run on each CPU to safely access per-CPU data.
 */
static void
_ebpf_memory_rebalance_worker(_In_ cxplat_preemptible_work_item_t* work_item, _In_opt_ void* work_item_context)
{
    UNREFERENCED_PARAMETER(work_item);
    ebpf_memory_manager_t* context = (ebpf_memory_manager_t*)work_item_context;

    if (context == NULL) {
        return;
    }

    for (uint32_t i = 0; i < context->cpu_count; i++) {
        GROUP_AFFINITY old_affinity;
        ebpf_result_t affinity_result = ebpf_set_current_thread_cpu_affinity(i, &old_affinity);
        if (affinity_result != EBPF_SUCCESS) {
            continue;
        }

        KIRQL old_irql = ebpf_raise_irql_to_dispatch_if_needed();
        _ebpf_memory_rebalance_cpu(context, i);
        ebpf_lower_irql_from_dispatch_if_needed(old_irql);

        ebpf_restore_current_thread_cpu_affinity(&old_affinity);
    }

    InterlockedExchange(&context->rebalance_pending, 0);
}

/**
 * @brief Synchronous rebalance.
 * Called on the slow path when both per-CPU and global pools are empty.
 * Waits for any in-flight async rebalance to complete, then triggers a new
 * async rebalance and waits for it to finish. This avoids the sync path
 * directly touching other CPUs' per-CPU arrays (which would race with
 * concurrent alloc/free on those CPUs).
 */
static void
_ebpf_memory_synchronous_rebalance(_Inout_ ebpf_memory_manager_t* context)
{
    // Wait for any in-flight async rebalance to complete.
    // The async worker clears rebalance_pending to 0 when done.
    while (ReadAcquire(&context->rebalance_pending) != 0) {
        YieldProcessor();
    }

    // Trigger a new async rebalance and wait for it to complete.
    // The trigger sets pending to 1 and queues the work item.
    if (InterlockedCompareExchange(&context->rebalance_pending, 1, 0) == 0) {
        cxplat_queue_preemptible_work_item(context->rebalance_work_item);
    }

    // Wait for this rebalance to complete.
    while (ReadAcquire(&context->rebalance_pending) != 0) {
        YieldProcessor();
    }
}
