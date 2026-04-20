// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    // Opaque handle returned by initialize.
    typedef struct _ebpf_memory_manager ebpf_memory_manager_t;

    /**
     * @brief Initialize the memory manager with a pre-allocated pool of blocks.
     *
     * @param[out] context Pointer to receive the allocated memory manager context.
     * @param[in] block_count Total number of pre-allocated blocks (N).
     * @param[in] block_size Usable size of each block in bytes (S).
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources.
     * @retval EBPF_INVALID_ARGUMENT Invalid parameters.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_memory_manager_initialize(_Out_ ebpf_memory_manager_t** context, uint32_t block_count, size_t block_size);

    /**
     * @brief Allocate one block from the pool.
     *
     * @param[in,out] context The memory manager context.
     * @returns Pointer to a block of block_size bytes, or NULL if all blocks are in use.
     */
    _Must_inspect_result_ _Ret_maybenull_ void*
    ebpf_memory_manager_allocate(_Inout_ ebpf_memory_manager_t* context);

    /**
     * @brief Try to allocate one block from the pool without blocking.
     * Unlike ebpf_memory_manager_allocate, this never triggers a synchronous
     * rebalance. Returns NULL immediately if no block is available in the
     * per-CPU list or the global pool.
     *
     * @param[in,out] context The memory manager context.
     * @returns Pointer to a block of block_size bytes, or NULL if unavailable.
     */
    _Must_inspect_result_ _Ret_maybenull_ void*
    ebpf_memory_manager_try_allocate(_Inout_ ebpf_memory_manager_t* context);

    /**
     * @brief Return one block to the pool.
     *
     * @param[in,out] context The memory manager context.
     * @param[in] block Pointer to the block to return.
     */
    void
    ebpf_memory_manager_free(_Inout_ ebpf_memory_manager_t* context, _Frees_ptr_ void* block);

    /**
     * @brief Tear down the pool and free all resources.
     * All blocks must have been returned before calling this function.
     *
     * @param[in] context The memory manager context to uninitialize.
     */
    void
    ebpf_memory_manager_uninitialize(_Frees_ptr_ ebpf_memory_manager_t* context);

    /**
     * @brief Check if a block pointer belongs to this memory manager's pool.
     *
     * @param[in] context The memory manager context.
     * @param[in] block Pointer to check.
     * @returns true if the block is within this manager's raw allocation range.
     */
    bool
    ebpf_memory_manager_owns_block(_In_ const ebpf_memory_manager_t* context, _In_ const void* block);

#ifdef __cplusplus
}
#endif
