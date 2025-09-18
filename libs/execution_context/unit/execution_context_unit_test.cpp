// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_EXECUTION_CONTEXT_UNIT_TESTS

#include "catch_wrapper.hpp"
#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_ring_buffer.h"
#include "helpers.h"
#include "test_helper.hpp"

#include <iomanip>
#include <optional>
#include <set>

extern "C"
{
    // program context descriptor helpers
    // - Defined in ebpf_program.c, declared here for unit testing.
    void
    ebpf_program_set_header_context_descriptor(
        _In_ const ebpf_context_descriptor_t* context_descriptor, _Inout_ void* program_context);
    void
    ebpf_program_get_header_context_descriptor(
        _In_ const void* program_context, _Outptr_ const ebpf_context_descriptor_t** context_descriptor);
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
typedef struct _free_trampoline_table
{
    void
    operator()(_In_opt_ _Post_invalid_ ebpf_trampoline_table_t* table)
    {
        if (table != nullptr) {
            ebpf_free_trampoline_table(table);
        }
    }
} free_trampoline_table_t;

typedef std::unique_ptr<ebpf_trampoline_table_t, free_trampoline_table_t> ebpf_trampoline_table_ptr;
#endif

typedef class _ebpf_async_wrapper
{
  public:
    _ebpf_async_wrapper()
    {
        _event = CreateEvent(nullptr, false, false, nullptr);
        if (_event == INVALID_HANDLE_VALUE) {
            throw std::bad_alloc();
        }
        if (ebpf_async_set_completion_callback(this, _ebpf_async_wrapper::completion_callback) != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_async_set_completion_callback failed");
        }
    }
    ~_ebpf_async_wrapper()
    {
        if (!_completed) {
            ebpf_async_complete(this, 0, EBPF_CANCELED);
        }
    }

    ebpf_result_t
    get_result()
    {
        return _result;
    }

    bool
    get_completed()
    {
        return _completed;
    }

    size_t
    get_reply_size()
    {
        return _reply_size;
    }

    void
    wait()
    {
        REQUIRE(WaitForSingleObject(_event, INFINITE) == WAIT_OBJECT_0);
    }

  private:
    static void
    completion_callback(_In_ void* context, size_t reply_size, ebpf_result_t result)
    {
        ebpf_async_wrapper_t* async_wrapper = (ebpf_async_wrapper_t*)context;
        async_wrapper->_result = result;
        async_wrapper->_reply_size = reply_size;
        async_wrapper->_completed = true;
        SetEvent(async_wrapper->_event);
    }
    ebpf_result_t _result = EBPF_SUCCESS;
    size_t _reply_size = 0;
    bool _completed = false;
    HANDLE _event;
} ebpf_async_wrapper_t;

struct scoped_cpu_affinity
{
    scoped_cpu_affinity(uint32_t i) : old_affinity_mask{}
    {
        affinity_set = ebpf_set_current_thread_cpu_affinity(i, &old_affinity_mask) == EBPF_SUCCESS;
        REQUIRE(affinity_set);
    }
    ~scoped_cpu_affinity()
    {
        if (affinity_set) {
            ebpf_restore_current_thread_cpu_affinity(&old_affinity_mask);
        }
    }
    GROUP_AFFINITY old_affinity_mask;
    bool affinity_set = false;
};

class _ebpf_core_initializer
{
  public:
    void
    initialize()
    {
        REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    }
    ~_ebpf_core_initializer() { ebpf_core_terminate(); }
};

template <typename T> class ebpf_object_deleter
{
  public:
    void
    operator()(T* object)
    {
        EBPF_OBJECT_RELEASE_REFERENCE(reinterpret_cast<ebpf_core_object_t*>(object));
    }
};

typedef std::unique_ptr<ebpf_map_t, ebpf_object_deleter<ebpf_map_t>> map_ptr;
typedef std::unique_ptr<ebpf_program_t, ebpf_object_deleter<ebpf_program_t>> program_ptr;
typedef std::unique_ptr<ebpf_link_t, ebpf_object_deleter<ebpf_link_t>> link_ptr;

static const uint32_t _test_map_size = 512;

typedef enum _map_behavior_on_max_entries
{
    MAP_BEHAVIOR_FAIL,
    MAP_BEHAVIOR_REPLACE,
    MAP_BEHAVIOR_INSERT,
} map_behavior_on_max_entries_t;

static void
_test_crud_operations(ebpf_map_type_t map_type)
{
    _ebpf_core_initializer core;
    core.initialize();
    bool is_array;
    bool supports_find_and_delete;
    map_behavior_on_max_entries_t behavior_on_max_entries = MAP_BEHAVIOR_FAIL;
    bool run_at_dpc;
    ebpf_result_t error_on_full;
    ebpf_result_t expected_result;
    switch (map_type) {
    case BPF_MAP_TYPE_HASH:
        is_array = false;
        supports_find_and_delete = true;
        behavior_on_max_entries = MAP_BEHAVIOR_INSERT;
        run_at_dpc = false;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_ARRAY:
        is_array = true;
        supports_find_and_delete = false;
        run_at_dpc = false;
        error_on_full = EBPF_INVALID_ARGUMENT;
        break;
    case BPF_MAP_TYPE_PERCPU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        behavior_on_max_entries = MAP_BEHAVIOR_INSERT;
        run_at_dpc = true;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        is_array = true;
        supports_find_and_delete = false;
        run_at_dpc = false;
        error_on_full = EBPF_INVALID_ARGUMENT;
        break;
    case BPF_MAP_TYPE_LRU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        behavior_on_max_entries = MAP_BEHAVIOR_REPLACE;
        run_at_dpc = false;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
        is_array = false;
        supports_find_and_delete = true;
        behavior_on_max_entries = MAP_BEHAVIOR_REPLACE;
        run_at_dpc = true;
        error_on_full = EBPF_OUT_OF_SPACE;
        break;
    default:
        ebpf_assert((false, "Unsupported map type"));
        return;
    }
    std::optional<emulate_dpc_t> dpc;
    if (run_at_dpc) {
        dpc = {emulate_dpc_t(1)};
    }

    ebpf_map_definition_in_memory_t map_definition{map_type, sizeof(uint32_t), sizeof(uint64_t), _test_map_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    std::vector<uint8_t> value(ebpf_map_get_definition(map.get())->value_size);
    for (uint32_t key = 0; key < _test_map_size; key++) {
        *reinterpret_cast<uint64_t*>(value.data()) = static_cast<uint64_t>(key) * static_cast<uint64_t>(key);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                sizeof(key),
                reinterpret_cast<const uint8_t*>(&key),
                value.size(),
                value.data(),
                EBPF_ANY,
                0) == EBPF_SUCCESS);
    }

    // Test for inserting max_entries + 1.
    uint32_t bad_key = _test_map_size;
    *reinterpret_cast<uint64_t*>(value.data()) = static_cast<uint64_t>(bad_key) * static_cast<uint64_t>(bad_key);
    REQUIRE(
        ebpf_map_update_entry(
            map.get(),
            sizeof(bad_key),
            reinterpret_cast<const uint8_t*>(&bad_key),
            value.size(),
            value.data(),
            EBPF_ANY,
            0) == ((behavior_on_max_entries != MAP_BEHAVIOR_FAIL) ? EBPF_SUCCESS : error_on_full));

    if (behavior_on_max_entries != MAP_BEHAVIOR_REPLACE) {
        expected_result = (behavior_on_max_entries == MAP_BEHAVIOR_INSERT)
                              ? EBPF_SUCCESS
                              : (is_array ? EBPF_INVALID_ARGUMENT : EBPF_KEY_NOT_FOUND);
        REQUIRE(
            ebpf_map_delete_entry(map.get(), sizeof(bad_key), reinterpret_cast<const uint8_t*>(&bad_key), 0) ==
            expected_result);
    }

    // Now the map has `_test_map_size` entries.

    for (uint32_t key = 0; key < _test_map_size; key++) {
        if (behavior_on_max_entries == MAP_BEHAVIOR_REPLACE) {
            // If map behavior is MAP_BEHAVIOR_REPLACE, then 0th entry would have been evicted.
            expected_result = key == 0 ? EBPF_OBJECT_NOT_FOUND : EBPF_SUCCESS;
        } else if (behavior_on_max_entries == MAP_BEHAVIOR_INSERT) {
            expected_result = EBPF_SUCCESS;
        } else {
            expected_result = key == _test_map_size ? EBPF_OBJECT_NOT_FOUND : EBPF_SUCCESS;
        }
        REQUIRE(
            ebpf_map_find_entry(
                map.get(), sizeof(key), reinterpret_cast<const uint8_t*>(&key), value.size(), value.data(), 0) ==
            expected_result);
        if (expected_result == EBPF_SUCCESS) {
            REQUIRE(*reinterpret_cast<uint64_t*>(value.data()) == key * key);
        }
    }

    uint32_t previous_key;
    uint32_t next_key;
    std::set<uint32_t> keys;
    for (uint32_t key = 0; key < _test_map_size; key++) {
        REQUIRE(
            ebpf_map_next_key(
                map.get(),
                sizeof(key),
                key == 0 ? nullptr : reinterpret_cast<const uint8_t*>(&previous_key),
                reinterpret_cast<uint8_t*>(&next_key)) == EBPF_SUCCESS);

        previous_key = next_key;
        keys.insert(previous_key);
    }
    REQUIRE(keys.size() == _test_map_size);

    REQUIRE(
        ebpf_map_next_key(
            map.get(),
            sizeof(previous_key),
            reinterpret_cast<const uint8_t*>(&previous_key),
            reinterpret_cast<uint8_t*>(&next_key)) == EBPF_NO_MORE_KEYS);

    std::vector<size_t> batch_test_sizes = {
        1,
        17,
        _test_map_size / 4,
        _test_map_size,
        _test_map_size * 2,
    };
    for (size_t batch_count : batch_test_sizes) {

        keys.clear();
        size_t effective_key_size = ebpf_map_get_definition(map.get())->key_size;
        size_t effective_value_size = ebpf_map_get_definition(map.get())->value_size;
        std::vector<uint8_t> batch_data(batch_count * (effective_key_size + effective_value_size));
        ebpf_result_t return_value = EBPF_SUCCESS;

        for (uint32_t index = 0; return_value == EBPF_SUCCESS; index++) {
            size_t batch_data_size = batch_data.size();
            return_value = ebpf_map_get_next_key_and_value_batch(
                map.get(),
                sizeof(previous_key),
                index == 0 ? nullptr : reinterpret_cast<uint8_t*>(&previous_key),
                &batch_data_size,
                batch_data.data(),
                0);

            if (return_value == EBPF_NO_MORE_KEYS) {
                break;
            }

            REQUIRE(return_value == EBPF_SUCCESS);

            REQUIRE(batch_data_size <= batch_data.size());
            size_t returned_batch_count = batch_data_size / (effective_key_size + effective_value_size);

            // Verify that all keys are returned.
            for (uint32_t batch_index = 0; batch_index < returned_batch_count; batch_index++) {
                uint32_t current_key = *reinterpret_cast<uint32_t*>(
                    &batch_data[batch_index * (effective_key_size + effective_value_size)]);
                uint64_t current_value = *reinterpret_cast<uint64_t*>(
                    &batch_data[batch_index * (effective_key_size + effective_value_size) + effective_key_size]);
                keys.insert(current_key);
                REQUIRE(current_value == current_key * current_key);
            }
            previous_key = *reinterpret_cast<uint32_t*>(
                &batch_data[(returned_batch_count - 1) * (effective_key_size + effective_value_size)]);
        }
        REQUIRE(keys.size() == _test_map_size);
    }

    for (const auto key : keys) {
        REQUIRE(
            ebpf_map_delete_entry(map.get(), sizeof(key), reinterpret_cast<const uint8_t*>(&key), 0) == EBPF_SUCCESS);
    }

    if (supports_find_and_delete) {
        uint32_t key = 0;
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                sizeof(key),
                reinterpret_cast<const uint8_t*>(&key),
                value.size(),
                value.data(),
                EBPF_ANY,
                0) == EBPF_SUCCESS);

        REQUIRE(
            ebpf_map_find_entry(
                map.get(),
                sizeof(key),
                reinterpret_cast<const uint8_t*>(&key),
                value.size(),
                value.data(),
                EBPF_MAP_FIND_FLAG_DELETE) == EBPF_SUCCESS);

        REQUIRE(
            ebpf_map_find_entry(
                map.get(), sizeof(key), reinterpret_cast<const uint8_t*>(&key), value.size(), value.data(), 0) ==
            EBPF_OBJECT_NOT_FOUND);
    } else {
        uint32_t key = 0;
        REQUIRE(
            ebpf_map_find_entry(
                map.get(),
                sizeof(key),
                reinterpret_cast<const uint8_t*>(&key),
                value.size(),
                value.data(),
                EBPF_MAP_FIND_FLAG_DELETE) == EBPF_INVALID_ARGUMENT);
    }

    auto retrieved_map_definition = *ebpf_map_get_definition(map.get());
    retrieved_map_definition.value_size = ebpf_map_get_effective_value_size(map.get());
    REQUIRE(memcmp(&retrieved_map_definition, &map_definition, sizeof(map_definition)) == 0);

    // Negative test for key size.
    uint32_t key = 0;
    REQUIRE(
        ebpf_map_next_key(
            map.get(), sizeof(key) - 1, reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(ebpf_map_push_entry(map.get(), value.size(), value.data(), 0) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_map_pop_entry(map.get(), value.size(), value.data(), 0) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_map_peek_entry(map.get(), value.size(), value.data(), 0) == EBPF_INVALID_ARGUMENT);
}

#define MAP_TEST(MAP_TYPE) \
    TEST_CASE("map_crud_operations:" #MAP_TYPE, "[execution_context]") { _test_crud_operations(MAP_TYPE); }

MAP_TEST(BPF_MAP_TYPE_HASH);
MAP_TEST(BPF_MAP_TYPE_ARRAY);
MAP_TEST(BPF_MAP_TYPE_PERCPU_HASH);
MAP_TEST(BPF_MAP_TYPE_PERCPU_ARRAY);
MAP_TEST(BPF_MAP_TYPE_LRU_HASH);
MAP_TEST(BPF_MAP_TYPE_LRU_PERCPU_HASH);

TEST_CASE("map_create_invalid", "[execution_context][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();

    // Define map definitions with invalid parameters.
    std::map<std::string, ebpf_map_definition_in_memory_t> invalid_map_definitions = {
        {
            "BPF_MAP_TYPE_ARRAY",
            {
                BPF_MAP_TYPE_ARRAY,
                4,
                4284506112, // Value size / capacity combination allocates >128GB.
                105512960,
            },
        },
        {
            "BPF_MAP_TYPE_RINGBUF",
            {
                BPF_MAP_TYPE_RINGBUF,
                4, // Key size must be 0 for ring buffer.
                20,
                20,
            },
        },
        {
            "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
            {
                BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                4, // Key size must be 0 for perf event array.
                20,
                20,
            },
        },
        {
            "BPF_MAP_TYPE_HASH_OF_MAPS",
            {
                BPF_MAP_TYPE_HASH_OF_MAPS,
                4,
                0, // Value size must equal sizeof(ebpf_id_t)
                10,
                1,
            },
        },
        {
            "BPF_MAP_TYPE_ARRAY_OF_MAPS",
            {
                BPF_MAP_TYPE_ARRAY_OF_MAPS,
                4,
                0, // Value size must equal sizeof(ebpf_id_t)
                10,
                1,
            },
        },
    };

    for (const auto& [name, def] : invalid_map_definitions) {
        cxplat_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
        ebpf_handle_t handle;
        ebpf_handle_t inner_handle = ebpf_handle_invalid;
        CAPTURE(name);
        REQUIRE(ebpf_core_create_map(&utf8_name, &def, inner_handle, &handle) == EBPF_INVALID_ARGUMENT);
    }
}

// Helper struct to represent a 32 bit IP prefix.
typedef struct _lpm_trie_32_key
{
    uint32_t prefix_length;
    uint8_t value[4];
} lpm_trie_32_key_t;

// Helper function to create a string representation of a 32 bit ip prefix.
std::string
_ip32_prefix_string(uint32_t prefix_length, const uint8_t value[])
{
    std::string key_string = std::to_string(value[0]) + "." + std::to_string(value[1]) + "." +
                             std::to_string(value[2]) + "." + std::to_string(value[3]) + "/" +
                             std::to_string(prefix_length);
    return key_string;
}

// Helper function to create a pair of lpm_trie_32_key_t and the string representation of the 32 bit ip prefix.
std::pair<lpm_trie_32_key_t, std::string>
_lpm_ip32_prefix_pair(uint32_t prefix_length, uint8_t byte0, uint8_t byte1, uint8_t byte2, uint8_t byte3)
{
    lpm_trie_32_key_t key{prefix_length, {byte0, byte1, byte2, byte3}};
    return {key, _ip32_prefix_string(prefix_length, key.value)};
}

TEST_CASE("map_crud_operations_lpm_trie_32", "[execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();
    const size_t max_string = 17;

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> keys{
        _lpm_ip32_prefix_pair(24, 192, 168, 15, 0),
        _lpm_ip32_prefix_pair(24, 192, 168, 16, 0),
        _lpm_ip32_prefix_pair(31, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(30, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(29, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(32, 192, 168, 15, 7),
        _lpm_ip32_prefix_pair(16, 192, 168, 0, 0),
        _lpm_ip32_prefix_pair(32, 10, 10, 255, 255),
        _lpm_ip32_prefix_pair(16, 10, 10, 0, 0),
        _lpm_ip32_prefix_pair(8, 10, 0, 0, 0),
        _lpm_ip32_prefix_pair(0, 0, 0, 0, 0),
    };

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> tests{
        {{32, 192, 168, 15, 1}, "192.168.15.0/24"},
        {{32, 192, 168, 15, 7}, "192.168.15.7/32"},
        {{32, 192, 168, 16, 25}, "192.168.16.0/24"},
        {{32, 192, 168, 14, 1}, "192.168.14.0/31"},
        {{32, 192, 168, 14, 2}, "192.168.14.0/30"},
        {{32, 192, 168, 14, 4}, "192.168.14.0/29"},
        {{32, 192, 168, 14, 9}, "192.168.0.0/16"},
        {{32, 10, 10, 255, 255}, "10.10.255.255/32"},
        {{32, 10, 10, 10, 10}, "10.10.0.0/16"},
        {{32, 10, 11, 10, 10}, "10.0.0.0/8"},
        {{8, 10, 10, 10, 10}, "10.0.0.0/8"},
        {{32, 11, 0, 0, 0}, "0.0.0.0/0"},
    };

    uint32_t max_entries = static_cast<uint32_t>(keys.size());
    ebpf_map_definition_in_memory_t map_definition{
        BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_32_key_t), max_string, max_entries};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    // Insert keys into the map.
    for (auto [key, key_string] : keys) {
        key_string.resize(max_string);
        CAPTURE(key_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(key_string.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Make sure we can find all the keys we just inserted.
    for (const auto& [key, correct_value] : keys) {
        std::string key_string = _ip32_prefix_string(key.prefix_length, key.value);
        CAPTURE(key_string, correct_value);
        char* return_value = nullptr;
        CHECK(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&return_value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        CHECK(return_value == correct_value);
    }

    // Lookup IP prefixes in the map.
    for (const auto& [key, correct_value] : tests) {
        std::string key_string = _ip32_prefix_string(key.prefix_length, key.value);
        CAPTURE(key_string, correct_value);
        char* return_value = nullptr;
        CHECK(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&return_value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        CHECK(return_value == correct_value);
    }

    {
        // Insert a new key.
        lpm_trie_32_key_t key = {32, 192, 168, 15, 1};
        std::string key_string = _ip32_prefix_string(key.prefix_length, key.value);
        CAPTURE(key_string);
        key_string.resize(max_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(key_string.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Re-insert the same keys (to test update)
    for (auto [key, key_string] : keys) {
        key_string.resize(max_string);
        CAPTURE(key_string);
        CHECK(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(key_string.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Delete all the keys.
    for (const auto& [key, key_string] : keys) {
        CAPTURE(key_string);
        CHECK(
            ebpf_map_delete_entry(map.get(), 0, reinterpret_cast<const uint8_t*>(&key), EBPF_MAP_FLAG_HELPER) ==
            EBPF_SUCCESS);
    }
}

TEST_CASE("map_crud_operations_lpm_trie_32", "[execution_context][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();
    const size_t max_string = 21;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_32_key_t), max_string, 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> invalid_keys{
        _lpm_ip32_prefix_pair((uint32_t)-1, 192, 168, 0, 1),
        _lpm_ip32_prefix_pair(33, 10, 0, 0, 1),
        _lpm_ip32_prefix_pair(100, 172, 16, 0, 1),
    };

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> keys{
        _lpm_ip32_prefix_pair(24, 192, 168, 15, 0),
        _lpm_ip32_prefix_pair(24, 192, 168, 16, 0),
        _lpm_ip32_prefix_pair(31, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(30, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(29, 192, 168, 14, 0),
        _lpm_ip32_prefix_pair(16, 192, 168, 0, 0),
        _lpm_ip32_prefix_pair(12, 172, 16, 0, 0),
        _lpm_ip32_prefix_pair(8, 10, 0, 0, 0),
    };

    std::vector<std::pair<lpm_trie_32_key_t, std::string>> negative_tests{
        _lpm_ip32_prefix_pair(32, 192, 169, 0, 0),
        _lpm_ip32_prefix_pair(24, 192, 169, 0, 0),
        _lpm_ip32_prefix_pair(15, 192, 168, 0, 0),
        _lpm_ip32_prefix_pair(0, 192, 168, 0, 0),
        _lpm_ip32_prefix_pair(12, 172, 48, 0, 0),
        _lpm_ip32_prefix_pair(11, 172, 16, 0, 0),
        _lpm_ip32_prefix_pair(8, 11, 0, 0, 0),
        _lpm_ip32_prefix_pair(8, 11, 0, 0, 0),
        _lpm_ip32_prefix_pair(0, 0, 0, 0, 0),
    };

    // Inserting invalid keys should return EBPF_INVALID_ARGUMENT.
    for (auto [key, key_string] : invalid_keys) {
        CAPTURE(key_string);
        key_string.resize(max_string);
        ebpf_result_t status = ebpf_map_update_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<const uint8_t*>(key_string.c_str()),
            EBPF_ANY,
            EBPF_MAP_FLAG_HELPER);
        REQUIRE(status == EBPF_INVALID_ARGUMENT);
    }

    // Looking up invalid keys should return EBPF_INVALID_ARGUMENT
    for (const auto& [key, key_string] : invalid_keys) {
        CAPTURE(key_string);
        char* return_value = nullptr;
        ebpf_result_t status = ebpf_map_find_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<uint8_t*>(&return_value),
            EBPF_MAP_FLAG_HELPER);
        REQUIRE(status == EBPF_INVALID_ARGUMENT);
        REQUIRE(return_value == nullptr);
    }

    // Deleting invalid keys should return EBPF_INVALID_ARGUMENT
    for (const auto& [key, key_string] : invalid_keys) {
        CAPTURE(key_string);
        ebpf_result_t status =
            ebpf_map_delete_entry(map.get(), 0, reinterpret_cast<const uint8_t*>(&key), EBPF_MAP_FLAG_HELPER);
        REQUIRE(status == EBPF_INVALID_ARGUMENT);
    }

    // Now insert some valid keys for testing.
    for (auto [key, key_string] : keys) {
        CAPTURE(key_string);
        key_string.resize(max_string);
        ebpf_result_t status = ebpf_map_update_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<const uint8_t*>(key_string.c_str()),
            EBPF_ANY,
            EBPF_MAP_FLAG_HELPER);
        REQUIRE(status == EBPF_SUCCESS);
    }

    // Sanity check by looking up the valid keys.
    for (const auto& [key, key_string] : keys) {
        CAPTURE(key_string);
        char* return_value = nullptr;
        ebpf_result_t status = ebpf_map_find_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<uint8_t*>(&return_value),
            EBPF_MAP_FLAG_HELPER);
        CAPTURE(return_value);
        REQUIRE(status == EBPF_SUCCESS);
        REQUIRE(return_value != nullptr);
        REQUIRE(return_value == key_string);
    }

    // Keys that don't exist should return EBPF_KEY_NOT_FOUND.
    for (const auto& [key, key_string] : negative_tests) {
        CAPTURE(key_string);
        char* return_value = nullptr;
        ebpf_result_t status = ebpf_map_find_entry(
            map.get(),
            0,
            reinterpret_cast<const uint8_t*>(&key),
            0,
            reinterpret_cast<uint8_t*>(&return_value),
            EBPF_MAP_FLAG_HELPER);
        CAPTURE(return_value);
        CHECK(status == EBPF_KEY_NOT_FOUND);
        CHECK(return_value == nullptr);
    }

    // Deleting keys that don't exist should return EBPF_KEY_NOT_FOUND.
    for (const auto& [key, key_string] : negative_tests) {
        CAPTURE(key_string);

#pragma warning(push)
#pragma warning(disable : 28193)
        // Analyze build throws 28193 for unexamined return value (status)
        ebpf_result_t status =
            ebpf_map_delete_entry(map.get(), 0, reinterpret_cast<const uint8_t*>(&key), EBPF_MAP_FLAG_HELPER);
#pragma warning(pop)
        REQUIRE(status == EBPF_KEY_NOT_FOUND);
    }
}

// Helper struct to represent a 128 bit prefix.
typedef struct _lpm_trie_128_key
{
    uint32_t prefix_length;
    uint8_t value[16];
} lpm_trie_128_key_t;

std::string
_lpm_128_simple_prefix_string(uint32_t prefix_length, uint8_t value)
{
    std::stringstream builder;
    builder << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (int)value << "/"
            << std::to_string(prefix_length);
    return builder.str();
}

// Helper function to create a pair of lpm_trie_128_key_t and the string representation.
// - Generates the prefix by duplicating the given value.
// - if prefix_string is empty, it is filled with "XX/N" where XX is value in hex, and N is prefix_length.
std::pair<lpm_trie_128_key_t, std::string>
_lpm_128_prefix_pair(uint32_t prefix_length, uint8_t value, std::string prefix_string = "")
{
    lpm_trie_128_key_t key{prefix_length};
    memset(key.value, value, (prefix_length + 7) / 8);

    if (prefix_string.empty()) {
        prefix_string = _lpm_128_simple_prefix_string(prefix_length, value);
    }

    return {key, prefix_string};
}

TEST_CASE("map_crud_operations_lpm_trie_128", "[execution_context]")
{
    _ebpf_core_initializer core;
    core.initialize();

    const size_t max_string = 20;
    std::vector<std::pair<lpm_trie_128_key_t, std::string>> keys{
        _lpm_128_prefix_pair(96, 0xCC),
        _lpm_128_prefix_pair(96, 0xCD),
        _lpm_128_prefix_pair(124, 0xDD),
        _lpm_128_prefix_pair(120, 0xDD),
        _lpm_128_prefix_pair(116, 0xDD),
        _lpm_128_prefix_pair(64, 0xAA),
        _lpm_128_prefix_pair(128, 0xBB),
        _lpm_128_prefix_pair(127, 0xBB),
        _lpm_128_prefix_pair(64, 0xBB),
        _lpm_128_prefix_pair(32, 0xBB),
        _lpm_128_prefix_pair(0, 0),
    };

    uint32_t max_entries = static_cast<uint32_t>(keys.size());
    ebpf_map_definition_in_memory_t map_definition{
        BPF_MAP_TYPE_LPM_TRIE, sizeof(lpm_trie_128_key_t), max_string, max_entries};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    std::vector<std::pair<lpm_trie_128_key_t, std::string>> tests{
        _lpm_128_prefix_pair(97, 0xCC, "CC/96"),
        _lpm_128_prefix_pair(120, 0xCD, "CD/96"),
        _lpm_128_prefix_pair(125, 0xDD, "DD/124"),
        _lpm_128_prefix_pair(124, 0xDD),
        _lpm_128_prefix_pair(123, 0xDD, "DD/120"),
        _lpm_128_prefix_pair(121, 0xDD, "DD/120"),
        _lpm_128_prefix_pair(120, 0xDD),
        _lpm_128_prefix_pair(119, 0xDD, "DD/116"),
        _lpm_128_prefix_pair(116, 0xDD),
        _lpm_128_prefix_pair(115, 0xDD, "00/0"),
        _lpm_128_prefix_pair(72, 0xAA, "AA/64"),
        _lpm_128_prefix_pair(128, 0xBB),
        _lpm_128_prefix_pair(127, 0xBB),
        _lpm_128_prefix_pair(126, 0xBB, "BB/64"),
        _lpm_128_prefix_pair(65, 0xBB, "BB/64"),
        _lpm_128_prefix_pair(64, 0xBB),
        _lpm_128_prefix_pair(63, 0xBB, "BB/32"),
        _lpm_128_prefix_pair(33, 0xBB, "BB/32"),
        _lpm_128_prefix_pair(32, 0xBB),
        _lpm_128_prefix_pair(31, 0xBB, "00/0"),
        _lpm_128_prefix_pair(128, 0xFF, "00/0"),
    };

    // Insert keys into the map.
    for (auto& [key, value] : keys) {
        std::string key_string = value;
        CAPTURE(key_string);
        key_string.resize(max_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<const uint8_t*>(key_string.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Verify looking up the keys we inserted returns the same value
    for (auto& [key, key_string] : keys) {
        CAPTURE(key_string);
        char* return_value = nullptr;
        CHECK(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&return_value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        CHECK(std::string(return_value) == key_string);
    }

    // Perform additional lookup tests
    for (auto& [key, correct_value] : tests) {
        std::string key_string = _lpm_128_simple_prefix_string(key.prefix_length, key.value[0]);
        CAPTURE(key_string, correct_value);
        char* return_value = nullptr;
        CHECK(
            ebpf_map_find_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&key),
                0,
                reinterpret_cast<uint8_t*>(&return_value),
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
        CHECK(std::string(return_value) == correct_value);
    }

    {
        // Update an existing entry, it should succeed.
        auto lpm_pair = _lpm_128_prefix_pair(32, 0xBB);
        std::string key_string = lpm_pair.second;
        CAPTURE(key_string);
        lpm_pair.second.resize(max_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&lpm_pair.first),
                0,
                reinterpret_cast<const uint8_t*>(lpm_pair.second.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }
    {
        // Add a new entry to the map, it should succeed.
        auto lpm_pair = _lpm_128_prefix_pair(33, 0xBB);
        std::string key_string = lpm_pair.second;
        CAPTURE(key_string);
        REQUIRE(
            ebpf_map_update_entry(
                map.get(),
                0,
                reinterpret_cast<const uint8_t*>(&lpm_pair.first),
                0,
                reinterpret_cast<const uint8_t*>(lpm_pair.second.c_str()),
                EBPF_ANY,
                EBPF_MAP_FLAG_HELPER) == EBPF_SUCCESS);
    }

    // Delete all the keys we originally inserted.
    for (const auto& [key, key_string] : keys) {
        CAPTURE(key_string);
        CHECK(
            ebpf_map_delete_entry(map.get(), 0, reinterpret_cast<const uint8_t*>(&key), EBPF_MAP_FLAG_HELPER) ==
            EBPF_SUCCESS);
    }
}

TEST_CASE("perf_event_array_unsupported_ops", "[execution_context][perf_event_array][negative]")
{
    _ebpf_core_initializer core;
    core.initialize();
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, 64 * 1024};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    uint32_t key = 0;
    uint32_t value2 = 0;
    REQUIRE(
        ebpf_map_update_entry(map.get(), sizeof(key), reinterpret_cast<uint8_t*>(&key), 0, nullptr, EBPF_ANY, 0) ==
        EBPF_INVALID_ARGUMENT);

    // Negative test cases.
    REQUIRE(
        ebpf_map_update_entry(
            map.get(), 0, nullptr, sizeof(value2), reinterpret_cast<uint8_t*>(&value2), EBPF_ANY, 0) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(ebpf_map_update_entry(map.get(), 0, nullptr, 0, nullptr, EBPF_ANY, 0) == EBPF_OPERATION_NOT_SUPPORTED);

    REQUIRE(ebpf_map_get_program_from_entry(map.get(), sizeof(&key), reinterpret_cast<uint8_t*>(&key)) == nullptr);
    REQUIRE(ebpf_map_get_program_from_entry(map.get(), 0, 0) == nullptr);

    REQUIRE(
        ebpf_map_find_entry(map.get(), sizeof(key), reinterpret_cast<uint8_t*>(&key), 0, nullptr, 0) ==
        EBPF_INVALID_ARGUMENT);
    REQUIRE(
        ebpf_map_find_entry(map.get(), 0, nullptr, sizeof(value2), reinterpret_cast<uint8_t*>(&value2), 0) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(ebpf_map_find_entry(map.get(), 0, nullptr, 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_delete_entry(map.get(), 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_next_key(map.get(), 0, nullptr, nullptr) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_push_entry(map.get(), 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_pop_entry(map.get(), 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
    REQUIRE(ebpf_map_peek_entry(map.get(), 0, nullptr, 0) == EBPF_OPERATION_NOT_SUPPORTED);
}

struct perf_event_array_test_async_context_t
{
    uint8_t* buffer = NULL;
    uint32_t buffer_size = 0;
    uint32_t cpu_id = 0;
    size_t consumer_offset = 0; // Offset of the consumer.
    size_t offset_mismatch_count = 0;
    size_t callback_count = 0;   // Number of callbacks received.
    size_t record_count = 0;     // Number of records consumed.
    size_t bad_record_count = 0; // Number of invalid records seen.
    size_t empty_callbacks = 0;  // Number of times we got a callback but there was no record.
    size_t discard_count = 0;    // Number of discarded records seen (should always be zero for perf event array).
    size_t locked_count =
        0; // Number of times we stopped reading because we saw a locked record instead of reaching the producer offset.
    size_t lost_count = 0;   // Number of lost records.
    size_t cancel_count = 0; // Number of times we were canceled.
    uint64_t value = 0;      // Value of the record consumed.
    ebpf_map_async_query_result_t async_query_result = {0};
};

/**
 * @brief Callback function for async query completion.
 *
 * Collects counts for verifying the test.
 *
 * @param context The test context.
 * @param output_buffer_length The length of the output buffer.
 * @param result The result of the async query.
 */
void
perf_event_array_test_async_complete(_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result)
{
    UNREFERENCED_PARAMETER(output_buffer_length);
    auto test_context = reinterpret_cast<perf_event_array_test_async_context_t*>(context);
    auto async_query_result = &test_context->async_query_result;
    test_context->callback_count++;
    test_context->lost_count += async_query_result->lost_count;

    if (result != EBPF_SUCCESS) {
        REQUIRE(result == EBPF_CANCELED);
        test_context->cancel_count++;
        return;
    }

    if (async_query_result->consumer != test_context->consumer_offset) {
        test_context->offset_mismatch_count++;
        test_context->consumer_offset = async_query_result->consumer;
    }
    size_t consumer_offset = test_context->consumer_offset;
    size_t producer_offset = async_query_result->producer;

    size_t record_count = 0;
    size_t discard_count = 0; // This should always be zero for perf event array.
    while (auto record = ebpf_ring_buffer_next_record(
               test_context->buffer, test_context->buffer_size, consumer_offset, producer_offset)) {
        if (ebpf_ring_buffer_record_is_locked(record)) {
            test_context->locked_count++;
            break;
        }
        if (ebpf_ring_buffer_record_is_discarded(record)) {
            discard_count++; // Should always be zero for perf event array.
        } else {
            record_count++;
        }
        if (ebpf_ring_buffer_record_length(record) != sizeof(uint64_t)) {
            test_context->bad_record_count++;
        } else {
            test_context->value = *(uint64_t*)(record->data);
        }
        consumer_offset += ebpf_ring_buffer_record_total_size(record);
    }
    test_context->consumer_offset = consumer_offset;
    test_context->record_count += record_count;
    test_context->discard_count += discard_count;
    if (record_count == 0) {
        test_context->empty_callbacks++;
    }
}

TEST_CASE("perf_event_array_output", "[execution_context][perf_event_array]")
{
    _ebpf_core_initializer core;
    core.initialize();
    uint32_t buffer_size = 64 * 1024;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, buffer_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    uint32_t cpu_id = 0;
    scoped_cpu_affinity cpu_affinity(cpu_id);

    struct
    {
        EBPF_CONTEXT_HEADER; // Unused for this test.
        int unused;
    } context{0};

    void* ctx = &context.unused;

    uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU;

    perf_event_array_test_async_context_t completion;
    completion.cpu_id = cpu_id;
    completion.buffer_size = buffer_size;
    REQUIRE(ebpf_map_query_buffer(map.get(), cpu_id, &completion.buffer, &completion.consumer_offset) == EBPF_SUCCESS);
    REQUIRE(ebpf_async_set_completion_callback(&completion, perf_event_array_test_async_complete) == EBPF_SUCCESS);
    REQUIRE(completion.consumer_offset == 0);
    // Initialize consumer offset in async result used to track current position.
    completion.async_query_result.consumer = completion.consumer_offset;

    uint64_t value = 1;
    REQUIRE(
        ebpf_perf_event_array_map_output_with_capture(
            ctx, map.get(), flags, reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    ebpf_result_t result = ebpf_map_async_query(map.get(), cpu_id, &completion.async_query_result, &completion);
    if (result != EBPF_PENDING) { // If async query failed synchronously, reset the completion callback.
        REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
    }
    REQUIRE(result == EBPF_PENDING);

    REQUIRE(completion.callback_count == 1);
    REQUIRE(completion.lost_count == 0);
    REQUIRE(completion.record_count == 1);
    REQUIRE(completion.empty_callbacks == 0);
    REQUIRE(completion.discard_count == 0);
    REQUIRE(completion.locked_count == 0);
    REQUIRE(completion.offset_mismatch_count == 0);
    REQUIRE(completion.bad_record_count == 0);
    REQUIRE(completion.cancel_count == 0);
    uint64_t producer_offset = completion.async_query_result.producer;
    uint64_t consumer_offset = completion.async_query_result.consumer;
    REQUIRE(consumer_offset == 0);
    REQUIRE(completion.consumer_offset == producer_offset);
    REQUIRE(producer_offset == ((EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) + sizeof(uint64_t) + 7) & ~7));
    REQUIRE(ebpf_map_return_buffer(map.get(), cpu_id, completion.consumer_offset - consumer_offset) == EBPF_SUCCESS);

    REQUIRE(completion.value == value);
}

TEST_CASE("perf_event_array_output_percpu", "[execution_context][perf_event_array]")
{
    _ebpf_core_initializer core;
    core.initialize();
    constexpr uint32_t buffer_size = 64 * 1024;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, buffer_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    uint32_t ring_count = ebpf_get_cpu_count();
    std::vector<perf_event_array_test_async_context_t> completions(ring_count);

    auto cleanup = std::unique_ptr<void, std::function<void(void*)>>(
        reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
        [&](void*) {
            // Cleanup - in unique_ptr scope guard to ensure cleanup on failure.
            // This guard ensures cleanup on fault injection and also verifies the callback counters.
            // Counters
            size_t total_callback_count = 0;
            size_t total_record_count = 0;
            size_t total_norecord_count = 0;
            size_t total_lost_count = 0;
            size_t cancel_count = 0;

            for (auto& completion : completions) {
                if (completion.buffer_size > 0) { // If buffer_size not set yet then we never started this query.
                    CAPTURE(
                        completion.cpu_id,
                        completion.record_count,
                        completion.norecord_count,
                        completion.cancel_count,
                        completion.lost_count);
                    CHECK(completion.callback_count <= 1);
                    CHECK(completion.lost_count == 0);
                    // We try canceling each operation, but only ones that haven't completed will actually cancel.
                    bool must_cancel = completion.callback_count == 0;
                    bool cancel_result = ebpf_async_cancel(&completion);
                    if (cancel_result == true) {
                        cancel_count++;
                    }
                    CHECK(cancel_result == must_cancel);
                    total_callback_count += completion.callback_count;
                    total_record_count += completion.record_count;
                    total_norecord_count += completion.norecord_count;
                    total_lost_count += completion.lost_count;
                    if (completion.record_count > 0) {
                        // This was the ring that got the record.
                        CHECK(completion.record_count == 1);
                        CHECK(completion.value == value);
                    }
                }
            }
        });

    // Map each ring and set up completion callbacks.
    for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
        auto& completion = completions[cpu_id];
        completion.cpu_id = cpu_id;
        // Map the ring memory.
        REQUIRE(
            ebpf_map_query_buffer(map.get(), completion.cpu_id, &completion.buffer, &completion.consumer_offset) ==
            EBPF_SUCCESS);

        // Set up the completion callback.
        REQUIRE(
            ebpf_async_set_completion_callback(
                &completion, [](_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result) {
                    UNREFERENCED_PARAMETER(output_buffer_length);
                    auto completion = reinterpret_cast<perf_event_array_test_async_context_t*>(context);
                    auto async_query_result = &completion->async_query_result;
                    completion->callback_count++;
                    completion->lost_count += async_query_result->lost_count;
                    auto record = ebpf_ring_buffer_next_record(
                        completion->buffer,
                        completion->buffer_size,
                        async_query_result->consumer,
                        async_query_result->producer);
                    if (record == nullptr) {
                        completion->norecord_count++;
                    } else if (!ebpf_ring_buffer_record_is_locked(record)) {
                        completion->record_count++;
                        completion->value = *(uint64_t*)(record->data);
                    }
                    if (result != EBPF_SUCCESS) {
                        REQUIRE(result == EBPF_CANCELED);
                        completion->cancel_count++;
                    }
                }) == EBPF_SUCCESS);

        // Start the async query.
        ebpf_result_t result = ebpf_map_async_query(map.get(), cpu_id, &completion.async_query_result, &completion);
        if (result != EBPF_PENDING) { // If async query failed synchronously, reset the completion callback.
            REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
        }
        completion.buffer_size = buffer_size; // After we set buffer_size the query will be cleaned up on exit.
        REQUIRE(result == EBPF_PENDING);
    }

    // Write the CPU ID to each ring.
    for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
        scoped_cpu_affinity cpu_affinity(cpu_id);

        struct
        {
            EBPF_CONTEXT_HEADER; // Unused for this test.
            int unused;
        } context{0};

        void* ctx = &context.unused;

        uint64_t value = cpu_id;
        uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU;

        REQUIRE(
            ebpf_perf_event_array_map_output_with_capture(
                ctx, map.get(), flags, reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);
    }

    // Verify the value written to each ring.
    for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
        auto& completion = completions[cpu_id];

        REQUIRE(completion.callback_count == 1);
        REQUIRE(completion.record_count == 1);
        REQUIRE(completion.value == cpu_id);
        REQUIRE(completion.lost_count == 0);
        REQUIRE(completion.empty_callbacks == 0);
        REQUIRE(completion.discard_count == 0);
        REQUIRE(completion.locked_count == 0);
        REQUIRE(completion.offset_mismatch_count == 0);
        REQUIRE(completion.bad_record_count == 0);
        REQUIRE(completion.cancel_count == 0);

        // Return the buffer space.
        REQUIRE(
            ebpf_map_return_buffer(
                map.get(), cpu_id, completion.consumer_offset - completion.async_query_result.consumer) ==
            EBPF_SUCCESS);
    }
}

TEST_CASE("perf_event_array_output_capture", "[execution_context][perf_event_array]")
{
    _ebpf_core_initializer core;
    core.initialize();
    constexpr uint32_t buffer_size = 64 * 1024;
    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, 0, buffer_size};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }
    uint32_t cpu_id = 0;
    scoped_cpu_affinity cpu_affinity(cpu_id);

    size_t consumer_offset = 0;
    uint8_t* buffer = nullptr;
    REQUIRE(ebpf_map_query_buffer(map.get(), 0, &buffer, &consumer_offset) == EBPF_SUCCESS);

    std::vector<uint8_t> test_context_data(64);
    for (size_t i = 0; i < test_context_data.size(); i++) {
        test_context_data[i] = static_cast<uint8_t>(i * 3);
    }
    struct
    {
        EBPF_CONTEXT_HEADER; // Unused for this test.
        uint8_t* data;
        uint8_t* data_end;
    } context{0};
    context.data = test_context_data.data();
    context.data_end = test_context_data.data() + test_context_data.size();

    void* ctx = &context.data;
    ebpf_context_descriptor_t context_descriptor = {0};
    context_descriptor.size = sizeof(context);
    context_descriptor.data = 0;
    context_descriptor.end = EBPF_OFFSET_OF(decltype(context), data_end) - EBPF_OFFSET_OF(decltype(context), data);

    ebpf_program_set_header_context_descriptor(&context_descriptor, ctx);

    uint64_t capture_length = 10;
    uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU |
                     ((capture_length << EBPF_MAP_FLAG_CTX_LENGTH_SHIFT) & EBPF_MAP_FLAG_CTX_LENGTH_MASK);

    perf_event_array_test_async_context_t completion;
    completion.cpu_id = cpu_id;
    completion.buffer_size = buffer_size;
    REQUIRE(ebpf_map_query_buffer(map.get(), cpu_id, &completion.buffer, &completion.consumer_offset) == EBPF_SUCCESS);
    REQUIRE(ebpf_async_set_completion_callback(&completion, perf_event_array_test_async_complete) == EBPF_SUCCESS);
    REQUIRE(completion.consumer_offset == 0);
    // Initialize consumer offset in async result used to track current position.
    completion.async_query_result.consumer = completion.consumer_offset;

    uint64_t value = 1;
    REQUIRE(
        ebpf_perf_event_array_map_output_with_capture(
            ctx, map.get(), flags, reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);

    ebpf_result_t result = ebpf_map_async_query(map.get(), cpu_id, &completion.async_query_result, &completion);
    if (result != EBPF_PENDING) { // If async query failed synchronously, reset the completion callback.
        REQUIRE(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
    }
    REQUIRE(result == EBPF_PENDING);

    uint64_t total_data_length = sizeof(value) + capture_length;
    CAPTURE(
        capture_length,
        completion.callback_count,
        completion.lost_count,
        completion.record_count,
        completion.empty_callbacks,
        completion.discard_count,
        completion.locked_count,
        completion.offset_mismatch_count,
        completion.bad_record_count,
        completion.cancel_count,
        completion.consumer_offset,
        completion.async_query_result.consumer,
        completion.async_query_result.producer);

    REQUIRE(completion.callback_count == 1);
    REQUIRE(completion.lost_count == 0);
    REQUIRE(completion.record_count == 1);
    REQUIRE(completion.empty_callbacks == 0);
    REQUIRE(completion.discard_count == 0);
    REQUIRE(completion.locked_count == 0);
    REQUIRE(completion.offset_mismatch_count == 0);
    REQUIRE(completion.bad_record_count == 1); // The completion code expects 8 bytes, we added capture.
    REQUIRE(completion.cancel_count == 0);
    uint64_t producer_offset = completion.async_query_result.producer;
    consumer_offset = completion.async_query_result.consumer;
    REQUIRE(consumer_offset == 0);
    REQUIRE(completion.consumer_offset == producer_offset);
    REQUIRE(producer_offset == ((EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) + (total_data_length) + 7) & ~7));

    auto record =
        ebpf_ring_buffer_next_record(completion.buffer, completion.buffer_size, consumer_offset, producer_offset);
    REQUIRE(record != nullptr);
    // We already checked the header in the completion, so we don't need to check it again.
    REQUIRE(memcmp(record->data, &value, sizeof(value)) == 0);
    REQUIRE(memcmp(record->data + sizeof(value), test_context_data.data(), capture_length) == 0);

    REQUIRE(ebpf_map_return_buffer(map.get(), cpu_id, completion.consumer_offset - consumer_offset) == EBPF_SUCCESS);
}

TEST_CASE("context_descriptor_header", "[platform][perf_event_array]")
{
    // Confirm context descriptor header in program context works as expected.

    struct context_t
    {
        uint8_t* data;
        uint8_t* data_end;
    };
    // Full context includes EBPF_CONTEXT_HEADER plus the program accessible portion.
    struct full_context_t
    {
        EBPF_CONTEXT_HEADER;
        context_t ctx;
    } context;

    // ctx points to the bpf-program accessible portion (just after the header).
    void* ctx = &context.ctx;

    // The context descriptor tells the platform where to find the data pointers.
    ebpf_context_descriptor_t context_descriptor = {
        sizeof(context_t), EBPF_OFFSET_OF(context_t, data), EBPF_OFFSET_OF(context_t, data_end), -1};
    ebpf_program_set_header_context_descriptor(&context_descriptor, ctx);

    const ebpf_context_descriptor_t* test_ctx_descriptor;
    ebpf_program_get_header_context_descriptor(ctx, &test_ctx_descriptor);
    REQUIRE(test_ctx_descriptor == &context_descriptor);

    const uint8_t *data_start, *data_end;

    context_descriptor = {
        sizeof(context.ctx), EBPF_OFFSET_OF(context_t, data), EBPF_OFFSET_OF(context_t, data_end), -1};
    context.ctx.data = (uint8_t*)((void*)0x0123456789abcdef);
    context.ctx.data_end = (uint8_t*)((void*)0xfedcba9876543210);
    ebpf_program_get_context_data(ctx, &data_start, &data_end);
    REQUIRE(data_start == context.ctx.data);
    REQUIRE(data_end == context.ctx.data_end);
}

TEST_CASE("perf_event_array_async_query", "[execution_context][perf_event_array]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_map_async_query_request_t request;
    ebpf_operation_map_async_query_reply_t reply;
    int async = 1;

    request.map_handle = ebpf_handle_invalid - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_ASYNC_QUERY, request, reply, &async) == EBPF_INVALID_OBJECT);

    request.map_handle = map_handles["BPF_MAP_TYPE_HASH"];
    REQUIRE(invoke_protocol(EBPF_OPERATION_MAP_ASYNC_QUERY, request, reply, &async) == EBPF_OPERATION_NOT_SUPPORTED);
}

// Helper utilities for tests (added for prog array refcount tests).
static ebpf_map_t*
_get_map_from_handle(ebpf_handle_t handle)
{
    ebpf_core_object_t* object = nullptr;
    ebpf_result_t result = EBPF_OBJECT_REFERENCE_BY_HANDLE(handle, EBPF_OBJECT_MAP, &object);
    if (result != EBPF_SUCCESS) {
        return nullptr;
    }
    return reinterpret_cast<ebpf_map_t*>(object);
}

static ebpf_program_t*
_get_program_from_handle(ebpf_handle_t handle)
{
    ebpf_core_object_t* object = nullptr;
    ebpf_result_t result = EBPF_OBJECT_REFERENCE_BY_HANDLE(handle, EBPF_OBJECT_PROGRAM, &object);
    if (result != EBPF_SUCCESS) {
        return nullptr;
    }
    return reinterpret_cast<ebpf_program_t*>(object);
}

TEST_CASE("prog_array_user_ref_drop_clears_entries", "[maps][prog_array][refcount]")
{
    _ebpf_core_initializer core; // Initialize core execution context.
    core.initialize();

    // Create a program info provider so that program creation succeeds.
    _program_info_provider program_info_provider; // XDP (first in list)
    REQUIRE(program_info_provider.initialize(EBPF_PROGRAM_TYPE_XDP) == EBPF_SUCCESS);

    // Create one sample program.
    std::string name = "p";
    std::string section = "s";
    std::string file = "f";
    ebpf_program_parameters_t program_params{
        EBPF_PROGRAM_TYPE_XDP,
        EBPF_PROGRAM_TYPE_XDP,
        {reinterpret_cast<uint8_t*>(name.data()), name.size()},
        {reinterpret_cast<uint8_t*>(section.data()), section.size()},
        {reinterpret_cast<uint8_t*>(file.data()), file.size()},
        EBPF_CODE_NONE};
    ebpf_handle_t program_handle = ebpf_handle_invalid;
    REQUIRE(ebpf_program_create_and_initialize(&program_params, &program_handle) == EBPF_SUCCESS);

    // Create PROG_ARRAY map.
    auto def = _map_definitions["BPF_MAP_TYPE_PROG_ARRAY"]; // key_size=4, value_size=4, max_entries=10
    cxplat_utf8_string_t map_name{reinterpret_cast<uint8_t*>(const_cast<char*>("pa")), 2};
    ebpf_handle_t map_handle = ebpf_handle_invalid;
    REQUIRE(ebpf_core_create_map(&map_name, &def, ebpf_handle_invalid, &map_handle) == EBPF_SUCCESS);

    // Insert the program into slot 0.
    uint32_t key = 0;
    ebpf_operation_map_update_element_request_t update_request{
        // minimal header usage pattern
        {sizeof(ebpf_operation_map_update_element_request_t), EBPF_OPERATION_MAP_UPDATE_ELEMENT},
        map_handle,
        EBPF_ANY};
    memcpy(update_request.key, &key, sizeof(key));
    // Value is a program handle.
    *(uint64_t*)update_request.value = (uint64_t)program_handle; // value_handle expected by core
    REQUIRE(
        ebpf_core_invoke_protocol_handler(
            EBPF_OPERATION_MAP_UPDATE_ELEMENT, &update_request, sizeof(update_request), nullptr, 0, nullptr, nullptr) ==
        EBPF_SUCCESS);

    // Fetch map object pointer.
    ebpf_map_t* map = _get_map_from_handle(map_handle);
    REQUIRE(map != nullptr);

    // Acquire an additional user reference (simulate another fd/pin) then release both.
    REQUIRE(ebpf_prog_array_map_acquire_user_reference(map) == EBPF_SUCCESS); // user_ref_count becomes 2.

    // Release one user reference - entries should still exist.
    ebpf_prog_array_map_release_user_reference(map); // user_ref_count -> 1

    // Read raw entry to confirm it's non-zero.
    uint32_t* entry_ptr_before = reinterpret_cast<uint32_t*>(&map->data[key * map->ebpf_map_definition.value_size]);
    REQUIRE(*entry_ptr_before != 0); // Program id present.

    // Release final user reference - should trigger clearing entries.
    ebpf_prog_array_map_release_user_reference(map); // user_ref_count -> 0 triggers clear

    uint32_t* entry_ptr_after = reinterpret_cast<uint32_t*>(&map->data[key * map->ebpf_map_definition.value_size]);
    REQUIRE(*entry_ptr_after == 0); // Cleared.

    // Release map object reference obtained via _get_map_from_handle.
    EBPF_OBJECT_RELEASE_REFERENCE(reinterpret_cast<ebpf_core_object_t*>(map));

    // Close handles.
    ebpf_handle_close(program_handle);
    ebpf_handle_close(map_handle);
}

TEST_CASE("prog_array_kernel_refs_hold_after_user_clear", "[maps][prog_array][refcount]")
{
    _ebpf_core_initializer core;
    core.initialize();
    _program_info_provider program_info_provider; // XDP
    REQUIRE(program_info_provider.initialize(EBPF_PROGRAM_TYPE_XDP) == EBPF_SUCCESS);

    // Create program.
    std::string name = "p";
    std::string section = "s";
    std::string file = "f";
    ebpf_program_parameters_t program_params{
        EBPF_PROGRAM_TYPE_XDP,
        EBPF_PROGRAM_TYPE_XDP,
        {reinterpret_cast<uint8_t*>(name.data()), name.size()},
        {reinterpret_cast<uint8_t*>(section.data()), section.size()},
        {reinterpret_cast<uint8_t*>(file.data()), file.size()},
        EBPF_CODE_NONE};
    ebpf_handle_t program_handle = ebpf_handle_invalid;
    REQUIRE(ebpf_program_create_and_initialize(&program_params, &program_handle) == EBPF_SUCCESS);

    // Create PROG_ARRAY map.
    auto def = _map_definitions["BPF_MAP_TYPE_PROG_ARRAY"];
    cxplat_utf8_string_t map_name{reinterpret_cast<uint8_t*>(const_cast<char*>("pb")), 2};
    ebpf_handle_t map_handle = ebpf_handle_invalid;
    REQUIRE(ebpf_core_create_map(&map_name, &def, ebpf_handle_invalid, &map_handle) == EBPF_SUCCESS);

    // Insert program at index 0.
    uint32_t key = 0;
    ebpf_operation_map_update_element_request_t update_request{
        {sizeof(update_request), EBPF_OPERATION_MAP_UPDATE_ELEMENT}, map_handle, EBPF_ANY};
    memcpy(update_request.key, &key, sizeof(key));
    *(uint64_t*)update_request.value = (uint64_t)program_handle;
    REQUIRE(
        ebpf_core_invoke_protocol_handler(
            EBPF_OPERATION_MAP_UPDATE_ELEMENT, &update_request, sizeof(update_request), nullptr, 0, nullptr, nullptr) ==
        EBPF_SUCCESS);

    ebpf_map_t* map = _get_map_from_handle(map_handle);
    REQUIRE(map != nullptr);

    // Acquire two kernel references.
    REQUIRE(ebpf_prog_array_map_acquire_kernel_reference(map) == EBPF_SUCCESS);
    REQUIRE(ebpf_prog_array_map_acquire_kernel_reference(map) == EBPF_SUCCESS);

    // Drop all user refs (initial one only). This should clear entries even though kernel refs remain.
    ebpf_prog_array_map_release_user_reference(map); // initial user ref -> 0 triggers clear

    uint32_t* entry_ptr = reinterpret_cast<uint32_t*>(&map->data[key * map->ebpf_map_definition.value_size]);
    REQUIRE(*entry_ptr == 0); // Cleared.

    // Release kernel references (should not attempt to clear again or crash).
    ebpf_prog_array_map_release_kernel_reference(map);
    ebpf_prog_array_map_release_kernel_reference(map);

    EBPF_OBJECT_RELEASE_REFERENCE(reinterpret_cast<ebpf_core_object_t*>(map));
    ebpf_handle_close(program_handle);
    ebpf_handle_close(map_handle);
}

TEST_CASE("prog_array_single_cleanup_only", "[maps][prog_array][refcount]")
{
    _ebpf_core_initializer core;
    core.initialize();
    _program_info_provider program_info_provider; // XDP
    REQUIRE(program_info_provider.initialize(EBPF_PROGRAM_TYPE_XDP) == EBPF_SUCCESS);

    // Create program.
    std::string name = "p";
    std::string section = "s";
    std::string file = "f";
    ebpf_program_parameters_t program_params{
        EBPF_PROGRAM_TYPE_XDP,
        EBPF_PROGRAM_TYPE_XDP,
        {reinterpret_cast<uint8_t*>(name.data()), name.size()},
        {reinterpret_cast<uint8_t*>(section.data()), section.size()},
        {reinterpret_cast<uint8_t*>(file.data()), file.size()},
        EBPF_CODE_NONE};
    ebpf_handle_t program_handle = ebpf_handle_invalid;
    REQUIRE(ebpf_program_create_and_initialize(&program_params, &program_handle) == EBPF_SUCCESS);

    // Create PROG_ARRAY map.
    auto def = _map_definitions["BPF_MAP_TYPE_PROG_ARRAY"];
    cxplat_utf8_string_t map_name{reinterpret_cast<uint8_t*>(const_cast<char*>("pc")), 2};
    ebpf_handle_t map_handle = ebpf_handle_invalid;
    REQUIRE(ebpf_core_create_map(&map_name, &def, ebpf_handle_invalid, &map_handle) == EBPF_SUCCESS);

    // Insert program at index 0.
    uint32_t key = 0;
    ebpf_operation_map_update_element_request_t update_request{
        {sizeof(update_request), EBPF_OPERATION_MAP_UPDATE_ELEMENT}, map_handle, EBPF_ANY};
    memcpy(update_request.key, &key, sizeof(key));
    *(uint64_t*)update_request.value = (uint64_t)program_handle;
    REQUIRE(
        ebpf_core_invoke_protocol_handler(
            EBPF_OPERATION_MAP_UPDATE_ELEMENT, &update_request, sizeof(update_request), nullptr, 0, nullptr, nullptr) ==
        EBPF_SUCCESS);

    ebpf_map_t* map = _get_map_from_handle(map_handle);
    REQUIRE(map != nullptr);

    // Add an extra user ref and a kernel ref.
    REQUIRE(ebpf_prog_array_map_acquire_user_reference(map) == EBPF_SUCCESS);   // user=2
    REQUIRE(ebpf_prog_array_map_acquire_kernel_reference(map) == EBPF_SUCCESS); // kernel=1

    // Drop two user refs -> triggers clear once.
    ebpf_prog_array_map_release_user_reference(map); // user=1
    ebpf_prog_array_map_release_user_reference(map); // user=0 -> clear
    uint32_t* entry_ptr_after_clear =
        reinterpret_cast<uint32_t*>(&map->data[key * map->ebpf_map_definition.value_size]);
    REQUIRE(*entry_ptr_after_clear == 0);

    // Attempt to release again (should be no-op and not crash; API spec allows ignoring).
    ebpf_prog_array_map_release_user_reference(map);

    // Release kernel ref (no second clear should occur, still zero).
    ebpf_prog_array_map_release_kernel_reference(map);
    REQUIRE(*entry_ptr_after_clear == 0);

    EBPF_OBJECT_RELEASE_REFERENCE(reinterpret_cast<ebpf_core_object_t*>(map));
    ebpf_handle_close(program_handle);
    ebpf_handle_close(map_handle);
}
