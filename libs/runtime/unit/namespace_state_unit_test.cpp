// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "ebpf_namespace.h"
#include "ebpf_namespace_test.h"

#include <atomic>
#include <barrier>
#include <future>
#include <semaphore>
#include <thread>
#include <vector>

static const GUID _namespace_a = {0x11111111, 0x1111, 0x1111, {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}};
static const GUID _namespace_b = {0xeeeeeeee, 0xeeee, 0xeeee, {0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee}};
static const GUID _namespace_null = {};

class namespace_state_fixture
{
  public:
    explicit namespace_state_fixture(bool initiate = true)
    {
        REQUIRE(ebpf_platform_initiate() == EBPF_SUCCESS);
        process = create_process(0x100, 1000);
        ebpf_namespace_test_select_process(process);
        if (initiate) {
            REQUIRE(ebpf_namespace_initiate() == EBPF_SUCCESS);
        }
    }

    ~namespace_state_fixture()
    {
        ebpf_namespace_terminate();
        ebpf_namespace_test_select_process(nullptr);
        ebpf_namespace_test_fail_next(EBPF_NAMESPACE_TEST_FAIL_NONE);
        ebpf_namespace_test_set_allocate_callback(nullptr, nullptr);
        for (auto* simulated : processes) {
            CHECK(ebpf_namespace_test_process_reference_count(simulated) == 1);
            ebpf_namespace_test_destroy_process(simulated);
        }
        ebpf_platform_terminate();
    }

    ebpf_namespace_test_process_t*
    create_process(uintptr_t identity, uint64_t start_key)
    {
        auto* simulated = ebpf_namespace_test_create_process(identity, start_key);
        REQUIRE(simulated != nullptr);
        processes.push_back(simulated);
        return simulated;
    }

    ebpf_request_context_t
    capture()
    {
        ebpf_request_context_t context{};
        REQUIRE(ebpf_namespace_capture_context(&context) == EBPF_SUCCESS);
        return context;
    }

    ebpf_namespace_test_process_t* process;

  private:
    std::vector<ebpf_namespace_test_process_t*> processes;
};

struct namespace_allocation_gate
{
    std::binary_semaphore entered{0};
    std::binary_semaphore resume{0};

    static void
    wait(_Inout_opt_ void* context)
    {
        auto* gate = static_cast<namespace_allocation_gate*>(context);
        gate->entered.release();
        gate->resume.acquire();
    }
};

TEST_CASE("namespace_NU01_unseen_roundtrip_idempotence_reset", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    size_t allocations = ebpf_namespace_test_allocation_count();
    auto unseen = fixture.capture();
    REQUIRE(unseen.namespace_id == _namespace_null);
    REQUIRE(unseen.namespace_generation == 0);
    REQUIRE(unseen.process_start_key == 1000);
    REQUIRE(ebpf_namespace_set_current(&_namespace_null) == EBPF_SUCCESS);
    REQUIRE(ebpf_namespace_test_allocation_count() == allocations);
    REQUIRE(ebpf_namespace_test_process_reference_count(fixture.process) == 1);

    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    auto selected = fixture.capture();
    REQUIRE(selected.namespace_id == _namespace_a);
    REQUIRE(selected.namespace_generation == 1);
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    REQUIRE(fixture.capture().namespace_generation == 1);
    REQUIRE(ebpf_namespace_test_allocation_count() == allocations + 1);
    REQUIRE(ebpf_namespace_test_process_reference_count(fixture.process) == 2);

    REQUIRE(ebpf_namespace_set_current(&_namespace_null) == EBPF_SUCCESS);
    GUID actual = _namespace_a;
    REQUIRE(ebpf_namespace_get_current(&actual) == EBPF_SUCCESS);
    REQUIRE(actual == _namespace_null);
    REQUIRE(fixture.capture().namespace_generation == 2);
    REQUIRE(selected.namespace_id == _namespace_a);
}

TEST_CASE("namespace_NU02_same_identity_snapshots_are_shared_across_threads", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    for (size_t thread = 0; thread < 3; thread++) {
        auto request = std::async(std::launch::async, [&]() {
            ebpf_namespace_test_select_process(fixture.process);
            ebpf_request_context_t context{};
            auto result = ebpf_namespace_capture_context(&context);
            ebpf_namespace_test_select_process(nullptr);
            return std::pair{result, context};
        });
        auto [result, context] = request.get();
        REQUIRE(result == EBPF_SUCCESS);
        REQUIRE(context.namespace_id == _namespace_a);
        REQUIRE(context.namespace_generation == 1);
    }
    // Selecting an adapter caller is not a namespace reset.
    ebpf_namespace_test_select_process(nullptr);
    ebpf_namespace_test_select_process(fixture.process);
    REQUIRE(fixture.capture().namespace_id == _namespace_a);
}

TEST_CASE("namespace_NU03_distinct_process_identities_start_unselected", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    for (auto* other : {fixture.create_process(0x200, 2000), fixture.create_process(0x300, 3000)}) {
        ebpf_namespace_test_select_process(other);
        REQUIRE(fixture.capture().namespace_id == _namespace_null);
        REQUIRE(ebpf_namespace_set_current(&_namespace_b) == EBPF_SUCCESS);
        REQUIRE(fixture.capture().namespace_id == _namespace_b);
    }
    ebpf_namespace_test_select_process(fixture.process);
    REQUIRE(fixture.capture().namespace_id == _namespace_a);
}

TEST_CASE(
    "namespace_NU04_NU06_exit_removes_membership_but_snapshot_survives_identity_reuse", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    auto captured = fixture.capture();
    REQUIRE(ebpf_namespace_test_process_reference_count(fixture.process) == 2);
    ebpf_namespace_test_exit_process(fixture.process);
    REQUIRE(ebpf_namespace_test_process_reference_count(fixture.process) == 1);
    ebpf_request_context_t unchanged = captured;
    REQUIRE(ebpf_namespace_capture_context(&unchanged) == EBPF_INVALID_STATE);
    REQUIRE(unchanged.namespace_id == captured.namespace_id);
    REQUIRE(ebpf_namespace_set_current(&_namespace_b) == EBPF_INVALID_STATE);

    // Reuse even the identity token, not merely its numeric PID.
    auto* replacement = fixture.create_process(0x100, 1001);
    ebpf_namespace_test_select_process(replacement);
    REQUIRE(fixture.capture().namespace_id == _namespace_null);
    REQUIRE(fixture.capture().namespace_generation == 0);
    REQUIRE(ebpf_namespace_set_current(&_namespace_b) == EBPF_SUCCESS);
    REQUIRE(captured.namespace_id == _namespace_a);
    REQUIRE(captured.namespace_generation == 1);
    REQUIRE(captured.process_start_key == 1000);
}

TEST_CASE("namespace_NU05_exit_cancels_SET_paused_before_insertion", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    namespace_allocation_gate gate;
    ebpf_namespace_test_set_allocate_callback(namespace_allocation_gate::wait, &gate);
    auto set = std::async(std::launch::async, [&]() {
        ebpf_namespace_test_select_process(fixture.process);
        auto result = ebpf_namespace_set_current(&_namespace_a);
        ebpf_namespace_test_select_process(nullptr);
        return result;
    });
    gate.entered.acquire();
    ebpf_namespace_test_notify_exit_process(fixture.process);
    gate.resume.release();
    auto result = set.get();
    ebpf_namespace_test_set_allocate_callback(nullptr, nullptr);
    ebpf_namespace_test_exit_process(fixture.process);
    REQUIRE(result == EBPF_INVALID_STATE);
    REQUIRE(ebpf_namespace_test_process_reference_count(fixture.process) == 1);
    REQUIRE(ebpf_namespace_set_current(&_namespace_b) == EBPF_INVALID_STATE);
}

TEST_CASE("namespace_NU09_GUID_and_generation_publish_coherently", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    std::barrier start(3);
    std::atomic<bool> valid{true};
    auto reader = [&]() {
        ebpf_namespace_test_select_process(fixture.process);
        start.arrive_and_wait();
        for (size_t index = 0; index < 10000; index++) {
            ebpf_request_context_t context{};
            if (ebpf_namespace_capture_context(&context) != EBPF_SUCCESS ||
                context.namespace_id != (context.namespace_generation % 2 ? _namespace_a : _namespace_b)) {
                valid.store(false);
            }
        }
        ebpf_namespace_test_select_process(nullptr);
    };
    std::thread first(reader);
    std::thread second(reader);
    start.arrive_and_wait();
    bool writer_valid = true;
    for (uint64_t generation = 2; generation <= 10000; generation++) {
        if (ebpf_namespace_set_current(generation % 2 ? &_namespace_a : &_namespace_b) != EBPF_SUCCESS) {
            writer_valid = false;
        }
    }
    first.join();
    second.join();
    REQUIRE(writer_valid);
    REQUIRE(valid.load());
    REQUIRE(fixture.capture().namespace_generation == 10000);
}

TEST_CASE("namespace_NU09_NU10_snapshot_is_immutable_across_ordered_publication", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    std::binary_semaphore captured{0};
    std::binary_semaphore published{0};
    ebpf_request_context_t old_context{};
    ebpf_request_context_t new_context{};
    ebpf_result_t capture_result = EBPF_FAILED;
    std::thread request([&]() {
        ebpf_namespace_test_select_process(fixture.process);
        capture_result = ebpf_namespace_capture_context(&old_context);
        captured.release();
        published.acquire();
        // Model retaining the captured value after another caller publishes B.
        new_context = old_context;
        ebpf_namespace_test_select_process(nullptr);
    });
    captured.acquire();
    auto set_result = ebpf_namespace_set_current(&_namespace_b);
    published.release();
    request.join();
    REQUIRE(capture_result == EBPF_SUCCESS);
    REQUIRE(set_result == EBPF_SUCCESS);
    REQUIRE(new_context.namespace_id == _namespace_a);
    REQUIRE(new_context.namespace_generation == 1);
    REQUIRE(fixture.capture().namespace_id == _namespace_b);
    REQUIRE(fixture.capture().namespace_generation == 2);
}

TEST_CASE("namespace_NU12_state_allocation_and_identity_failures_are_explicit", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    for (auto failure :
         {EBPF_NAMESPACE_TEST_FAIL_ALLOCATE,
          EBPF_NAMESPACE_TEST_FAIL_REFERENCE_ENTRY,
          EBPF_NAMESPACE_TEST_FAIL_REFERENCE_CURRENT}) {
        ebpf_namespace_test_fail_next(failure);
        REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_NO_MEMORY);
        REQUIRE(fixture.capture().namespace_id == _namespace_null);
        REQUIRE(ebpf_namespace_test_process_reference_count(fixture.process) == 1);
    }
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    auto unchanged = fixture.capture();
    ebpf_namespace_test_fail_next(EBPF_NAMESPACE_TEST_FAIL_REFERENCE_CURRENT);
    REQUIRE(ebpf_namespace_capture_context(&unchanged) == EBPF_NO_MEMORY);
    REQUIRE(unchanged.namespace_id == _namespace_a);
    REQUIRE(unchanged.namespace_generation == 1);
    REQUIRE(fixture.capture().namespace_id == _namespace_a);
}

TEST_CASE("namespace_NU12_callback_registration_failure_and_retry", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture(false);
    auto registrations = ebpf_namespace_test_registration_count();
    auto unregistrations = ebpf_namespace_test_unregistration_count();
    ebpf_namespace_test_fail_next(EBPF_NAMESPACE_TEST_FAIL_REGISTER);
    REQUIRE(ebpf_namespace_initiate() == EBPF_NO_MEMORY);
    REQUIRE(ebpf_namespace_test_registration_count() == registrations);
    ebpf_request_context_t context{};
    REQUIRE(ebpf_namespace_capture_context(&context) == EBPF_INVALID_STATE);
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_INVALID_STATE);
    ebpf_namespace_terminate();
    REQUIRE(ebpf_namespace_test_unregistration_count() == unregistrations);
    REQUIRE(ebpf_namespace_initiate() == EBPF_SUCCESS);
    REQUIRE(ebpf_namespace_initiate() == EBPF_ALREADY_INITIALIZED);
    REQUIRE(ebpf_namespace_test_registration_count() == registrations + 1);
    REQUIRE(fixture.capture().namespace_id == _namespace_null);
}

TEST_CASE("namespace_NU52_shutdown_drains_inflight_SET_and_reinitializes_cleanly", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    auto saved = fixture.capture();
    auto* other = fixture.create_process(0x200, 2000);
    namespace_allocation_gate gate;
    ebpf_namespace_test_set_allocate_callback(namespace_allocation_gate::wait, &gate);
    auto set = std::async(std::launch::async, [&]() {
        ebpf_namespace_test_select_process(other);
        auto result = ebpf_namespace_set_current(&_namespace_b);
        ebpf_namespace_test_select_process(nullptr);
        return result;
    });
    gate.entered.acquire();
    auto unregistrations = ebpf_namespace_test_unregistration_count();
    auto shutdown = std::async(std::launch::async, []() { ebpf_namespace_terminate(); });
    // Unregistration precedes waiting for the still-paused request's rundown.
    while (ebpf_namespace_test_unregistration_count() == unregistrations) {
        std::this_thread::yield();
    }
    bool waiting = shutdown.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
    gate.resume.release();
    auto result = set.get();
    shutdown.get();
    ebpf_namespace_test_set_allocate_callback(nullptr, nullptr);
    REQUIRE(waiting);
    REQUIRE(result == EBPF_INVALID_STATE);
    REQUIRE(ebpf_namespace_test_unregistration_count() == unregistrations + 1);
    REQUIRE(ebpf_namespace_test_process_reference_count(fixture.process) == 1);
    REQUIRE(ebpf_namespace_test_process_reference_count(other) == 1);
    REQUIRE(saved.namespace_id == _namespace_a);
    ebpf_namespace_terminate();
    REQUIRE(ebpf_namespace_test_unregistration_count() == unregistrations + 1);
    REQUIRE(ebpf_namespace_initiate() == EBPF_SUCCESS);
    REQUIRE(fixture.capture().namespace_id == _namespace_null);
    REQUIRE(fixture.capture().namespace_generation == 0);
}

TEST_CASE("namespace_concurrent_first_SET_retries_without_duplicate_entries", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    namespace_allocation_gate gate;
    ebpf_namespace_test_set_allocate_callback(namespace_allocation_gate::wait, &gate);
    auto first = std::async(std::launch::async, [&]() {
        ebpf_namespace_test_select_process(fixture.process);
        auto result = ebpf_namespace_set_current(&_namespace_a);
        ebpf_namespace_test_select_process(nullptr);
        return result;
    });
    gate.entered.acquire();
    ebpf_namespace_test_set_allocate_callback(nullptr, nullptr);
    auto second_result = ebpf_namespace_set_current(&_namespace_b);
    gate.resume.release();
    auto first_result = first.get();
    REQUIRE(second_result == EBPF_SUCCESS);
    REQUIRE(first_result == EBPF_SUCCESS);
    REQUIRE(fixture.capture().namespace_id == _namespace_a);
    REQUIRE(fixture.capture().namespace_generation == 2);
    REQUIRE(ebpf_namespace_test_process_reference_count(fixture.process) == 2);
}

TEST_CASE("namespace_real_process_adapter_roundtrip_is_shared_by_threads", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    ebpf_namespace_test_select_process(nullptr);
    auto initial = fixture.capture();
    REQUIRE(initial.namespace_id == _namespace_null);
    REQUIRE(initial.namespace_generation == 0);
    REQUIRE(initial.process_start_key != 0);
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);

    auto request = std::async(std::launch::async, []() {
        ebpf_request_context_t context{};
        return std::pair{ebpf_namespace_capture_context(&context), context};
    });
    auto [result, context] = request.get();
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(context.namespace_id == _namespace_a);
    REQUIRE(context.namespace_generation == 1);
    REQUIRE(context.process_start_key == initial.process_start_key);
}

TEST_CASE("namespace_invalid_arguments_do_not_mutate_selection", "[namespace][namespace_state]")
{
    namespace_state_fixture fixture;
    REQUIRE(ebpf_namespace_set_current(&_namespace_a) == EBPF_SUCCESS);
    REQUIRE(ebpf_namespace_set_current(nullptr) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_namespace_get_current(nullptr) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_namespace_capture_context(nullptr) == EBPF_INVALID_ARGUMENT);
    auto captured = fixture.capture();
    REQUIRE(captured.namespace_id == _namespace_a);
    REQUIRE(captured.namespace_generation == 1);
}
