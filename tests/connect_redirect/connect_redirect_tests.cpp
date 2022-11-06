// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This module facilitates testing various connect redirect scenarios by sending traffic to both
// local system and a remote system, both running TCP / UDP listeners.

#define CATCH_CONFIG_RUNNER

#include "catch_wrapper.hpp"
#include "ebpf_udp.h"
#include "socket_helper.h"

#include <chrono>
#include <future>
using namespace std::chrono_literals;

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_nethooks.h"
#include "ebpf_structs.h"
#include "socket_helper.h"
#include "socket_tests_common.h"

#include <mstcpip.h>

#define CLIENT_MESSAGE "eBPF for Windows!"
#define NUM_ADDRESS_FAMILY 2

static std::string _family;
static std::string _protocol;
static std::string _vip_v4;
static std::string _vip_v6;
static std::string _local_ip_v4;
static std::string _local_ip_v6;
static std::string _remote_ip_v4;
static std::string _remote_ip_v6;
static uint16_t _remote_port = 4444;

typedef struct _test_addresses
{
    struct sockaddr_storage loopback_address;
    struct sockaddr_storage remote_address;
    struct sockaddr_storage local_address;
    struct sockaddr_storage vip_address;
} test_addresses_t;

typedef struct _test_globals
{
    ADDRESS_FAMILY family;
    IPPROTO protocol;
    uint16_t remote_port;
    test_addresses_t addresses[NUM_ADDRESS_FAMILY];
} test_globals_t;

static test_globals_t _globals;

inline static IPPROTO
_get_protocol_from_string(std::string protocol)
{
    if (protocol.compare("udp") == 0 || protocol.compare("UDP") == 0) {
        return IPPROTO_UDP;
    }
    return IPPROTO_TCP;
}

inline static ADDRESS_FAMILY
_get_address_family_from_string(std::string family)
{
    if (family.compare("AF_INET") == 0 || family.compare("af_inet") == 0) {
        return AF_INET;
    }
    return AF_INET6;
}

static void
_initialize_test_globals()
{
    ADDRESS_FAMILY family;
    get_address_from_string(_remote_ip_v4, _globals.addresses[0].remote_address, &family);
    REQUIRE(family == AF_INET);
    get_address_from_string(_local_ip_v4, _globals.addresses[0].local_address, &family);
    REQUIRE(family == AF_INET);
    get_address_from_string(_vip_v4, _globals.addresses[0].vip_address, &family);
    REQUIRE(family == AF_INET);
    IN6ADDR_SETV4MAPPED(
        (PSOCKADDR_IN6)&_globals.addresses[0].loopback_address, &in4addr_loopback, scopeid_unspecified, 0);

    get_address_from_string(_remote_ip_v6, _globals.addresses[1].remote_address, &family);
    REQUIRE(family == AF_INET6);
    get_address_from_string(_local_ip_v6, _globals.addresses[1].local_address, &family);
    REQUIRE(family == AF_INET6);
    get_address_from_string(_vip_v6, _globals.addresses[1].vip_address, &family);
    REQUIRE(family == AF_INET6);
    IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&_globals.addresses[1].loopback_address);

    _globals.remote_port = _remote_port;
}

static void
_load_and_attach_ebpf_programs(_Outptr_ struct bpf_object** return_object)
{
    struct bpf_object* object = bpf_object__open("cgroup_sock_addr2.o");
    REQUIRE(object != nullptr);
    REQUIRE(bpf_object__load(object) == 0);

    bpf_program* connect_program_v4 = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(connect_program_v4 != nullptr);

    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program_v4)), 0, BPF_CGROUP_INET4_CONNECT, 0);
    REQUIRE(result == 0);

    bpf_program* connect_program_v6 = bpf_object__find_program_by_name(object, "authorize_connect6");
    REQUIRE(connect_program_v6 != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program_v6)), 0, BPF_CGROUP_INET6_CONNECT, 0);
    REQUIRE(result == 0);

    *return_object = object;
}

static void
_update_policy_map(
    _In_ const struct bpf_object* object,
    _In_ sockaddr_storage& destination,
    _In_ sockaddr_storage& proxy,
    uint16_t port,
    uint32_t protocol,
    bool add)
{
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);

    // Insert / delete redirect policy entry in the map.
    destination_entry_t key = {0};
    destination_entry_t value = {0};

    struct sockaddr_in6* v6_destination = (struct sockaddr_in6*)&destination;
    struct sockaddr_in6* v6_proxy = (struct sockaddr_in6*)&proxy;
    if (_globals.family == AF_INET) {
        const uint8_t* v4_destination = IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)&v6_destination->sin6_addr);
        const uint8_t* v4_proxy = IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)&v6_proxy->sin6_addr);

        key.destination_ip.ipv4 = *((uint32_t*)v4_destination);
        value.destination_ip.ipv4 = *((uint32_t*)v4_proxy);
    } else {
        memcpy(key.destination_ip.ipv6, v6_destination->sin6_addr.u.Byte, sizeof(key.destination_ip.ipv6));
        memcpy(value.destination_ip.ipv6, v6_proxy->sin6_addr.u.Byte, sizeof(value.destination_ip.ipv6));
    }
    key.destination_port = value.destination_port = htons(port);
    key.protocol = protocol;

    if (add) {
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        REQUIRE(bpf_map_delete_elem(map_fd, &key) == 0);
    }
}

void
connect_redirect_test(
    _In_ const struct bpf_object* object,
    _In_ sender_socket_t* sender_socket,
    _In_ sockaddr_storage& destination,
    _In_ sockaddr_storage& proxy)
{
    // Update policy in the map to redirect the connection to the proxy.
    _update_policy_map(object, destination, proxy, _globals.remote_port, _globals.protocol, true);

    // Try to send and receive message to "destination". It should succeed.
    sender_socket->send_message_to_remote_host(CLIENT_MESSAGE, destination, _globals.remote_port);
    sender_socket->complete_async_send(1000, expected_result_t::success);

    sender_socket->post_async_receive();
    sender_socket->complete_async_receive(2000, false);

    uint32_t bytes_received = 0;
    char* received_message = nullptr;
    sender_socket->get_received_message(bytes_received, received_message);

    // TODO: The message returned by the listener should be unique so that we know
    // for sure that the connection was indeed redirected.
    REQUIRE(memcmp(received_message, "test_message", strlen(received_message)) == 0);

    // Remove entry from policy map.
    _update_policy_map(object, destination, proxy, _globals.remote_port, _globals.protocol, false);
}

void
authorize_test(
    _In_ const struct bpf_object* object, _In_ sender_socket_t* sender_socket, _In_ sockaddr_storage& destination)
{
    // Default behavior of the eBPF program is to block the connection.

    // Send should fail as the connection is blocked.
    sender_socket->send_message_to_remote_host(CLIENT_MESSAGE, destination, _globals.remote_port);
    sender_socket->complete_async_send(1000, expected_result_t::failure);

    // Receive should timeout as connection is blocked.
    sender_socket->post_async_receive(true);
    sender_socket->complete_async_receive(1000, true);

    // Now update the policy map to allow the connection and test again.
    connect_redirect_test(object, sender_socket, destination, destination);
}

void
delete_sender_socket(_In_ sender_socket_t* sender_socket)
{
    if (_globals.protocol == IPPROTO_TCP) {
        delete ((stream_sender_socket_t*)sender_socket);
    } else {
        delete ((datagram_sender_socket_t*)sender_socket);
    }
}

void
get_sender_socket(_Inout_ sender_socket_t** sender_socket)
{
    sender_socket_t* old_socket = *sender_socket;
    sender_socket_t* new_socket = nullptr;
    if (_globals.protocol == IPPROTO_TCP) {
        new_socket = (sender_socket_t*)new stream_sender_socket_t(SOCK_STREAM, IPPROTO_TCP, 0);
    } else {
        new_socket = (sender_socket_t*)new datagram_sender_socket_t(SOCK_DGRAM, IPPROTO_UDP, 0);
    }

    *sender_socket = new_socket;
    if (old_socket) {
        delete_sender_socket(old_socket);
    }
}

void
authorize_test_wrapper(_In_ const struct bpf_object* object, _In_ sockaddr_storage& destination)
{
    sender_socket_t* sender_socket = nullptr;
    get_sender_socket(&sender_socket);

    authorize_test(object, sender_socket, destination);

    delete_sender_socket(sender_socket);
}

void
connect_redirect_test_wrapper(
    _In_ const struct bpf_object* object, _In_ sockaddr_storage& destination, _In_ sockaddr_storage& proxy)
{
    sender_socket_t* sender_socket = nullptr;
    get_sender_socket(&sender_socket);

    connect_redirect_test(object, sender_socket, destination, proxy);

    delete_sender_socket(sender_socket);
}

void
connect_redirect_tests_common(_In_ const struct bpf_object* object, _In_ test_addresses_t& addresses)
{
    // First cateogory is authorize tests.

    // Loopback address.
    printf("Loobpack authorize\n");
    authorize_test_wrapper(object, addresses.loopback_address);

    // Remote address.
    printf("Remote authorize\n");
    authorize_test_wrapper(object, addresses.remote_address);

    // Local non-loopback address.
    printf("Local non-loopback authorize\n");
    authorize_test_wrapper(object, addresses.local_address);

    // Second category is connection redirection tests.

    // Remote -> Remote
    printf("Remote             -> Remote\n");
    connect_redirect_test_wrapper(object, addresses.vip_address, addresses.remote_address);

    // Remote -> Loopback
    printf("Remote             -> Loopback\n");
    connect_redirect_test_wrapper(object, addresses.vip_address, addresses.loopback_address);

    // Remote -> Local non-loopback
    printf("Remote             -> Local non-loopback\n");
    connect_redirect_test_wrapper(object, addresses.vip_address, addresses.local_address);

    // Loopback -> Remote
    printf("Loopback           -> Remote\n");
    connect_redirect_test_wrapper(object, addresses.loopback_address, addresses.remote_address);

    // Loopback -> Local non-loopback
    printf("Loopback           -> Local non-loopback\n");
    connect_redirect_test_wrapper(object, addresses.loopback_address, addresses.local_address);

    // Local non-loopback -> Loopback
    printf("Local non-loopback -> Loopback\n");
    connect_redirect_test_wrapper(object, addresses.local_address, addresses.loopback_address);

    // Local non-loopback -> Remote
    printf("Local non-loopback -> Remote\n");
    connect_redirect_test_wrapper(object, addresses.local_address, addresses.remote_address);
}

TEST_CASE("connect_redirect_tests", "[connect_redirect_tests]")
{
    _initialize_test_globals();

    struct bpf_object* object = nullptr;
    _load_and_attach_ebpf_programs(&object);

    ADDRESS_FAMILY families[NUM_ADDRESS_FAMILY] = {AF_INET, AF_INET6};

    for (uint32_t i = 0; i < NUM_ADDRESS_FAMILY; i++) {
        _globals.family = families[i];

        _globals.protocol = IPPROTO_TCP;
        connect_redirect_tests_common(object, _globals.addresses[i]);

        _globals.protocol = IPPROTO_UDP;
        connect_redirect_tests_common(object, _globals.addresses[i]);
    }

    // This should also detach the programs as they are not pinned.
    bpf_object__close(object);
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli = session.cli() | Opt(_vip_v4, "v4 Virtual / Load Balanced IP")["-v"]["--virtual-ip-v4"]("IPv4 VIP") |
               Opt(_vip_v6, "v6 Virtual / Load Balanced IP")["-v"]["--virtual-ip-v6"]("IPv6 VIP") |
               Opt(_local_ip_v4, "v4 local IP")["-l"]["--local-ip-v4"]("Local IPv4 IP") |
               Opt(_local_ip_v6, "v6 local IP")["-l"]["--local-ip-v6"]("Local IPv6 IP") |
               Opt(_remote_ip_v4, "v4 Remote IP")["-r"]["--remote-ip-v4"]("IPv4 Remote IP") |
               Opt(_remote_ip_v6, "v6 Remote IP")["-r"]["--remote-ip-v6"]("IPv6 Remote IP") |
               Opt(_remote_port, "Destination Port")["-t"]["--destination-port"]("Destination Port");

    session.cli(cli);

    int returnCode = session.applyCommandLine(argc, argv);
    if (returnCode != 0)
        return returnCode;

    WSAData data;

    int error = WSAStartup(2, &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    session.run();
    WSACleanup();
}