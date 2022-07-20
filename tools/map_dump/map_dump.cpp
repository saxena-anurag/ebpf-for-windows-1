// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define USER_MODE
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <codecvt>
#include <map>
#include <io.h>
#include <string>
#include <vector>
#include <winsock2.h>
#include <WS2tcpip.h>

#include "map_dump.h"
extern "C"
{
#include "ebpf_api.h"
#define __doxygen
#include "linux/bpf.h"
#include "bpf/bpf.h"
}

#define DEFAULT_MAP_PIN_PATH_PREFIX "/ebpf/global/"

#define MAP_OF_POLICY_MAPS "map_policy_maps"
#define COMPARTMENT_POLICY_MAP "compartment_policy_map"
#define IP_CACHE_MAP "ip_cache_map"

#define MAX_POD_SIZE 15
#define POLICY_MAP_SIZE 200
#define IP_CACHE_MAP_SIZE 1000

#define MAXIMUM_IP_BUFFER_SIZE 65

typedef enum direction
{
    INGRESS,
    EGRESS,
} direction_t;

typedef struct policy_map_key
{
    uint32_t remote_pod_label_id;
    uint8_t direction;
    uint16_t remote_port;
    uint8_t protocol; // by default, we are using TCP protocol
} policy_map_key_t;

typedef struct map_properties
{
    fd_t map_fd;
    ebpf_map_type_t map_type;
    int key_size;
    int value_size;
    int max_entries;
} map_properties_t;

typedef struct ip_address
{
    union
    {
        uint32_t ipv4; ///< In network byte order.
        uint8_t ipv6[16];
    };
} ip_address_t;

std::map<std::string, map_properties_t> map_name_to_properties;

std::string
integer_to_v4_address_string(uint32_t address)
{
    char ip_string[MAXIMUM_IP_BUFFER_SIZE] = {0};
    InetNtopA(AF_INET, &address, ip_string, MAXIMUM_IP_BUFFER_SIZE);
    return std::string(ip_string);
}

uint32_t
initialize_map_entries()
{
    try {
        // Insert the eBPF maps needed for NPM.

        // Top level policy map.
        map_name_to_properties[std::string(MAP_OF_POLICY_MAPS)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_ARRAY_OF_MAPS, sizeof(uint32_t), sizeof(uint32_t), MAX_POD_SIZE};

        // Per compartment policy map.
        map_name_to_properties[std::string(COMPARTMENT_POLICY_MAP)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH, sizeof(policy_map_key_t), sizeof(uint32_t), POLICY_MAP_SIZE};

        // IP cache map.
        map_name_to_properties[std::string(IP_CACHE_MAP)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH, sizeof(ip_address_t), sizeof(uint32_t), IP_CACHE_MAP_SIZE};
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

std::string
get_map_pin_path(const char* map_name)
{
    std::string map_path = std::string(DEFAULT_MAP_PIN_PATH_PREFIX);
    map_path += map_name;

    return map_path;
}

fd_t
get_map_fd(const char* map_name)
{
    // First check if the map fd is cached.
    std::map<std::string, map_properties_t>::iterator it;
    it = map_name_to_properties.find(std::string(map_name));
    if (it == map_name_to_properties.end()) {
        // We should never be here.
        return ebpf_fd_invalid;
    }
    if (it->second.map_fd != ebpf_fd_invalid) {
        return it->second.map_fd;
    }

    // Map fd is invalid. Open fd to the map.
    std::string pin_path = get_map_pin_path(map_name);
    fd_t fd = bpf_obj_get(pin_path.c_str());
    if (fd != ebpf_fd_invalid) {
        it->second.map_fd = fd;
        return fd;
    }

    printf("get_map_fd: pinned map %s not found, creating one\n", map_name);

    // TODO: Remove this code later.
    // Map not created yet. Create and pin the map.
    fd = bpf_create_map(it->second.map_type, it->second.key_size, it->second.value_size, it->second.max_entries, 0);
    if (fd > 0) {
        // Map created. Now pin the map.
        int error = bpf_obj_pin(fd, pin_path.c_str());
        if (error != 0) {
            // close map fd.
            _close(fd);
            return ebpf_fd_invalid;
        }

        it->second.map_fd = fd;
        return fd;
    }

    return ebpf_fd_invalid;
}

void
print_policy_map_entry(_In_ const policy_map_key_t* key, _In_ const uint32_t* value)
{
    printf(
        "%13s   %11s   %13s   %7s\n",
        std::to_string(key->remote_pod_label_id).c_str(),
        (key->direction == 1 ? "egress" : "ingress"),
        std::to_string(_byteswap_ushort(key->remote_port)).c_str(),
        std::to_string(*value).c_str());
}

void
print_policy_map_header(uint32_t compartment_id)
{
    printf("\n\nCOMPARTMENT ID %d:\n\n", compartment_id);
    printf("   Remote Pod\n");
    printf("     Label ID     Direction     Remote Port     Value\n");
    printf("=============   ===========   =============   =======\n");
}

void
print_ip_cache_map_entry(_In_ const ip_address_t* key, _In_ const uint32_t* value)
{
    printf("%13s    %8s\n", integer_to_v4_address_string(key->ipv4).c_str(), std::to_string(*value).c_str());
}

void
print_ip_cache_map_header()
{
    printf("   IP Address       Value\n");
    printf("=============    ========\n");
}

uint32_t
print_policy_map(fd_t policy_map_fd, uint32_t compartment_id)
{
    uint32_t result = ERROR_SUCCESS;
    policy_map_key_t key = {0};
    uint32_t value;
    bool entry_found = false;

    print_policy_map_header(compartment_id);

    result = bpf_map_get_next_key(policy_map_fd, nullptr, &key);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }
    entry_found = true;

    result = bpf_map_lookup_elem(policy_map_fd, &key, &value);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    print_policy_map_entry(&key, &value);

    while (true) {
        result = bpf_map_get_next_key(policy_map_fd, &key, &key);
        if (result != ERROR_SUCCESS) {
            break;
        }

        result = bpf_map_lookup_elem(policy_map_fd, &key, &value);
        if (result != ERROR_SUCCESS) {
            break;
        }

        print_policy_map_entry(&key, &value);
    }

Exit:
    return result;
}

uint32_t
print_policy_maps()
{
    uint32_t result = ERROR_SUCCESS;
    bool compartment_entry_found = false;

    // First get the FD for the top level map.
    fd_t global_policy_map_fd = get_map_fd(MAP_OF_POLICY_MAPS);
    if (global_policy_map_fd == ebpf_fd_invalid) {
        printf("Failed to get map fd for map %s\n", MAP_OF_POLICY_MAPS);
        return ERROR_NOT_FOUND;
    }

    printf("\nPrinting the per-compartment policy maps entries:\n");

    // Get inner map fd for each index.
    for (uint32_t index = 0; index < MAX_POD_SIZE; index++) {
        ebpf_id_t policy_map_id;
        fd_t policy_map_fd;
        result = bpf_map_lookup_elem(global_policy_map_fd, &index, &policy_map_id);
        if (result != 0) {
            return result;
        }

        policy_map_fd = bpf_map_get_fd_by_id(policy_map_id);
        if (policy_map_fd <= 0) {
            continue;
        }

        compartment_entry_found = true;
        print_policy_map(policy_map_fd, index);
    }

    if (!compartment_entry_found) {
        printf("\n\tNo entries found.\n");
    }

    return result;
}

uint32_t
print_ip_cache_map()
{
    uint32_t result = ERROR_SUCCESS;
    ip_address_t key = {0};
    uint32_t value;

    // First get the FD for the top level map.
    fd_t ip_cache_map_fd = get_map_fd(IP_CACHE_MAP);
    if (ip_cache_map_fd == ebpf_fd_invalid) {
        printf("Failed to get map fd for map %s\n", IP_CACHE_MAP);
        return ERROR_NOT_FOUND;
    }

    printf("\n\nPrinting IP cache map entries:\n\n\n");
    print_ip_cache_map_header();

    result = bpf_map_get_next_key(ip_cache_map_fd, nullptr, &key);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    result = bpf_map_lookup_elem(ip_cache_map_fd, &key, &value);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    print_ip_cache_map_entry(&key, &value);

    while (true) {
        result = bpf_map_get_next_key(ip_cache_map_fd, &key, &key);
        if (result != ERROR_SUCCESS) {
            break;
        }

        result = bpf_map_lookup_elem(ip_cache_map_fd, &key, &value);
        if (result != ERROR_SUCCESS) {
            break;
        }

        print_ip_cache_map_entry(&key, &value);
    }

Exit:
    return result;
}

uint32_t
print_all_map_entries()
{
    print_policy_maps();
    print_ip_cache_map();

    return 0;
}

void
test_populate_map_entries()
{
#define INNER_MAP_COUNT 3
#define IP_ADDRESS_COUNT 3

    int error;
    fd_t inner_maps[INNER_MAP_COUNT];
    fd_t ip_cache_map;

    uint32_t pod_label_id = 1;
    bool ingress = true;
    uint16_t remote_port = 5000;
    uint32_t value = 1;

    uint32_t ip_addresses[] = {0x0101010A, 0x0201010A, 0x02010114};

    // Create inner policy maps.
    for (uint32_t i = 0; i < INNER_MAP_COUNT; i++) {
        inner_maps[i] =
            bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(policy_map_key_t), sizeof(uint32_t), POLICY_MAP_SIZE, 0);
        if (inner_maps[i] == ebpf_fd_invalid) {
            printf("Failed to create inner_map[%d]\n", i);
            return;
        }
    }

    // Create outer map.
    fd_t outer_map_fd = bpf_create_map_in_map(
        BPF_MAP_TYPE_ARRAY_OF_MAPS, MAP_OF_POLICY_MAPS, sizeof(uint32_t), inner_maps[0], MAX_POD_SIZE, 0);
    if (outer_map_fd == ebpf_fd_invalid) {
        printf("Failed to create outer map\n");
        return;
    }

    std::string pin_path = get_map_pin_path(MAP_OF_POLICY_MAPS);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, pin_path.c_str());
    if (error != 0) {
        printf("Failed to pin the outer map\n");
        return;
    }

    // Insert inner maps in outer map.
    for (uint32_t i = 0; i < INNER_MAP_COUNT; i++) {
        uint32_t key = i * 2 + 1;
        error = bpf_map_update_elem(outer_map_fd, &key, &inner_maps[i], 0);
        if (error != 0) {
            printf("Failed to update outer map with inner map [%d]\n", i);
            return;
        }
    }

    // Insert 3 entries in the first inner map.
    for (uint32_t i = 0; i < 3; i++) {
        policy_map_key_t key = {0};
        uint32_t map_value = value++;
        key.remote_pod_label_id = pod_label_id++;
        key.direction = ingress ? 0 : 1;
        ingress = !ingress;
        key.remote_port = remote_port++;

        error = bpf_map_update_elem(inner_maps[0], &key, &map_value, 0);
        if (error != 0) {
            printf("Failed to update entry [%d] in inner map 1\n", i);
            return;
        }
    }

    // Insert 2 entries in the second inner map.
    for (uint32_t i = 0; i < 2; i++) {
        policy_map_key_t key = {0};
        uint32_t map_value = value++;
        key.remote_pod_label_id = pod_label_id++;
        key.direction = ingress ? 0 : 1;
        ingress = !ingress;
        key.remote_port = remote_port++;

        error = bpf_map_update_elem(inner_maps[1], &key, &map_value, 0);
        if (error != 0) {
            printf("Failed to update entry [%d] in inner map 1\n", i);
            return;
        }
    }

    // Create and pin IP_CACHE_MAP
    ip_cache_map = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(ip_address_t), sizeof(uint32_t), IP_CACHE_MAP_SIZE, 0);
    if (ip_cache_map == ebpf_fd_invalid) {
        printf("Failed to create IP cache map\n");
        return;
    }

    // Pin IP cache map
    std::string ip_cache_pin_path = get_map_pin_path(IP_CACHE_MAP);

    // Pin the outer map.
    error = bpf_obj_pin(ip_cache_map, ip_cache_pin_path.c_str());
    if (error != 0) {
        printf("Failed to pin IP cache map\n");
        return;
    }

    // Add entries to ip cache map.
    for (uint32_t i = 0; i < IP_ADDRESS_COUNT; i++) {
        ip_address_t address = {0};
        address.ipv4 = ip_addresses[i];
        uint32_t map_value = value++;
        error = bpf_map_update_elem(ip_cache_map, &address, &map_value, 0);
        if (error != 0) {
            printf("Failed to add IP [%d] to IP cache map\n", i);
            return;
        }
    }

    return;
}

void
test_clear_map_entries()
{
    std::string policy_map_pin_path = get_map_pin_path(MAP_OF_POLICY_MAPS);
    fd_t policy_map_fd = bpf_obj_get(policy_map_pin_path.c_str());
    if (policy_map_fd != ebpf_fd_invalid) {
        ebpf_object_unpin(policy_map_pin_path.c_str());

        // Remove all the inner map entries.
        for (uint32_t i = 0; i < MAX_POD_SIZE; i++) {
            fd_t inner_map_fd = ebpf_fd_invalid;
            bpf_map_update_elem(policy_map_fd, &i, &inner_map_fd, 0);
        }
    }

    std::string ip_cache_map_pin_path = get_map_pin_path(IP_CACHE_MAP);
    fd_t ip_cache_map_fd = bpf_obj_get(ip_cache_map_pin_path.c_str());
    if (ip_cache_map_fd != ebpf_fd_invalid) {
        ebpf_object_unpin(ip_cache_map_pin_path.c_str());
    }
}
