// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "socket_helper.h"

#include <windows.h>
#include <io.h>
#include <iostream>
#include <string>
#include <vector>

#define htonl(x) _byteswap_ulong(x)
#define htons(x) _byteswap_ushort(x)
#define ntohl(x) _byteswap_ulong(x)
#define ntohs(x) _byteswap_ushort(x)

const char* authorize_v4_program = "authorize_connect4";
// const char* authorize_v6_program = "authorize_connect6";

const char* egress_connection_policy_map = "policy_map";
// const char* egress_statistics_map = "egress_statistics_map";

static std::string _add_operation("add");
static std::string _delete_operation("delete");

typedef struct _ip_address
{
    union
    {
        uint32_t ipv4;
        uint32_t ipv6[4];
    };
} ip_address_t;

typedef struct _destination_entry
{
    ip_address_t destination_ip;
    uint16_t destination_port;
    uint32_t protocol;
} destination_entry_t;

typedef struct _process_entry
{
    uint32_t count;
    wchar_t name[32];
} process_entry_t;

int
load(int argc, char** argv)
{
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_program* v4_program = nullptr;
    // bpf_program* v6_program = nullptr;
    bpf_link* v4_link = nullptr;
    // bpf_link* v6_link = nullptr;
    bpf_map* policy_map = nullptr;
    // bpf_map* stats_map = nullptr;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    object = bpf_object__open("drivers\\redirect.bpf.sys");
    if (object == nullptr) {
        fprintf(stderr, "Failed to open sock_addr eBPF program\n");
        return 1;
    }

    result = ebpf_object_set_execution_type(object, EBPF_EXECUTION_NATIVE);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to set execution type\n");
        return 1;
    }

    if (bpf_object__load(object) < 0) {
        fprintf(stderr, "Failed to load sock_addr eBPF program\n");
        bpf_object__close(object);
        return 1;
    }

    v4_program = bpf_object__find_program_by_name(object, authorize_v4_program);
    if (v4_program == nullptr) {
        fprintf(stderr, "Failed to find v4 connect program\n");
        return 1;
    }

    // v6_program = bpf_object__find_program_by_name(object, authorize_v6_program);
    // if (v6_program == nullptr) {
    //     fprintf(stderr, "Failed to find v6 connect program\n");
    //     return 1;
    // }

    policy_map = bpf_object__find_map_by_name(object, egress_connection_policy_map);
    if (policy_map == nullptr) {
        fprintf(stderr, "Failed to find %s map\n", egress_connection_policy_map);
        return 1;
    }

    // stats_map = bpf_object__find_map_by_name(object, egress_statistics_map);
    // if (stats_map == nullptr) {
    //     fprintf(stderr, "Failed to find %s map\n", egress_statistics_map);
    //     return 1;
    // }

    // Attach both the programs.
    result = ebpf_program_attach(v4_program, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, nullptr, 0, &v4_link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }
    fprintf(stdout, "Attached v4 eBPF program\n");
    // result = ebpf_program_attach(v6_program, &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT, nullptr, 0, &v6_link);
    // if (result != ERROR_SUCCESS) {
    //     fprintf(stderr, "Failed to attach eBPF program\n");
    //     return 1;
    // }
    // fprintf(stdout, "Attached v6 eBPF program\n");

    // Pin both the programs.
    if (bpf_obj_pin(bpf_program__fd(v4_program), authorize_v4_program) < 0) {
        fprintf(stderr, "Failed to pin eBPF program [%s]: %d\n", authorize_v4_program, errno);
        return 1;
    }
    fprintf(stdout, "Pinned v4 eBPF program to \"%s\"\n", authorize_v4_program);
    // if (bpf_obj_pin(bpf_program__fd(v6_program), authorize_v6_program) < 0) {
    //     fprintf(stderr, "Failed to pin eBPF program [%s]: %d\n", authorize_v6_program, errno);
    //     return 1;
    // }
    // fprintf(stdout, "Pinned v6 eBPF program to \"%s\"\n", authorize_v6_program);

    // Pin both the maps.
    if (bpf_obj_pin(bpf_map__fd(policy_map), egress_connection_policy_map) < 0) {
        fprintf(stderr, "Failed to pin eBPF map [%s]: %d\n", egress_connection_policy_map, errno);
        return 1;
    }
    fprintf(stdout, "Pinned eBPF map to \"%s\"\n", egress_connection_policy_map);
    // if (bpf_obj_pin(bpf_map__fd(stats_map), egress_statistics_map) < 0) {
    //     fprintf(stderr, "Failed to pin eBPF map [%s]: %d\n", egress_statistics_map, errno);
    //     return 1;
    // }
    // fprintf(stdout, "Pinned eBPF map to \"%s\"\n", egress_statistics_map);

    fprintf(stdout, "\nDone.\n");
    return 0;
}

int
unload(int argc, char** argv)
{
    int result = 0;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    result = ebpf_object_unpin(authorize_v4_program);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF program from \"%s\": %d\n", authorize_v4_program, result);
        result = 1;
    }
    fprintf(stdout, "Unpinned v4 eBPF program from \"%s\"\n", authorize_v4_program);

    // result = ebpf_object_unpin(authorize_v6_program);
    // if (result != ERROR_SUCCESS) {
    //     fprintf(stderr, "Failed to unpin eBPF program from \"%s\": %d\n", authorize_v6_program, result);
    //     result = 1;
    // }
    // fprintf(stdout, "Unpinned v6 eBPF program from \"%s\"\n", authorize_v6_program);

    result = ebpf_object_unpin(egress_connection_policy_map);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF map from \"%s\": %d\n", egress_connection_policy_map, result);
        result = 1;
    }
    fprintf(stdout, "Unpinned eBPF map from \"%s\"\n", egress_connection_policy_map);

    // result = ebpf_object_unpin(egress_statistics_map);
    // if (result != ERROR_SUCCESS) {
    //     fprintf(stderr, "Failed to unpin eBPF map from \"%s\": %d\n", egress_statistics_map, result);
    //     result = 1;
    // }
    // fprintf(stdout, "Unpinned eBPF map from \"%s\"\n", egress_statistics_map);

    fprintf(stdout, "\nDone.\n");
    return result;
}

// int
// stats(int argc, char** argv)
// {
//     uint32_t result;
//     fd_t map_fd;
//     uint32_t key = 0;
//     uint32_t v4_redirect = 0;
//     uint32_t v4_allow = 0;
//     uint32_t v6_redirect = 0;
//     uint32_t v6_allow = 0;

//     UNREFERENCED_PARAMETER(argc);
//     UNREFERENCED_PARAMETER(argv);

//     map_fd = bpf_obj_get((char*)egress_statistics_map);
//     if (map_fd == ebpf_fd_invalid) {
//         fprintf(stderr, "Failed to look up statistics map.\n");
//         return 1;
//     }

//     // Get v4 values.
//     result = bpf_map_lookup_elem(map_fd, &key, &v4_allow);
//     if (result != 0) {
//         fprintf(stderr, "Failed to read entry from stats map: %d\n", result);
//         return 1;
//     }
//     key++;
//     result = bpf_map_lookup_elem(map_fd, &key, &v4_redirect);
//     if (result != 0) {
//         fprintf(stderr, "Failed to read entry from stats map: %d\n", result);
//         return 1;
//     }

//     // Get v6 values.
//     key++;
//     result = bpf_map_lookup_elem(map_fd, &key, &v6_allow);
//     if (result != 0) {
//         fprintf(stderr, "Failed to read entry from stats map: %d\n", result);
//         return 1;
//     }
//     key++;
//     result = bpf_map_lookup_elem(map_fd, &key, &v6_redirect);
//     if (result != 0) {
//         fprintf(stderr, "Failed to read entry from stats map: %d\n", result);
//         return 1;
//     }

//     printf("STATISTICS:\n");
//     printf("  Allowed v4    : %d\n", v4_allow);
//     printf("  Allowed v6    : %d\n", v6_allow);
//     printf("  Redirected v4 : %d\n", v4_redirect);
//     printf("  Redirected v6 : %d\n\n", v6_redirect);

//     return 0;
// }

int
proxy(int argc, char** argv)
{
    struct sockaddr_storage destination_ip;
    struct sockaddr_storage proxy_ip;
    uint16_t destination_port;
    uint16_t proxy_port;
    destination_entry_t key = {0};
    destination_entry_t value = {0};
    ADDRESS_FAMILY family1, family2;
    bool add = false;

    WSAData data;

    if (argc != 5) {
        fprintf(stderr, "invalid parameters\n");
        return 1;
    }

    std::string operation(argv[0]);

    if (operation.compare(_add_operation) != 0 && operation.compare(_delete_operation) != 0) {
        fprintf(stderr, "invalid operation: %s\n", operation.c_str());
        return 1;
    }
    if (operation.compare(_add_operation) == 0) {
        add = true;
    }

    int error = WSAStartup(2, &data);
    if (error != 0) {
        fprintf(stderr, "Unable to load Winsock: %d\n", error);
        return 1;
    }

    std::string destination_ip_string(argv[1]);
    std::string proxy_ip_string(argv[3]);

    // printf("reached 1\n");

    // printf("destination_ip_string = %s\n", destination_ip_string.c_str());
    // printf("proxy_ip_string = %s\n", proxy_ip_string.c_str());

    get_address_from_string(destination_ip_string, destination_ip, false, &family1);
    get_address_from_string(proxy_ip_string, proxy_ip, false, &family2);

    // printf("reached 2\n");

    if (family1 != family2) {
        fprintf(stderr, "Invalid parameter: Both addresses should be same family\n");
        return 1;
    }

    destination_port = htons((uint16_t)atoi(argv[2]));
    proxy_port = htons((uint16_t)atoi(argv[4]));

    fd_t map_fd;
    uint32_t result;

    // printf("reached 3\n");

    INET_SET_ADDRESS(family1, (PUCHAR)&key.destination_ip, INETADDR_ADDRESS((PSOCKADDR)&destination_ip));
    INET_SET_ADDRESS(family1, (PUCHAR)&value.destination_ip, INETADDR_ADDRESS((PSOCKADDR)&proxy_ip));

    key.destination_port = destination_port;
    key.protocol = IPPROTO_TCP;

    value.destination_port = proxy_port;

    // printf("reached 4\n");

    map_fd = bpf_obj_get((char*)egress_connection_policy_map);
    if (map_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to look up policy map.\n");
        return 1;
    }

    if (add) {
        result = bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY);
        if (result != EBPF_SUCCESS) {
            fprintf(stderr, "Failed to add proxy entry: %d\n", result);
            return 1;
        }

        fprintf(stdout, "Added proxy entry.\n");
    } else {
        result = bpf_map_delete_elem(map_fd, &key);
        if (result != EBPF_SUCCESS) {
            fprintf(stderr, "Failed to delete proxy entry: %d\n", result);
            return 1;
        }

        fprintf(stdout, "Deleted proxy entry.\n");
    }

    _close(map_fd);
    WSACleanup();

    return 0;
}

typedef int (*operation_t)(int argc, char** argv);
struct
{
    const char* name;
    const char* help;
    operation_t operation;
} commands[]{
    {"load", "load\tLoad the sock_addr eBPF program", load},
    {"unload", "unload\tUnload the sock_addr eBPF program", unload},
    // {"stats", "stats\tPrint the stats for the eBPF program", stats},
    {"proxy", "proxy {add|delete} dst_ip dst_port proxy_ip proxy_port\tConfigure proxy", proxy}};

void
print_usage(char* path)
{
    fprintf(stderr, "Usage: %s command\n", path);
    for (auto& cmd : commands) {
        fprintf(stderr, "\t%s\n", cmd.name);
    }
}

int
main(int argc, char** argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    for (const auto& cmd : commands) {
        if (_stricmp(cmd.name, argv[1]) == 0) {
            return cmd.operation(argc - 2, argv + 2);
        }
    }
    print_usage(argv[0]);
    return 1;
}
