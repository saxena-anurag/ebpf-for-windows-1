// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"

#include <windows.h>
#include <io.h>
#include <iostream>
#include <string>

const char* authorize_v4_program = "authorize_connect4";
const char* authorize_v6_program = "authorize_connect6";

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
    bpf_program* v6_program = nullptr;
    bpf_link* v4_link = nullptr;
    bpf_link* v6_link = nullptr;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    object = bpf_object__open("cgroup_sock_addr.sys");
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

    v6_program = bpf_object__find_program_by_name(object, authorize_v6_program);
    if (v6_program == nullptr) {
        fprintf(stderr, "Failed to find v6 connect program\n");
        return 1;
    }

    // Attach both the programs.
    result = ebpf_program_attach(v4_program, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, nullptr, 0, &v4_link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }
    fprintf(stdout, "Attached v4 eBPF program\n");
    result = ebpf_program_attach(v6_program, &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT, nullptr, 0, &v6_link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }
    fprintf(stdout, "Attached v6 eBPF program\n");

    // Pin both the programs.
    if (bpf_obj_pin(bpf_program__fd(v4_program), authorize_v4_program) < 0) {
        fprintf(stderr, "Failed to pin eBPF program [%s]: %d\n", authorize_v4_program, errno);
        return 1;
    }
    fprintf(stdout, "Pinned v4 eBPF program to \"%s\"\n", authorize_v4_program);
    if (bpf_obj_pin(bpf_program__fd(v6_program), authorize_v6_program) < 0) {
        fprintf(stderr, "Failed to pin eBPF program [%s]: %d\n", authorize_v6_program, errno);
        return 1;
    }
    fprintf(stdout, "Pinned v6 eBPF program to \"%s\"\n", authorize_v6_program);

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
    result = ebpf_object_unpin(authorize_v6_program);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF program from \"%s\": %d\n", authorize_v6_program, result);
        result = 1;
    }
    fprintf(stdout, "Unpinned v6 eBPF program from \"%s\"\n", authorize_v6_program);

    fprintf(stdout, "\nDone.\n");
    return result;
}

typedef int (*operation_t)(int argc, char** argv);
struct
{
    const char* name;
    const char* help;
    operation_t operation;
} commands[]{
    {"load", "load\tLoad the port quota eBPF program", load},
    {"unload", "unload\tUnload the port quota eBPF program", unload}};

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
