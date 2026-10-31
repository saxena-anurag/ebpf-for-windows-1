// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

// Returns -1 for the normal Catch runner, otherwise the child process's exit code.
int
namespace_test_child(int argc, char** argv);
