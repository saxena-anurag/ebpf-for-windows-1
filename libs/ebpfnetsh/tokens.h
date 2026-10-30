// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#define TOKEN_ATTACHED L"attached"
#define TOKEN_COMPARTMENT L"compartment"
#define TOKEN_EXECUTION L"execution"
#define TOKEN_FILENAME L"filename"
#define TOKEN_HASHONLY L"hashonly"
#define TOKEN_ID L"id"
#define TOKEN_INTERFACE L"interface"
#define TOKEN_LEVEL L"level"
#define TOKEN_MAP_FLAGS L"flags"
#define TOKEN_MAP_INNERID L"innerid"
#define TOKEN_MAP_KEY L"key"
#define TOKEN_MAP_KEYSIZE L"keysize"
#define TOKEN_MAP_MAXENTRIES L"maxentries"
#define TOKEN_MAP_NAME L"name"
#define TOKEN_MAP_VALUE L"value"
#define TOKEN_MAP_VALUESIZE L"valuesize"
#define TOKEN_NAMESPACE L"namespace"
#define TOKEN_PINNED L"pinned"
#define TOKEN_PINPATH L"pinpath"
#define TOKEN_PROGRAM L"program"
#define TOKEN_SECTION L"section"
#define TOKEN_TYPE L"type"

typedef enum
{
    VL_NORMAL = 0,
    VL_INFORMATIONAL = 1,
    VL_VERBOSE = 2,
} VERBOSITY_LEVEL;

extern TOKEN_VALUE g_LevelEnum[3];
