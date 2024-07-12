#pragma once
#include <wtypes.h>
#include <cstdint>

BOOL FindPattern(udmpparser::UserDumpParser& dump, const BYTE* pattern, size_t patternSize, uintptr_t* CookieMonsterInstances, size_t& instanceCount);
BOOL FindDLLPattern(udmpparser::UserDumpParser& dump, const char* dllName, const BYTE* pattern, size_t patternSize, uintptr_t& offset);

void WalkCredentialMap(udmpparser::UserDumpParser& dump, uintptr_t cookieMapAddress);