#pragma once
#include <minwindef.h>

void WalkCookieMap(HANDLE hProcess, uintptr_t cookieMapAddress);
BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster);
BOOL FindDllPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t moduleAddr, DWORD moduleSize, uintptr_t& resultAddress);