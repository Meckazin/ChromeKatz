#pragma once
#include <wtypes.h>
#include <cstdint>

enum TargetVersion {
	Chrome,
	Edge,
	Webview2
};

void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset);
BOOL FindPattern(udmpparser::UserDumpParser& dump, const BYTE* pattern, size_t patternSize, uintptr_t* CookieMonsterInstances, size_t& instanceCount);
BOOL FindLargestSection(udmpparser::UserDumpParser& dump, std::string moduleName, uintptr_t& resultAddress);

void WalkCredentialMap(udmpparser::UserDumpParser& dump, uintptr_t cookieMapAddress);