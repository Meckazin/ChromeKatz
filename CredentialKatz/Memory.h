#pragma once
#include <minwindef.h>

enum TargetVersion {
	Chrome,
	Edge,
	Webview2
};

void WalkCredentialMap(HANDLE hProcess, uintptr_t credentialMapAddress);
BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster);
BOOL FindLargestSection(HANDLE hProcess, uintptr_t moduleAddr, uintptr_t& resultAddress);
void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset);