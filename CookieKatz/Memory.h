#pragma once
#include <minwindef.h>

enum TargetVersion {
	Chrome,
	Edge,
	Webview2,
	OldChrome,
	OldEdge,
	Chrome124,
	Chrome130,
	Edge130
};

void WalkCookieMap(HANDLE hProcess, uintptr_t cookieMapAddress, TargetVersion targetConfig);
BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster);
BOOL FindLargestSection(HANDLE hProcess, uintptr_t moduleAddr, uintptr_t& resultAddress);
void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset);