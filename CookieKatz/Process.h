#pragma once
#include <minwindef.h>

void FindAllSuitableProcesses();
BOOL FindCorrectChromePID(DWORD* pid, HANDLE* hProcess);
BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress);