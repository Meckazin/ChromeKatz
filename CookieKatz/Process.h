#pragma once
#include <minwindef.h>
#include "Memory.h"

void FindAllSuitableProcesses(LPCWSTR processName);
BOOL FindCorrectProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess);
BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize);

BOOL GetProcessHandle(DWORD pid, HANDLE* hProcess);
BOOL GetProcessName(HANDLE hProcess, TargetVersion& targetBrowser);
BOOL IsWow64(HANDLE hProcess);