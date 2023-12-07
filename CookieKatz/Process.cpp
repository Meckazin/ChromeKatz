#define _AMD64_

#include "PEB.h"
#include "Helper.h"
#include "Tokens.h"

#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,		  // Note: this is kernel mode only
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass			 // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

BOOL ReadRemoteProcessPEB(IN HANDLE hProcess, OUT PEB* peb) {

    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll == NULL || hNtDll == INVALID_HANDLE_VALUE) {
        DebugPrintErrorWithMessage(TEXT("LoadLibrary could not load ntdll"));
        return FALSE;
    }
    NtQueryInformationProcess pNtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION processInfo{ 0 };
    ULONG szInfo = 0;

    if (SUCCEEDED(pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &processInfo, sizeof(PROCESS_BASIC_INFORMATION), &szInfo))
        && szInfo == sizeof(PROCESS_BASIC_INFORMATION)
        && processInfo.PebBaseAddress) {

        size_t szPEB = 0;

        if (!ReadProcessMemory(hProcess, processInfo.PebBaseAddress, peb, sizeof(PEB), &szPEB) || szPEB < sizeof(PEB)) {
            DebugPrintErrorWithMessage(TEXT("Failed to read Chrome PEB"));
            return FALSE;
        }
        else
            return TRUE;
    }
    else
    {
        DebugPrintErrorWithMessage(TEXT("ProcessBasicInformation failed"));
        return FALSE;
    }

    return FALSE;
}

BOOL ReadPEBProcessParameters(HANDLE hProcess, PEB* peb, WCHAR** args) {

    UNICODE_STRING commandLine;
    if (!ReadProcessMemory(hProcess, &peb->ProcessParameters->CommandLine, &commandLine, sizeof(commandLine), NULL))
    {
        DebugPrintErrorWithMessage(TEXT("Could not read CommandLine!\n"));
        return FALSE;
    }

    *args = (WCHAR*)malloc(commandLine.MaximumLength);
    if (*args != 0 && !ReadProcessMemory(hProcess, commandLine.Buffer, *args, commandLine.MaximumLength, NULL))
    {
        DebugPrintErrorWithMessage(TEXT("Could not read the command line string!\n"));
        free(*args);
        return FALSE;
    }

    return TRUE;
}

BOOL FindCorrectChromePID(DWORD* pid, HANDLE* hProcess)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DebugPrintErrorWithMessage(TEXT("CreateToolhelp32Snapshot failed"));
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        DebugPrintErrorWithMessage(TEXT("Process32First failed"));
        CloseHandle(hProcessSnap);
        return(FALSE);
    }

    //Target Chrome process has the following flag, this is how we find the right PID
    //--utility-sub-type=network.mojom.NetworkService
    const WCHAR* flags = TEXT("--utility-sub-type=network.mojom.NetworkService");

    do
    {
        if (wcscmp(pe32.szExeFile,L"chrome.exe") == 0)
        {
            PEB peb = { 0 };
            HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (ReadRemoteProcessPEB(hHandle, &peb))
            {
                WCHAR* commandLine{0};
                if (ReadPEBProcessParameters(hHandle, &peb, &commandLine) && &commandLine != 0)
                {
                    if (wcsstr(commandLine, flags) != 0)
                    {
                        printf("[+] Found Chrome process: %d\n", pe32.th32ProcessID);
                        printf("    Process owner: ");
                        GetTokenUser(hHandle);
                        printf("\n\n");

                        *pid = pe32.th32ProcessID;
                        *hProcess = hHandle;
                        free(commandLine);
                        CloseHandle(hProcessSnap);
                        return TRUE;
                    }
                    free(commandLine);
                }
            }
            CloseHandle(hHandle);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return FALSE;
}

void FindAllSuitableProcesses()
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DebugPrintErrorWithMessage(TEXT("CreateToolhelp32Snapshot failed"));
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        DebugPrintErrorWithMessage(TEXT("Process32First failed"));
        CloseHandle(hProcessSnap);
        return;
    }

    //Target Chrome process has the following flag, this is how we find the right PID
    //--utility-sub-type=network.mojom.NetworkService
    const WCHAR* flags = TEXT("--utility-sub-type=network.mojom.NetworkService");

    do
    {
        if (wcscmp(pe32.szExeFile, L"chrome.exe") == 0)
        {
            PEB peb = { 0 };
            HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (ReadRemoteProcessPEB(hHandle, &peb))
            {
                WCHAR* commandLine{ 0 };
                if (ReadPEBProcessParameters(hHandle, &peb, &commandLine) && &commandLine != 0)
                {
                    if (wcsstr(commandLine, flags) != 0)
                    {
                        printf("[+] Found Chrome process: %d\n", pe32.th32ProcessID);
                        printf("    Process owner: ");
                        GetTokenUser(hHandle);
                        printf("\n\n");
                    }
                }
                free(commandLine);
            }
            CloseHandle(hHandle);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress) {

    HMODULE hModules[1024];
    DWORD cbNeeded;

    if (!EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded, LIST_MODULES_ALL)) {
        DebugPrintErrorWithMessage(TEXT("EnumProcessModulesEx failed"));
        return FALSE;
    }

    for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
        wchar_t szModuleName[MAX_PATH];
        if (GetModuleBaseName(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(wchar_t)) == 0) {
            DebugPrintErrorWithMessage(TEXT("GetModuleBaseName failed"));
            continue;
        }
        if (_wcsicmp(szModuleName, moduleName) == 0) {
            MODULEINFO moduleInfo;
            if (!GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(moduleInfo))) {
                DebugPrintErrorWithMessage(TEXT("GetModuleInformation failed"));
                return FALSE;
            }
            baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
            return TRUE;
        }
    }

    return FALSE;
}