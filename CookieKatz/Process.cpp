#define _AMD64_
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <Shlwapi.h>

#include "PEB.h"
#include "Helper.h"
#include "Tokens.h"
#include "Memory.h"

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
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("LoadLibrary could not load ntdll"));
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
            DEBUG_PRINT_ERROR_MESSAGE(TEXT("Failed to read Chrome PEB"));
            return FALSE;
        }
        else
            return TRUE;
    }
    else
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("ProcessBasicInformation failed"));
        return FALSE;
    }

    return FALSE;
}

BOOL ReadPEBProcessParameters(HANDLE hProcess, PEB* peb, WCHAR** args) {

    UNICODE_STRING commandLine;
    if (!ReadProcessMemory(hProcess, &peb->ProcessParameters->CommandLine, &commandLine, sizeof(commandLine), NULL))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Could not read CommandLine!\n"));
        return FALSE;
    }

    *args = (WCHAR*)malloc(commandLine.MaximumLength);
    if (*args != 0 && !ReadProcessMemory(hProcess, commandLine.Buffer, *args, commandLine.MaximumLength, NULL))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Could not read the command line string!\n"));
        free(*args);
        return FALSE;
    }

    return TRUE;
}

BOOL FindCorrectProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("CreateToolhelp32Snapshot failed"));
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Process32First failed"));
        CloseHandle(hProcessSnap);
        return(FALSE);
    }

    //Target Chrome process has the following flag, this is how we find the right PID
    //--utility-sub-type=network.mojom.NetworkService
    const WCHAR* flags = TEXT("--utility-sub-type=network.mojom.NetworkService");

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
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
                        PRINTW(L"[+] Found browser process: %d\n", pe32.th32ProcessID);
                        PRINTW(L"    Process owner: ");
                        GetTokenUser(hHandle);
                        PRINTW(L"\n\n");

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

void FindAllSuitableProcesses(LPCWSTR processName)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("CreateToolhelp32Snapshot failed"));
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Process32First failed"));
        CloseHandle(hProcessSnap);
        return;
    }

    //Target Chrome process has the following flag, this is how we find the right PID
    //--utility-sub-type=network.mojom.NetworkService
    const WCHAR* flags = TEXT("--utility-sub-type=network.mojom.NetworkService");

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
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
                        PRINTW(L"[+] Found browser process: %d\n", pe32.th32ProcessID);
                        PRINTW(L"    Process owner: ");
                        GetTokenUser(hHandle);
                        PRINTW(L"\n\n");
                    }
                }
                free(commandLine);
            }
            CloseHandle(hHandle);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize) {

    DWORD szModules = sizeof(HMODULE) * 1024; //Should be enough ;)
    HMODULE* hModules = (HMODULE*)malloc(szModules);
    DWORD cbNeeded;

    if (hModules == 0 || !EnumProcessModulesEx(hProcess, hModules, szModules, &cbNeeded, LIST_MODULES_ALL)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("EnumProcessModulesEx failed"));
        free(hModules);
        return FALSE;
    }

    for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
        wchar_t szModuleName[MAX_PATH];
        if (GetModuleBaseName(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(wchar_t)) == 0) {
            DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetModuleBaseName failed"));
            continue;
        }
        if (_wcsicmp(szModuleName, moduleName) == 0) {
            MODULEINFO moduleInfo;
            if (!GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(moduleInfo))) {
                DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetModuleInformation failed"));
                free(hModules);
                return FALSE;
            }
            baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
            *moduleSize = moduleInfo.SizeOfImage;
            free(hModules);
            return TRUE;
        }
    }
    free(hModules);
    return FALSE;
}

BOOL GetProcessName(HANDLE hProcess, TargetVersion &targetBrowser) {

    wchar_t processPath[MAX_PATH];
    DWORD size = sizeof(processPath) / sizeof(processPath[0]);

    // Query the full process image name
    if (!QueryFullProcessImageName(hProcess, 0, processPath, &size)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("QueryFullProcessImageName failed to get target process name"));
        return FALSE;
    }

    const wchar_t* executableName = PathFindFileName(processPath);
    if (wcscmp(executableName, L"chrome.exe") == 0)
    {
        targetBrowser = Chrome;
        return TRUE;
    }
    if (wcscmp(executableName, L"msedge.exe") == 0)
    {
        targetBrowser = Edge;
        return TRUE;
    }
    if (wcscmp(executableName, L"msedgewebview2.exe") == 0)
    {
        targetBrowser = Webview2;
        return TRUE;
    }
    return FALSE;
}

BOOL GetProcessHandle(DWORD pid, HANDLE* hProcess) {
    HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hHandle == NULL || hHandle == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("OpenProcess failed"));
        return FALSE;
    }
    *hProcess = hHandle;
    return TRUE;
}

BOOL IsWow64(HANDLE hProcess) {
    BOOL isBrowserWow64 = FALSE;
    if (!IsWow64Process(hProcess, &isBrowserWow64)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("IsWow64Process failed for browser process"));
        CloseHandle(hProcess);
        return TRUE;
    }
    if (isBrowserWow64) {
        CloseHandle(hProcess);
        return TRUE;
    }

    return FALSE;
}