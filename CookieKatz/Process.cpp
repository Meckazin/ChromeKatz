#define _AMD64_
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <Shlwapi.h>

#include "PEB.h"
#include "Helper.h"
#include "Tokens.h"
#include "Memory.h"
#include "Process.h"

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

BOOL Process::ReadRemoteProcessPEB(OUT PEB* peb) {

    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll == NULL || hNtDll == INVALID_HANDLE_VALUE) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("LoadLibrary could not load ntdll"), hOutFile);
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
            DEBUG_PRINT_ERROR_MESSAGE(TEXT("Failed to read Chrome PEB"), hOutFile);
            return FALSE;
        }
        else
            return TRUE;
    }
    else
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("ProcessBasicInformation failed"), hOutFile);
        return FALSE;
    }

    return FALSE;
}

BOOL Process::ReadPEBProcessParameters(PEB* peb, WCHAR** args) {

    UNICODE_STRING commandLine;
    if (!ReadProcessMemory(hProcess, &peb->ProcessParameters->CommandLine, &commandLine, sizeof(commandLine), NULL))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Could not read CommandLine!\n"), hOutFile);
        return FALSE;
    }

    *args = (WCHAR*)malloc(commandLine.MaximumLength);
    if (*args != 0 && !ReadProcessMemory(hProcess, commandLine.Buffer, *args, commandLine.MaximumLength, NULL))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Could not read the command line string!\n"), hOutFile);
        free(*args);
        return FALSE;
    }

    return TRUE;
}

BOOL Process::FindCorrectProcessPID(LPCWSTR processName, DWORD* pid)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("CreateToolhelp32Snapshot failed"), hOutFile);
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Process32First failed"), hOutFile);
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
            this->hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (ReadRemoteProcessPEB(&peb))
            {
                WCHAR* commandLine{0};
                if (ReadPEBProcessParameters(&peb, &commandLine) && &commandLine != 0)
                {
                    if (wcsstr(commandLine, flags) != 0)
                    {
                        PRINTW(this->hOutFile, L"[+] Found browser process: %d\n", pe32.th32ProcessID);
                        PRINTW(this->hOutFile, L"    Process owner: ");
                        GetTokenUser(this->hProcess, this->hOutFile);
                        PRINTW(this->hOutFile, L"\n\n");

                        *pid = pe32.th32ProcessID;
                        free(commandLine);
                        CloseHandle(hProcessSnap);
                        return TRUE;
                    }
                    free(commandLine);
                }
            }
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return FALSE;
}

void Process::FindAllSuitableProcesses(LPCWSTR processName)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("CreateToolhelp32Snapshot failed"), hOutFile);
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Process32First failed"), hOutFile);
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
            this->hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (ReadRemoteProcessPEB(&peb))
            {
                WCHAR* commandLine{ 0 };
                if (ReadPEBProcessParameters(&peb, &commandLine) && &commandLine != 0)
                {
                    if (wcsstr(commandLine, flags) != 0)
                    {
                        PRINTW(this->hOutFile, L"[+] Found browser process: %d\n", pe32.th32ProcessID);
                        PRINTW(this->hOutFile, L"    Process owner: ");
                        GetTokenUser(this->hProcess, this->hOutFile);
                        PRINTW(this->hOutFile, L"\n\n");
                    }
                }
                free(commandLine);
            }
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

BOOL Process::GetRemoteModuleBaseAddress(const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize) {

    DWORD szModules = sizeof(HMODULE) * 1024; //Should be enough ;)
    HMODULE* hModules = (HMODULE*)malloc(szModules);
    DWORD cbNeeded;

    if (hModules == 0 || !EnumProcessModulesEx(hProcess, hModules, szModules, &cbNeeded, LIST_MODULES_ALL)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("EnumProcessModulesEx failed"), hOutFile);
        free(hModules);
        return FALSE;
    }

    for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
        wchar_t szModuleName[MAX_PATH];
        if (GetModuleBaseName(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(wchar_t)) == 0) {
            DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetModuleBaseName failed"), hOutFile);
            continue;
        }
        if (_wcsicmp(szModuleName, moduleName) == 0) {
            MODULEINFO moduleInfo;
            if (!GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(moduleInfo))) {
                DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetModuleInformation failed"), hOutFile);
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

BOOL Process::GetProcessName() {

    wchar_t processPath[MAX_PATH];
    DWORD size = sizeof(processPath) / sizeof(processPath[0]);

    // Query the full process image name
    if (!QueryFullProcessImageName(hProcess, 0, processPath, &size)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("QueryFullProcessImageName failed to get target process name"), hOutFile);
        return FALSE;
    }

    const wchar_t* executableName = PathFindFileName(processPath);
    if (wcscmp(executableName, L"chrome.exe") == 0)
    {
        this->targetConfig = Chrome;
        return TRUE;
    }
    if (wcscmp(executableName, L"msedge.exe") == 0)
    {
        this->targetConfig = Edge;
        return TRUE;
    }
    if (wcscmp(executableName, L"msedgewebview2.exe") == 0)
    {
        this->targetConfig = Webview2;
        return TRUE;
    }
    return FALSE;
}

BOOL Process::GetProcessHandle(DWORD pid) {
    HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hHandle == NULL || hHandle == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("OpenProcess failed"), hOutFile);
        return FALSE;
    }
    this->hProcess = hHandle;
    return TRUE;
}

BOOL Process::IsWow64() {
    BOOL isBrowserWow64 = FALSE;
    if (!IsWow64Process(hProcess, &isBrowserWow64)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("IsWow64Process failed for browser process"), hOutFile);
        return TRUE;
    }
    if (isBrowserWow64) {
        return TRUE;
    }

    return FALSE;
}