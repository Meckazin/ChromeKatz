#define _AMD64_
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <Shlwapi.h>

#include "Helper.h"
#include "Tokens.h"
#include "Memory.h"

BOOL GetProcessName(HANDLE hProcess, LPCWSTR& targetBrowser) {

    wchar_t processPath[MAX_PATH];
    DWORD size = sizeof(processPath) / sizeof(processPath[0]);

    // Query the full process image name
    if (!QueryFullProcessImageName(hProcess, 0, processPath, &size)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("QueryFullProcessImageName failed to get target process name"));
        return FALSE;
    }

    const wchar_t* executableName = PathFindFileName(processPath);
    if (wcscmp(executableName, targetBrowser) == 0)
        return TRUE;
    if (wcscmp(executableName, targetBrowser) == 0)
        return TRUE;
    if (wcscmp(executableName, targetBrowser) == 0)
        return TRUE;

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

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
        {
            HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);

            if (!GetProcessName(hParent, processName))
            {
                HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

                PRINT("[+] Found browser process: %d\n", pe32.th32ProcessID);
                PRINT("    Process owner: ");
                GetTokenUser(hHandle);
                PRINT("\n\n");

                CloseHandle(hHandle);
            }
            CloseHandle(hParent);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
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

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
        {
            HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);

            if (!GetProcessName(hParent, processName))
            {
                CloseHandle(hParent);

                HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

                PRINT("[+] Found %ls main process PID: %lu\n", processName, pe32.th32ProcessID);
                *pid = pe32.th32ProcessID;
                *hProcess = hHandle;
                return TRUE;
            }
            CloseHandle(hParent);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return FALSE;
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