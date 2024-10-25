#pragma once
#include <minwindef.h>

struct BrowserVersion {
    WORD highMajor;
    WORD lowMajor;
    WORD highMinor;
    WORD lowMinor;
};

BOOL GetBrowserVersion(HANDLE hProcess, BrowserVersion& browserVersion);