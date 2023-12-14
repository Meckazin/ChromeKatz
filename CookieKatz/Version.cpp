#include <Windows.h>
#include "Helper.h"
#include <stdio.h>

#pragma comment(lib,"version.lib")
BOOL GetChromeVersion(WORD& ChromeMajorVersion) {
    DWORD dwHandle;
    //X86 is not supported, for now...
    LPCWCH fileName = TEXT("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");

    DWORD dwSize = GetFileVersionInfoSize(fileName, &dwHandle);
    if (dwSize == 0) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetFileVersionInfoSize failed"));
        return FALSE;
    }

    BYTE* buffer = static_cast<BYTE*>(malloc(dwSize));
    if (buffer == nullptr || !GetFileVersionInfo(fileName, 0, dwSize, buffer)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetFileVersionInfo failed"));
        free(buffer);
        return FALSE;
    }

    VS_FIXEDFILEINFO* fileInfo;
    UINT len = 0;
    if (!VerQueryValue(buffer, TEXT("\\"), reinterpret_cast<void**>(&fileInfo), &len)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("VerQueryValue failed"));
        free(buffer);
        return FALSE;
    }

    if (len == 0) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("VerQueryValue returned empty VS_FIXEDFILEINFO"));
        free(buffer);
        return FALSE;
    }

    printf("[*] Chrome Version: %hu.%hu.%hu.%hu\n",
        HIWORD(fileInfo->dwProductVersionMS),
        LOWORD(fileInfo->dwProductVersionMS),
        HIWORD(fileInfo->dwProductVersionLS),
        LOWORD(fileInfo->dwProductVersionLS)
    );
    ChromeMajorVersion = HIWORD(fileInfo->dwProductVersionMS);

    free(buffer);
    return TRUE;
}

struct SupportedVersions {
    WORD majorVersion;
    BYTE pattern[114];
};

SupportedVersions* GetSupportedVersions(size_t& szSupported) {

    const size_t szArr = 2;
    SupportedVersions* versionsArr = new SupportedVersions[szArr];
    szSupported = szArr;

    //This could be one way to have separate byte pattern for each Chrome version
    // I can't be bothered...
    versionsArr[0] = { 120, { 
        0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89,
        0xCE, 0xE8, 0xC0, 0xD5, 0xFF, 0xFF, 0x85, 0xFF, 0x74, 0x08,
        0x48, 0x89, 0xF1, 0xE8, 0xE4, 0xB8, 0x66, 0xFD, 0x48, 0x89,
        0xF0, 0x48
    } };

    return versionsArr;
}

BOOL GetSearchPattern(BYTE* pattern) {
    WORD ChromeMajorVersion = 0;
    if (!GetChromeVersion(ChromeMajorVersion))
    {
        printf("[-] Failed to determine Chrome version\n");
        return FALSE;
    }

    size_t szArrSize = 0;
    SupportedVersions* supportedVersions = GetSupportedVersions(szArrSize);

    for (int i = 0; i < szArrSize; ++i) {
        if (supportedVersions[i].majorVersion == ChromeMajorVersion)
        {
            memcpy(pattern, &supportedVersions[i].pattern, (sizeof(BYTE)*144));
            return TRUE;
        }
    }

    printf("[-] This version of Chrome is not supported!\n");
    return FALSE;
};