#include <Windows.h>
#include <Psapi.h>

#include "Helper.h"
#include "Version.h"

#pragma comment(lib,"version.lib")
BOOL GetBrowserVersion(HANDLE hProcess, BrowserVersion& browserVersion) {

    LPWSTR filePath = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
    if (filePath == NULL || GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH) == 0) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetModuleFileNameEx failed"));
        free(filePath);
        return FALSE;
    }
    DWORD dwHandle;
    DWORD dwSize = GetFileVersionInfoSize(filePath, &dwHandle);
    if (dwSize == 0) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetFileVersionInfoSize failed"));
        free(filePath);
        return FALSE;
    }

    BYTE* buffer = (BYTE*)malloc(dwSize);
    if (buffer == nullptr || !GetFileVersionInfo(filePath, 0, dwSize, buffer)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("GetFileVersionInfo failed"));
        free(buffer);
        free(filePath);
        return FALSE;
    }

    free(filePath);

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

    PRINT("[*] Browser Version: %hu.%hu.%hu.%hu\n\n",
        HIWORD(fileInfo->dwProductVersionMS),
        LOWORD(fileInfo->dwProductVersionMS),
        HIWORD(fileInfo->dwProductVersionLS),
        LOWORD(fileInfo->dwProductVersionLS)
    );

    browserVersion.highMajor = HIWORD(fileInfo->dwProductVersionMS);
    browserVersion.lowMajor = LOWORD(fileInfo->dwProductVersionMS);
    browserVersion.highMinor = HIWORD(fileInfo->dwProductVersionLS);
    browserVersion.lowMinor = LOWORD(fileInfo->dwProductVersionLS);

    free(buffer);
    return TRUE;
}