#include <Windows.h>
#include <format>
#include <Shlwapi.h>

void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        byteArray[i] = static_cast<BYTE>(value & 0xFF);
        value >>= 8;
    }
}
BOOL CreateOutputFile(char* path, HANDLE* hFile) {

    DWORD dwAttr = GetFileAttributesA(path);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        //Path is to a directory, append the default filename
        if (dwAttr & FILE_ATTRIBUTE_DIRECTORY) {
            if (path[strlen(path) - 1] != '\\')
                strcat_s(path, MAX_PATH, "\\cookies.log");
            else
                strcat_s(path, MAX_PATH, "cookies.log");
        }
        else {
            char dirPath[MAX_PATH];
            strcpy_s(dirPath, MAX_PATH, path);

            char* lastSeparator = strrchr(dirPath, '\\');
            *lastSeparator = '\0';

            DWORD dirAttr = GetFileAttributesA(dirPath);
            if (dirAttr == INVALID_FILE_ATTRIBUTES || (dirAttr & FILE_ATTRIBUTE_DIRECTORY)) {
                return FALSE; //Path doesn't exists
            }
        }
    }
    else
        return FALSE;
    
    *hFile = CreateFileA(path, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (*hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    return TRUE;
}

wchar_t* GetLastErrorAsString() {

    DWORD dwError = GetLastError();
    if (dwError == 0) {
        return (wchar_t*)L"";
    }

    LPWSTR messageBuffer = NULL;

    size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dwError, LANG_NEUTRAL, (LPWSTR)&messageBuffer, 0, NULL);

    if (size > 0)
        return messageBuffer;

    return (wchar_t*)L"";
}
wchar_t* GetErrorString(IN DWORD dwError) {
    if (dwError == 0) {
        return (wchar_t*)L"";
    }

    LPWSTR messageBuffer = NULL;

    size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dwError, LANG_NEUTRAL, (LPWSTR)&messageBuffer, 0, NULL);

    if (size > 0)
        return messageBuffer;

    return (wchar_t*)L"";
}

void DebugPrint(const wchar_t* buf, HANDLE hFile) {

#ifdef _DEBUG
    std::wstring output = std::format(L"[DEBUG] {}\n", buf);
    if (hFile != nullptr)
        WriteFile(hFile, output.c_str(), (output.length() * sizeof(wchar_t)), NULL, NULL);
    else
        wprintf(std::format(L"[DEBUG] {}\n", buf).c_str());
#endif // DEBUG

}
void DebugPrintErrorWithMessage(const wchar_t* buf, HANDLE hFile) {

#ifdef _DEBUG
    DWORD dwError = GetLastError();
    std::wstring output;
    if (dwError != 0) {
        wchar_t* errorBuf = GetLastErrorAsString();
        output = std::format(L"[ERROR] {}, Error code: {}, Error string: {}\n", buf, dwError, errorBuf);
    }
    else
        output = std::format(L"[ERROR] {}, Unknown error occured!\n", buf);

    if (hFile != nullptr) {
        int mblen = WideCharToMultiByte(CP_UTF8, 0, output.c_str(), wcslen(output.c_str()), NULL, 0, NULL, NULL);
        char* out = (char*)malloc(mblen + 1);
        memset(out, 0, mblen + 1);

        char* outbuf = (char*)malloc(mblen + 1);
        WideCharToMultiByte(CP_UTF8, 0, output.c_str(), mblen, outbuf, mblen, NULL, NULL);

        WriteFile(hFile, outbuf, mblen, NULL, NULL);
        free(out);
    }
    else
        wprintf(std::format(L"[DEBUG] {}\n", buf).c_str());

#endif // DEBUG

}

void PrintErrorWithMessage(const wchar_t* buf, HANDLE hFile) {

    DWORD dwError = GetLastError();
    std::wstring output;
    if (dwError != 0) {
        wchar_t* errorBuf = GetLastErrorAsString();
        output = std::format(L"[ERROR] {}, Error code: {}, Error string: {}\n", buf, dwError, errorBuf);
    }
    else
        output = std::format(L"[ERROR] {}, Unknown error occured!\n", buf);

    if (hFile != nullptr) {
        int mblen = WideCharToMultiByte(CP_UTF8, 0, output.c_str(), wcslen(output.c_str()), NULL, 0, NULL, NULL);
        char* out = (char*)malloc(mblen + 1);
        memset(out, 0, mblen + 1);

        char* outbuf = (char*)malloc(mblen + 1);
        WideCharToMultiByte(CP_UTF8, 0, output.c_str(), mblen, outbuf, mblen, NULL, NULL);

        WriteFile(hFile, outbuf, mblen, NULL, NULL);
        free(out);
    }
    else
        wprintf(std::format(L"[DEBUG] {}\n", output).c_str());
}
void PrintMessageW(HANDLE hFile, const wchar_t* _Format, ...) {
    va_list args;
    wchar_t buffer[5 * 1024];

    va_start(args, _Format);
    vswprintf(buffer, sizeof(buffer) / sizeof(wchar_t), _Format, args);
    va_end(args);

    int mblen = WideCharToMultiByte(CP_UTF8, 0, buffer, wcslen(buffer), NULL, 0, NULL, NULL);
    char* out = (char*)malloc(mblen+1);
    memset(out, 0, mblen + 1);

    WideCharToMultiByte(CP_UTF8, 0, buffer, wcslen(buffer), out, mblen, NULL, NULL);

    if (hFile != nullptr)
        WriteFile(hFile, out, mblen, NULL, NULL);
    else
        printf("%s",out);

    free(out);
}
void PrintMessageA(HANDLE hFile, const char* _Format, ...) {
    va_list args;
    char buffer[5 * 1024];
    memset(buffer, 0, 5 * 1024);

    va_start(args, _Format);
    vsnprintf(buffer, sizeof(buffer), _Format, args);
    va_end(args);

    if (hFile != nullptr)
        WriteFile(hFile, buffer, (strlen(buffer)), NULL, NULL);
    else
        printf("%s",buffer);
}
int my_sscanf_s(const char* buffer, const char* format, ...) {
    return sscanf_s(buffer, format);
}