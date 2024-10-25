#include <Windows.h>
#include <format>

const char* StateToString(const uint32_t State) {
    switch (State) {
    case 0x10'00: {
        return "MEM_COMMIT";
    }

    case 0x20'00: {
        return "MEM_RESERVE";
    }

    case 0x1'00'00: {
        return "MEM_FREE";
    }

    default: {
        return "UNKNOWN";
    }
    }
}
const char* TypeToString(const uint32_t Type) {
    switch (Type) {
    case 0x2'00'00: {
        return "MEM_PRIVATE";
    }
    case 0x4'00'00: {
        return "MEM_MAPPED";
    }
    case 0x1'00'00'00: {
        return "MEM_IMAGE";
    }
    default: {
        return "UNKNOWN";
    }
    }
}

void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        byteArray[i] = static_cast<BYTE>(value & 0xFF);
        value >>= 8;
    }
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

void DebugPrint(const wchar_t* buf) {

#ifdef _DEBUG
    if (wcslen(buf) > 0)
        wprintf(std::format(L"[DEBUG] {}\n", buf).c_str());
#endif // DEBUG

}
void DebugPrintErrorWithMessage(const wchar_t* buf) {

#ifdef _DEBUG
    DWORD dwError = GetLastError();
    if (dwError != 0)
    {
        wchar_t* errorBuf = GetLastErrorAsString();
        wprintf(std::format(L"[ERROR] {}, Error code: {}, Error string: {}\n", buf, dwError, errorBuf).c_str());
    }
    else
        wprintf(std::format(L"[ERROR] {}, Unknown error occured!\n", buf).c_str());

#endif // DEBUG

}

void PrintErrorWithMessage(const wchar_t* buf) {
    DWORD dwError = GetLastError();
    if (dwError != 0)
    {
        wchar_t* errorBuf = GetLastErrorAsString();
        wprintf(std::format(L"[ERROR] {}, Error code: {}, Error string: {}\n", buf, dwError, errorBuf).c_str());
    }
    else
        wprintf(std::format(L"[ERROR] {}, Unknown error occured!\n", buf).c_str());
}
void PrintMessageW(wchar_t const* const _Format, ...) {
    wprintf(_Format);
}
void PrintMessageA(char const* const _Format, ...) {
    printf(_Format);
}
int my_sscanf_s(const char* buffer, const char* format, ...) {
    return sscanf_s(buffer, format);
}