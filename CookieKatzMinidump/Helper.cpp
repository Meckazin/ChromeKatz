#include <format>
#include <Windows.h>


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
void PrintErrorWithMessage(const wchar_t* buf) {
    DWORD dwError = GetLastError();
    if (dwError != 0)
    {
        wchar_t* errorBuf = GetLastErrorAsString();
        wprintf(std::format(L"[-] {}, Error code: {}, Error string: {}\n", buf, dwError, errorBuf).c_str());
    }
    else
        wprintf(std::format(L"[-] {}, Unknown error occured!\n", buf).c_str());
}
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
