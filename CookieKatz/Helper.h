#pragma once
void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size);
void PrintErrorWithMessage(const wchar_t* buf);
#ifdef _DEBUG
#define DEBUG_PRINT_ERROR_MESSAGE(...) DebugPrintErrorWithMessage(__VA_ARGS__)
#define DEBUG_PRINT(...) DebugPrint(__VA_ARGS__)
#else
#define DEBUG_PRINT_ERROR_MESSAGE(...)
#define DEBUG_PRINT(...)
#endif

#ifdef _DEBUG
//Debug functions
void DebugPrint(const wchar_t* print);
#endif

void DebugPrintErrorWithMessage(const wchar_t* buf);