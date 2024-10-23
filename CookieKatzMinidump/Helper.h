#pragma once
const char* StateToString(const uint32_t State);
const char* TypeToString(const uint32_t Type);
void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size);
void PrintErrorWithMessage(const wchar_t* buf);
#ifdef _DEBUG
void DebugPrint(const wchar_t* print);
void DebugPrintErrorWithMessage(const wchar_t* buf);
#define DEBUG_PRINT_ERROR_MESSAGE(...) DebugPrintErrorWithMessage(__VA_ARGS__)
#define DEBUG_PRINT(...) DebugPrint(__VA_ARGS__)
#else
#define DEBUG_PRINT_ERROR_MESSAGE(...)
#define DEBUG_PRINT(...)
#endif

#ifdef BOF //TODO
#include "beacon.h"

#define PRINT(...) BeaconFormatPrintf(__VA_ARGS__)
#define PRINTW(...) BeaconPrintf(__VA_ARGS__)
#define SSCAN(...)
#else
void PrintMessageW(wchar_t const* const _Format, ...);
void PrintMessageA(char const* const _Format, ...);
int my_sscanf_s(const char* buffer, const char* format, ...);
#define PRINTW(...) PrintMessageW(__VA_ARGS__)
#define PRINT(...) PrintMessageA(__VA_ARGS__)
#define SSCAN(...) my_sscanf_s(__VA_ARGS__)
#endif