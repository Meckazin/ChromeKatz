#pragma once
void PrintErrorWithMessage(const wchar_t* buf);
const char* StateToString(const uint32_t State);
const char* TypeToString(const uint32_t Type);
void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size);