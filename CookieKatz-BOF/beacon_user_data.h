/*
 * Beacon User Data (BUD)
 * -------------------------
 * Beacon User Data is a data structure that holds values which can be
 * passed from a User Defined Reflective Loader to Beacon.
 *
 * Cobalt Strike 4.x
 * ChangeLog:
 *    5/9/2023: initial version for 4.9
 */
#ifndef _BEACON_USER_DATA_H
#define _BEACON_USER_DATA_H

#include <Windows.h>

#define DLL_BEACON_USER_DATA 0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32

/* Syscalls API */
typedef struct
{
    PVOID fnAddr;
    PVOID jmpAddr;
    DWORD sysnum;
} SYSCALL_API_ENTRY;

typedef struct
{
    SYSCALL_API_ENTRY ntAllocateVirtualMemory;
    SYSCALL_API_ENTRY ntProtectVirtualMemory;
    SYSCALL_API_ENTRY ntFreeVirtualMemory;
    SYSCALL_API_ENTRY ntGetContextThread;
    SYSCALL_API_ENTRY ntSetContextThread;
    SYSCALL_API_ENTRY ntResumeThread;
    SYSCALL_API_ENTRY ntCreateThreadEx;
    SYSCALL_API_ENTRY ntOpenProcess;
    SYSCALL_API_ENTRY ntOpenThread;
    SYSCALL_API_ENTRY ntClose;
    SYSCALL_API_ENTRY ntCreateSection;
    SYSCALL_API_ENTRY ntMapViewOfSection;
    SYSCALL_API_ENTRY ntUnmapViewOfSection;
    SYSCALL_API_ENTRY ntQueryVirtualMemory;
    SYSCALL_API_ENTRY ntDuplicateObject;
    SYSCALL_API_ENTRY ntReadVirtualMemory;
    SYSCALL_API_ENTRY ntWriteVirtualMemory;
} SYSCALL_API;

/* Beacon User Data
 *
 * version format: 0xMMmmPP, where MM = Major, mm = Minor, and PP = Patch
 * e.g. 0x040900 -> CS 4.9
*/
typedef struct
{
    unsigned int version;
    SYSCALL_API* syscalls;
    char         custom[BEACON_USER_DATA_CUSTOM_SIZE];
} USER_DATA, *PUSER_DATA;

#endif
