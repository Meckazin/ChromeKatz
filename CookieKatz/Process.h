#pragma once
#include <minwindef.h>
#include "Memory.h"
#include "PEB.h"

class Process {
private:
	HANDLE hProcess = nullptr;
	HANDLE hOutFile = nullptr;

	BOOL ReadRemoteProcessPEB(OUT PEB* peb);
	BOOL ReadPEBProcessParameters(PEB* peb, WCHAR** args);

public:
	TargetVersion targetConfig = Chrome;

	Process() {}

	//Only use this object to close these handles
	~Process() {
		CloseHandle(this->hProcess);
		CloseHandle(this->hOutFile);
	}

	HANDLE GetPrivateHandle() {
		return this->hProcess;
	}
	void SetPrivateHandle(HANDLE hProcess) {
		this->hProcess = hProcess;
	}
	void SetFileHandle(HANDLE hFile) {
		this->hOutFile = hFile;
	}
	HANDLE GetFileHandle() {
		return this->hOutFile;
	}

	void FindAllSuitableProcesses(LPCWSTR processName);
	BOOL FindCorrectProcessPID(LPCWSTR processName, DWORD* pid);
	BOOL GetRemoteModuleBaseAddress(const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize);

	BOOL GetProcessHandle(DWORD pid);
	BOOL GetProcessName();
	BOOL IsWow64();
};