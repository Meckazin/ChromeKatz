#include <Windows.h>
#include <cstdint>
#include "udmp-parser.h"
#include "Helper.h"
#include "Memory.h"

#pragma region structs
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

struct RemoteVector {
	uintptr_t begin_;
	uintptr_t end_;
	uintptr_t unk; //Seems to be same as the end_ ?
};

struct ProcessBoundString {
	RemoteVector maybe_encrypted_data_;
	size_t original_size_;
	BYTE unk[8]; //No clue
	bool encrypted_ = false;
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
	ProcessBoundString value; //size 48
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
	ProcessBoundString value;
	int64_t expiry_date;
	int64_t last_access_date;
	int64_t last_update_date;
	CookiePriority priority;       //Not implemented
	CookieSourceType source_type;    //Not implemented
};
#pragma endregion

#pragma region OldVersions
struct CanonicalCookieOld {
	OptimizedString name;
	OptimizedString value;
	OptimizedString domain;
	OptimizedString path;
	int64_t creation_date;
	int64_t expiry_date;
	int64_t last_access_date;
	int64_t last_update_date;
};

struct CanonicalCookie124 {
	uintptr_t _vfptr; //CanonicalCookie Virtual Function table address. This could also be used to scrape all cookies as it is backed by the chrome.dll
	OptimizedString name;
	OptimizedString domain;
	OptimizedString path;
	int64_t creation_date;
	bool secure;
	bool httponly;
	CookieSameSite same_site;
	BYTE partition_key[120];  //Not implemented //This really should be 128 like in Edge... but for some reason it is not?
	CookieSourceScheme source_scheme;
	int source_port;    //Not implemented //End of Net::CookieBase
	OptimizedString value;
	int64_t expiry_date;
	int64_t last_access_date;
	int64_t last_update_date;
	CookiePriority priority;       //Not implemented
	CookieSourceType source_type;    //Not implemented
};

struct CanonicalCookieChrome130 {
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

struct CanonicalCookieEdge130 {
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

	PatchPattern(newPattern, baseAddrPattern, 16);
	PatchPattern(newPattern, baseAddrPattern, 24);
	PatchPattern(newPattern, baseAddrPattern, 56);
	PatchPattern(newPattern, baseAddrPattern, 80);
	PatchPattern(newPattern, baseAddrPattern, 136);
	PatchPattern(newPattern, baseAddrPattern, 168);
	PatchPattern(newPattern, baseAddrPattern, 176);
	PatchPattern(newPattern, baseAddrPattern, 184);

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
				if (instanceCount >= 1000) {
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

void ReadVector(udmpparser::UserDumpParser& dump, RemoteVector vector, DWORD origSize) {
	size_t szSize = vector.end_ - vector.begin_;
	if (szSize <= 0) {
		//Some cookies just are like that. tapad.com cookie: TapAd_3WAY_SYNCS for example is buggy even with browser tools
		printf("[-] Invalid value length\n");
		return;
	}

	BYTE* buf = (BYTE*)malloc(szSize + 1); //+1 for the string termination
	if (buf == 0 || !ReadDumpMemory(dump, vector.begin_, buf, szSize)) {
		DEBUG_PRINT_ERROR_MESSAGE(TEXT("Failed to read encrypted cookie value"));
		free(buf);
		return;
	}

	memcpy_s(buf + szSize, 1, "\0", 1);
	PRINT("%s\n", buf);

	free(buf);
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

void PrintTimeStamp(int64_t timeStamp) {
	ULONGLONG fileTimeTicks = timeStamp * 10;

	FILETIME fileTime;
	fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
	fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

	SYSTEMTIME systemTime;
	FileTimeToSystemTime(&fileTime, &systemTime);

	printf("%04hu-%02hu-%02hu %02hu:%02hu:%02hu\n",
		systemTime.wYear, systemTime.wMonth, systemTime.wDay,
		systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
}

void PrintValuesEdge(CanonicalCookieEdge130 cookie, udmpparser::UserDumpParser& dump) {
	PRINT("    Name: ");
	ReadString(dump, cookie.name);
	PRINT("    Value: ");
	ReadString(dump, cookie.value);
	PRINT("    Domain: ");
	ReadString(dump, cookie.domain);
	PRINT("    Path: ");
	ReadString(dump, cookie.path);
	PRINT("    Creation time: ");
	PrintTimeStamp(cookie.creation_date);
	PRINT("    Expiration time: ");
	PrintTimeStamp(cookie.expiry_date);
	PRINT("    Last accessed: ");
	PrintTimeStamp(cookie.last_access_date);
	PRINT("    Last updated: ");
	PrintTimeStamp(cookie.last_update_date);
	PRINT("    Secure: %s\n", cookie.secure ? "True" : "False");
	PRINT("    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

	PRINT("\n");
}

void PrintValuesEdge(CanonicalCookieEdge cookie, udmpparser::UserDumpParser& dump) {
	PRINT("    Name: ");
	ReadString(dump, cookie.name);
	PRINT("    Value: ");
	ReadVector(dump, cookie.value.maybe_encrypted_data_, cookie.value.original_size_);
	PRINT("    Domain: ");
	ReadString(dump, cookie.domain);
	PRINT("    Path: ");
	ReadString(dump, cookie.path);
	PRINT("    Creation time: ");
	PrintTimeStamp(cookie.creation_date);
	PRINT("    Expiration time: ");
	PrintTimeStamp(cookie.expiry_date);
	PRINT("    Last accessed: ");
	PrintTimeStamp(cookie.last_access_date);
	PRINT("    Last updated: ");
	PrintTimeStamp(cookie.last_update_date);
	PRINT("    Secure: %s\n", cookie.secure ? "True" : "False");
	PRINT("    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

	PRINT("\n");
}

void PrintValuesChrome(CanonicalCookieChrome cookie, udmpparser::UserDumpParser& dump) {
	PRINT("    Name: ");
	ReadString(dump, cookie.name);
	PRINT("    Value: ");
	ReadVector(dump, cookie.value.maybe_encrypted_data_, cookie.value.original_size_);
	PRINT("    Domain: ");
	ReadString(dump, cookie.domain);
	PRINT("    Path: ");
	ReadString(dump, cookie.path);
	PRINT("    Creation time: ");
	PrintTimeStamp(cookie.creation_date);
	PRINT("    Expiration time: ");
	PrintTimeStamp(cookie.expiry_date);
	PRINT("    Last accessed: ");
	PrintTimeStamp(cookie.last_access_date);
	PRINT("    Last updated: ");
	PrintTimeStamp(cookie.last_update_date);
	PRINT("    Secure: %s\n", cookie.secure ? "True" : "False");
	PRINT("    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

	PRINT("\n");
}

void PrintValuesChrome(CanonicalCookieChrome130 cookie, udmpparser::UserDumpParser& dump) {
	PRINT("    Name: ");
	ReadString(dump, cookie.name);
	PRINT("    Value: ");
	ReadString(dump, cookie.value);
	PRINT("    Domain: ");
	ReadString(dump, cookie.domain);
	PRINT("    Path: ");
	ReadString(dump, cookie.path);
	PRINT("    Creation time: ");
	PrintTimeStamp(cookie.creation_date);
	PRINT("    Expiration time: ");
	PrintTimeStamp(cookie.expiry_date);
	PRINT("    Last accessed: ");
	PrintTimeStamp(cookie.last_access_date);
	PRINT("    Last updated: ");
	PrintTimeStamp(cookie.last_update_date);
	PRINT("    Secure: %s\n", cookie.secure ? "True" : "False");
	PRINT("    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

	PRINT("\n");
}

void PrintValuesChrome(CanonicalCookie124 cookie, udmpparser::UserDumpParser& dump) {
	PRINT("    Name: ");
	ReadString(dump, cookie.name);
	PRINT("    Value: ");
	ReadString(dump, cookie.value);
	PRINT("    Domain: ");
	ReadString(dump, cookie.domain);
	PRINT("    Path: ");
	ReadString(dump, cookie.path);
	PRINT("    Creation time: ");
	PrintTimeStamp(cookie.creation_date);
	PRINT("    Expiration time: ");
	PrintTimeStamp(cookie.expiry_date);
	PRINT("    Last accessed: ");
	PrintTimeStamp(cookie.last_access_date);
	PRINT("    Last updated: ");
	PrintTimeStamp(cookie.last_update_date);
	PRINT("    Secure: %s\n", cookie.secure ? "True" : "False");
	PRINT("    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

	PRINT("\n");
}

void PrintValuesOld(CanonicalCookieOld cookie, udmpparser::UserDumpParser& dump) {
	PRINT("    Name: ");
	ReadString(dump, cookie.name);
	PRINT("    Value: ");
	ReadString(dump, cookie.value);
	PRINT("    Domain: ");
	ReadString(dump, cookie.domain);
	PRINT("    Path: ");
	ReadString(dump, cookie.path);
	PRINT("    Creation time: ");
	PrintTimeStamp(cookie.creation_date);
	PRINT("    Expiration time: ");
	PrintTimeStamp(cookie.expiry_date);
	PRINT("    Last accessed: ");
	PrintTimeStamp(cookie.last_access_date);
	PRINT("    Last updated: ");
	PrintTimeStamp(cookie.last_update_date);

	PRINT("\n");
}

void ProcessNodeValue(udmpparser::UserDumpParser& dump, uintptr_t Valueaddr, TargetVersion targetConfig) {

	if (targetConfig == Chrome) {
		CanonicalCookieChrome cookie = { 0 };
		if (!ReadDumpMemory(dump, Valueaddr, &cookie, sizeof(CanonicalCookieChrome))) {
			PrintErrorWithMessage(TEXT("Failed to read cookie struct"));
			return;
		}
		PrintValuesChrome(cookie, dump);

	}
	else if (targetConfig == Edge) {
		CanonicalCookieEdge cookie = { 0 };
		if (!ReadDumpMemory(dump, Valueaddr, &cookie, sizeof(CanonicalCookieEdge))) {
			PrintErrorWithMessage(TEXT("Failed to read cookie struct"));
			return;
		}
		PrintValuesEdge(cookie, dump);
	}
	else if (targetConfig == OldChrome) {
		CanonicalCookieOld cookie = { 0 };
		if (!ReadDumpMemory(dump, Valueaddr, &cookie, sizeof(CanonicalCookieOld))) {
			PrintErrorWithMessage(TEXT("Failed to read cookie struct"));
			return;
		}
		PrintValuesOld(cookie, dump);
	}
	else if (targetConfig == Chrome124) {
		CanonicalCookie124 cookie = { 0 };
		if (!ReadDumpMemory(dump, Valueaddr, &cookie, sizeof(CanonicalCookie124))) {
			PrintErrorWithMessage(TEXT("Failed to read cookie struct"));
			return;
		}
		PrintValuesChrome(cookie, dump);
	}
	else {
		PRINT("[-] Could not read cookie values: Unknown configuration %d", targetConfig);
	}
}

void ProcessNode(udmpparser::UserDumpParser& dump, const Node& node, TargetVersion targetConfig) {
	// Process the current node
	printf("Cookie Key: ");
	ReadString(dump, node.key);

	ProcessNodeValue(dump, node.valueAddress, targetConfig);

	// Process the left child if it exists
	if (node.left != 0) {
		Node leftNode;
		if (ReadDumpMemory(dump, node.left, &leftNode, sizeof(Node)))
			ProcessNode(dump, leftNode, targetConfig);
		else
			printf("Error reading left node");
	}

	// Process the right child if it exists
	if (node.right != 0) {
		Node rightNode;
		if (ReadDumpMemory(dump, node.right, &rightNode, sizeof(Node)))
			ProcessNode(dump, rightNode, targetConfig);
		else
			printf("Error reading right node");
	}
}

void WalkCookieMap(udmpparser::UserDumpParser& dump, uintptr_t cookieMapAddress, TargetVersion targetConfig) {

	RootNode cookieMap;

	if (!ReadDumpMemory(dump, cookieMapAddress, &cookieMap, sizeof(RootNode))) {
		printf("[-] Failed to read the root node from address: 0x%p\n", (void*)cookieMapAddress);
		return;
	}

	if (cookieMap.size == 0) {
		printf("[*] This cookie map was empty\n\n");
		return;

	}
	printf("[*] Number of available cookies: %Iu\n\n", cookieMap.size);

	// Process the first node in the binary search tree
	Node firstNode;
	if (ReadDumpMemory(dump, cookieMap.firstNode, &firstNode, sizeof(Node)))
		ProcessNode(dump, firstNode, targetConfig);
	else
		printf("[-] Failed to read the first node from address: 0x%p\n", (void*)cookieMap.firstNode);

	printf("\n");
}