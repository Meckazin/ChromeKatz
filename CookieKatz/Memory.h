#pragma once
#include <minwindef.h>
#include <cstdint>

enum TargetVersion {
	Chrome,
	Edge,
	Webview2,
	OldChrome,
	OldEdge,
	Chrome124,
	Chrome130,
	Edge130
};

#pragma region Structs

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

class Memory {
private:
	HANDLE hProcess = NULL;
	HANDLE hOutFile = NULL;
	TargetVersion targetConfig = Chrome;
    BOOL injected = false;

    void PrintAndDecrypt(BYTE* buf, DWORD dwSize, size_t origSize);
	BYTE* PatchBaseAddress(const BYTE* pattern, size_t patternSize, uintptr_t baseAddress);
	BOOL MyMemCmp(BYTE* source, const BYTE* searchPattern, size_t num);
	void ProcessNode(const Node& node);
	void ProcessNodeValue(uintptr_t Valueaddr);
	void PrintValuesOld(CanonicalCookieOld cookie);
	void PrintValuesChrome(CanonicalCookie124 cookie);
	void PrintValuesChrome(CanonicalCookieChrome130 cookie);
	void PrintValuesChrome(CanonicalCookieChrome cookie);
	void PrintValuesEdge(CanonicalCookieEdge cookie);
	void PrintValuesEdge(CanonicalCookieEdge130 cookie);
	void PrintTimeStamp(int64_t timeStamp);
	void ReadString(OptimizedString string);
	void ReadVector(RemoteVector vector, size_t origSize);

public:
	Memory(HANDLE hProcess, TargetVersion targetConfig, BOOL injected) {
		this->hProcess = hProcess;
		this->targetConfig = targetConfig;
        this->injected = injected;
	}
	Memory(HANDLE hProcess, TargetVersion targetConfig, BOOL injected, HANDLE hOutFile) {
		this->hProcess = hProcess;
		this->targetConfig = targetConfig;
		this->hOutFile = hOutFile;
        this->injected = injected;
	}

	void WalkCookieMap(uintptr_t cookieMapAddress);
	BOOL FindPattern(const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster);
	BOOL FindLargestSection(uintptr_t moduleAddr, uintptr_t& resultAddress);
	void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset);
};