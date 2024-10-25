#include <Windows.h>

#include "Helper.h"
#include <stdio.h>

#define MAX_NAME 256

BOOL GetTokenUser(IN HANDLE hProcess) {

	HANDLE hToken = NULL;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		DEBUG_PRINT_ERROR_MESSAGE(L"GetTokenUser OpenProcessToken failed!");
		return FALSE;
	}

	PTOKEN_USER hTokenUser = { 0 };
	DWORD dwSize = 0;

	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize)) {
		DWORD dwError = GetLastError();
		if (dwError != ERROR_INSUFFICIENT_BUFFER) {
			DEBUG_PRINT_ERROR_MESSAGE(L"GetTokenUser GetTokenInformation querying buffer size failed!");
			return FALSE;
		}
	}

	hTokenUser = (PTOKEN_USER)malloc(dwSize);

	if (!GetTokenInformation(hToken, TokenUser, hTokenUser, dwSize, &dwSize)) {
		DEBUG_PRINT_ERROR_MESSAGE(L"GetTokenUser GetTokenInformation failed!");
		free(hTokenUser);
		return FALSE;
	}

	if (hTokenUser == NULL) {
		free(hTokenUser);
		return FALSE;
	}

	wchar_t* UserName = new wchar_t[MAX_NAME];
	UserName[0] = L'\0';
	wchar_t* DomainName = new wchar_t[MAX_NAME];
	DomainName[0] = L'\0';

	DWORD dwMaxUserName = MAX_NAME;
	DWORD dwMaxDomainName = MAX_NAME;
	SID_NAME_USE SidUser = SidTypeUser;
	if (!LookupAccountSidW(NULL, hTokenUser->User.Sid, UserName, &dwMaxUserName, DomainName, &dwMaxDomainName, &SidUser)) {
		DEBUG_PRINT_ERROR_MESSAGE(L"GetTokenUser LookupAccountSidW failed!");
		free(hTokenUser);
		return FALSE;
	}

	PRINTW(DomainName);
	PRINTW(L"\\");
	PRINTW(UserName);

	free(hTokenUser);
	delete[] UserName;
	delete[] DomainName;
	return TRUE;
}