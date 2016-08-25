// stdafx.cpp : source file that includes just the standard includes
// TestIntelPt.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "stdafx.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file

// Get if a file Exist
bool FileExists(LPTSTR fileName) {
	HANDLE h = NULL;
	DWORD lastErr = 0;
	DWORD fileAttr = 0;

	// Get if file is an ADS
	LPTSTR slash = wcsrchr(fileName, L'\\');
	if (slash) slash++;
	else slash = fileName;
	LPTSTR colon = wcsrchr(slash, L':');
	if (colon) colon[0] = 0;
	fileAttr = GetFileAttributes(fileName);
	if (fileAttr == INVALID_FILE_ATTRIBUTES) fileAttr = 0;

	if ((fileAttr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
		// File is a directory
		return true;
	else
		// File is a file
		h = CreateFile(fileName, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	lastErr = GetLastError();

	if (colon) colon[0] = L':';

	if (h == INVALID_HANDLE_VALUE)
		return false;
	else {
		CloseHandle(h);
		return true;
	}
}

#pragma region Generic Environment Console functions
// Get Last Win32 Error description
LPTSTR GetWin32ErrorMessage(DWORD errNum) {
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf = NULL;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
	return (LPTSTR)lpMsgBuf;
}

// Read a line of input from a console
DWORD ReadLine(LPTSTR buff, int buffCch) {
	HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
	CONSOLE_READCONSOLE_CONTROL cControl = { 0 };
	DWORD dwCharRead = 0;
	cControl.nLength = sizeof(CONSOLE_READCONSOLE_CONTROL);
	cControl.dwCtrlWakeupMask = (ULONG)L'\n';
	ReadConsole(hConsole, buff, buffCch, &dwCharRead, &cControl);
	return dwCharRead;
}

void SetConsoleColor(ConsoleColor c){
	HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hCon, c);
}

// Color WPrintf 
void cl_wprintf(ConsoleColor c, LPTSTR string, LPVOID arg1, LPVOID arg2, LPVOID arg3, LPVOID arg4) {
	SetConsoleColor(c);
	wprintf(string, arg1, arg2, arg3, arg4);
	SetConsoleColor(GRAY);
}
#pragma endregion