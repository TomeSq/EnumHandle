// EnumHandle.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

#include <Windows.h>
#include <Winternl.h>
#include <psapi.h>

#include <vector>

#include "..\CommonFiles\EnsureCleanup.h"

#pragma comment(lib, "Psapi.Lib")

//プロセス名を出力する。
void PrintProcessName(DWORD pid) 
{
	DWORD cbNeeded;
	CEnsureCloseHandle hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (NULL != hProcess) {
		HMODULE hModule;
		if (::EnumProcessModulesEx(hProcess, &hModule, sizeof(HMODULE), &cbNeeded, LIST_MODULES_ALL)) {
			wchar_t moduleName[MAX_PATH] = { L'\0' };
			::GetModuleFileNameExW(hProcess, hModule, moduleName, _countof(moduleName));
			::wprintf(L"%s\n", moduleName);
		}
		hProcess.Cleanup();
	}
}

int main()
{
	BOOL isProcessGetEnd;
	DWORD cbNeeded;
	std::vector<DWORD> process(4096);

	//プロセス一覧を列挙
	isProcessGetEnd = TRUE;
	do {
		::EnumProcesses(&process[0], process.size()*sizeof(DWORD), &cbNeeded);
		if (cbNeeded/sizeof(DWORD) >= process.size()) {
			process.resize(process.size() * 2);
		} else {
			isProcessGetEnd = FALSE;
		}
	} while (isProcessGetEnd);

	//プロセス名を出力する
	int processNum = cbNeeded / sizeof(DWORD);
	for (int i = 0; i < processNum; i++) {
		PrintProcessName(process[i]);
	}


    return 0;
}

