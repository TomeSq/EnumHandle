// EnumHandle.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

#include <Ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <Winternl.h>
#include <psapi.h>

#include <vector>
#include <memory>

#include "..\CommonFiles\EnsureCleanup.h"

#pragma comment(lib, "Psapi.Lib")
#pragma comment(lib, "ntdll.Lib")


#define SystemHandleInformation 16
#define ObjectNameInformation 1
//#define ObjectNameInformation 1


typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;


typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);


typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return ::GetProcAddress(::GetModuleHandleA(LibraryName), ProcName);
}


_NtQuerySystemInformation ApiNtQuerySystemInformation;
_NtDuplicateObject ApiNtDuplicateObject;
_NtQueryObject ApiNtQueryObject;


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
			::wprintf(L"■%s\n", moduleName);
		}
		hProcess.Cleanup();
	}
}

void PrintHandle(DWORD pid) 
{
	CEnsureCloseHandle hProcess = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
	if (NULL == hProcess) {
		::wprintf(L"Could not open PID %d! (Don't try to open a system process.)\n", pid);
		return;
	}

	//該当プロセスの状態を取得
	NTSTATUS status;
	ULONG returnLength = 4096;
	std::unique_ptr<char> pHandleBuf(new char[returnLength]);
	while((status = ::NtQuerySystemInformation(
				(SYSTEM_INFORMATION_CLASS)SystemHandleInformation, 
				pHandleBuf.get(), 
				returnLength, 
				&returnLength)) == STATUS_INFO_LENGTH_MISMATCH) 
	{
		pHandleBuf.reset(new char[returnLength]);
	}

	if (!NT_SUCCESS(status)) {
		::wprintf(L"NtQuerySystemInformation failed![%ld]\n", pid);
		return;
	}

	SYSTEM_HANDLE_INFORMATION* pHandleInfo = (SYSTEM_HANDLE_INFORMATION*)pHandleBuf.get();
	for (ULONG i = 0; i < pHandleInfo->HandleCount; i++) 
	{
		SYSTEM_HANDLE *syshandle = &pHandleInfo->Handles[i];
		
		if (syshandle->ProcessId != pid) {
			continue;
		}

		//ハンドルを複製する
		HANDLE dupHandleTmp(NULL);
		status = ApiNtDuplicateObject(hProcess, (HANDLE)syshandle->Handle, ::GetCurrentProcess(), &dupHandleTmp, 0, 0, 0);
		if (!NT_SUCCESS(status)) {
			::wprintf(L"ZwDuplicateObject Error!\n");
			continue;
		}
		CEnsureCloseHandle dupHandle(dupHandleTmp);


		//以下のハンドルの場合は無視しないとハングしたりするので無視する。
		if ((syshandle->GrantedAccess == 0x0012019f)
			|| (syshandle->GrantedAccess == 0x001a019f)
			|| (syshandle->GrantedAccess == 0x00120189)
			|| (syshandle->GrantedAccess == 0x00120089)
			|| (syshandle->GrantedAccess == 0x00100000)) 
		{
			continue;
		}

		//オブジェクト情報の取得
		returnLength = 4096;
		std::unique_ptr<char> pObjectBuf(new char[returnLength]);
		while((status = ::NtQueryObject(
								dupHandle, 
								OBJECT_INFORMATION_CLASS::ObjectTypeInformation,
								pObjectBuf.get(), 
								returnLength, 
								&returnLength)) == STATUS_INFO_LENGTH_MISMATCH) 
		{
			pObjectBuf.reset(new char[returnLength]);
		}

		if (!NT_SUCCESS(status)) {
			::wprintf(L"NtQueryObject Error!\n");
			continue;
		}

		//オブジェクト名の取得
		returnLength = 4096;
		std::unique_ptr<char> pObjectNameBuf(new char[returnLength]);
		while ((status = ::NtQueryObject(
								dupHandle, 
								(OBJECT_INFORMATION_CLASS)ObjectNameInformation, 
								pObjectNameBuf.get(), 
								returnLength, 
								&returnLength) == STATUS_INFO_LENGTH_MISMATCH)) 
		{
			pObjectBuf.reset(new char[returnLength]);
		}

		UNICODE_STRING objectName = *(PUNICODE_STRING)pObjectNameBuf.get();
		if (objectName.Length) {
			::wprintf(L"%s\n", objectName.Buffer);
		}
	}


	hProcess.Cleanup();
}

int main()
{
	BOOL isProcessGetEnd;
	DWORD cbNeeded;
	std::vector<DWORD> process(4096);

	// DLLのメソッドをロードする
	ApiNtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	ApiNtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	ApiNtQueryObject = (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

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

	//ハンドル一覧を出力する
	int processNum = cbNeeded / sizeof(DWORD);
	for (int i = 0; i < processNum; i++) {
		PrintProcessName(process[i]);
		PrintHandle(process[i]);
	}


    return 0;
}

