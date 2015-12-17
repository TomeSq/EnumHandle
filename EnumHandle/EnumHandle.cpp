// EnumHandle.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

#include <Ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <Winternl.h>
#include <psapi.h>
#include <locale.h>

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



void NtStatusString(NTSTATUS code, std::vector<wchar_t>& message)
{
	LPVOID lpMessageBuffer;
	HMODULE Hand = LoadLibraryW(L"NTDLL.DLL");

	::FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_FROM_HMODULE |
		FORMAT_MESSAGE_MAX_WIDTH_MASK,
		Hand,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&lpMessageBuffer,
		0,
		NULL);

	size_t len = ::lstrlenW((LPCWSTR)lpMessageBuffer) + 1;
	message.resize(len);
	::wcscpy_s(&message[0], len, (LPCWSTR)lpMessageBuffer);

	// Free the buffer allocated by the system.
	LocalFree(lpMessageBuffer);
	FreeLibrary(Hand);
}

void PrintNtStatusErrorMessage(LPCWSTR message, NTSTATUS status, std::vector<std::unique_ptr<wchar_t[]>>* output)
{
	std::unique_ptr<wchar_t[]> str(new wchar_t[1024]);
	std::vector<wchar_t> ntstatusMsg;
	NtStatusString(status, ntstatusMsg);
//	::wprintf(L"%s[%#x]%s\n", message, status, &ntstatusMsg[0]);
	::swprintf_s(str.get(), 1024, L"%s[%#x]%s\n", message, status, &ntstatusMsg[0]);
//	output->push_back(std::make_unique<wchar_t[]>(str));
	output->push_back(std::move(str));
}


PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return ::GetProcAddress(::GetModuleHandleA(LibraryName), ProcName);
}


_NtQuerySystemInformation ApiNtQuerySystemInformation;
_NtDuplicateObject ApiNtDuplicateObject;
_NtQueryObject ApiNtQueryObject;


//プロセス名を出力する。
void PrintProcessName(DWORD pid, std::vector<std::unique_ptr<wchar_t[]>>* output)
{
	DWORD cbNeeded;
	CEnsureCloseHandle hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (NULL != hProcess) {
		HMODULE hModule;
		if (::EnumProcessModulesEx(hProcess, &hModule, sizeof(HMODULE), &cbNeeded, LIST_MODULES_ALL)) {
			std::unique_ptr<wchar_t[]> moduleName(new wchar_t[MAX_PATH]);
			::GetModuleFileNameExW(hProcess, hModule, moduleName.get(), MAX_PATH);
			::wcscat_s(moduleName.get(), MAX_PATH, L"\n");
			output->push_back(std::move(moduleName));
		}
		hProcess.Cleanup();
	}
}

void PrintHandle(DWORD pid, std::vector<std::unique_ptr<wchar_t[]>>* output)
{
	CEnsureCloseHandle hProcess = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
	if (NULL == hProcess) {
		//std::unique_ptr<wchar_t[]> message(new wchar_t[1024]);
		//::swprintf_s(message.get(), 1024, L"Could not open PID %d! (Don't try to open a system process.)\n", pid);
		//output->push_back(std::move(message));
		return;
	}

	//該当プロセスの状態を取得
	NTSTATUS status;
	ULONG returnLength = 4096;
	std::unique_ptr<char[]> pHandleBuf(new char[returnLength]);
	while((status = ::NtQuerySystemInformation(
				(SYSTEM_INFORMATION_CLASS)SystemHandleInformation, 
				pHandleBuf.get(), 
				returnLength, 
				&returnLength)) == STATUS_INFO_LENGTH_MISMATCH) 
	{
		pHandleBuf.reset(new char[returnLength]);
	}

	if (!NT_SUCCESS(status)) {
		//std::unique_ptr<wchar_t[]> message(new wchar_t[1024]);
		//::swprintf_s(message.get(), 1024, L"NtQuerySystemInformation failed![pid:%ld]", pid);
		//PrintNtStatusErrorMessage(message.get(), status, output);
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
			//std::unique_ptr<wchar_t[]> message(new wchar_t[1024]);
			//::swprintf_s(message.get(), 1024, L"NtDuplicateObject Error!(Handle:%#x)", syshandle->Handle);
			//PrintNtStatusErrorMessage(message.get(), status, output);
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
		std::unique_ptr<char[]> pObjectTypeBuf(new char[returnLength]);
		while((status = ::NtQueryObject(
								dupHandle, 
								OBJECT_INFORMATION_CLASS::ObjectTypeInformation,
								pObjectTypeBuf.get(),
								returnLength, 
								&returnLength)) == STATUS_INFO_LENGTH_MISMATCH) 
		{
			pObjectTypeBuf.reset(new char[returnLength]);
		}

		if (!NT_SUCCESS(status)) {
			//std::unique_ptr<wchar_t[]> message(new wchar_t[1024]);
			//::swprintf_s(message.get(), 1024, L"NtQueryObject ObjectTypeInformation Get Error!");
			//PrintNtStatusErrorMessage(message.get(), status, output);
			continue;
		}

		//オブジェクト名の取得
		returnLength = 4096;
		std::unique_ptr<char[]> pObjectNameBuf(new char[returnLength]);
		while ((status = ::NtQueryObject(
								dupHandle, 
								(OBJECT_INFORMATION_CLASS)ObjectNameInformation, 
								pObjectNameBuf.get(), 
								returnLength, 
								&returnLength) == STATUS_INFO_LENGTH_MISMATCH)) 
		{
			pObjectNameBuf.reset(new char[returnLength]);
		}

		if (!NT_SUCCESS(status)) {
			//std::unique_ptr<wchar_t[]> message(new wchar_t[1024]);
			//::swprintf_s(message.get(), 1024, L"NtQueryObject ObjectNameInformation Get Error!");
			//PrintNtStatusErrorMessage(message.get(), status, output);
			continue;
		}


		OBJECT_TYPE_INFORMATION *objectTypeInfo = (OBJECT_TYPE_INFORMATION*)pObjectTypeBuf.get();
		UNICODE_STRING objectName = *(PUNICODE_STRING)pObjectNameBuf.get();
		if (objectName.Length) {
			std::unique_ptr<wchar_t[]> message(new wchar_t[1024]);
			::swprintf_s(message.get(), 1024,
				L"[%#x] %.*s: %.*s\n",
				syshandle->Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer,
				objectName.Length / 2,
				objectName.Buffer
				);
			output->push_back(std::move(message));
		}
		else
		{
			/* Print something else. */
			std::unique_ptr<wchar_t[]> message(new wchar_t[1024]);
			::swprintf_s(message.get(), 1024,
				L"[%#x] %.*s: (unnamed)\n",
				syshandle->Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer
				);
			output->push_back(std::move(message));
		}

		dupHandle.Cleanup();
	}


	hProcess.Cleanup();
}

int wmain(int argc, wchar_t *argv[])
{
	::setlocale(LC_ALL, "JPN");

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

	std::vector<std::unique_ptr<wchar_t[]>> output;

	//ハンドル一覧を出力する
	int processNum = cbNeeded / sizeof(DWORD);
	for (int i = 0; i < processNum; i++) {
		PrintProcessName(process[i], &output);
		PrintHandle(process[i], &output);
	}

	for (auto it = output.begin(); it != output.end(); ++it)
	{
		::wprintf_s(L"%s", (*it).get());
	}

    return 0;
}

