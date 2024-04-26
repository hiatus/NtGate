#pragma once

#include "api.h"
#include "gate.h"

#include <Windows.h>

#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#endif


static SYSCALL_INFO_TABLE SyscallInfoTable;


extern VOID SyscallPrepare(DWORD wSsn, PVOID pSyscallRet);
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

	if (InitSyscallInfo(&SyscallInfoTable.NtAllocateReserveObject, pLdrDataEntry->DllBase, pImageExportDirectory, 0x965bca26b5a701ae) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtAllocateReserveObject\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtAllocateReserveObject, SyscallInfoTable.NtAllocateReserveObject.dwSsn,
		SyscallInfoTable.NtAllocateReserveObject.pAddress, SyscallInfoTable.NtAllocateReserveObject.pSyscallRet
	);
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

	if (InitSyscallInfo(&SyscallInfoTable.NtCreateProcessEx, pLdrDataEntry->DllBase, pImageExportDirectory, 0x006c2f481ebe0bc6) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtCreateProcessEx\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtCreateProcessEx, SyscallInfoTable.NtCreateProcessEx.dwSsn,
		SyscallInfoTable.NtCreateProcessEx.pAddress, SyscallInfoTable.NtCreateProcessEx.pSyscallRet
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

	if (InitSyscallInfo(&SyscallInfoTable.NtOpenProcess, pLdrDataEntry->DllBase, pImageExportDirectory, 0x718cca1f5291f6e7) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtOpenProcess\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtOpenProcess, SyscallInfoTable.NtOpenProcess.dwSsn,
		SyscallInfoTable.NtOpenProcess.pAddress, SyscallInfoTable.NtOpenProcess.pSyscallRet
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

	if (InitSyscallInfo(&SyscallInfoTable.NtQueryInformationProcess, pLdrDataEntry->DllBase, pImageExportDirectory, 0xd902864579da8171) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtQueryInformationProcess\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtQueryInformationProcess, SyscallInfoTable.NtQueryInformationProcess.dwSsn,
		SyscallInfoTable.NtQueryInformationProcess.pAddress, SyscallInfoTable.NtQueryInformationProcess.pSyscallRet
	);
#endif

	if (InitSyscallInfo(&SyscallInfoTable.NtQueueApcThreadEx, pLdrDataEntry->DllBase, pImageExportDirectory, 0x5d25d3cc80a44184) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtQueueApcThreadEx\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtQueueApcThreadEx, SyscallInfoTable.NtQueueApcThreadEx.dwSsn,
		SyscallInfoTable.NtQueueApcThreadEx.pAddress, SyscallInfoTable.NtQueueApcThreadEx.pSyscallRet
	);
#endif

	if (InitSyscallInfo(&SyscallInfoTable.NtReadVirtualMemory, pLdrDataEntry->DllBase, pImageExportDirectory, 0x3a501544bfe708b2) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtReadVirtualMemory\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtReadVirtualMemory, SyscallInfoTable.NtReadVirtualMemory.dwSsn,
		SyscallInfoTable.NtReadVirtualMemory.pAddress, SyscallInfoTable.NtReadVirtualMemory.pSyscallRet
	);
#endif

	if (InitSyscallInfo(&SyscallInfoTable.NtResumeThread, pLdrDataEntry->DllBase, pImageExportDirectory, 0xa5073bcb80d0459f) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtResumeThread\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtResumeThread, SyscallInfoTable.NtResumeThread.dwSsn,
		SyscallInfoTable.NtResumeThread.pAddress, SyscallInfoTable.NtResumeThread.pSyscallRet
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

	if (InitSyscallInfo(&SyscallInfoTable.NtWriteVirtualMemory, pLdrDataEntry->DllBase, pImageExportDirectory, 0x68a3c2ba486f0741) < 0)
		return FALSE;

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = &SyscallInfoTable.NtWriteVirtualMemory\n"
		"\t.dwSsn       = 0x%02x\n"
		"\t.pAddress    = 0x%p\n"
		"\t.pSyscallRet = 0x%p\n\n",
		&SyscallInfoTable.NtWriteVirtualMemory, SyscallInfoTable.NtWriteVirtualMemory.dwSsn,
		SyscallInfoTable.NtWriteVirtualMemory.pAddress, SyscallInfoTable.NtWriteVirtualMemory.pSyscallRet
	);
#endif

	return TRUE;
}

NTSTATUS NtAllocateReserveObject(_Out_ PHANDLE MemoryReserveHandle, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ MEMORY_RESERVE_OBJECT_TYPE ObjectType)
{
	SyscallPrepare(SyscallInfoTable.NtAllocateReserveObject.dwSsn, SyscallInfoTable.NtAllocateReserveObject.pSyscallRet);
	return SyscallExec(MemoryReserveHandle, ObjectAttributes, ObjectType);
}

NTSTATUS NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect)
{
	SyscallPrepare(SyscallInfoTable.NtAllocateVirtualMemory.dwSsn, SyscallInfoTable.NtAllocateVirtualMemory.pSyscallRet);
	return SyscallExec(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtCreateProcessEx(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ParentProcess, _In_ ULONG Flags, _In_opt_ HANDLE SectionHandle, _In_opt_ HANDLE DebugPort, _In_opt_ HANDLE ExceptionPort, _In_ BOOLEAN InJob)
{
	SyscallPrepare(SyscallInfoTable.NtCreateProcessEx.dwSsn, SyscallInfoTable.NtCreateProcessEx.pSyscallRet);
	return SyscallExec(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob);
}

NTSTATUS NtCreateThreadEx(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle, _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags, _In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize, _In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList)
{
	SyscallPrepare(SyscallInfoTable.NtCreateThreadEx.dwSsn, (PVOID)SyscallInfoTable.NtCreateThreadEx.pSyscallRet);
	return SyscallExec(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NtOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK AccessMask, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId)
{
	SyscallPrepare(SyscallInfoTable.NtOpenProcess.dwSsn, SyscallInfoTable.NtOpenProcess.pSyscallRet);
	return SyscallExec(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
}

NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection)
{
	SyscallPrepare(SyscallInfoTable.NtProtectVirtualMemory.dwSsn, SyscallInfoTable.NtProtectVirtualMemory.pSyscallRet);
	return SyscallExec(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS NtQueryInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass, _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength)
{
	SyscallPrepare(SyscallInfoTable.NtProtectVirtualMemory.dwSsn, SyscallInfoTable.NtProtectVirtualMemory.pSyscallRet);
	return SyscallExec(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NtQueueApcThreadEx(_In_ HANDLE ThreadHandle, _In_ HANDLE UserApcReserveHandle, _In_ PPS_APC_ROUTINE ApcRoutine, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2, _In_opt_ PVOID SystemArgument3)
{
	SyscallPrepare(SyscallInfoTable.NtQueueApcThreadEx.dwSsn, SyscallInfoTable.NtQueueApcThreadEx.pSyscallRet);
	return SyscallExec(ThreadHandle, UserApcReserveHandle, ApcRoutine, SystemArgument1, SystemArgument2, SystemArgument3);
}

NTSTATUS NtReadVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _Out_ PVOID Buffer, _In_ ULONG NumberOfBytesToRead, _Out_opt_ PULONG NumberOfBytesReaded)
{
	SyscallPrepare(SyscallInfoTable.NtResumeThread.dwSsn, SyscallInfoTable.NtResumeThread.pSyscallRet);
	return SyscallExec(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}

NTSTATUS NtResumeThread(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG SuspendCount)
{
	SyscallPrepare(SyscallInfoTable.NtResumeThread.dwSsn, SyscallInfoTable.NtResumeThread.pSyscallRet);
	return SyscallExec(ThreadHandle, SuspendCount);
}

NTSTATUS NtWaitForSingleObject(_In_ HANDLE ObjectHandle, _In_ BOOLEAN Alertable OPTIONAL, _In_ PLARGE_INTEGER TimeOut)
{
	SyscallPrepare(SyscallInfoTable.NtWaitForSingleObject.dwSsn, (PVOID)SyscallInfoTable.NtWaitForSingleObject.pSyscallRet);
	return SyscallExec(ObjectHandle, Alertable, TimeOut);
}

NTSTATUS NtWriteVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ PVOID Buffer, _In_ ULONG NumberOfBytesToWrite, _Out_opt_ PULONG NumberOfBytesWritten)
{
	SyscallPrepare(SyscallInfoTable.NtWriteVirtualMemory.dwSsn, (PVOID)SyscallInfoTable.NtWriteVirtualMemory.pSyscallRet);
	return SyscallExec(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}