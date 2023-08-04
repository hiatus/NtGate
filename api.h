#pragma once

#include "gate.h"
#include <Windows.h>


// Available APIs
typedef struct {
	SYSCALL_INFO NtAllocateVirtualMemory;
	SYSCALL_INFO NtCreateProcessEx;
	SYSCALL_INFO NtCreateThreadEx;
	SYSCALL_INFO NtOpenProcess;
	SYSCALL_INFO NtProtectVirtualMemory;
	SYSCALL_INFO NtQueueApcThreadEx;
	SYSCALL_INFO NtResumeThread;
	SYSCALL_INFO NtWaitForSingleObject;
	SYSCALL_INFO NtWriteVirtualMemory;
} SYSCALL_INFO_TABLE;


BOOL InitApi(VOID);

NTSTATUS NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect);
NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection);
NTSTATUS NtCreateProcessEx(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ParentProcess, _In_ ULONG Flags, _In_opt_ HANDLE SectionHandle, _In_opt_ HANDLE DebugPort, _In_opt_ HANDLE ExceptionPort, _In_ BOOLEAN InJob);
NTSTATUS NtCreateThreadEx(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle, _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags, _In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize, _In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList);
NTSTATUS NtOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK AccessMask, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId);
NTSTATUS NtQueueApcThreadEx(_In_ HANDLE ThreadHandle, _In_ USER_APC_OPTION UserApcOption, _In_ PPS_APC_ROUTINE ApcRoutine, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2, _In_opt_ PVOID SystemArgument3);
NTSTATUS NtWaitForSingleObject(_In_ HANDLE ObjectHandle, _In_ BOOLEAN Alertable OPTIONAL, _In_ PLARGE_INTEGER TimeOut);
NTSTATUS NtWriteVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ PVOID Buffer, _In_ ULONG NumberOfBytesToWrite, _Out_opt_ PULONG NumberOfBytesWritten);