#pragma once

#include "gate.h"
#include <Windows.h>


// Available APIs
typedef struct {
	SYSCALL_INFO NtAllocateVirtualMemory;
	SYSCALL_INFO NtCreateThreadEx;
	SYSCALL_INFO NtProtectVirtualMemory;
	SYSCALL_INFO NtWaitForSingleObject;
} SYSCALL_INFO_TABLE;


BOOL InitApi(VOID);

NTSTATUS NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect);
NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection);
NTSTATUS NtCreateThreadEx(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle, _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags, _In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize, _In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList);
NTSTATUS NtWaitForSingleObject(_In_ HANDLE ObjectHandle, _In_ BOOLEAN Alertable OPTIONAL, _In_ PLARGE_INTEGER TimeOut);