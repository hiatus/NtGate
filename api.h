#pragma once

#include "gate.h"
#include <Windows.h>


// Available APIs
typedef struct {
	SYSCALL_INFO NtAllocateReserveObject;
	SYSCALL_INFO NtAllocateVirtualMemory;
	SYSCALL_INFO NtCreateProcessEx;
	SYSCALL_INFO NtCreateThreadEx;
	SYSCALL_INFO NtOpenProcess;
	SYSCALL_INFO NtProtectVirtualMemory;
	SYSCALL_INFO NtQueryInformationProcess;
	SYSCALL_INFO NtQueueApcThreadEx;
	SYSCALL_INFO NtReadVirtualMemory;
	SYSCALL_INFO NtResumeThread;
	SYSCALL_INFO NtWaitForSingleObject;
	SYSCALL_INFO NtWriteVirtualMemory;
} SYSCALL_INFO_TABLE;


BOOL InitApi(VOID);

NTSTATUS NtAllocateReserveObject(_Out_ PHANDLE MemoryReserveHandle, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ MEMORY_RESERVE_OBJECT_TYPE ObjectType);
NTSTATUS NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect);
NTSTATUS NtCreateProcessEx(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ParentProcess, _In_ ULONG Flags, _In_opt_ HANDLE SectionHandle, _In_opt_ HANDLE DebugPort, _In_opt_ HANDLE ExceptionPort, _In_ BOOLEAN InJob);
NTSTATUS NtCreateThreadEx(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle, _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags, _In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize, _In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList);
NTSTATUS NtOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK AccessMask, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId);
NTSTATUS NtQueryInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass, _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
NTSTATUS NtQueueApcThreadEx(_In_ HANDLE ThreadHandle, _In_ HANDLE UserApcReserveHandle, _In_ PPS_APC_ROUTINE ApcRoutine, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2, _In_opt_ PVOID SystemArgument3);
NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection);
NTSTATUS NtReadVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _Out_ PVOID Buffer, _In_ ULONG NumberOfBytesToRead, _Out_opt_ PULONG NumberOfBytesReaded);
NTSTATUS NtResumeThread(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG SuspendCount);
NTSTATUS NtWaitForSingleObject(_In_ HANDLE ObjectHandle, _In_ BOOLEAN Alertable OPTIONAL, _In_ PLARGE_INTEGER TimeOut);
NTSTATUS NtWriteVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ PVOID Buffer, _In_ ULONG NumberOfBytesToWrite, _Out_opt_ PULONG NumberOfBytesWritten);