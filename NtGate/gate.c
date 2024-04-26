#pragma once

#include "gate.h"
#include <Windows.h>

#define PREV -32
#define NEXT 32
#define MAX_NEIGHBOURS 500


static DWORD64 djb2(PBYTE str);
static PTEB RtlGetThreadEnvironmentBlock(VOID);


DWORD InitSyscallInfo(_Out_ PSYSCALL_INFO pSyscallInfo, _In_ PVOID pModuleBase, _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD64 dwHash)
{
	BYTE low, high;

	PDWORD pdwFunctions;
	PDWORD pdwNames;
	PWORD pwNameOrdinals;

	PCHAR pcName = NULL;
	PVOID pAddress = NULL;

	ULONG_PTR ulpAddress;

	pSyscallInfo->dwSsn = -1;
	pSyscallInfo->pAddress = NULL;
	pSyscallInfo->pSyscallRet = NULL;

	pdwFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	pdwNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	pwNameOrdinals = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
		pcName = (PCHAR)((PBYTE)pModuleBase + pdwNames[i]);
		pAddress = (PBYTE)pModuleBase + pdwFunctions[pwNameOrdinals[i]];

		if (djb2((PBYTE)pcName) != dwHash)
			continue;

		/*
			Handle non-hooked functions

			mov r10, rcx
			mov rax, <ssn>
		*/
		if (*((PBYTE)pAddress + 0) == 0x4c && *((PBYTE)pAddress + 1) == 0x8b && *((PBYTE)pAddress + 2) == 0xd1 &&
			*((PBYTE)pAddress + 3) == 0xb8 && *((PBYTE)pAddress + 6) == 0x00 && *((PBYTE)pAddress + 7) == 0x00) {

			high = *((PBYTE)pAddress + 5);
			low = *((PBYTE)pAddress + 4);

			pSyscallInfo->pAddress = pAddress;
			pSyscallInfo->dwSsn = (high << 8) | low;

			break;
		}

		/*
			Handle hooked functions

			jmp <edr.dll>
			; or
			mov r10, rcx
			jmp <edr.dll>
		*/
		if (*((PBYTE)pAddress) != 0xe9 && *((PBYTE)pAddress + 3) != 0xe9)
			continue;

		// Derive SSN from neighbour syscalls
		for (WORD idx = 1; idx <= MAX_NEIGHBOURS; idx++) {
			if (*((PBYTE)pAddress + 0 + idx * NEXT) == 0x4c && *((PBYTE)pAddress + 1 + idx * NEXT) == 0x8b &&
				*((PBYTE)pAddress + 2 + idx * NEXT) == 0xd1 && *((PBYTE)pAddress + 3 + idx * NEXT) == 0xb8 &&
				*((PBYTE)pAddress + 6 + idx * NEXT) == 0x00 && *((PBYTE)pAddress + 7 + idx * NEXT) == 0x00) {

				high = *((PBYTE)pAddress + 5 + idx * NEXT);
				low = *((PBYTE)pAddress + 4 + idx * NEXT);

				pSyscallInfo->pAddress = pAddress;
				pSyscallInfo->dwSsn = (high << 8) | low - idx;

				break;
			}

			if (*((PBYTE)pAddress + 0 + idx * PREV) == 0x4c && *((PBYTE)pAddress + 1 + idx * PREV) == 0x8b &&
				*((PBYTE)pAddress + 2 + idx * PREV) == 0xd1 && *((PBYTE)pAddress + 3 + idx * PREV) == 0xb8 &&
				*((PBYTE)pAddress + 6 + idx * PREV) == 0x00 && *((PBYTE)pAddress + 7 + idx * PREV) == 0x00) {

				high = *((PBYTE)pAddress + 5 + idx * PREV);
				low = *((PBYTE)pAddress + 4 + idx * PREV);

				pSyscallInfo->pAddress = pAddress;
				pSyscallInfo->dwSsn = (high << 8) | low + idx;

				break;
			}
		}
	}

	if (pSyscallInfo->dwSsn < 0)
		return pSyscallInfo->dwSsn;

	ulpAddress = (ULONG_PTR)pSyscallInfo->pAddress + 0x40;

	for (DWORD i = 0, j = 1; i <= 512; i++, j++) {
		if (*((PBYTE)ulpAddress + i) == 0x0f && *((PBYTE)ulpAddress + j) == 0x05) {
			pSyscallInfo->pSyscallRet = (PVOID)((ULONG_PTR)ulpAddress + i);
			break;
		}
	}

	if (!pSyscallInfo->pSyscallRet) {
		pSyscallInfo->pAddress = NULL;
		pSyscallInfo->pSyscallRet = NULL;

		return (pSyscallInfo->dwSsn = -1);
	}

	return pSyscallInfo->dwSsn;
}

DWORD64 djb2(PBYTE str)
{
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

static PTEB RtlGetThreadEnvironmentBlock(VOID)
{
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}