# NtGate
Transparently call Nt* API functions using Halo's Gate and indirect syscalls. This code builds
around the original Hell's Gate implementation and it's successors and aims to abstract away it's
internals to provide a transparent interface to some commonly used NTAPI functions. PoC included in
main.c.

## Included Nt* Functions
- NtAllocateReserveObject
- NtAllocateVirtualMemory
- NtCreateProcessEx
- NtCreateThreadEx
- NtOpenProcess
- NtProtectVirtualMemory
- NtQueueApcThreadEx
- NtReadVirtualMemory
- NtResumeThread
- NtWaitForSingleObject
- NtWriteVirtualMemory