# NtGate
Transparently call Nt* API functions using Halo's Gate and indirect syscalls. This code builds
around the original Hell's Gate implementation and it's successors and aims to abstract away it's
internals to provide a transparent interface to some NTAPI functions commonly used during malware
development. A basic NtCreateThreadEx PoC is included in main.c.

## Included Nt* Functions
- NtAllocateReserveObject
- NtAllocateVirtualMemory
- NtCreateProcessEx
- NtCreateThreadEx
- NtOpenProcess
- NtProtectVirtualMemory
- NtQueryInformationProcess
- NtQueueApcThreadEx
- NtReadVirtualMemory
- NtResumeThread
- NtWaitForSingleObject
- NtWriteVirtualMemory

## References
This wouldn't be possible without the awesome work of some people.

- The original [Hell's Gate implementation](https://github.com/am0nsec/HellsGate) by [am0nsec](https://twitter.com/am0nsec) and [smelly__vx](https://twitter.com/smelly__vx).
- The [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) technique by Reenz0h from Sektor7.
