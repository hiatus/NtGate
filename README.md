# NtGate
Transparently call Nt* API functions using Halo's Gate and indirect syscalls. This code builds
around the original Hell's Gate implementation and it's successors and aims to abstract away it's
internals to provide a transparent interface to some commonly used NTAPI functions. PoC included in
main.c.

## Included Nt* Functions
- NtAllocateVirtualMemory
- NtProtectVirtualMemory
- NtCreateThreadEx
- NtWaitForSingleObject

## References
- [HellsGate](https://github.com/am0nsec/HellsGate) by [@am0nsec](https://github.com/am0nsec) and @RtlMateusz.
- [HalosGate](https://blog.sektor7.net/#!res/2021/halosgate.md) by Reenz0h from Sektor7.
