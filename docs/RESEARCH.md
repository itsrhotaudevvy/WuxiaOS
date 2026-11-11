# Research and implementation rules

WuxiaOS uses primary documentation and research papers as design inputs, not as proof of security. Implementation claims must include executable tests or a precise statement of what remains unimplemented.

## Compatibility evidence

- Microsoft PE/COFF specification: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Microsoft, dispatch routines and IRQL: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/dispatch-routines-and-irqls
- Microsoft, WDF/WDF driver model and IRP documentation: https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/
- Microsoft, Windows syscall/ABI documentation: use the Windows SDK and relevant per-build documentation when adding a service table.

## Security and research

- OpenBSD pledge/unveil: https://www.openbsd.org/papers/BeckPledgeUnveilBSDCan2018.pdf
- OpenBSD W^X: https://www.openbsd.org/papers/hackfest2015-w-xor-x.pdf
- Microsoft Singularity sealed-process research: https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/EuroSys2007_SealedProcesses.pdf

Research informs design and testing; it does not make the resulting system bulletproof.
