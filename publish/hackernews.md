**Title:** Show HN: LID – Bypassing AppArmor via eBPF pathname rewriting, zero audit trace

**URL:** https://github.com/azqzazq1/LID

**Top comment:**

LID demonstrates an architectural gap between Linux's LSM framework and the eBPF subsystem.

The LSM framework correctly guarantees that security modules can only add restrictions — `call_int_hook` short-circuits on the first denial, so no module (including BPF LSM) can undo another's deny decision. That design is sound.

But eBPF kprobes operate outside the LSM framework. By attaching to `do_sys_openat2` and using `bpf_probe_write_user` to rewrite the filename in user memory before the kernel copies it, you can change what AppArmor sees. AppArmor checks the rewritten path (pointing to a hard link), grants access, and the process reads the protected file. No denial is ever generated.

Requires root/CAP_BPF. Only affects pathname-based MACs (AppArmor, not SELinux). Full technical writeup in the repo.

Companion to SunnyDayBPF (https://github.com/azqzazq1/SunnyDayBPF) — that one manipulates post-syscall telemetry. This one manipulates pre-check arguments. Different timing, same eBPF foundation.
