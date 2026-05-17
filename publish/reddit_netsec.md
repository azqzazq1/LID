**Title:** LID — Bypassing AppArmor via eBPF pathname rewriting (pre-LSM syscall argument manipulation, zero audit trace)

**URL:** https://github.com/azqzazq1/LID

**Comment to post immediately after submission:**

I built a tool that bypasses AppArmor mandatory access control using eBPF — without disabling it and without generating any audit log entries.

**How it works:**

1. A BPF kprobe attaches to `do_sys_openat2` (kernel's internal open handler)
2. Before the kernel copies the filename from userspace, the kprobe rewrites it via `bpf_probe_write_user`
3. The rewritten path points to a hard link of the target file at an AppArmor-allowed path
4. AppArmor is pathname-based, so it checks the allowed path and grants access
5. The process reads the protected file content. No denial is generated. Audit log is empty.

**Why this is interesting:**

The LSM framework's `call_int_hook` correctly prevents BPF LSM from overriding other LSMs (short-circuits on first denial). So BPF LSM **cannot** undo an AppArmor deny — the framework is sound. But kprobes operate *outside* the LSM framework entirely and can manipulate syscall arguments before any LSM check runs.

This is an architectural gap between two kernel subsystems with incompatible trust assumptions, not a bug in either one.

**Requirements:** Root/CAP_BPF, CONFIG_BPF_KPROBE_OVERRIDE=y (Ubuntu default), writable user-space path buffer.

**Limitations:** Only works on pathname-based MACs (AppArmor, TOMOYO). SELinux is label/inode-based and isn't affected. Path must be in writable user memory (stack/heap, not .rodata).

Full research paper in the repo: [docs/RESEARCH.md](https://github.com/azqzazq1/LID/blob/main/docs/RESEARCH.md)

This is a companion to my earlier research [SunnyDayBPF](https://github.com/azqzazq1/SunnyDayBPF) which manipulates telemetry post-syscall. LID operates pre-check. Combined: bypass the gate + blind the cameras.

Happy to answer technical questions.
