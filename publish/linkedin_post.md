New Security Research: LID — Linux Integrity Drift

I've published original research demonstrating an architectural gap in the Linux kernel's security model.

The Linux Security Module (LSM) framework guarantees that security modules can only add restrictions — they cannot override each other's deny decisions. This guarantee has held for over 20 years, and it's correct.

But eBPF kprobes operate outside the LSM framework entirely.

LID attaches a BPF kprobe to the kernel's file-open path and rewrites the filename in user memory before any security module checks it. Combined with AppArmor's pathname-based access control model, this enables transparent file access bypass with zero audit log entries.

Key findings:
→ The BPF LSM framework cannot override other LSMs (by design — verified)
→ But kprobes can manipulate syscall arguments before LSM hooks run
→ AppArmor's pathname-based model is vulnerable to path rewriting + hard links
→ The bypass generates no security events — the denial never occurs

This is a companion to my earlier SunnyDayBPF research (post-syscall telemetry manipulation). LID operates pre-check; SunnyDayBPF operates post-check. Different timing, complementary effects.

The research includes a full PoC, technical paper, and automated demonstration scripts.

GitHub: https://github.com/azqzazq1/LID

#cybersecurity #linux #ebpf #kernelsecurity #redteam #securityresearch #apparmor #infosec
