# LID-001: AppArmor Bypass via eBPF Pathname Rewriting

**Vector:** BPF kprobe on `do_sys_openat2` + `bpf_probe_write_user`
**Target:** AppArmor (pathname-based MAC)
**Impact:** Transparent file access bypass with zero audit trace
**Requires:** Root / CAP_BPF + CAP_PERFMON

## Summary

A BPF kprobe attached to `do_sys_openat2` rewrites the filename in user memory before `copy_from_user`. Combined with a hard link (same inode, different path), AppArmor checks the rewritten path, grants access, and the process reads the denied file's content. No denial is ever generated.

## The Gap

The LSM framework assumes all security decisions flow through `call_int_hook`. eBPF kprobes execute before any LSM hook is consulted. The kprobe modifies the input to the security check, making the check's correctness irrelevant.

## PoC

See `src/bpf/lid.bpf.c` and `src/loader/lid_loader.c` in the project root. Run `scripts/run_demo.sh` for the full demonstration.

## Affected

- AppArmor (pathname-based) — **vulnerable**
- SELinux (inode-based) — not affected by path rewriting
- TOMOYO (pathname-based) — likely vulnerable
- Smack (label-based) — not affected
