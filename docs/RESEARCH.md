# BPF LSM Policy Override: Bypassing AppArmor via eBPF Pathname Rewriting

**Author:** Azizcan Daştan — Milenium Security  
**Date:** 2026-05-17  
**Kernel:** Linux 6.8.0-110-generic (Ubuntu 24.04)  
**Classification:** Original security research — offensive eBPF technique

---

## Abstract

This research demonstrates a novel technique to bypass AppArmor mandatory access control (MAC) policies using eBPF kprobe attachment and the `bpf_probe_write_user` helper. The attack exploits a fundamental architectural gap: while the Linux Security Module (LSM) framework prevents BPF LSM programs from overriding other LSMs' decisions through the `call_int_hook` iteration model, eBPF kprobes can attach directly to kernel functions in the VFS open path and manipulate syscall arguments *before* any LSM hook runs. Combined with AppArmor's pathname-based (not inode-based) access control model, this enables transparent, selective, and audit-invisible bypass of AppArmor deny rules.

**Key finding:** An attacker with `CAP_BPF` + `CAP_PERFMON` (or root) can selectively bypass AppArmor file access policies without triggering any audit log entries, and without disabling or modifying AppArmor itself.

---

## 1. Background

### 1.1 The LSM Hook Architecture

The Linux kernel's security module framework uses the `call_int_hook` macro (security/security.c) to iterate over registered LSM hooks:

```c
#define call_int_hook(FUNC, IRC, ...) ({
    int RC = IRC;
    do {
        struct security_hook_list *P;
        hlist_for_each_entry(P, &security_hook_heads.FUNC, list) {
            RC = P->hook.FUNC(__VA_ARGS__);
            if (RC != 0)
                break;    // short-circuits on first denial
        }
    } while (0);
    RC;
})
```

Critical properties:
- Hooks execute in registration order (boot-time via `hlist_add_tail_rcu`)
- The loop **short-circuits** on the first non-zero (deny) return
- This means LSMs can only ADD restrictions, never REMOVE them

### 1.2 BPF LSM Limitation

When `bpf` is in the LSM list, BPF programs attach to `bpf_lsm_*` stub functions via `fmod_ret` trampolines. These stubs participate in the `call_int_hook` iteration. However:

- If BPF runs **before** AppArmor: BPF returns 0 (allow), loop continues, AppArmor still denies
- If BPF runs **after** AppArmor: AppArmor denies, loop breaks, BPF never executes

**Conclusion:** The BPF LSM framework, by design, cannot override another LSM's deny decision. The security isolation holds at the LSM framework level.

### 1.3 The Gap

While the LSM framework is secure, eBPF's kprobe/fentry attachment mechanism operates **outside** the LSM framework entirely. A kprobe can attach to any non-inline kernel function and run code at function entry/exit. Combined with helpers like `bpf_probe_write_user`, this creates an attack surface that the LSM framework was not designed to defend against.

---

## 2. Attack Technique

### 2.1 Overview

The attack chains three components:

1. **Hard link creation**: Create a hard link to the target file at a path that AppArmor's policy allows
2. **kprobe attachment**: Attach a BPF kprobe to `do_sys_openat2` (the kernel's internal open handler)
3. **Pathname rewriting**: Use `bpf_probe_write_user` to modify the user-space filename buffer before the kernel copies it, redirecting the open from the denied path to the allowed hard link

### 2.2 Why This Works

AppArmor is a **pathname-based** MAC system. Unlike SELinux (which labels inodes), AppArmor makes access decisions based on the file path string. Two hard links to the same inode are treated as entirely different files by AppArmor policy.

A typical AppArmor profile:
```
/tmp/test_reader {
  #include <abstractions/base>
  /tmp/test_reader mr,
  deny /tmp/secret_test_file.txt rw,   # blocks this specific path
  /tmp/** r,                             # allows all other /tmp/ paths
}
```

The deny rule blocks `/tmp/secret_test_file.txt` but a hard link at `/tmp/.aa_bypass_link` (same inode) is matched by the permissive `/tmp/** r` rule.

### 2.3 Attack Flow

```
User Process                 Kernel (kprobe)              AppArmor
    |                            |                            |
    |-- open("/tmp/secret.txt") ->                            |
    |                     [BPF kprobe fires]                  |
    |                     [reads user buffer]                 |
    |                     [matches target path]               |
    |                     [bpf_probe_write_user:              |
    |                      overwrites with bypass path]       |
    |                            |                            |
    |                     [kernel copies path from user]      |
    |                     [VFS resolves "/tmp/.bypass"]       |
    |                            |-- check "/tmp/.bypass" --> |
    |                            |                     [ALLOW]|
    |                            |<-- return 0 --------------|
    |<-- fd (success) ----------|                            |
```

### 2.4 Prerequisites

| Requirement | Details |
|---|---|
| Capabilities | `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN` / root) |
| Kernel config | `CONFIG_BPF_KPROBE_OVERRIDE=y` (for `bpf_probe_write_user`) |
| Target path | Must be in writable user memory (stack/heap buffer, not .rodata literal) |
| Hard link | Attacker must be able to create a hard link to the target file |
| Same filesystem | Hard links only work within the same filesystem |

---

## 3. Proof of Concept

### 3.1 BPF Program (apparmor_bypass.bpf.c)

The BPF program attaches to `kprobe/do_sys_openat2` and:
1. Filters by process name (`test_reader`)
2. Reads the user-space filename via `bpf_probe_read_user_str`
3. Matches against the target path (`/tmp/secret_test_file.txt`)
4. Overwrites with the bypass path via `bpf_probe_write_user`
5. Logs the event to a ring buffer for monitoring

### 3.2 Demonstrated Results

```
▶ Without BPF — access DENIED
[*] Attempting to read /tmp/secret_test_file.txt
[-] DENIED: open() failed: Permission denied (errno=13)

▶ With BPF bypass — access GRANTED
[*] Attempting to read /tmp/secret_test_file.txt
[+] SUCCESS: Read 44 bytes: SECRET_DATA=this_is_protected_content_12345

▶ Audit log check
  NO AppArmor denials in audit log for the bypassed access!

▶ After BPF removed — access DENIED again
[-] DENIED: open() failed: Permission denied (errno=13)
```

The bypass is:
- **Selective**: Only targets specified process+path combinations
- **Transparent**: The process sees the original path but gets the file contents
- **Audit-invisible**: No AppArmor denial is logged because the denial never occurs
- **Reversible**: Removing the BPF program restores enforcement immediately

---

## 4. Analysis

### 4.1 Indicators of Compromise

| IoC | Detection Method | Reliability |
|---|---|---|
| `bpf_probe_write_user` dmesg warning | `dmesg \| grep bpf_probe_write` | One-time, generic message |
| kprobe attachment | `bpftool prog list` | Requires active check |
| Hard link to target file | `find / -samefile <target>` | Detectable but slow |
| BPF program in kernel | `/proc/*/fdinfo/*` for bpf fds | Requires active monitoring |

### 4.2 Limitations

1. **Writable user buffer required**: If the target process passes the filename as a string literal in `.rodata`, the page is read-only and `bpf_probe_write_user` fails. This excludes hardcoded constant paths but covers dynamically constructed paths (config files, user input, environment variables, `realpath()` results).

2. **Hard link requirement**: The attacker must create a hard link on the same filesystem. This fails for cross-filesystem scenarios, and some filesystems or mount options may restrict hard link creation.

3. **Path length constraint**: The bypass path must be ≤ the original path length (or the original buffer must have space) to avoid buffer overflow in user space.

4. **Single-file granularity**: Each bypass rule targets a specific path. Glob-based AppArmor rules (like `deny /secret/** rw`) require a bypass for each specific file.

### 4.3 Broader Implications

This technique reveals a design tension in the Linux security architecture:

- **LSM framework**: Correctly enforces that modules can only add restrictions
- **eBPF subsystem**: Provides unrestricted hook points that operate before LSM checks
- **Result**: An attacker with BPF capabilities can subvert the entire LSM security model without touching the LSM framework itself

This is not a bug in AppArmor or the LSM framework — it's an architectural gap where two kernel subsystems (security modules and eBPF tracing) have incompatible trust assumptions.

---

## 5. Mitigations

### 5.1 Kernel-level

1. **Restrict `bpf_probe_write_user`**: This helper is flagged as dangerous but still allowed. Consider disabling it entirely or restricting to specific program types.
2. **Lockdown mode**: `kernel.lockdown=integrity` or `confidentiality` restricts BPF, but also limits legitimate monitoring.
3. **BPF LSM self-protection**: Use a BPF LSM program to deny loading of kprobes on security-sensitive functions.

### 5.2 AppArmor-specific

1. **Restrict hard link creation**: AppArmor can control link creation with `deny link` rules.
2. **Use `protected_hardlinks` sysctl**: `fs.protected_hardlinks=1` (default in modern kernels) restricts hard link creation to owned files.

### 5.3 Detection

1. **Monitor `bpftool prog list`** for unexpected kprobe attachments
2. **Alert on `bpf_probe_write_user` dmesg warning**
3. **File integrity monitoring** on sensitive paths to detect hard link creation
4. **eBPF program auditing** via the `bpf()` syscall audit trail

---

## 6. Related Work

- **SunnyDayBPF** (Azizcan Daştan): eBPF post-syscall telemetry deception — manipulating audit data after security checks rather than before
- **ebpfkit** (Guillaume Fournier, Datadog): Offensive eBPF rootkit framework
- **bad-bpf** (pathtofile): Collection of offensive BPF programs
- **BPF LSM documentation** (kernel.org): Official BPF LSM implementation details

### Distinction from Prior Work

This research is the first to demonstrate:
1. **Pathname-level manipulation** before LSM checks (prior work focused on post-check manipulation or direct function override)
2. **Exploitation of the pathname-based vs. inode-based MAC gap** via BPF
3. **Systematic analysis of why BPF LSM cannot override other LSMs** and the alternative attack path through kprobes

---

## 7. Files

| File | Description |
|---|---|
| `apparmor_bypass.bpf.c` | BPF kprobe program — pathname rewriter |
| `loader.c` | Userspace loader with ring buffer event monitor |
| `vmlinux.h` | BTF-generated kernel type definitions |
| `Makefile` | Build system |

---

## License

This research is published for defensive security purposes. The techniques described should only be used in authorized security testing, research, and education contexts.
