
<p align="center">
<br>

```
  ██╗     ██╗██████╗ 
  ██║     ██║██╔══██╗
  ██║     ██║██║  ██║
  ██║     ██║██║  ██║
  ███████╗██║██████╔╝
  ╚══════╝╚═╝╚═════╝ 
```

</p>

<h3 align="center">Linux Integrity Drift</h3>
<p align="center"><i>— "Linux is Dying" —</i></p>

<br>

<p align="center">
  <img src="https://img.shields.io/badge/Linux-5.18+-0078D4?style=for-the-badge&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/LSM-BYPASSED-DC3545?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Findings-4_Vectors-F36D00?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Audit_Log-INVISIBLE-000000?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <a href="https://doi.org/10.5281/zenodo.20257645"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.20257645.svg" height="28" /></a>
</p>

<p align="center">
  <b>Systematic discovery of kernel code paths that bypass LSM security guarantees</b><br>
  <sub>The gate was never breached. It was walked around.</sub>
</p>

---

<br>

## What is LID?

The Linux Security Module framework has one core guarantee that has held for **20+ years**:

> *Security modules can only **add** restrictions. They can never **remove** them.*

This guarantee is correct. LID doesn't break it.

**LID finds kernel code paths that bypass LSM hooks entirely** — subsystems that perform security-sensitive operations without consulting the LSM framework. The security check is correct. The problem is that the kernel never asks.

<br>

## Understanding What LID Is (and Isn't)

Each finding has two distinct dimensions that should not be conflated:

### A) Policy Visibility Gap

The architectural blind spot. The question is not "can an attacker exploit this?" but:

- What does AppArmor/SELinux actually **see**?
- What does the audit log **record**?
- What does your SIEM/EDR **observe**?
- What does the policy engine **think** happened?

If a security-sensitive operation occurs and the enforcement layer never even evaluates it, you have a visibility gap — regardless of whether an attacker can practically abuse it today. This matters for **compliance**, **forensics**, and **defense-in-depth assumptions**.

### B) Practical Escalation Path

The real-world exploitability question:

- Does this cross a privilege boundary?
- Does an attacker need existing root/CAP_BPF to trigger it?
- Is an exploit chain required, or is it standalone?
- What is the actual impact — data access, privilege escalation, policy evasion?

**These two things are different.** A finding can be a critical visibility gap (your monitoring is blind) without being a practical privilege escalation (attacker already needs root). Conversely, a finding can be a direct escalation path with minimal prerequisites.

| Finding | Visibility Gap | Practical Escalation |
|:---|:---|:---|
| **LID-001** | **Critical** — AppArmor sees nothing, audit log empty, zero forensic trace | **Limited** — requires root or CAP_BPF+CAP_PERFMON (already privileged). Not a privilege escalation. Impact: policy evasion + audit blindness. |
| **LID-002** | **High** — `security_file_receive()` never fires, fd transfer invisible to all LSMs | **High** — works from **unprivileged** userspace via io_uring. Crosses LSM enforcement boundary without any privilege. |
| **LID-003** | **High** — `security_sb_mount()` bypassed, AppArmor mount policy is dead code | **Medium** — requires mount namespace access (CAP_SYS_ADMIN in user ns). Available in many container configs. |
| **LID-004** | **Critical** — AppArmor sees nothing, zero BPF hooks (0/9), no audit trace for any BPF token operation | **Medium** — requires bpffs delegation by host + CAP_BPF in user namespace. Available in container runtimes with BPF delegation (LXD/Incus). |

<br>

## Reproducibility Matrix

Each finding has specific kernel/config/privilege requirements. **If your environment doesn't match, the finding will not reproduce.**

### LID-001: eBPF Pathname Rewriting

| Condition | Required | Notes |
|:---|:---|:---|
| Kernel version | 5.x+ | Tested on 5.15, 6.1, 6.6, 6.8 |
| `CONFIG_BPF_SYSCALL` | `=y` | Default on all major distros |
| `CONFIG_BPF_KPROBE_OVERRIDE` | `=y` | Ubuntu/Debian enable it, **RHEL does not** |
| `CONFIG_SECURITY_APPARMOR` | `=y` | Target LSM must be AppArmor |
| AppArmor profile | Enforcing, deny rule on target path | Works with any path-based deny rule |
| Privileges | `root` or `CAP_BPF` + `CAP_PERFMON` | **Cannot run unprivileged** |
| `kernel.lockdown` | `none` or `integrity` | `confidentiality` mode blocks kprobe attach |
| `kernel.unprivileged_bpf_disabled` | Irrelevant | Requires CAP_BPF regardless |
| `fs.protected_hardlinks` | `0` for cross-user links | `1` (default) still allows same-user hard links |
| SELinux instead of AppArmor | **Does not work** | SELinux is inode-based, not pathname-based |

### LID-002: io_uring MSG_RING

| Condition | Required | Notes |
|:---|:---|:---|
| Kernel version | 6.0+ | `IORING_MSG_SEND_FD` added in 6.0 |
| `CONFIG_IO_URING` | `=y` | Default on all major distros |
| Privileges | **None** | Works from unprivileged userspace |
| `io_uring_disabled` sysctl | `0` (default) | `2` blocks unprivileged, `1` blocks all |
| Target LSM | Any (SELinux, AppArmor, Smack) | `security_file_receive()` is a generic LSM hook |
| `kernel.lockdown` | Irrelevant | No BPF involved |

### LID-004: BPF Token AppArmor Blindness

| Condition | Required | Notes |
|:---|:---|:---|
| Kernel version | 6.9+ | BPF token introduced in 6.9 |
| `CONFIG_BPF_SYSCALL` | `=y` | Default on all major distros |
| `CONFIG_SECURITY_APPARMOR` | `=y` | Ubuntu/Debian default |
| bpffs with delegation | Yes | Host must mount with `delegate_*` options |
| Privileges | CAP_BPF in user namespace | Trivially available to userns root |
| SELinux instead of AppArmor | **Not affected** | SELinux implements all 9 BPF hooks |

### LID-003: New Mount API

| Condition | Required | Notes |
|:---|:---|:---|
| Kernel version | 5.2+ | `fsopen`/`fsmount` introduced in 5.2 |
| `CONFIG_SECURITY_APPARMOR` | `=y` | Only AppArmor is affected |
| Privileges | `CAP_SYS_ADMIN` in user namespace | Available with `unshare -m` |
| SELinux instead of AppArmor | **Does not work** | SELinux implements `security_sb_kern_mount()` |
| Container runtime | Depends on seccomp filter | Docker default seccomp blocks `fsopen` — Podman/LXC may not |

### Quick Reference: What Blocks Each Finding

| Environment | LID-001 | LID-002 | LID-003 | LID-004 |
|:---|:---|:---|:---|:---|
| Ubuntu 22.04+ (AppArmor, default) | **Works** | **Works** | **Works** | **Works** (6.9+) |
| Debian 12+ (AppArmor) | **Works** | **Works** | **Works** | **Works** (6.9+) |
| RHEL/Fedora (SELinux) | No | **Works** | No | No |
| `lockdown=confidentiality` | No | **Works** | **Works** | Partially |
| Unprivileged user | No | **Works** | Depends on user ns | Depends on bpffs delegation |
| Container (no CAP_BPF) | No | Depends on io_uring | Depends on seccomp | No |

<br>

## Findings

| ID | Vector | Target | What Happens |
|:---|:---|:---|:---|
| [**LID-001**](findings/lid-001-ebpf-pathname/) | eBPF kprobe pathname rewriting | AppArmor | kprobe rewrites filename before `copy_from_user` → AppArmor checks wrong path |
| [**LID-002**](findings/lid-002-iouring-msgring/) | io_uring MSG_RING SEND_FD | SELinux, AppArmor, Smack | fd transfer skips `security_file_receive()` — every other fd transfer calls it |
| [**LID-003**](findings/lid-003-mount-api/) | New mount API (fsopen/fsmount) | AppArmor | `security_sb_mount()` never called — AppArmor's only mount hook bypassed |
| [**LID-004**](findings/lid-004-bpf-token/) | BPF token delegation | AppArmor, Smack | Zero BPF hooks — token creation, usage, capability delegation completely invisible |

<br>

## The Pattern

Every finding follows the same pattern:

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    THE LID PATTERN                          │
  │                                                             │
  │   Kernel Subsystem A               LSM Framework            │
  │   (eBPF / io_uring / mount API)    (AppArmor / SELinux)     │
  │                                                             │
  │   ┌───────────────────┐                                     │
  │   │ Performs operation │──── should call ──── security_*()   │
  │   │ or manipulates    │          but                        │
  │   │ security input    │     DOESN'T  ██                     │
  │   └───────────────────┘                                     │
  │                                                             │
  │   The LSM framework is correct.                             │
  │   The kernel just doesn't always use it.                    │
  └─────────────────────────────────────────────────────────────┘
```

Two kernel subsystems. Incompatible trust assumptions. One gap.

<br>

---

## LID-001: eBPF Pathname Rewriting

**The flagship finding.** A BPF kprobe on `do_sys_openat2` rewrites the filename in user memory before the kernel copies it. AppArmor checks the rewritten path, grants access. Zero audit trace.

```
  process: open("/tmp/secret.txt")
       │
       ▼
  do_sys_openat2()
       │
    ★ LID kprobe fires here
    │  bpf_probe_write_user()
    │  rewrites "/tmp/secret.txt" → "/tmp/.bypass_link"
       │
       ▼
  getname_flags()          ← kernel copies the (rewritten) path
       │
       ▼
  security_file_open()     ← LSM hooks check "/tmp/.bypass_link"
       │                      AppArmor: ALLOW ✓
       ▼
  VFS opens inode          ← same file content (hard link)
       │
       ▼
  return fd to process     ← success, zero audit trace
```

### Quick Start

```bash
sudo ./scripts/check_prerequisites.sh
sudo ./scripts/setup_env.sh
make
sudo ./scripts/setup_demo.sh
sudo ./scripts/run_demo.sh
```

### Demo Output

```
╔══════════════════════════════════════════════════════════╗
║  Phase 1: AppArmor ENFORCING — access should be DENIED   ║
╚══════════════════════════════════════════════════════════╝

  $ /tmp/test_reader
  [-] DENIED: open() failed: Permission denied (errno=13)

╔══════════════════════════════════════════════════════════╗
║  Phase 2: Loading LID — BPF kprobe pathname rewrite       ║
╚══════════════════════════════════════════════════════════╝

  [*] BPF kprobe attached to do_sys_openat2

╔══════════════════════════════════════════════════════════╗
║  Phase 3: With LID active — access should be GRANTED      ║
╚══════════════════════════════════════════════════════════╝

  $ /tmp/test_reader
  [+] SUCCESS: Read 44 bytes: SECRET_DATA=this_is_protected_content_12345

╔══════════════════════════════════════════════════════════╗
║  Phase 4: Stealth check — audit log inspection             ║
╚══════════════════════════════════════════════════════════╝

  $ dmesg | grep apparmor | grep DENIED
  (empty — no denial was ever generated)
```

<br>

---

## LID-002: io_uring MSG_RING Missing LSM Hook

`IORING_OP_MSG_RING` with `IORING_MSG_SEND_FD` transfers file descriptors between io_uring rings **without calling `security_file_receive()`**. Every other fd transfer mechanism calls it:

```
  MSG_RING SEND_FD:    __io_fixed_fd_install()  ← NO security_file_receive()
  FIXED_FD_INSTALL:    receive_fd()             ← security_file_receive() ✓
  SCM_RIGHTS:          receive_fd()             ← security_file_receive() ✓
  binder:              security_binder_transfer_file()                    ✓
```

**Bug location:** `io_uring/msg_ring.c`, `io_msg_install_complete()` — calls `__io_fixed_fd_install()` directly, skipping the LSM hook.

**Verified with ftrace:** `security_file_receive` fires for SCM_RIGHTS but not for MSG_RING.

**Affected:** Linux 5.18+ through v7.1-rc3 (unfixed as of 2026-05-17).

**PoC:** [`findings/lid-002-iouring-msgring/msg_ring_bypass.c`](findings/lid-002-iouring-msgring/)

<br>

---

## LID-003: New Mount API Bypasses AppArmor

The new mount API (`fsopen` + `fsconfig` + `fsmount` + `move_mount`) **never calls `security_sb_mount()`** — the only mount hook AppArmor implements.

```
  OLD API:  mount("proc", "/mnt", "proc", 0, NULL)
            → security_sb_mount()  → AppArmor: DENY ✗

  NEW API:  fsopen("proc") → fsconfig(CMD_CREATE) → fsmount() → move_mount()
            → security_sb_kern_mount()  → AppArmor: (not implemented) → ALLOW ✓
```

AppArmor registers **4** mount hooks. SELinux registers **14**. The new mount API uses hooks that only SELinux implements.

Additional gaps found:
- **`open_tree(OPEN_TREE_CLONE)`**: Zero security hooks — bypasses bind-mount policy
- **`mount_setattr()`**: No LSM hook exists in the kernel at all
- **`move_mount()` with detached mounts**: AppArmor sees NULL source path

**Details:** [`findings/lid-003-mount-api/`](findings/lid-003-mount-api/)

<br>

---

## LID-004: BPF Token — AppArmor Zero Coverage

The BPF token subsystem (Linux 6.9+) delegates BPF capabilities to unprivileged processes in user namespaces. The kernel defines **9 BPF LSM hooks**. SELinux implements all 9 with real `avc_has_perm()` enforcement. AppArmor implements **zero**.

```
  Kernel defines 9 BPF LSM hooks:
  ┌─────────────────────────────────────────────────────────────────┐
  │  bpf, bpf_map, bpf_prog, bpf_map_create, bpf_prog_load,      │
  │  bpf_token_create, bpf_token_free, bpf_token_cmd,             │
  │  bpf_token_capable                                             │
  └─────────────────────────────────────────────────────────────────┘

  SELinux:   ████████████████████████████  9/9 implemented
  AppArmor:                                0/9 implemented
  Smack:                                   0/9 implemented
```

On Ubuntu/Debian, a container with bpffs delegation can:
- Create BPF tokens → AppArmor sees nothing
- Use tokens to load tracing programs → AppArmor sees nothing
- Delegate CAP_PERFMON → disable Spectre mitigations → AppArmor sees nothing

**Details:** [`findings/lid-004-bpf-token/`](findings/lid-004-bpf-token/)

<br>

---

## Architecture: Why BPF LSM Can't Fix This

```
  LSM Hook Chain: call_int_hook(file_open, ...)

  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
  │  Lockdown    │──>│  Capability  │──>│   AppArmor   │──>│  BPF LSM    │
  │  return 0    │   │  return 0    │   │  return -13  │   │  (never     │
  │  (allow)     │   │  (allow)     │   │  (DENY) ██   │   │   reached)  │
  └─────────────┘   └─────────────┘   └──────┬───────┘   └─────────────┘
                                              │
                                         loop breaks
                                         RC = -EACCES

  ★ The LSM framework is correct. No module can undo another's denial.
  ★ LID operates OUTSIDE the framework — before hooks run, or where hooks don't exist.
```

<br>

## Companion: SunnyDayBPF

```
                   ┌───────────────────────────────────────┐
                   │          THE ATTACK TIMELINE           │
                   │                                       │
  Syscall Entry    │  ★ LID ─── manipulates input          │
       │           │     (security check sees wrong data)  │
       ▼           │                                       │
  LSM Check        │     LSM allows (or never runs) ✓      │
       │           │                                       │
       ▼           │                                       │
  Syscall Exit     │  ★ SunnyDayBPF ─── rewrites telemetry │
       │           │     (monitoring sees wrong data)      │
       ▼           │                                       │
  Audit/Log        │     SIEM sees nothing ✓               │
                   │                                       │
                   │  Combined: ghost access                │
                   └───────────────────────────────────────┘
```

<br>

## Project Structure

```
LID/
├── src/
│   ├── bpf/
│   │   └── lid.bpf.c              # BPF kprobe — pathname rewriter (LID-001)
│   └── loader/
│       └── lid_loader.c           # Userspace loader + event monitor
├── findings/
│   ├── lid-001-ebpf-pathname/     # eBPF pathname rewriting bypass
│   ├── lid-002-iouring-msgring/   # io_uring MSG_RING missing LSM hook
│   │   ├── msg_ring_bypass.c      # PoC with ftrace verification
│   │   └── ADVISORY.md            # Technical advisory
│   ├── lid-003-mount-api/         # New mount API AppArmor bypass
│   └── lid-004-bpf-token/        # BPF token AppArmor/Smack zero coverage
├── tests/
│   └── test_reader.c              # Victim binary for LID-001 demo
├── scripts/
│   ├── check_prerequisites.sh     # Verify system requirements
│   ├── setup_env.sh               # Install build dependencies
│   ├── setup_demo.sh              # Create demo environment
│   ├── run_demo.sh                # Run full LID-001 demonstration
│   └── teardown.sh                # Clean up everything
├── docs/
│   └── RESEARCH.md                # Full technical research paper
├── publish/                       # Articles for Medium, dev.to, etc.
├── Makefile
├── LICENSE
├── SECURITY.md
└── README.md
```

<br>

## Stealth Profile (LID-001)

| Indicator | Visibility | Notes |
|:---|:---|:---|
| AppArmor audit log | **Nothing** | Denial never occurs |
| `auditd` / `journald` | **Nothing** | No security event generated |
| `dmesg` | One-time warning | Generic `bpf_probe_write_user` message |
| `bpftool prog list` | Visible | Shows attached kprobe (if checked) |
| Hard link on disk | Detectable | `find -samefile` (slow, noisy) |

<br>

## Mitigations

| Mitigation | Effectiveness | Tradeoff |
|:---|:---|:---|
| `kernel.lockdown=confidentiality` | Blocks BPF entirely | Kills legitimate monitoring |
| Disable `bpf_probe_write_user` | Prevents LID-001 path rewrite | Requires kernel rebuild |
| `fs.protected_hardlinks=1` | Limits hard link creation | Default on modern kernels |
| Monitor `bpftool prog list` | Detects attached probes | Requires active polling |
| Migrate to SELinux | Inode-based, defeats path rewriting | Complex migration |
| Restrict io_uring | Blocks LID-002 | May break applications |

For detailed mitigation guidance, see [`docs/RESEARCH.md`](docs/RESEARCH.md).

<br>

## Requirements

See the [Reproducibility Matrix](#reproducibility-matrix) for full per-finding details. Summary:

| Finding | Min Kernel | Privileges | Target LSM |
|:---|:---|:---|:---|
| LID-001 | 5.x+ | root / CAP_BPF+CAP_PERFMON | AppArmor only |
| LID-002 | 6.0+ | **None** | Any (SELinux, AppArmor, Smack) |
| LID-003 | 5.2+ | CAP_SYS_ADMIN (user ns ok) | AppArmor only |
| LID-004 | 6.9+ | CAP_BPF (user ns ok) | AppArmor, Smack |

<br>

## Author

<table>
<tr>
<td>

**Azizcan Daştan**  
Milenium Security

- GitHub: [@azqzazq1](https://github.com/azqzazq1)


</td>
</tr>
</table>

<br>

## Disclaimer

This tool is published for **authorized security testing, research, and educational purposes only.** Do not use against systems you do not own or have explicit written permission to test.

---

<p align="center">
  <b>LID</b> — because the integrity was never locked.
</p>
