
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
  <img src="https://img.shields.io/badge/Linux-6.8+-0078D4?style=for-the-badge&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/eBPF-kprobe-F36D00?style=for-the-badge" />
  <img src="https://img.shields.io/badge/AppArmor-BYPASSED-DC3545?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Audit_Log-INVISIBLE-000000?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<p align="center">
  <b>Bypassing AppArmor MAC policies via eBPF pathname rewriting</b><br>
  <sub>Before the kernel even asks for permission.</sub>
</p>

---

<br>

## The Problem

The Linux Security Module framework has one core guarantee that has held for **20+ years**:

> *Security modules can only **add** restrictions. They can never **remove** them.*

The `call_int_hook` macro enforces this — it iterates every LSM and **short-circuits on the first denial**:

```c
hlist_for_each_entry(P, &security_hook_heads.FUNC, list) {
    RC = P->hook.FUNC(__VA_ARGS__);
    if (RC != 0)
        break;    // first deny wins — game over
}
```

No LSM — including BPF LSM — can undo another module's decision. The framework is sound.

**LID doesn't break the framework. It doesn't even touch it.**

<br>

## The Technique

LID attaches a BPF kprobe to `do_sys_openat2` — the kernel's internal file-open handler. Before the kernel copies the filename from userspace, LID rewrites it in user memory. AppArmor then checks the **rewritten** path, not the original.

Combined with a hard link (same inode, different name), AppArmor sees an allowed path and grants access to the denied file's content.

```
                    ┌──────────────────────────────────────────────┐
                    │              KERNEL SPACE                     │
                    │                                              │
 ┌──────────┐      │  ┌────────────────────────────────────────┐  │
 │          │      │  │         do_sys_openat2                  │  │
 │  User    │ open │  │                                        │  │
 │  Process ├─────>│  │  ┌──────────────────────────────────┐  │  │
 │          │      │  │  │  ★ BPF KPROBE (LID)              │  │  │
 │          │      │  │  │                                  │  │  │
 │          │      │  │  │  1. Read user buffer             │  │  │
 │          │      │  │  │  2. Match "/secret/file"         │  │  │
 │          │      │  │  │  3. Rewrite → "/allowed/link"    │  │  │
 │          │      │  │  │                                  │  │  │
 │          │      │  │  └──────────────────────────────────┘  │  │
 │          │      │  │         │                              │  │
 │          │      │  │         ▼                              │  │
 │          │      │  │  copy_from_user(filename)              │  │
 │          │      │  │  ── sees rewritten path ──             │  │
 │          │      │  │         │                              │  │
 │          │      │  │         ▼                              │  │
 │          │      │  │  ┌──────────────────────────────────┐  │  │
 │          │      │  │  │  LSM: call_int_hook(file_open)   │  │  │
 │          │      │  │  │                                  │  │  │
 │          │      │  │  │  AppArmor checks "/allowed/link" │  │  │
 │          │      │  │  │  ──────────────────> ALLOW ✓     │  │  │
 │          │      │  │  │                                  │  │  │
 │          │      │  │  │  (never sees "/secret/file")     │  │  │
 │          │      │  │  └──────────────────────────────────┘  │  │
 │          │      │  │         │                              │  │
 │          │      │  │         ▼                              │  │
 │  fd ◄────┤      │  │  VFS opens inode (same data!)         │  │
 │  reads   │      │  │                                        │  │
 │  secret! │      │  └────────────────────────────────────────┘  │
 └──────────┘      │                                              │
                    │  Audit log: (empty)                          │
                    └──────────────────────────────────────────────┘
```

### Why AppArmor Falls

AppArmor is **pathname-based** — not inode-based like SELinux. Two hard links to the same file are two completely different identities in AppArmor's world:

```
  /tmp/secret_test_file.txt   ─┐
                                ├── same inode (4483), same data
  /tmp/.aa_bypass_link        ─┘

  AppArmor profile:
    deny /tmp/secret_test_file.txt rw    ← blocks this path
    /tmp/** r                             ← allows this path
```

Rewrite the path → bypass the rule → read the same data. **AppArmor was never defeated — it was deceived.**

<br>

## Quick Start

```bash
# 1. Check system requirements
sudo ./scripts/check_prerequisites.sh

# 2. Install dependencies & generate vmlinux.h
sudo ./scripts/setup_env.sh

# 3. Build LID
make

# 4. Set up demo (AppArmor profile, test file, hard link)
sudo ./scripts/setup_demo.sh

# 5. Run the full demonstration
sudo ./scripts/run_demo.sh
```

<br>

## Demo

```
  ██╗     ██╗██████╗
  ██║     ██║██╔══██╗        Linux Integrity Drift
  ██║     ██║██║  ██║        Full Demonstration
  ██║     ██║██║  ██║
  ███████╗██║██████╔╝        "Linux is Dying"
  ╚══════╝╚═╝╚═════╝

╔══════════════════════════════════════════════════════════╗
║  Phase 1: AppArmor ENFORCING — access should be DENIED   ║
╚══════════════════════════════════════════════════════════╝

  $ /tmp/test_reader
  [*] Attempting to read /tmp/secret_test_file.txt
  [-] DENIED: open() failed: Permission denied (errno=13)

╔══════════════════════════════════════════════════════════╗
║  Phase 2: Loading LID — BPF kprobe pathname rewrite       ║
╚══════════════════════════════════════════════════════════╝

  [*] BPF kprobe attached to do_sys_openat2
  [*] Target: /tmp/secret_test_file.txt → /tmp/.aa_bypass_link

╔══════════════════════════════════════════════════════════╗
║  Phase 3: With LID active — access should be GRANTED      ║
╚══════════════════════════════════════════════════════════╝

  $ /tmp/test_reader
  [*] Attempting to read /tmp/secret_test_file.txt
  [+] SUCCESS: Read 44 bytes: SECRET_DATA=this_is_protected_content_12345

  [BYPASS] pid=518899 comm=test_reader
           original:  /tmp/secret_test_file.txt
           rewritten: /tmp/.aa_bypass_link

╔══════════════════════════════════════════════════════════╗
║  Phase 4: Stealth check — audit log inspection             ║
╚══════════════════════════════════════════════════════════╝

  $ dmesg | grep apparmor | grep DENIED
  (empty — no denial was ever generated)

╔══════════════════════════════════════════════════════════╗
║  Phase 5: Unloading LID — enforcement restored             ║
╚══════════════════════════════════════════════════════════╝

  $ /tmp/test_reader
  [-] DENIED: open() failed: Permission denied (errno=13)
```

**The bypass is selective, transparent, audit-invisible, and fully reversible.**

<br>

## Architecture Deep Dive

### The LSM Deadlock (Why BPF LSM Can't Help)

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

  ─── If BPF is BEFORE AppArmor ───

  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
  │  BPF LSM    │──>│  ...         │──>│  AppArmor    │
  │  return 0   │   │              │   │  return -13  │
  │  (allow)    │   │              │   │  (DENY) ██   │
  └─────────────┘   └──────────────┘   └──────────────┘

  BPF returns 0 → loop continues → AppArmor still denies
  BPF returns -EACCES → can only ADD restrictions, not remove

  ★ CONCLUSION: Within the LSM framework, there is NO position
    where BPF can override AppArmor's denial. By design.
```

### LID's Approach: Go Around, Not Through

```
  SYSCALL: openat2("/secret/file")
       │
       ▼
  ┌─────────────────────────────┐
  │  do_sys_openat2()           │
  │  ┌───────────────────────┐  │
  │  │ ★ LID kprobe          │  │ ◄── BEFORE kernel copies the path
  │  │ bpf_probe_write_user  │  │
  │  │ "/secret" → "/link"   │  │
  │  └───────────────────────┘  │
  │       │                     │
  │       ▼                     │
  │  getname_flags()            │ ◄── kernel copies (rewritten) path
  │       │                     │
  │       ▼                     │
  │  path_openat()              │
  │       │                     │
  │       ▼                     │
  │  security_file_open()       │ ◄── LSM hooks check "/link" (allowed)
  │       │                     │
  │       ▼                     │
  │  ✓ success                  │
  └─────────────────────────────┘
```

**The kprobe fires before `copy_from_user`. The LSM framework never sees the original path.**

<br>

## Stealth Profile

| Indicator | Visibility | Notes |
|:---|:---|:---|
| AppArmor audit log | **Nothing** | Denial never occurs |
| `auditd` / `journald` | **Nothing** | No security event generated |
| `dmesg` | One-time warning | Generic `bpf_probe_write_user` message |
| `bpftool prog list` | Visible | Shows attached kprobe (if checked) |
| Hard link on disk | Detectable | `find -samefile` (slow, noisy) |

<br>

## Companion: SunnyDayBPF

LID is the offensive counterpart to [**SunnyDayBPF**](https://github.com/azqzazq1/SunnyDayBPF):

```
                   ┌───────────────────────────────────────┐
                   │          THE ATTACK TIMELINE           │
                   │                                       │
  Syscall Entry    │  ★ LID ─── rewrites path              │
       │           │     (security check sees wrong path)  │
       ▼           │                                       │
  LSM Check        │     AppArmor allows ✓                 │
       │           │                                       │
       ▼           │                                       │
  Syscall Exit     │  ★ SunnyDayBPF ─── rewrites telemetry │
       │           │     (monitoring sees wrong data)      │
       ▼           │                                       │
  Audit/Log        │     Wazuh/auditd sees nothing ✓       │
                   │                                       │
                   │  Combined: ghost access                │
                   └───────────────────────────────────────┘
```

| | SunnyDayBPF | LID |
|:---|:---|:---|
| **When** | Post-syscall | Pre-LSM-check |
| **What** | Telemetry data | Syscall arguments |
| **Effect** | Blind the cameras | Bypass the gate |
| **Combined** | Full ghost access | |

<br>

## Requirements

| Requirement | Details |
|:---|:---|
| Kernel | 5.x+ with BPF support |
| Config | `CONFIG_BPF_KPROBE_OVERRIDE=y` (Ubuntu default) |
| Privileges | Root or `CAP_BPF` + `CAP_PERFMON` |
| Target | AppArmor (pathname-based MAC) |
| Path type | Writable user memory (stack/heap, not `.rodata`) |

<br>

## Project Structure

```
LID/
├── src/
│   ├── bpf/
│   │   └── lid.bpf.c              # BPF kprobe — pathname rewriter
│   └── loader/
│       └── lid_loader.c           # Userspace loader + event monitor
├── tests/
│   └── test_reader.c              # Victim binary for demonstration
├── scripts/
│   ├── check_prerequisites.sh     # Verify system requirements
│   ├── setup_env.sh               # Install build dependencies
│   ├── setup_demo.sh              # Create demo environment
│   ├── run_demo.sh                # Run full demonstration
│   └── teardown.sh                # Clean up everything
├── docs/
│   └── RESEARCH.md                # Full technical research paper
├── Makefile
├── LICENSE
└── README.md
```

<br>

## Mitigations

| Mitigation | Effectiveness | Tradeoff |
|:---|:---|:---|
| `kernel.lockdown=confidentiality` | Blocks BPF entirely | Kills legitimate monitoring |
| Disable `bpf_probe_write_user` | Prevents path rewrite | Requires kernel rebuild |
| `fs.protected_hardlinks=1` | Limits hard link creation | Default on modern kernels |
| Monitor `bpftool prog list` | Detects attached probes | Requires active polling |
| BPF LSM self-protection | Block kprobes on VFS functions | Complex to implement |

For detailed mitigation guidance, see [`docs/RESEARCH.md`](docs/RESEARCH.md).

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
