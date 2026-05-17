# I Bypassed AppArmor Without Disabling It — Using eBPF

## The Linux kernel's security guarantee held for 20 years. I walked around it.

The Linux Security Module framework has one iron rule:

> Security modules can only add restrictions. They can never remove them.

I didn't break that rule. I walked around it.

The result: full file access through AppArmor mandatory access control, with zero audit log entries, without disabling or modifying AppArmor itself.

The tool is called LID — Linux Integrity Drift. "Linux is Dying."

---

## The Setup

AppArmor is a mandatory access control (MAC) system used on Ubuntu, Debian, SUSE, and most enterprise Linux distributions. It confines processes to a set of allowed file paths.

Here's a simple AppArmor profile:

```
/tmp/test_reader {
  deny /tmp/secret_test_file.txt rw,
  /tmp/** r,
}
```

This says: test_reader can read anything in /tmp/ except secret_test_file.txt.

And it works:

```
$ /tmp/test_reader
[-] DENIED: open() failed: Permission denied (errno=13)
```

AppArmor is doing its job. The kernel's LSM framework iterates every security module, and AppArmor says no.

Or is it?

---

## The Technique

I wrote a BPF kprobe that attaches to do_sys_openat2 — the kernel's internal file-open handler. It fires before the kernel copies the filename from userspace. At that point, the filename is still sitting in a writable user-space buffer.

So I rewrote it.

```
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(bypass_apparmor, int dfd, const char *filename, ...)
{
    bpf_probe_read_user_str(path_buf, sizeof(path_buf), filename);

    if (matches_target(path_buf)) {
        bpf_probe_write_user((void *)filename, bypass_path, len);
    }
}
```

The trick: I created a hard link to the secret file at a path AppArmor allows:

```
ln /tmp/secret_test_file.txt /tmp/.aa_bypass_link
```

AppArmor is pathname-based — not inode-based like SELinux. Two hard links to the same file are completely different identities to AppArmor. The deny rule blocks /tmp/secret_test_file.txt but the permissive /tmp/** rule allows /tmp/.aa_bypass_link.

The BPF kprobe rewrites the path before the kernel copies it. AppArmor checks the allowed path. Grants access. Process reads the protected file's content.

---

## The Result

```
$ /tmp/test_reader                  → DENIED: Permission denied

$ sudo ./lid_loader &               → BPF kprobe attached

$ /tmp/test_reader                  → SUCCESS: SECRET_DATA=this_is_protected...

$ dmesg | grep apparmor | grep DENIED → (empty)
```

AppArmor was never defeated. It was deceived. It correctly enforced its policy — on the wrong path.

---

## Why BPF LSM Can't Do This

You might think: "Just use BPF LSM to override AppArmor." I tried. It can't.

The kernel's call_int_hook macro iterates LSM hooks and short-circuits on the first denial:

```
hlist_for_each_entry(P, &security_hook_heads.FUNC, list) {
    RC = P->hook.FUNC(__VA_ARGS__);
    if (RC != 0)
        break;    // first deny wins
}
```

If BPF runs before AppArmor: BPF allows, loop continues, AppArmor still denies.
If BPF runs after AppArmor: AppArmor denies, loop breaks, BPF never runs.

The LSM framework is secure. No module can undo another's denial.

But kprobes don't go through the framework. They attach directly to kernel functions and execute before any LSM hook is consulted.

Two kernel subsystems. Incompatible trust assumptions. One gap.

---

## The Architecture

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
VFS opens inode          ← same file content
     │
     ▼
return fd to process     ← success, zero audit trace
```

---

## Stealth Profile

This isn't just a bypass — it's an invisible bypass.

- AppArmor audit log: Empty — denial never occurred
- auditd / journald: Nothing — no security event generated
- dmesg: One generic bpf_probe_write_user warning (one-time, doesn't say what was written)
- bpftool prog list: Shows kprobe if someone actively checks

---

## The Bigger Picture: LID + SunnyDayBPF

This technique pairs with my earlier research SunnyDayBPF — which manipulates telemetry data after syscalls complete.

SunnyDayBPF: post-syscall, rewrites telemetry → blinds the cameras
LID: pre-LSM-check, rewrites syscall args → bypasses the gate

Combined: ghost access. Bypass the security check, then rewrite what the monitoring system observed. The SIEM sees nothing. The analyst sees nothing.

---

## Limitations

Being honest about what this can't do:

1. Writable buffer required — if the path is a string literal in read-only memory (.rodata), bpf_probe_write_user fails. Most real programs use dynamically constructed paths though.

2. Hard link needed — attacker must create a hard link on the same filesystem.

3. Root/CAP_BPF required — you need privileges to load BPF programs. But the value isn't "root can read files" (trivial). It's "root can read files without AppArmor knowing."

4. AppArmor only — SELinux uses inode labels, not paths. Path rewriting doesn't help there.

---

## What This Means

This isn't a bug in AppArmor. It's not a bug in eBPF. It's a design gap where two kernel subsystems have incompatible trust assumptions:

The LSM framework assumes all security decisions flow through its hook chain. The eBPF subsystem provides hook points that execute before those security decisions.

When you can modify the input to a security check, the correctness of the check itself doesn't matter.

The gate was never breached. It was misdirected.

---

Full PoC, research paper, and automated demo: https://github.com/azqzazq1/LID

DOI: 10.5281/zenodo.20257645

Azizcan Daştan — Milenium Security

Tags: #Cybersecurity #Linux #eBPF #KernelSecurity #AppArmor #RedTeam #SecurityResearch #InfoSec
