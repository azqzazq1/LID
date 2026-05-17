# Security Policy

## Purpose

LID (Linux Integrity Drift) is a **security research tool** published for defensive research, authorized penetration testing, and educational purposes. It demonstrates an architectural gap between the Linux Security Module framework and the eBPF subsystem.

## Responsible Use

This tool is intended for:

- **Security researchers** studying LSM and eBPF interactions
- **Red team operators** with written authorization from the system owner
- **Blue team / detection engineers** building detections for eBPF-based threats
- **Educators** teaching kernel security architecture

This tool is **NOT** intended for:

- Unauthorized access to systems you do not own
- Circumventing security controls in production without authorization
- Any activity that violates applicable laws or regulations

## Reporting Security Issues

If you discover a security vulnerability in LID itself (e.g., a way the loader could be exploited), please report it responsibly:

1. **Do not** open a public GitHub issue
2. Contact: **azqzazq1** via [GitHub](https://github.com/azqzazq1)
3. Allow 90 days for response before public disclosure

## Affected Software

The technique demonstrated by LID affects:

| Component | Affected | Why |
|---|---|---|
| AppArmor | Yes | Pathname-based MAC — susceptible to path rewriting |
| SELinux | No | Inode/label-based MAC — path rewriting doesn't help |
| TOMOYO | Likely | Pathname-based, similar architecture to AppArmor |
| Smack | No | Label-based |

## Kernel Mitigations

System administrators can mitigate this technique:

```bash
# 1. Enable kernel lockdown (strongest, but limits legitimate BPF use)
# Add to kernel command line:
#   lockdown=confidentiality

# 2. Restrict unprivileged BPF (default on most distros)
sysctl kernel.unprivileged_bpf_disabled=1

# 3. Protect hard links (default on modern kernels)
sysctl fs.protected_hardlinks=1

# 4. Monitor for BPF program loading
# Watch for kprobe attachments:
bpftool prog list | grep kprobe

# 5. Alert on bpf_probe_write_user usage
dmesg | grep bpf_probe_write_user
```

## Detection

Security teams should monitor for:

1. **`bpf_probe_write_user` kernel warning** — fires once per loader in `dmesg`
2. **Unexpected kprobe attachments** — check `bpftool prog list` periodically
3. **Hard links to sensitive files** — file integrity monitoring
4. **`bpf()` syscall audit events** — enable BPF auditing in your SIEM

## Coordinated Disclosure

The underlying architectural gap (eBPF kprobes operating outside the LSM trust boundary) is a known design property of the Linux kernel, not a specific vulnerability. It has been discussed in kernel mailing lists in the context of `bpf_probe_write_user` safety. This research provides the first public proof-of-concept demonstrating practical exploitation against AppArmor.

No CVE has been requested as this is a design-level concern, not a specific software bug.
