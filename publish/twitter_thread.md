THREAD (copy each tweet separately):

---

TWEET 1:
🔓 New research: LID — Linux Integrity Drift

I bypassed AppArmor without disabling it, without modifying it, and without leaving a single audit log entry.

Using eBPF.

Thread 🧵👇

---

TWEET 2:
The Linux Security Module framework has one guarantee that held for 20+ years:

"Modules can only ADD restrictions, never REMOVE them."

call_int_hook short-circuits on first denial. No LSM — including BPF LSM — can undo another's deny.

The framework is sound. I didn't break it.

---

TWEET 3:
Instead, I attached a BPF kprobe to do_sys_openat2 — the kernel's file-open handler.

Before the kernel copies the filename from userspace, my kprobe rewrites it in user memory via bpf_probe_write_user.

AppArmor then checks the REWRITTEN path. Not the original.

---

TWEET 4:
The trick: AppArmor is pathname-based. A hard link to the same file at a different path is a completely different identity.

deny /tmp/secret.txt → BLOCKED
/tmp/.bypass_link   → ALLOWED (same inode, same data)

Rewrite the path → bypass the rule → read the data.

---

TWEET 5:
Result:

❌ Without LID: Permission denied
✅ With LID: SUCCESS — reads protected content
📋 Audit log: (empty)

AppArmor was never defeated. It was deceived.

---

TWEET 6:
This pairs with my earlier research SunnyDayBPF:

🔴 LID: rewrites path BEFORE security check → bypass
🔴 SunnyDayBPF: rewrites telemetry AFTER syscall → stealth

Combined: bypass the gate + blind the cameras = ghost access.

---

TWEET 7:
The real finding isn't "root can read files" — that's trivial.

It's that two kernel subsystems (LSM and eBPF) have incompatible trust assumptions. The LSM framework assumes all decisions flow through its hooks. eBPF provides hooks that execute before them.

---

TWEET 8:
Full PoC, research paper, and automated demo scripts:

🔗 https://github.com/azqzazq1/LID

MIT licensed. Responsible use only.

LID — because the integrity was never locked.
