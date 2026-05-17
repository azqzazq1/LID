# Security Advisory: Missing LSM Hook in io_uring MSG_RING SEND_FD

## Summary

The `IORING_OP_MSG_RING` operation with `IORING_MSG_SEND_FD` flag transfers file descriptors between io_uring rings without calling the `security_file_receive()` LSM hook, bypassing SELinux, AppArmor, and Smack access control policies on file descriptor transfers.

## Affected Versions

- Linux kernel 5.18+ (when `IORING_MSG_SEND_FD` was introduced)
- Confirmed present in: 6.8, 6.12, 6.14, 6.15, 7.0, 7.1-rc3
- All major distributions with io_uring enabled

## Technical Details

### Root Cause

In `io_uring/msg_ring.c`, the function `io_msg_install_complete()` transfers a file descriptor to another io_uring ring's fixed file table by calling `__io_fixed_fd_install()` directly. This low-level function manages file table slot allocation only — it does not call `security_file_receive()`.

```c
// io_uring/msg_ring.c:188 — VULNERABLE
static int io_msg_install_complete(struct io_kiocb *req, unsigned int issue_flags)
{
    ...
    ret = __io_fixed_fd_install(target_ctx, src_file, msg->dst_fd);
    // ^^^ NO security_file_receive() call
    ...
}
```

### Comparison with Correct Implementations

Every other fd transfer mechanism in the kernel calls `security_file_receive()`:

| Mechanism | Calls security_file_receive? | Path |
|:---|:---|:---|
| SCM_RIGHTS (unix socket) | YES | `scm_detach_fds()` → `receive_fd()` → `security_file_receive()` |
| IORING_OP_FIXED_FD_INSTALL | YES | `io_install_fixed_fd()` → `receive_fd()` → `security_file_receive()` |
| binder_translate_fd | YES | `binder_translate_fd()` → `security_binder_transfer_file()` |
| **IORING_OP_MSG_RING SEND_FD** | **NO** | `io_msg_install_complete()` → `__io_fixed_fd_install()` |

### Proof of Concept

The included `msg_ring_bypass.c` demonstrates:

1. Phase 1: Transfers a file descriptor via MSG_RING SEND_FD — succeeds without triggering `security_file_receive()`
2. Phase 2: Transfers the same file descriptor via SCM_RIGHTS — triggers `security_file_receive()` (verified via ftrace)

### ftrace Verification

```
# ftrace output during PoC execution:
# Phase 1 (MSG_RING SEND_FD): NO security_file_receive trace entry
# Phase 2 (SCM_RIGHTS):
  msg_ring_bypass-531174  security_file_receive <-receive_fd
```

## Impact

### SELinux
SELinux implements `selinux_file_receive()` which checks `file_has_perm(cred, file, file_to_av(file))`. The `fd { use }` permission check is completely bypassed for MSG_RING fd transfers.

### AppArmor
AppArmor implements `apparmor_file_receive()` which calls `common_file_perm(OP_FRECEIVE, ...)`. File receive mediation is bypassed.

### Smack
Smack implements `smack_file_receive()` which verifies Smack label access. Label-based fd transfer controls are bypassed.

### Audit
No audit record is generated for the fd transfer via MSG_RING (the `audit_skip` flag is set for MSG_RING operations).

## Suggested Fix

Add `security_file_receive()` check in `io_msg_install_complete()` before calling `__io_fixed_fd_install()`:

```c
static int io_msg_install_complete(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_ring_ctx *target_ctx = req->file->private_data;
    struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
    struct file *src_file = msg->src_file;
    int ret;

    if (unlikely(io_double_lock_ctx(target_ctx, issue_flags)))
        return -EAGAIN;

+   ret = security_file_receive(src_file);
+   if (ret)
+       goto out_unlock;

    ret = __io_fixed_fd_install(target_ctx, src_file, msg->dst_fd);
    if (ret < 0)
        goto out_unlock;
    ...
}
```

## Disclosure Timeline

- 2026-05-17: Vulnerability discovered during systematic io_uring LSM hook audit
- 2026-05-17: PoC developed and verified with ftrace

## Credit

Azizcan Daştan — Milenium Security

## References

- `io_uring/msg_ring.c` — vulnerable code
- `io_uring/openclose.c` — correct implementation (FIXED_FD_INSTALL)
- `fs/file.c:receive_fd()` — LSM-checked fd installation
- `include/linux/lsm_hook_defs.h:188` — file_receive hook definition
