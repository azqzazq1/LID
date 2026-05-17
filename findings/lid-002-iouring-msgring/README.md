# LID-002: Missing LSM Hook in io_uring MSG_RING SEND_FD

**Vector:** `IORING_OP_MSG_RING` with `IORING_MSG_SEND_FD`
**Target:** SELinux, AppArmor, Smack (all LSMs implementing `file_receive`)
**Impact:** fd transfer between io_uring rings bypasses LSM policy
**Requires:** Unprivileged (io_uring access)

## Summary

`IORING_OP_MSG_RING` with `IORING_MSG_SEND_FD` transfers file descriptors between io_uring rings via `__io_fixed_fd_install()` without calling `security_file_receive()`. Every other fd transfer mechanism in the kernel (SCM_RIGHTS, FIXED_FD_INSTALL, binder) calls this hook.

## The Gap

```
MSG_RING SEND_FD:    io_msg_install_complete() → __io_fixed_fd_install()  ← NO LSM hook
FIXED_FD_INSTALL:    io_install_fixed_fd()     → receive_fd()             ← security_file_receive() ✓
SCM_RIGHTS:          scm_detach_fds()          → receive_fd()             ← security_file_receive() ✓
```

Bug location: `io_uring/msg_ring.c`, function `io_msg_install_complete()`, line 188.

## Verification

ftrace confirms `security_file_receive` is called for SCM_RIGHTS but NOT for MSG_RING:

```
# Phase 1 (MSG_RING): no ftrace entry for security_file_receive
# Phase 2 (SCM_RIGHTS):
  msg_ring_bypass  security_file_receive <-receive_fd
```

## Affected Versions

Linux 5.18+ through v7.1-rc3 (confirmed unfixed as of 2026-05-17).

## PoC

See `msg_ring_bypass.c` in this directory. Compile with `gcc -o msg_ring_bypass msg_ring_bypass.c -luring`.
