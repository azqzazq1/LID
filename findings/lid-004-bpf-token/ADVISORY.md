# Security Advisory: AppArmor Zero Coverage on BPF Token Subsystem

## Summary

AppArmor implements zero BPF LSM hooks (0 out of 9 defined by the kernel). The BPF token delegation mechanism (introduced in Linux 6.9) allows controlled BPF access for unprivileged users in non-init user namespaces. On AppArmor systems, all BPF token operations execute without any LSM mediation, policy evaluation, or audit logging.

SELinux has implemented full BPF token enforcement in mainline. AppArmor and Smack have not.

## Affected Versions

- Linux kernel 6.9+ (BPF token introduction)
- All AppArmor versions through current mainline
- All Smack versions through current mainline
- Ubuntu 24.04+, Debian 13+, and derivatives with AppArmor default

## Technical Details

### Root Cause

AppArmor's `apparmor_hooks[]` array in `security/apparmor/lsm.c` contains zero entries for any BPF-related LSM hook. The kernel defines 9 BPF hooks:

| Hook | Purpose | AppArmor |
|:---|:---|:---|
| `bpf` | Gate BPF syscall commands | Not implemented |
| `bpf_map` | Mediate map access | Not implemented |
| `bpf_prog` | Mediate program access | Not implemented |
| `bpf_map_create` | Label new maps | Not implemented |
| `bpf_prog_load` | Label new programs | Not implemented |
| `bpf_token_create` | Gate token creation | Not implemented |
| `bpf_token_free` | Clean up token security blob | Not implemented |
| `bpf_token_cmd` | Gate per-command token usage | Not implemented |
| `bpf_token_capable` | Gate capability delegation via token | Not implemented |

When no LSM registers an `int`-returning hook, the LSM framework's `call_int_hook()` returns the default value of `0` (permit).

### Impact

On AppArmor-enforcing systems with BPF token delegation:

1. **No policy enforcement**: AppArmor cannot restrict which processes create or use BPF tokens
2. **No audit logging**: No AppArmor audit events are generated for any BPF operation
3. **Invisible capability delegation**: Tokens silently grant CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN equivalents within user namespaces
4. **Verifier relaxation**: Token-delegated CAP_PERFMON disables Spectre mitigations and enables kernel pointer leaks in BPF programs

### Contrast with SELinux

SELinux (mainline) implements:
- `selinux_bpf_token_create()` — checks `BPF__MAP_CREATE_AS` and `BPF__PROG_LOAD_AS` permissions via `avc_has_perm()`
- `selinux_bpf_token_cmd()` — enforces per-command permission bitmask
- `selinux_bpf_token_capable()` — mediates capability delegation through AVC

On a SELinux system, BPF token usage is fully mediated and auditable. On an AppArmor system, it is completely invisible.

### Additional Finding: Missing Token Reference Count

In `kernel/bpf/fixups.c`, `bpf_jit_subprogs()` copies `prog->aux->token` to subprogram aux structs without calling `bpf_token_inc()`. This raw pointer copy creates a latent use-after-free condition: if the subprogram free path ever calls `bpf_token_put()`, the token's refcount will underflow.

## Suggested Fix

### Minimum (token hooks only):

```c
LSM_HOOK_INIT(bpf_token_create, apparmor_bpf_token_create),
LSM_HOOK_INIT(bpf_token_cmd, apparmor_bpf_token_cmd),
LSM_HOOK_INIT(bpf_token_capable, apparmor_bpf_token_capable),
```

### Full parity (all BPF hooks):

```c
LSM_HOOK_INIT(bpf, apparmor_bpf),
LSM_HOOK_INIT(bpf_map, apparmor_bpf_map),
LSM_HOOK_INIT(bpf_prog, apparmor_bpf_prog),
LSM_HOOK_INIT(bpf_map_create, apparmor_bpf_map_create),
LSM_HOOK_INIT(bpf_prog_load, apparmor_bpf_prog_load),
LSM_HOOK_INIT(bpf_token_create, apparmor_bpf_token_create),
LSM_HOOK_INIT(bpf_token_cmd, apparmor_bpf_token_cmd),
LSM_HOOK_INIT(bpf_token_capable, apparmor_bpf_token_capable),
```

## Disclosure Timeline

- 2026-05-25: Vulnerability discovered during BPF token security audit
- 2026-05-25: Source-level verification against kernel v6.9 and mainline

## Credit

Azizcan Daştan — Milenium Security

## References

- `security/apparmor/lsm.c` — zero BPF hooks
- `security/selinux/hooks.c:7300-7376` — SELinux BPF token enforcement
- `include/linux/lsm_hook_defs.h:431-435` — BPF token hook definitions
- `kernel/bpf/token.c` — BPF token implementation
- LWN: [BPF token](https://lwn.net/Articles/959350/)
- LWN: [Delegating privilege with BPF tokens](https://lwn.net/Articles/935195/)
