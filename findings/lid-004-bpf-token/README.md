# LID-004: AppArmor Zero Coverage on BPF Token Operations

**Vector:** BPF token delegation operates with zero LSM mediation on AppArmor
**Target:** AppArmor (zero BPF hooks of any kind)
**Impact:** Token creation, usage, and capability delegation invisible to AppArmor policy and audit
**Requires:** bpffs mounted with delegation options + CAP_BPF in user namespace

## Summary

AppArmor implements **zero** BPF LSM hooks — not just token hooks, but no `bpf`, `bpf_map`, `bpf_prog`, or `bpf_token_*` hooks at all. The kernel defines 4 BPF token hooks (`bpf_token_create`, `bpf_token_free`, `bpf_token_cmd`, `bpf_token_capable`), and SELinux now implements all of them with real `avc_has_perm()` enforcement. AppArmor registers none.

This means on Ubuntu/Debian (AppArmor default), a process in a container with bpffs delegation can create and use BPF tokens with zero LSM mediation, zero policy evaluation, and zero audit trace.

## The Gap

```
SELinux (mainline):
  bpf_token_create  → selinux_bpf_token_create()  → avc_has_perm() ✓
  bpf_token_cmd     → selinux_bpf_token_cmd()     → permission check ✓
  bpf_token_capable → selinux_bpf_token_capable()  → capability check ✓
  bpf              → selinux_bpf()                → BPF__MAP_CREATE / BPF__PROG_LOAD ✓

AppArmor (mainline):
  bpf_token_create  → (not implemented)            → default 0 (ALLOW) ✓
  bpf_token_cmd     → (not implemented)            → default 0 (ALLOW) ✓
  bpf_token_capable → (not implemented)            → default 0 (ALLOW) ✓
  bpf              → (not implemented)            → default 0 (ALLOW) ✓
```

Smack also registers zero BPF hooks.

## Hook Registration Comparison

| Hook | Defined in kernel | SELinux | AppArmor | Smack |
|:---|:---|:---|:---|:---|
| `bpf` | Yes | Yes | **NO** | **NO** |
| `bpf_map` | Yes | Yes | **NO** | **NO** |
| `bpf_prog` | Yes | Yes | **NO** | **NO** |
| `bpf_map_create` | Yes | Yes | **NO** | **NO** |
| `bpf_prog_load` | Yes | Yes | **NO** | **NO** |
| `bpf_token_create` | Yes | Yes | **NO** | **NO** |
| `bpf_token_free` | Yes | Yes (cleanup) | **NO** | **NO** |
| `bpf_token_cmd` | Yes | Yes | **NO** | **NO** |
| `bpf_token_capable` | Yes | Yes | **NO** | **NO** |

AppArmor: **0 out of 9** BPF hooks implemented.

## Attack Chain

```
1. Host admin mounts bpffs with delegation into container namespace:
   mount -t bpf bpf /container/bpffs -o delegate_cmds=any,delegate_progs=any,delegate_attachs=any

2. Container process (CAP_BPF + CAP_PERFMON in userns) creates token:
   token_fd = bpf(BPF_TOKEN_CREATE, {bpffs_fd})
   → security_bpf_token_create()      → AppArmor: (noop) → ALLOW

3. Process uses token to load tracing program:
   bpf(BPF_PROG_LOAD, {token_fd, BPF_PROG_TYPE_TRACING})
   → security_bpf(BPF_PROG_LOAD)      → AppArmor: (noop) → ALLOW
   → security_bpf_token_cmd(PROG_LOAD) → AppArmor: (noop) → ALLOW

4. Token grants CAP_PERFMON equivalent via namespace check:
   bpf_token_capable(token, CAP_PERFMON)
   → ns_capable(token->userns, CAP_PERFMON)  → PASS (userns root)
   → security_bpf_token_capable()             → AppArmor: (noop) → ALLOW

5. Verifier relaxes security constraints:
   allow_ptr_leaks    = true    ← kernel address disclosure
   allow_uninit_stack = true    ← uninitialized stack info leak
   bypass_spec_v1     = true    ← Spectre v1 mitigations disabled
   bypass_spec_v4     = true    ← Spectre v4 mitigations disabled

6. AppArmor audit log: NOTHING
   AppArmor policy evaluation: NEVER HAPPENED
```

## Verifier Relaxation Impact

When a token delegates `CAP_PERFMON`, the BPF verifier disables safety constraints:

| Verifier Flag | Effect | Risk |
|:---|:---|:---|
| `allow_ptr_leaks` | Kernel pointer values exposed to BPF program | KASLR bypass, kernel address disclosure |
| `allow_uninit_stack` | Uninitialized stack memory readable | Kernel stack info leak |
| `bypass_spec_v1` | Array bounds masking disabled | Spectre v1 side-channel attacks |
| `bypass_spec_v4` | Speculative store bypass protection disabled | Spectre v4 attacks |

Combined: a BPF program with these relaxations can construct **kernel memory read primitives** from within a user namespace.

## Source Evidence

### AppArmor — `security/apparmor/lsm.c` (mainline)

```
$ grep -c "bpf" security/apparmor/lsm.c
0
```

Zero matches. No BPF hooks registered in the `apparmor_hooks[]` array.

### LSM Hook Defaults — `include/linux/lsm_hook_defs.h`

```c
LSM_HOOK(int, 0, bpf_token_create, struct bpf_token *token, ...)
LSM_HOOK(int, 0, bpf_token_cmd, const struct bpf_token *token, enum bpf_cmd cmd)
LSM_HOOK(int, 0, bpf_token_capable, const struct bpf_token *token, int cap)
```

Default return value is `0` (permit). When no LSM registers the hook, `call_int_hook()` returns 0 unconditionally.

### Token Capability Check — `kernel/bpf/token.c`

```c
bool bpf_token_capable(const struct bpf_token *token, int cap)
{
    struct user_namespace *userns;
    userns = token ? token->userns : &init_user_ns;
    if (!bpf_ns_capable(userns, cap))
        return false;
    if (token && security_bpf_token_capable(token, cap) < 0)  // AppArmor: always 0
        return false;
    return true;
}
```

The `security_bpf_token_capable()` call is the only LSM gate on token capability delegation. On AppArmor systems, it unconditionally returns 0.

## Reproducibility

| Condition | Required | Notes |
|:---|:---|:---|
| Kernel version | 6.9+ | BPF token introduced in 6.9 |
| `CONFIG_BPF_SYSCALL` | `=y` | Default on all major distros |
| `CONFIG_SECURITY_APPARMOR` | `=y` | Ubuntu/Debian default |
| bpffs with delegation | Yes | Must be mounted by privileged host process |
| Privileges | CAP_BPF in user namespace | Trivially available to userns root |
| SELinux instead of AppArmor | **Not affected** | SELinux implements all BPF token hooks |

### What Blocks This

| Environment | Affected? |
|:---|:---|
| Ubuntu 24.04+ (AppArmor, default) | **YES** |
| Debian 13+ (AppArmor) | **YES** |
| RHEL/Fedora (SELinux) | No — SELinux enforces token hooks |
| Container without bpffs delegation | No — no token creation possible |
| `kernel.lockdown=confidentiality` | Partially — blocks some BPF attach types |

## Additional Finding: Missing `bpf_token_inc()` Refcount

Related to the BPF token subsystem: in `kernel/bpf/fixups.c`, the function `bpf_jit_subprogs()` copies `prog->aux->token` to subprogram aux structs as a raw pointer without calling `bpf_token_inc()`. The reference count is not incremented. Currently safe because subprogram cleanup does not call `bpf_token_put()`, but this is a fragile invariant — any future refactoring adding `bpf_token_put()` to subprogram free path would cause a use-after-free on `struct bpf_token`.

## Suggested Fix

AppArmor should implement BPF token hooks at minimum:

```c
// security/apparmor/lsm.c — suggested additions

static int apparmor_bpf_token_create(struct bpf_token *token,
                                     union bpf_attr *attr,
                                     const struct path *path)
{
    // Mediate token creation against AppArmor profile
    // Check if current profile allows BPF token creation
}

static int apparmor_bpf_token_cmd(const struct bpf_token *token,
                                  enum bpf_cmd cmd)
{
    // Mediate per-command token usage
}

static int apparmor_bpf_token_capable(const struct bpf_token *token,
                                      int cap)
{
    // Mediate capability delegation through tokens
}

// In apparmor_hooks[] array:
LSM_HOOK_INIT(bpf_token_create, apparmor_bpf_token_create),
LSM_HOOK_INIT(bpf_token_cmd, apparmor_bpf_token_cmd),
LSM_HOOK_INIT(bpf_token_capable, apparmor_bpf_token_capable),
```

Additionally, AppArmor should implement the base BPF hooks (`bpf`, `bpf_map`, `bpf_prog`) to achieve parity with SELinux on BPF mediation.

## Credit

Azizcan Daştan — Milenium Security

## References

- `security/apparmor/lsm.c` — zero BPF hooks
- `include/linux/lsm_hook_defs.h:431-435` — BPF token hook definitions
- `kernel/bpf/token.c:17-28` — `bpf_token_capable()` with LSM callout
- `security/selinux/hooks.c:7300-7376` — SELinux token enforcement (mainline)
- `security/security.c:5483-5552` — LSM framework dispatch functions
