# LID-003: AppArmor Bypass via New Mount API (fsopen/fsconfig/fsmount)

**Vector:** New mount API syscalls bypass `security_sb_mount()`
**Target:** AppArmor (only implements `sb_mount`, `sb_umount`, `sb_pivotroot`, `move_mount`)
**Impact:** Complete bypass of AppArmor mount type/source/option restrictions
**Requires:** Unprivileged (in user namespace) or CAP_SYS_ADMIN

## Summary

AppArmor's mount mediation relies entirely on the `security_sb_mount()` hook. The new mount API (`fsopen` + `fsconfig` + `fsmount` + `move_mount`) never calls `security_sb_mount()`. Instead it calls hooks that AppArmor does not implement: `security_fs_context_parse_param`, `security_sb_kern_mount`, `security_sb_set_mnt_opts`.

## The Gaps

| Operation | Old API Hook | New API Hook | AppArmor implements? |
|:---|:---|:---|:---|
| Create mount | `security_sb_mount` | `security_sb_kern_mount` | **NO** |
| Mount options | `security_sb_mount` | `security_fs_context_parse_param` | **NO** |
| Bind mount | `security_sb_mount` | (none for `open_tree(CLONE)`) | **N/A** |
| Remount | `security_sb_mount` | `security_sb_remount` | **NO** |
| Change flags | `security_sb_mount` | (none for `mount_setattr`) | **N/A** |

AppArmor registers only 4 mount hooks (vs SELinux's 14).

## Attack Chain

```bash
# This would be blocked by "deny mount fstype=proc" in AppArmor:
mount -t proc proc /target

# This bypasses it completely:
fd=$(fsopen proc 0)
fsconfig $fd CMD_CREATE
mfd=$(fsmount $fd 0 0)
move_mount $mfd "" /target MOVE_MOUNT_F_EMPTY_PATH
```

## Additional Gaps

- **`open_tree(OPEN_TREE_CLONE)`**: Zero security hooks — bypasses bind-mount policy
- **`mount_setattr()`**: No LSM hook exists in the kernel at all — can remove nosuid/noexec/nodev
- **`move_mount()` with detached mounts**: AppArmor sees source path as NULL (wildcard match)

## Related

Ubuntu bug #2052662 covers the `move_mount` detached mount issue. The `open_tree(CLONE)` and `mount_setattr` gaps are additional findings.
