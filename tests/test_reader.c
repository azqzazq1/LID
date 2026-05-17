// LID — test victim binary
// Attempts to read /tmp/secret_test_file.txt under AppArmor confinement.
// Path is stored in writable stack memory so bpf_probe_write_user can modify it.

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define TARGET_FILE "/tmp/secret_test_file.txt"

int main(void)
{
    printf("[*] PID: %d\n", getpid());
    printf("[*] Attempting to read %s\n", TARGET_FILE);

    char path[256];
    snprintf(path, sizeof(path), "%s", TARGET_FILE);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("[-] DENIED: open() failed: %s (errno=%d)\n", strerror(errno), errno);
        return 1;
    }

    char buf[512] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n > 0) {
        printf("[+] SUCCESS: Read %zd bytes: %s", n, buf);
        if (buf[n - 1] != '\n')
            printf("\n");
    }

    return 0;
}
