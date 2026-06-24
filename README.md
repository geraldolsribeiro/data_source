# Linux User-Space Sniffer with AF_PACKET + TPACKET_V3

Linux-native packet capture demo using AF_PACKET raw sockets and TPACKET_V3 memory-mapped RX rings.

## Design goal

Minimize packet loss in user space by letting the Linux kernel buffer and batch packets before the C++ capture loop processes them.

No user-space sniffer can guarantee that no packets are missed under all loads. This project focuses on reducing loss probability and making loss observable.

## Architecture rationale

### AF_PACKET raw socket

AF_PACKET is the Linux-native interface for receiving link-layer frames in user space. It keeps the implementation in normal C++ while still using kernel packet capture facilities.

### TPACKET_V3 packet mmap

TPACKET_V3 provides a memory-mapped RX ring. The kernel fills packet blocks and userspace consumes them without one syscall per packet.

Benefits:

- fewer syscalls
- batched packet delivery
- kernel-managed buffering
- direct userspace access to packet data

### Large RX ring

The ring uses large blocks and many blocks so short traffic bursts can be absorbed before userspace catches up. Larger rings do not guarantee zero loss, but they reduce drops when the parser is briefly delayed.

### Kernel-side BPF filter

The classic BPF filter rejects non-IPv4/IPv6 frames before they enter the userspace processing path. This reduces CPU work and ring pressure.

### Memory locking

The capture path tries `mlockall(MCL_CURRENT | MCL_FUTURE)` to reduce page-fault risk during capture. Failure is reported as a warning because systems often restrict locked memory.

### Drop observability

The program reads `PACKET_STATISTICS` on shutdown. These counters are essential because packet loss cannot be ruled out mathematically in user space.

## Implementation layout

- `src/main.cpp` — argument handling and top-level orchestration
- `src/capture.cpp` — socket setup, RX ring setup, polling, block processing
- `src/bpf.cpp` — kernel-side IPv4/IPv6 filter
- `src/implementation.cpp` — Ethernet/VLAN/IP parsing and summary output
- `src/fd.cpp` — RAII file descriptor wrapper
- `src/parsed_packet.cpp` — packet metadata type

## Tuning ideas

For heavier workloads, consider:

- increasing ring size
- pinning the process to a CPU
- tuning NIC IRQ affinity
- reducing stdout work in the hot path
- using `PACKET_FANOUT` with one socket per worker thread
- increasing `RLIMIT_MEMLOCK` so `mlockall()` succeeds

## Build

```bash
make
```

## Test

```bash
make test
```
