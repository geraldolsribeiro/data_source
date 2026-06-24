#include "bpf.hpp"

#include "implementation.hpp"

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#include <cstddef>

// Classic BPF filter: accept IPv4/IPv6, including VLAN-tagged frames.
//
// | Step | BPF action                          | Purpose                  |
// |------|-------------------------------------|--------------------------|
// | 1    | Load half-word at byte 12           | Read outer EtherType     |
// | 2    | Compare with ETH_P_IP               | Accept plain IPv4        |
// | 3    | Compare with ETH_P_IPV6             | Accept plain IPv6        |
// | 4    | Compare with ETH_P_8021Q/8021AD/9100| Detect VLAN tag          |
// | 5    | Reject if not IP or VLAN            | Drop irrelevant traffic  |
// | 6    | Load half-word at byte 16           | Read VLAN inner EtherType|
// | 7    | Compare inner type with IPv4/IPv6   | Accept VLAN IP traffic   |
// | 8    | Return 0xffffffff or 0              | Keep full packet or drop |
//
// Why this matters:
//
// Without this filter, every Ethernet frame that reaches the interface can be
// copied into the packet ring: ARP, LLDP, STP, non-IP VLAN payloads, and other
// traffic that this sniffer does not parse. That wastes ring space and CPU time.
//
// Filtering in the kernel lowers userspace CPU cost and reduces pressure on the
// RX ring. By rejecting non-IP frames before they enter the TPACKET_V3 ring,
// unrelated L2 traffic does not compete with the TCP/UDP streams being measured.
// This makes drops less likely during bursts, especially during high-rate iperf
// validation.
//
// This is still classic socket BPF attached to AF_PACKET, so the program stays
// a normal portable C++ userspace sniffer rather than depending on XDP/eBPF
// deployment.
void attach_ip_filter(int fd) {
  sock_filter code[] = {BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
                        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 8, 0),
                        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, 7, 0),
                        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_8021Q, 3, 0),
                        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_8021AD, 2, 0),
                        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x9100, 1, 0),
                        BPF_STMT(BPF_RET | BPF_K, 0),
                        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 16),
                        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 1, 0),
                        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, 0, 1),
                        BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
                        BPF_STMT(BPF_RET | BPF_K, 0)};

  sock_fprog prog{};
  prog.len = static_cast<unsigned short>(std::size(code));
  prog.filter = code;
  die_if(::setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0,
         "setsockopt SO_ATTACH_FILTER");
}
