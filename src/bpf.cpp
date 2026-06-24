#include "bpf.hpp"

#include "implementation.hpp"

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#include <cstddef>

// Classic BPF filter: accept IPv4/IPv6, including VLAN-tagged frames.
//
//   EtherType@12 -> IPv4/IPv6 ? accept : VLAN ? inspect inner EtherType
//                                      : reject
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
