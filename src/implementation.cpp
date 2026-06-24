#include "implementation.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

// Packet layout:
//
//   +--------+---------+---------+---------+----------+
//   | ETH    | VLAN?   | IP      | L4      | payload  |
//   +--------+---------+---------+---------+----------+
//       ^        ^
//       |        +-- optional 4-byte tag before inner EtherType
//       +----------- EtherType read at byte 12
//
// Validation note:
// iperf traffic is TCP or UDP, so those paths are kept small and fast. The
// parser still keeps ICMP and other common IP protocols visible so the sniffer
// remains general-purpose rather than iperf-only.

// Shared shutdown flag. It is intentionally simple: the signal handler only
// changes this flag and the capture loop exits at a block boundary.
bool running = true;

// Stop the capture loop on SIGINT/SIGTERM.
void on_signal(int) { running = false; }

// Raise a readable exception on syscall failure.
void die_if(bool cond, const std::string &msg) {
  if (cond) throw std::runtime_error(msg + ": " + std::strerror(errno));
}

// Enable promiscuous mode on the chosen interface.
void enable_promiscuous(int fd, unsigned ifindex) {
  packet_mreq mreq{};
  mreq.mr_ifindex = static_cast<int>(ifindex);
  mreq.mr_type = PACKET_MR_PROMISC;
  die_if(::setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
                      sizeof(mreq)) < 0,
         "setsockopt PACKET_ADD_MEMBERSHIP");
}

// Read Ethernet EtherType and skip one VLAN tag when present. This function
// deliberately only performs L2 classification; deeper protocol parsing is done
// after dispatch so malformed or unsupported packets can be ignored cheaply.
ParsedPacket parse_packet(const uint8_t *packet, uint32_t len) {
  ParsedPacket result{};
  if (len < sizeof(ethhdr)) return result;

  const auto *eth = reinterpret_cast<const ethhdr *>(packet);
  result.ethertype = ntohs(eth->h_proto);
  result.l3_offset = sizeof(ethhdr);

  if ((result.ethertype == ETH_P_8021Q || result.ethertype == ETH_P_8021AD ||
       result.ethertype == 0x9100) &&
      len >= sizeof(ethhdr) + 4) {
    result.ethertype = ntohs(*reinterpret_cast<const uint16_t *>(packet + 16));
    result.l3_offset += 4;
  }

  result.is_ipv4 = result.ethertype == ETH_P_IP;
  result.is_ipv6 = result.ethertype == ETH_P_IPV6;
  return result;
}

// Map L4 protocol numbers to tcpdump-like labels.
namespace {

const char *transport_name(uint8_t proto) {
  switch (proto) {
  case IPPROTO_TCP:
    return "TCP";
  case IPPROTO_UDP:
    return "UDP";
  case IPPROTO_ICMP:
    return "ICMP";
  case IPPROTO_ICMPV6:
    return "ICMP6";
  case IPPROTO_IGMP:
    return "IGMP";
#ifdef IPPROTO_GRE
  case IPPROTO_GRE:
    return "GRE";
#endif
#ifdef IPPROTO_ESP
  case IPPROTO_ESP:
    return "ESP";
#endif
#ifdef IPPROTO_AH
  case IPPROTO_AH:
    return "AH";
#endif
#ifdef IPPROTO_SCTP
  case IPPROTO_SCTP:
    return "SCTP";
#endif
  default:
    return nullptr;
  }
}

// Print ports when the transport header is complete enough to read safely.
// Bounds checks are mandatory because snaplen can be shorter than wire length.
bool read_ports(uint8_t proto, const uint8_t *l4, uint32_t l4_len,
                uint16_t &src_port, uint16_t &dst_port) {
  if (proto == IPPROTO_TCP && l4_len >= sizeof(tcphdr)) {
    const auto *tcp = reinterpret_cast<const tcphdr *>(l4);
    src_port = ntohs(tcp->source);
    dst_port = ntohs(tcp->dest);
    return true;
  }

  if (proto == IPPROTO_UDP && l4_len >= sizeof(udphdr)) {
    const auto *udp = reinterpret_cast<const udphdr *>(l4);
    src_port = ntohs(udp->source);
    dst_port = ntohs(udp->dest);
    return true;
  }

  return false;
}

void print_tcp_details(const uint8_t *l4, uint32_t l4_len) {
  if (l4_len < sizeof(tcphdr)) return;

  const auto *tcp = reinterpret_cast<const tcphdr *>(l4);
  std::cout << " flags [";
  if (tcp->fin) std::cout << "F";
  if (tcp->syn) std::cout << "S";
  if (tcp->rst) std::cout << "R";
  if (tcp->psh) std::cout << "P";
  if (tcp->ack) std::cout << "A";
  if (tcp->urg) std::cout << "U";
  std::cout << "] seq " << ntohl(tcp->seq) << " ack " << ntohl(tcp->ack_seq);
}

void print_transport_summary(const char *ip_label, const char *src,
                             const char *dst, uint8_t proto,
                             const uint8_t *l4, uint32_t l4_len,
                             uint32_t packet_len, const char *hop_label,
                             uint8_t hop_value) {
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  const bool has_ports = read_ports(proto, l4, l4_len, src_port, dst_port);

  std::cout << ip_label << ' ' << src;
  if (has_ports) std::cout << '.' << src_port;
  std::cout << " > " << dst;
  if (has_ports) std::cout << '.' << dst_port;

  if (const char *name = transport_name(proto)) {
    std::cout << ' ' << name;
  } else {
    std::cout << " proto " << static_cast<int>(proto);
  }

  if (proto == IPPROTO_TCP) print_tcp_details(l4, l4_len);

  std::cout << ' ' << hop_label << ' ' << static_cast<int>(hop_value)
            << " len " << packet_len << '\n';
}

} // namespace

// Print a one-line IPv4 summary. The function validates IHL before touching L4
// fields because IPv4 options make the transport offset variable.
void parse_ipv4_packet(const uint8_t *packet, uint32_t len, size_t l3_offset) {
  if (len < l3_offset + sizeof(iphdr)) return;

  const auto *ip = reinterpret_cast<const iphdr *>(packet + l3_offset);
  const size_t ihl = static_cast<size_t>(ip->ihl) * 4;
  if (ihl < sizeof(iphdr) || len < l3_offset + ihl) return;

  char src[INET_ADDRSTRLEN] = {};
  char dst[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
  inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

  const uint8_t *l4 = packet + l3_offset + ihl;
  const uint32_t l4_len = len - static_cast<uint32_t>(l3_offset + ihl);

  print_transport_summary("IP", src, dst, ip->protocol, l4, l4_len, len, "ttl",
                          ip->ttl);
}

void parse_ipv6_packet(const uint8_t *packet, uint32_t len, size_t l3_offset) {
  if (len < l3_offset + sizeof(ip6_hdr)) return;

  const auto *ip6 = reinterpret_cast<const ip6_hdr *>(packet + l3_offset);
  char src[INET6_ADDRSTRLEN] = {};
  char dst[INET6_ADDRSTRLEN] = {};
  inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
  inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

  const uint8_t *l4 = packet + l3_offset + sizeof(ip6_hdr);
  const uint32_t l4_len = len - static_cast<uint32_t>(l3_offset + sizeof(ip6_hdr));

  print_transport_summary("IP6", src, dst, ip6->ip6_nxt, l4, l4_len, len,
                          "hlim", ip6->ip6_hlim);
}

void dispatch_ip_packet(const ParsedPacket &pkt, const uint8_t *packet,
                        uint32_t len) {
  if (pkt.is_ipv4) parse_ipv4_packet(packet, len, pkt.l3_offset);
  else if (pkt.is_ipv6) parse_ipv6_packet(packet, len, pkt.l3_offset);
}
