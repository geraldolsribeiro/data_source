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

#include <cctype>
#include <cstring>
#include <iomanip>
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

// Read Ethernet EtherType and skip one VLAN tag when present.
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
static const char *transport_name(uint8_t proto) {
  switch (proto) {
  case IPPROTO_TCP:
    return "TCP";
  case IPPROTO_UDP:
    return "UDP";
  case IPPROTO_ICMP:
    return "ICMP";
  case IPPROTO_ICMPV6:
    return "ICMP6";
  default:
    return nullptr;
  }
}

static void print_transport_ports(uint8_t proto, const uint8_t *l4, uint32_t len) {
  if (proto == IPPROTO_TCP && len >= sizeof(tcphdr)) {
    const auto *tcp = reinterpret_cast<const tcphdr *>(l4);
    std::cout << ntohs(tcp->source) << " > " << ntohs(tcp->dest);
  } else if (proto == IPPROTO_UDP && len >= sizeof(udphdr)) {
    const auto *udp = reinterpret_cast<const udphdr *>(l4);
    std::cout << ntohs(udp->source) << " > " << ntohs(udp->dest);
  }
}

// Emit a short hex preview of the payload.
static void dump_hex(const uint8_t *data, uint32_t len, uint32_t max_len = 16) {
  const uint32_t n = len < max_len ? len : max_len;
  std::cout << " |";
  for (uint32_t i = 0; i < n; ++i) {
    std::cout << ' ' << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<unsigned>(data[i]);
  }
  std::cout << std::dec << std::setfill(' ');
}

// Output format roughly follows tcpdump: endpoint info, protocol, flags, TTL,
// and a short hex preview of the payload.

// Print a one-line IPv4 summary.
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

  std::cout << "IP " << src;
  if (transport_name(ip->protocol)) {
    std::cout << ".";
    print_transport_ports(ip->protocol, l4, l4_len);
  }
  std::cout << " > " << dst;

  if (const char *name = transport_name(ip->protocol)) {
    std::cout << " " << name;
    if (ip->protocol == IPPROTO_TCP && l4_len >= sizeof(tcphdr)) {
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
  } else {
    std::cout << " proto " << static_cast<int>(ip->protocol);
  }

  std::cout << " ttl " << static_cast<int>(ip->ttl) << " len " << len;
  if (l4_len > 0) dump_hex(l4, l4_len);
  std::cout << "\n";
}

// Print a one-line IPv6 summary.
void parse_ipv6_packet(const uint8_t *packet, uint32_t len, size_t l3_offset) {
  if (len < l3_offset + sizeof(ip6_hdr)) return;

  const auto *ip6 = reinterpret_cast<const ip6_hdr *>(packet + l3_offset);
  char src[INET6_ADDRSTRLEN] = {};
  char dst[INET6_ADDRSTRLEN] = {};
  inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
  inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

  const uint8_t *l4 = packet + l3_offset + sizeof(ip6_hdr);
  const uint32_t l4_len = len - static_cast<uint32_t>(l3_offset + sizeof(ip6_hdr));

  std::cout << "IP6 " << src << " > " << dst;
  if (const char *name = transport_name(ip6->ip6_nxt)) {
    std::cout << " " << name << " ";
    print_transport_ports(ip6->ip6_nxt, l4, l4_len);
  } else {
    std::cout << " nh " << static_cast<int>(ip6->ip6_nxt);
  }
  std::cout << " hlim " << static_cast<int>(ip6->ip6_hlim) << " len " << len;
  if (l4_len > 0) dump_hex(l4, l4_len);
  std::cout << "\n";
}

// Route the packet to the right IP parser.
void dispatch_ip_packet(const ParsedPacket &pkt, const uint8_t *packet,
                        uint32_t len) {
  if (pkt.is_ipv4) parse_ipv4_packet(packet, len, pkt.l3_offset);
  else if (pkt.is_ipv6) parse_ipv6_packet(packet, len, pkt.l3_offset);
}
