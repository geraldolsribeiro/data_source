#include "implementation.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

bool running = true;

void on_signal(int) { running = false; }

void die_if(bool cond, const std::string &msg) {
  if (cond) throw std::runtime_error(msg + ": " + std::strerror(errno));
}

void enable_promiscuous(int fd, unsigned ifindex) {
  packet_mreq mreq{};
  mreq.mr_ifindex = static_cast<int>(ifindex);
  mreq.mr_type = PACKET_MR_PROMISC;
  die_if(::setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
                      sizeof(mreq)) < 0,
         "setsockopt PACKET_ADD_MEMBERSHIP");
}

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

void parse_ipv4_packet(const uint8_t *packet, uint32_t len, size_t l3_offset) {
  (void)packet;
  (void)len;
  (void)l3_offset;
}

void parse_ipv6_packet(const uint8_t *packet, uint32_t len, size_t l3_offset) {
  (void)packet;
  (void)len;
  (void)l3_offset;
}

void dispatch_ip_packet(const ParsedPacket &pkt, const uint8_t *packet,
                        uint32_t len) {
  if (pkt.is_ipv4) parse_ipv4_packet(packet, len, pkt.l3_offset);
  else if (pkt.is_ipv6) parse_ipv6_packet(packet, len, pkt.l3_offset);
}
