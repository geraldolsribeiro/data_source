#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "external/doctest.h"

#include "implementation.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

namespace {

struct EthIpv4Packet {
  std::array<uint8_t, 14 + 20> bytes{};

  EthIpv4Packet() {
    // EtherType IPv4.
    bytes[12] = 0x08;
    bytes[13] = 0x00;
    // IPv4 header length = 20 bytes.
    bytes[14] = 0x45;
    bytes[23] = 17; // UDP
  }
};

struct EthVlanIpv6Packet {
  std::array<uint8_t, 14 + 4 + 40> bytes{};

  EthVlanIpv6Packet() {
    // Outer EtherType = 802.1Q VLAN.
    bytes[12] = 0x81;
    bytes[13] = 0x00;
    // Inner EtherType = IPv6.
    bytes[16] = 0x86;
    bytes[17] = 0xdd;
  }
};

struct ShortFrame {
  std::array<uint8_t, 10> bytes{};
};

struct EthArpPacket {
  std::array<uint8_t, 14> bytes{};

  EthArpPacket() {
    // EtherType ARP.
    bytes[12] = 0x08;
    bytes[13] = 0x06;
  }
};

static std::string capture_stdout(void (*fn)(const uint8_t *, uint32_t, size_t),
                                  const uint8_t *packet, uint32_t len,
                                  size_t l3_offset = 0) {
  std::ostringstream out;
  auto *old = std::cout.rdbuf(out.rdbuf());
  fn(packet, len, l3_offset);
  std::cout.rdbuf(old);
  return out.str();
}

} // namespace

TEST_CASE("parse_packet returns empty data for short frames") {
  ShortFrame pkt{};
  auto parsed = parse_packet(pkt.bytes.data(), pkt.bytes.size());

  CHECK(parsed.ethertype == 0);
  CHECK(parsed.l3_offset == 0);
  CHECK_FALSE(parsed.is_ipv4);
  CHECK_FALSE(parsed.is_ipv6);
}

TEST_CASE("parse_packet identifies IPv4 frames") {
  EthIpv4Packet pkt{};
  auto parsed = parse_packet(pkt.bytes.data(), pkt.bytes.size());

  CHECK(parsed.ethertype == 0x0800);
  CHECK(parsed.l3_offset == 14);
  CHECK(parsed.is_ipv4);
  CHECK_FALSE(parsed.is_ipv6);
}

TEST_CASE("parse_packet skips VLAN tags") {
  EthVlanIpv6Packet pkt{};
  auto parsed = parse_packet(pkt.bytes.data(), pkt.bytes.size());

  CHECK(parsed.ethertype == 0x86dd);
  CHECK(parsed.l3_offset == 18);
  CHECK_FALSE(parsed.is_ipv4);
  CHECK(parsed.is_ipv6);
}

TEST_CASE("parse_packet ignores non-IP frames") {
  EthArpPacket pkt{};
  auto parsed = parse_packet(pkt.bytes.data(), pkt.bytes.size());

  CHECK(parsed.ethertype == 0x0806);
  CHECK(parsed.l3_offset == 14);
  CHECK_FALSE(parsed.is_ipv4);
  CHECK_FALSE(parsed.is_ipv6);
}

TEST_CASE("parse_ipv4_packet prints a tcpdump-like line") {
  std::array<uint8_t, 14 + 20 + 8> pkt{};
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  pkt[14] = 0x45;
  pkt[23] = 17;
  pkt[26] = 1;
  pkt[27] = 2;
  pkt[28] = 3;
  pkt[29] = 4;
  pkt[30] = 5;
  pkt[31] = 6;
  pkt[32] = 7;
  pkt[33] = 8;
  pkt[34] = 0x1f;
  pkt[35] = 0x90;
  pkt[36] = 0x00;
  pkt[37] = 0x35;

  const auto out = capture_stdout(parse_ipv4_packet, pkt.data(), pkt.size(), 14);
  CHECK(out.find("IP 1.2.3.4.8080 > 5.6.7.8.53") != std::string::npos);
  CHECK(out.find("UDP") != std::string::npos);
}

TEST_CASE("parse_ipv6_packet prints a tcpdump-like line") {
  std::array<uint8_t, 14 + 40 + 8> pkt{};
  pkt[12] = 0x86;
  pkt[13] = 0xdd;
  pkt[20] = 17;
  pkt[21] = 64;
  pkt[22] = 0;
  pkt[23] = 0;
  pkt[24] = 0;
  pkt[25] = 0;
  pkt[26] = 0;
  pkt[27] = 0;
  pkt[28] = 0;
  pkt[29] = 1;
  pkt[30] = 0;
  pkt[31] = 0;
  pkt[32] = 0;
  pkt[33] = 0;
  pkt[34] = 0;
  pkt[35] = 0;
  pkt[36] = 0;
  pkt[37] = 2;

  const auto out = capture_stdout(parse_ipv6_packet, pkt.data(), pkt.size(), 14);
  CHECK(out.find("IP6") != std::string::npos);
  CHECK(out.find("hlim 64") != std::string::npos);
}

TEST_CASE("parse_ipv4_packet prints ICMP summaries") {
  std::array<uint8_t, 14 + 20 + 8> pkt{};
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  pkt[14] = 0x45;
  pkt[22] = 64;
  pkt[23] = 1;
  pkt[26] = 192;
  pkt[27] = 0;
  pkt[28] = 2;
  pkt[29] = 1;
  pkt[30] = 198;
  pkt[31] = 51;
  pkt[32] = 100;
  pkt[33] = 2;

  const auto out = capture_stdout(parse_ipv4_packet, pkt.data(), pkt.size(), 14);
  CHECK(out.find("IP 192.0.2.1 > 198.51.100.2 ICMP") != std::string::npos);
}

TEST_CASE("parse_ipv4_packet prints TCP details") {
  std::array<uint8_t, 14 + 20 + 20 + 4> pkt{};
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  pkt[14] = 0x45;
  pkt[22] = 64;
  pkt[23] = 6;
  pkt[26] = 10;
  pkt[27] = 0;
  pkt[28] = 0;
  pkt[29] = 1;
  pkt[30] = 10;
  pkt[31] = 0;
  pkt[32] = 0;
  pkt[33] = 2;
  pkt[34] = 0x30;
  pkt[35] = 0x39;
  pkt[36] = 0x00;
  pkt[37] = 0x50;
  pkt[46] = 0x50;
  pkt[47] = 0x12;
  pkt[48] = 0x12;
  pkt[49] = 0x34;
  pkt[50] = 0x56;
  pkt[51] = 0x78;
  pkt[52] = 0x00;
  pkt[53] = 0x01;
  pkt[54] = 0xde;
  pkt[55] = 0xad;

  const auto out = capture_stdout(parse_ipv4_packet, pkt.data(), pkt.size(), 14);
  CHECK(out.find("TCP flags [SA]") != std::string::npos);
  CHECK(out.find("seq 0") != std::string::npos);
  CHECK(out.find("ack 0") != std::string::npos);
}

TEST_CASE("parse_ipv4_packet prints a compact UDP line") {
  std::array<uint8_t, 14 + 20 + 12> pkt{};
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  pkt[14] = 0x45;
  pkt[23] = 17;
  pkt[26] = 1;
  pkt[27] = 1;
  pkt[28] = 1;
  pkt[29] = 1;
  pkt[30] = 2;
  pkt[31] = 2;
  pkt[32] = 2;
  pkt[33] = 2;
  pkt[34] = 0x1f;
  pkt[35] = 0x90;
  pkt[36] = 0x00;
  pkt[37] = 0x35;
  pkt[38] = 0xaa;
  pkt[39] = 0xbb;
  pkt[40] = 0xcc;
  pkt[41] = 0xdd;
  pkt[42] = 0xee;
  pkt[43] = 0xff;
  pkt[44] = 0x11;
  pkt[45] = 0x22;

  const auto out = capture_stdout(parse_ipv4_packet, pkt.data(), pkt.size(), 14);
  CHECK(out.find("IP 1.1.1.1.8080 > 2.2.2.2.53 UDP") != std::string::npos);
}
