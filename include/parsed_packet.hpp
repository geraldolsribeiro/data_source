#pragma once

#include <cstddef>
#include <cstdint>

// Minimal L2 parse result used for IP dispatch.
struct ParsedPacket {
  uint16_t ethertype = 0;
  size_t l3_offset = 0;
  bool is_ipv4 = false;
  bool is_ipv6 = false;
};
