#include "capture.hpp"

#include "bpf.hpp"
#include "implementation.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>

// RX ring flow:
//
//   [KERNEL fills block] -> [TP_STATUS_USER] -> [userspace parses] -> [TP_STATUS_KERNEL]
//           ^                                                         |
//           +--------------------------- reuse ------------------------+

// Create the raw socket used for link-layer capture.
int create_packet_socket() { return ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); }

// Configure packet-socket options before the RX ring is created.
void configure_packet_socket(int fd) {
  int version = TPACKET_V3;
  die_if(::setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version,
                      sizeof(version)) < 0,
         "setsockopt PACKET_VERSION");
  attach_ip_filter(fd);
}

// Drive the poll/read/parse/recycle loop.
void run_capture_loop(int fd, unsigned ifindex, const std::string &ifname) {
  constexpr unsigned block_size = 1 << 22;
  constexpr unsigned block_nr = 64;
  constexpr unsigned frame_size = 2048;

  // Ring layout: bigger blocks mean fewer wakeups, fewer drops.
  tpacket_req3 req{};
  req.tp_block_size = block_size;
  req.tp_block_nr = block_nr;
  req.tp_frame_size = frame_size;
  req.tp_frame_nr = (block_size / frame_size) * block_nr;
  req.tp_retire_blk_tov = 60;
  req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

  die_if(::setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0,
         "setsockopt PACKET_RX_RING");

  const size_t mmap_size = req.tp_block_size * req.tp_block_nr;
  void *ring = ::mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_LOCKED, fd, 0);
  die_if(ring == MAP_FAILED, "mmap packet ring");

  sockaddr_ll bind_addr{};
  bind_addr.sll_family = AF_PACKET;
  bind_addr.sll_protocol = htons(ETH_P_ALL);
  bind_addr.sll_ifindex = static_cast<int>(ifindex);
  die_if(::bind(fd, reinterpret_cast<sockaddr *>(&bind_addr),
                sizeof(bind_addr)) < 0,
         "bind interface");

  enable_promiscuous(fd, ifindex);

  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;

  uint64_t packets = 0;
  unsigned block_index = 0;
  std::cout << "Capturing IPv4/IPv6 traffic on " << ifname << "\n";

  // Block handoff diagram:
  //   KERNEL fills block -> TP_STATUS_USER -> userspace parses -> TP_STATUS_KERNEL
  while (running) {
    auto *block = reinterpret_cast<tpacket_block_desc *>(
        static_cast<std::byte *>(ring) + block_index * req.tp_block_size);
    if (!(block->hdr.bh1.block_status & TP_STATUS_USER)) {
      int rc = ::poll(&pfd, 1, 1000);
      if (rc < 0 && errno != EINTR) throw std::runtime_error("poll failed");
      continue;
    }

    // Each block holds a packed list of packet records.
    const uint32_t num_pkts = block->hdr.bh1.num_pkts;
    uint32_t offset = block->hdr.bh1.offset_to_first_pkt;
    for (uint32_t i = 0; i < num_pkts; ++i) {
      // Walk the record chain using tp_next_offset.
      auto *hdr = reinterpret_cast<tpacket3_hdr *>(
          reinterpret_cast<uint8_t *>(block) + offset);
      const auto *packet = reinterpret_cast<const uint8_t *>(hdr) + hdr->tp_mac;
      const uint32_t len = hdr->tp_snaplen;
      ++packets;
      dispatch_ip_packet(parse_packet(packet, len), packet, len);
      offset += hdr->tp_next_offset;
    }

    block->hdr.bh1.block_status = TP_STATUS_KERNEL;
    block_index = (block_index + 1) % req.tp_block_nr;
  }

  // Print kernel counters so drops can be spotted during tuning.
  tpacket_stats_v3 stats{};
  socklen_t stats_len = sizeof(stats);
  if (::getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &stats_len) == 0) {
    std::cerr << "\nCaptured packets: " << packets << "\n";
    std::cerr << "Kernel packets:    " << stats.tp_packets << "\n";
    std::cerr << "Kernel drops:      " << stats.tp_drops << "\n";
    std::cerr << "Freeze q count:    " << stats.tp_freeze_q_cnt << "\n";
  }

  ::munmap(ring, mmap_size);
}
