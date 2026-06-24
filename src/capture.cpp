#include "capture.hpp"

#include "bpf.hpp"
#include "implementation.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace {

constexpr unsigned kBlockSize = 1 << 22; // 4 MiB
constexpr unsigned kBlockCount = 64;     // 256 MiB ring
constexpr unsigned kFrameSize = 2048;
constexpr int kPollTimeoutMs = 1000;

struct RxRing {
  void *base = nullptr;
  size_t size = 0;
  tpacket_req3 request{};
};

// RX ring handoff:
//
//   +--------+     +----------------+     +-----------+     +------------------+
//   | kernel | --> | TP_STATUS_USER | --> | userspace | --> | TP_STATUS_KERNEL |
//   +--------+     +----------------+     +-----------+     +------------------+
//       ^                                                        |
//       +--------------------------- reuse ----------------------+
//
// TPACKET_V3 amortizes syscall overhead by delivering packets in blocks. The
// capture loop must return every consumed block to TP_STATUS_KERNEL quickly;
// slow parsers or blocking output increase the chance of kernel drops.

tpacket_req3 make_ring_request() {
  tpacket_req3 req{};
  req.tp_block_size = kBlockSize;
  req.tp_block_nr = kBlockCount;
  req.tp_frame_size = kFrameSize;
  req.tp_frame_nr = (kBlockSize / kFrameSize) * kBlockCount;
  req.tp_retire_blk_tov = 60;
  req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
  return req;
}

void try_lock_process_memory() {
  if (::mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
    std::cerr << "warning: mlockall failed; capture may be more drop-prone: "
              << std::strerror(errno) << "\n";
  }
}

RxRing create_rx_ring(int fd) {
  RxRing ring{};
  ring.request = make_ring_request();

  die_if(::setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring.request,
                      sizeof(ring.request)) < 0,
         "setsockopt PACKET_RX_RING");

  try_lock_process_memory();

  ring.size = ring.request.tp_block_size * ring.request.tp_block_nr;
  ring.base = ::mmap(nullptr, ring.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                     0);
  die_if(ring.base == MAP_FAILED, "mmap packet ring");
  return ring;
}

void bind_to_interface(int fd, unsigned ifindex) {
  sockaddr_ll bind_addr{};
  bind_addr.sll_family = AF_PACKET;
  bind_addr.sll_protocol = htons(ETH_P_ALL);
  bind_addr.sll_ifindex = static_cast<int>(ifindex);

  die_if(::bind(fd, reinterpret_cast<sockaddr *>(&bind_addr),
                sizeof(bind_addr)) < 0,
         "bind interface");
}

tpacket_block_desc *block_at(const RxRing &ring, unsigned block_index) {
  return reinterpret_cast<tpacket_block_desc *>(
      static_cast<std::byte *>(ring.base) +
      block_index * ring.request.tp_block_size);
}

void process_packet_record(tpacket3_hdr *hdr, uint64_t &packets) {
  const auto *packet = reinterpret_cast<const uint8_t *>(hdr) + hdr->tp_mac;
  const uint32_t len = hdr->tp_snaplen;

  ++packets;
  dispatch_ip_packet(parse_packet(packet, len), packet, len);
}

void process_ready_block(tpacket_block_desc *block, uint64_t &packets) {
  uint32_t offset = block->hdr.bh1.offset_to_first_pkt;

  for (uint32_t i = 0; i < block->hdr.bh1.num_pkts; ++i) {
    auto *hdr = reinterpret_cast<tpacket3_hdr *>(
        reinterpret_cast<uint8_t *>(block) + offset);
    process_packet_record(hdr, packets);
    offset += hdr->tp_next_offset;
  }
}

bool wait_for_block(pollfd &pfd) {
  const int rc = ::poll(&pfd, 1, kPollTimeoutMs);
  if (rc < 0 && errno != EINTR) {
    throw std::runtime_error("poll failed");
  }
  return rc > 0;
}

void release_block(tpacket_block_desc *block) {
  block->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

void print_packet_stats(int fd, uint64_t packets) {
  tpacket_stats_v3 stats{};
  socklen_t stats_len = sizeof(stats);

  if (::getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &stats_len) != 0) {
    return;
  }

  std::cerr << "\nCaptured packets: " << packets << "\n";
  std::cerr << "Kernel packets:    " << stats.tp_packets << "\n";
  std::cerr << "Kernel drops:      " << stats.tp_drops << "\n";
  std::cerr << "Freeze q count:    " << stats.tp_freeze_q_cnt << "\n";
}

} // namespace

int create_packet_socket() {
  return ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
}

void configure_packet_socket(int fd) {
  int version = TPACKET_V3;
  die_if(::setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version,
                      sizeof(version)) < 0,
         "setsockopt PACKET_VERSION");
  attach_ip_filter(fd);
}

void run_capture_loop(int fd, unsigned ifindex, const std::string &ifname) {
  RxRing ring = create_rx_ring(fd);
  bind_to_interface(fd, ifindex);
  enable_promiscuous(fd, ifindex);

  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;

  uint64_t packets = 0;
  unsigned block_index = 0;

  std::cout << "Capturing IPv4/IPv6 traffic on " << ifname << "\n";

  while (running) {
    tpacket_block_desc *block = block_at(ring, block_index);

    if (!(block->hdr.bh1.block_status & TP_STATUS_USER)) {
      wait_for_block(pfd);
      continue;
    }

    process_ready_block(block, packets);
    release_block(block);
    block_index = (block_index + 1) % ring.request.tp_block_nr;
  }

  print_packet_stats(fd, packets);
  ::munmap(ring.base, ring.size);
}
