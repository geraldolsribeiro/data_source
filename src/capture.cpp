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

// Ring sizing is intentionally centralized so capture-loss tuning has a single
// place to start. Current ring memory is 4 MiB * 64 = 256 MiB, plus normal
// process overhead. This favors burst tolerance over minimum latency.
constexpr unsigned kBlockSize = 1 << 22; // 4 MiB
constexpr unsigned kBlockCount = 64;     // 256 MiB ring
constexpr unsigned kFrameSize = 2048;
constexpr int kPollTimeoutMs = 1000;

// Small ownership record for the mmap-backed packet ring. The actual lifetime
// is managed explicitly in run_capture_loop() because the ring is tied to the
// packet socket and must be unmapped after PACKET_STATISTICS are read.
struct RxRing {
  void *base = nullptr;
  size_t size = 0;
  tpacket_req3 request{};
};

// TPACKET_V3 memory-mapped RX flow:
//
//   setup phase
//   -----------
//   socket(AF_PACKET)
//        |
//        v
//   setsockopt(PACKET_VERSION = TPACKET_V3)
//        |
//        v
//   setsockopt(PACKET_RX_RING = tpacket_req3)
//        |
//        v
//   mmap(fd)  --->  one shared ring visible to kernel and userspace
//
//   runtime phase
//   -------------
//
//        shared mmap ring
//   +----------------------------------------------------------+
//   | block 0 | block 1 | block 2 | ... | block N             |
//   +----------------------------------------------------------+
//       ^                         ^
//       |                         |
//       |                         +-- userspace reads packets from ready blocks
//       +-- kernel writes packets into reusable blocks
//
//   block ownership handoff
//   -----------------------
//
//   +--------+     +----------------+     +-----------+     +------------------+
//   | kernel | --> | TP_STATUS_USER | --> | userspace | --> | TP_STATUS_KERNEL |
//   +--------+     +----------------+     +-----------+     +------------------+
//       ^                                                        |
//       +--------------------------- reuse ----------------------+
//
//   block contents
//   --------------
//
//   +----------------------+-----------------------------------+
//   | tpacket_block_desc   | block metadata                    |
//   |  - num_pkts          | number of packet records          |
//   |  - offset_first_pkt  | first tpacket3_hdr offset         |
//   |  - block_status      | kernel/userspace ownership        |
//   +----------------------+-----------------------------------+
//   | tpacket3_hdr | packet bytes | tpacket3_hdr | packet ... |
//   +----------------------------------------------------------+
//        |    |    |
//        |    |    +-- tp_next_offset: next packet record
//        |    +------- tp_snaplen: captured bytes available
//        +------------ tp_mac: offset to Ethernet header
//
// Benefits of this design:
// - avoids one recvfrom()/read() syscall per packet;
// - avoids copying each packet into a userspace buffer in the hot path;
// - batches packets into blocks, reducing wakeups under high packet rates;
// - lets the kernel absorb bursts while userspace catches up;
// - exposes PACKET_STATISTICS so drops can be measured and tuned.
//
// Important consequence: parser/output latency directly affects loss. If
// userspace holds blocks too long, the kernel can run out of reusable blocks and
// increment PACKET_STATISTICS drop counters.

// Build the TPACKET_V3 ring request.
//
// tpacket_req3 fields used here:
// - tp_block_size:       bytes per block handed between kernel/userspace
// - tp_block_nr:         number of blocks in the ring
// - tp_frame_size:       nominal packet slot size used to derive frame count
// - tp_frame_nr:         total frame count implied by blocks and frame size
// - tp_retire_blk_tov:   timeout for delivering partially filled blocks
// - tp_feature_req_word: optional metadata requested from the kernel
//
// Larger blocks improve batching. The retire timeout prevents low-traffic links
// from waiting forever for a block to fill completely.
tpacket_req3 make_ring_request() {
  tpacket_req3 req{};
  req.tp_block_size = kBlockSize;
  req.tp_block_nr = kBlockCount;
  req.tp_frame_size = kFrameSize;
  req.tp_frame_nr = (kBlockSize / kFrameSize) * kBlockCount;
  // Partially filled blocks are retired after ~60 ms. Lower values reduce
  // latency at the cost of more frequent wakeups.
  req.tp_retire_blk_tov = 60;
  req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
  return req;
}

// Best-effort page-fault reduction. The program still runs if this fails,
// because many systems require elevated RLIMIT_MEMLOCK for mlockall().
void try_lock_process_memory() {
  if (::mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
    std::cerr << "warning: mlockall failed; capture may be more drop-prone: "
              << std::strerror(errno) << "\n";
  }
}

// Ask the kernel to allocate the PACKET_RX_RING, then mmap it into userspace.
// After mmap(), packet bytes are read directly from shared kernel/user memory;
// there is no recvfrom() copy per packet in the hot path.
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

// Bind after ring setup so the socket only receives frames from the selected
// link. The interface index comes from if_nametoindex() in main().
void bind_to_interface(int fd, unsigned ifindex) {
  sockaddr_ll bind_addr{};
  bind_addr.sll_family = AF_PACKET;
  bind_addr.sll_protocol = htons(ETH_P_ALL);
  bind_addr.sll_ifindex = static_cast<int>(ifindex);

  die_if(::bind(fd, reinterpret_cast<sockaddr *>(&bind_addr),
                sizeof(bind_addr)) < 0,
         "bind interface");
}

// Compute the address of a TPACKET_V3 block in the mmap region. Blocks are
// fixed-size and indexed circularly; packet records inside each block are
// variable-length and linked by tp_next_offset.
tpacket_block_desc *block_at(const RxRing &ring, unsigned block_index) {
  return reinterpret_cast<tpacket_block_desc *>(
      static_cast<std::byte *>(ring.base) +
      block_index * ring.request.tp_block_size);
}

// Process one tpacket3_hdr record.
//
// - tp_mac:     offset from the record to the captured Ethernet header
// - tp_snaplen: captured byte count available to userspace
//
// tp_snaplen can be smaller than the original wire length, so every parser must
// bounds-check before reading headers.
void process_packet_record(tpacket3_hdr *hdr, uint64_t &packets) {
  const auto *packet = reinterpret_cast<const uint8_t *>(hdr) + hdr->tp_mac;
  const uint32_t len = hdr->tp_snaplen;

  ++packets;
  dispatch_ip_packet(parse_packet(packet, len), packet, len);
}

// Consume every packet in a block that the kernel has marked TP_STATUS_USER.
// The caller is responsible for returning the block to TP_STATUS_KERNEL.
void process_ready_block(tpacket_block_desc *block, uint64_t &packets) {
  uint32_t offset = block->hdr.bh1.offset_to_first_pkt;

  for (uint32_t i = 0; i < block->hdr.bh1.num_pkts; ++i) {
    auto *hdr = reinterpret_cast<tpacket3_hdr *>(
        reinterpret_cast<uint8_t *>(block) + offset);
    process_packet_record(hdr, packets);
    offset += hdr->tp_next_offset;
  }
}

// Sleep when the current block is not ready. Polling prevents a busy-spin while
// still waking promptly when the packet socket becomes readable.
bool wait_for_block(pollfd &pfd) {
  const int rc = ::poll(&pfd, 1, kPollTimeoutMs);
  if (rc < 0 && errno != EINTR) {
    throw std::runtime_error("poll failed");
  }
  return rc > 0;
}

// Return ownership of the block to the kernel. In TPACKET_V3 this is the key
// lifecycle transition: TP_STATUS_USER means userspace owns the block;
// TP_STATUS_KERNEL means the kernel can refill it.
void release_block(tpacket_block_desc *block) {
  block->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

// PACKET_STATISTICS is the feedback loop for tuning. Drops indicate that the
// kernel ring overflowed before userspace returned blocks quickly enough.
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

// ETH_P_ALL receives all link-layer protocols; the attached BPF filter then
// rejects traffic we do not want to parse.
int create_packet_socket() {
  return ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
}

// Socket version must be selected before PACKET_RX_RING is configured.
void configure_packet_socket(int fd) {
  int version = TPACKET_V3;
  die_if(::setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version,
                      sizeof(version)) < 0,
         "setsockopt PACKET_VERSION");
  attach_ip_filter(fd);
}

// Public capture entry point. Setup is separated from the hot loop so each
// decision is testable/reviewable and the loop stays focused on block turnover.
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
