#include "capture.hpp"
#include "fd.hpp"
#include "implementation.hpp"

#include <net/if.h>

#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char **argv) {
  try {
    if (argc != 2) {
      std::cerr << "Usage: " << argv[0] << " <interface>\n";
      return 1;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    const std::string ifname = argv[1];
    const unsigned ifindex = ::if_nametoindex(ifname.c_str());
    if (ifindex == 0) throw std::runtime_error("Unknown interface: " + ifname);

    Fd fd(create_packet_socket());
    die_if(fd.get() < 0, "socket AF_PACKET");
    configure_packet_socket(fd.get());
    run_capture_loop(fd.get(), ifindex, ifname);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
