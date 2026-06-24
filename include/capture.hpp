#pragma once

#include <string>

int create_packet_socket();

void configure_packet_socket(int fd);

void run_capture_loop(int fd, unsigned ifindex, const std::string &ifname);
