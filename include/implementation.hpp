#pragma once

#include <cstdint>
#include <string>

#include "parsed_packet.hpp"

extern bool running;

void on_signal(int);

void die_if(bool cond, const std::string &msg);

void enable_promiscuous(int fd, unsigned ifindex);

ParsedPacket parse_packet(const uint8_t *packet, uint32_t len);

void parse_ipv4_packet(const uint8_t *packet, uint32_t len, size_t l3_offset);

void parse_ipv6_packet(const uint8_t *packet, uint32_t len, size_t l3_offset);

void dispatch_ip_packet(const ParsedPacket &pkt, const uint8_t *packet,
                        uint32_t len);
