# Packet Capture Example

Linux AF_PACKET + TPACKET_V3 packet capture demo.

## Overview

This program:

- opens a raw Linux packet socket
- installs a BPF filter for IPv4/IPv6
- maps a TPACKET_V3 RX ring
- parses IP packets and prints a summary line

## Layout

- `src/main.cpp` — application entry point
- `src/capture.cpp` — socket, ring buffer, polling loop
- `src/bpf.cpp` — packet filter setup
- `src/implementation.cpp` — helpers and packet dispatch
- `src/fd.cpp` — RAII file descriptor wrapper
- `src/parsed_packet.cpp` — packet metadata type

## Layout

- `src/main.cpp` — application entry point
- `src/capture.cpp` — socket, ring buffer, polling loop
- `src/bpf.cpp` — packet filter setup
- `src/implementation.cpp` — helpers and packet dispatch
- `src/fd.cpp` — RAII file descriptor wrapper
- `src/parsed_packet.cpp` — packet metadata type
