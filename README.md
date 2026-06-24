# Packet Capture Example

Linux AF_PACKET + TPACKET_V3 packet capture demo.

## Layout

- `src/main.cpp` — application entry point
- `src/capture.cpp` — socket, ring buffer, polling loop
- `src/bpf.cpp` — packet filter setup
- `src/implementation.cpp` — helpers and packet dispatch
- `src/fd.cpp` — RAII file descriptor wrapper
- `src/parsed_packet.cpp` — packet metadata type
