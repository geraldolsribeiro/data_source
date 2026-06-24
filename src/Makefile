# Build the packet capture program.

CXX ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -I../include
TARGET := capture_ip
SRC := main.cpp capture.cpp bpf.cpp implementation.cpp fd.cpp parsed_packet.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@

clean:
	rm -f $(TARGET)
