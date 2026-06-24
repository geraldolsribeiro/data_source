CXX ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -I../include -I./external
TARGET := test_parse_packet
SRC := test_parse_packet.cpp ../src/implementation.cpp ../src/parsed_packet.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@

clean:
	rm -f $(TARGET)
