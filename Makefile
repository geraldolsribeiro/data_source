# Top-level Makefile for the packet capture example.

.PHONY: all clean

all:
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean
