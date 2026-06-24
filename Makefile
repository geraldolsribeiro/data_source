# Top-level Makefile for the packet capture example.

.PHONY: all clean test

all:
	$(MAKE) -C src

test:
	$(MAKE) -C test

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
