#include "fd.hpp"

#include <unistd.h>

Fd::Fd(int fd) : fd_(fd) {}
Fd::~Fd() {
  if (fd_ >= 0) ::close(fd_);
}
int Fd::get() const { return fd_; }
