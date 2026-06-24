#pragma once

// Small RAII wrapper for a file descriptor.
class Fd {
public:
  explicit Fd(int fd = -1);
  ~Fd();

  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;

  int get() const;

private:
  int fd_;
};
