#include "wallet.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <stdexcept>

extern "C" {
#include "fault_handler.h"
#include "rand.h"
}

namespace {

NTSTATUS fill_random(std::uint8_t* buf, std::size_t len) noexcept {
  while (len != 0) {
    const auto chunk = static_cast<ULONG>(std::min<std::size_t>(
        len, std::numeric_limits<ULONG>::max()));
    const NTSTATUS status = BCryptGenRandom(nullptr, buf, chunk,
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
      return status;
    }
    buf += chunk;
    len -= chunk;
  }
  return 0;
}

void format_random_error(char* message, std::size_t length,
                         NTSTATUS status) noexcept {
  std::snprintf(message, length,
                "BCryptGenRandom failed (NTSTATUS 0x%08lX)",
                static_cast<unsigned long>(status));
}

}  // namespace

extern "C" void random_buffer(std::uint8_t* buf, std::size_t len) {
  if (buf == nullptr && len != 0) {
    std::fputs("random_buffer received a null output buffer.\n", stderr);
    std::fflush(stderr);
    std::abort();
  }
  const NTSTATUS status = fill_random(buf, len);
  if (status != 0) {
    char message[80]{};
    format_random_error(message, sizeof(message), status);
    std::fprintf(stderr, "%s\n", message);
    std::fflush(stderr);
    std::abort();
  }
}

extern "C" void tc_fault_handler(const char* msg) {
  (void)msg;
  std::abort();
}

namespace keyforge {

void secure_wipe(void* data, std::size_t len) noexcept {
  if (data == nullptr) {
    if (len != 0) {
      std::abort();
    }
    return;
  }
  SecureZeroMemory(data, len);
}

void secure_random(std::uint8_t* data, std::size_t len) {
  if (data == nullptr && len != 0) {
    throw std::invalid_argument("secure_random received a null output buffer");
  }
  const NTSTATUS status = fill_random(data, len);
  if (status != 0) {
    char message[80]{};
    format_random_error(message, sizeof(message), status);
    throw std::runtime_error(message);
  }
}

}  // namespace keyforge
