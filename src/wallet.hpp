#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace keyforge {

void secure_wipe(void* data, std::size_t len) noexcept;
void secure_random(std::uint8_t* data, std::size_t len);

struct Wallet {
  std::string address;
  std::string private_key_text;
  std::array<std::uint8_t, 32> private_key{};

  Wallet() = default;
  Wallet(const Wallet&) = delete;
  Wallet& operator=(const Wallet&) = delete;
  Wallet(Wallet&&) = delete;
  Wallet& operator=(Wallet&&) = delete;
  ~Wallet();
};

bool mnemonic_from_entropy(const std::uint8_t* entropy, std::size_t len,
                           std::string& out);
bool mnemonic_valid(std::string_view mnemonic);
bool mnemonic_seed(const std::string& mnemonic, const std::string& passphrase,
                   std::array<std::uint8_t, 64>& out);
bool derive(const std::array<std::uint8_t, 64>& seed, int chain, Wallet& out);

}  // namespace keyforge
