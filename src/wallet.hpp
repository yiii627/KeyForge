#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace keyforge {

void secure_wipe(void* data, std::size_t len) noexcept;
void secure_random(std::uint8_t* data, std::size_t len);

enum class Chain { BTC, ETH, SOL, TRON };
enum class PrivateKeyFormat { Hex, Base58Keypair };

struct ChainInfo {
  Chain chain;
  const char* name;
  const char* curve;
  std::array<std::uint32_t, 5> path;
  std::size_t path_length;
  PrivateKeyFormat private_key_format;
};

const ChainInfo& chain_info(Chain chain);
std::string derivation_path(Chain chain);

struct Wallet {
  const Chain chain;
  std::string address;
  std::string private_key_text;
  std::array<std::uint8_t, 32> private_key{};

  explicit Wallet(Chain chain);
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
bool derive(const std::array<std::uint8_t, 64>& seed, Wallet& out);

}  // namespace keyforge
