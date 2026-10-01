#include "wallet.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

extern "C" {
#include "address.h"
#include "base58.h"
#include "bip32.h"
#include "bip39.h"
#include "hasher.h"
#include "segwit_addr.h"
}

namespace keyforge {
namespace {

constexpr std::uint32_t kHardened = 0x80000000u;

template <typename T>
class ClearOnExit {
 public:
  explicit ClearOnExit(T& value) : value_(value) {}
  ClearOnExit(const ClearOnExit&) = delete;
  ClearOnExit& operator=(const ClearOnExit&) = delete;
  ~ClearOnExit() { secure_wipe(&value_, sizeof(value_)); }

 private:
  T& value_;
};

bool valid_inputs(const std::string& mnemonic, const std::string& passphrase) {
  return passphrase.size() <= 256 &&
         passphrase.find('\0') == std::string::npos &&
         mnemonic_valid(mnemonic);
}

}  // namespace

Wallet::~Wallet() {
  secure_wipe(private_key.data(), private_key.size());
  if (!private_key_text.empty()) {
    secure_wipe(private_key_text.data(), private_key_text.size());
  }
}

bool mnemonic_from_entropy(const std::uint8_t* entropy, std::size_t len,
                           std::string& out) {
  if (!out.empty()) {
    secure_wipe(out.data(), out.size());
  }
  out.clear();
  if (entropy == nullptr || (len != 16 && len != 32)) {
    return false;
  }
  const char* phrase = mnemonic_from_data(entropy, len);
  if (phrase == nullptr) {
    return false;
  }
  struct MnemonicClear {
    ~MnemonicClear() { mnemonic_clear(); }
  } clear;
  out.assign(phrase);
  return true;
}

bool mnemonic_valid(std::string_view mnemonic) {
  if (mnemonic.empty() || mnemonic.size() > BIP39_MAX_MNEMONIC_LEN ||
      mnemonic.find('\0') != std::string_view::npos) {
    return false;
  }
  const auto words = 1 + std::count(mnemonic.begin(), mnemonic.end(), ' ');
  if (words != 12 && words != 24) {
    return false;
  }
  std::string text(mnemonic);
  const bool valid = mnemonic_check(text.c_str()) != 0;
  secure_wipe(text.data(), text.size());
  return valid;
}

bool mnemonic_seed(const std::string& mnemonic, const std::string& passphrase,
                   std::array<std::uint8_t, 64>& out) {
  out.fill(0);
  if (!valid_inputs(mnemonic, passphrase)) {
    return false;
  }
  mnemonic_to_seed(mnemonic.c_str(), passphrase.c_str(), out.data(), nullptr);
  return true;
}

bool derive(const std::array<std::uint8_t, 64>& seed, int chain, Wallet& out) {
  out.address.clear();
  if (!out.private_key_text.empty()) {
    secure_wipe(out.private_key_text.data(), out.private_key_text.size());
    out.private_key_text.clear();
  }
  secure_wipe(out.private_key.data(), out.private_key.size());
  if (chain < 0 || chain > 3) {
    return false;
  }
  HDNode node{};
  ClearOnExit<HDNode> clear_node(node);
  if (!hdnode_from_seed(seed.data(), seed.size(),
                        chain == 2 ? "ed25519" : "secp256k1", &node)) {
    return false;
  }
  constexpr std::uint32_t btc_path[] = {
      kHardened | 84u, kHardened | 0u, kHardened | 0u, 0u, 0u};
  constexpr std::uint32_t eth_path[] = {
      kHardened | 44u, kHardened | 60u, kHardened | 0u, 0u, 0u};
  constexpr std::uint32_t sol_path[] = {
      kHardened | 44u, kHardened | 501u, kHardened | 0u, kHardened | 0u};
  constexpr std::uint32_t tron_path[] = {
      kHardened | 44u, kHardened | 195u, kHardened | 0u, 0u, 0u};
  const std::uint32_t* path = chain == 0 ? btc_path :
                              chain == 1 ? eth_path :
                              chain == 2 ? sol_path : tron_path;
  for (std::size_t i = 0; i < (chain == 2 ? 4u : 5u); ++i) {
    if (!hdnode_private_ckd(&node, path[i])) {
      return false;
    }
  }
  std::array<std::uint8_t, 32> hash{};
  ClearOnExit<decltype(hash)> clear_hash(hash);
  char address[90]{};
  ClearOnExit<decltype(address)> clear_address(address);
  if (chain == 0) {
    if (hdnode_fill_public_key(&node) != 0) {
      return false;
    }
    hasher_Raw(HASHER_SHA2_RIPEMD, node.public_key,
               sizeof(node.public_key), hash.data());
    if (!segwit_addr_encode(address, "bc", 0, hash.data(), 20)) {
      return false;
    }
  } else if (chain == 1) {
    if (!hdnode_get_ethereum_pubkeyhash(&node, hash.data())) {
      return false;
    }
    ethereum_address_checksum(hash.data(), address, false, 0);
  } else if (chain == 2) {
    if (hdnode_fill_public_key(&node) != 0) {
      return false;
    }
    std::array<std::uint8_t, 64> keypair{};
    ClearOnExit<decltype(keypair)> clear_keypair(keypair);
    std::memcpy(keypair.data(), node.private_key, 32);
    std::memcpy(keypair.data() + 32, node.public_key + 1, 32);
    char encoded_key[100]{};
    ClearOnExit<decltype(encoded_key)> clear_encoded_key(encoded_key);
    std::size_t encoded_size = sizeof(encoded_key);
    if (!b58enc(encoded_key, &encoded_size, keypair.data(), keypair.size())) {
      return false;
    }
    encoded_size = sizeof(address);
    if (!b58enc(address, &encoded_size, node.public_key + 1, 32)) {
      return false;
    }
    out.private_key_text.assign(encoded_key);
  } else {
    std::array<std::uint8_t, 65> public_key{};
    ClearOnExit<decltype(public_key)> clear_public_key(public_key);
    if (ecdsa_get_public_key65(node.curve->params, node.private_key,
                               public_key.data()) != 0) {
      return false;
    }
    hasher_Raw(HASHER_SHA3K, public_key.data() + 1, 64, hash.data());
    std::array<std::uint8_t, 21> tron_address{};
    tron_address[0] = 0x41;
    std::memcpy(tron_address.data() + 1, hash.data() + 12, 20);
    if (base58_encode_check(tron_address.data(), tron_address.size(),
                            HASHER_SHA2D, address, sizeof(address)) == 0) {
      return false;
    }
  }
  const std::size_t address_len = strnlen(address, sizeof(address));
  if (address_len == sizeof(address)) {
    return false;
  }
  out.address.assign(address, address_len);
  if (chain != 2) {
    std::memcpy(out.private_key.data(), node.private_key, out.private_key.size());
  }
  return true;
}

}  // namespace keyforge
