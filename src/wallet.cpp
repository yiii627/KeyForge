#include "wallet.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
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

constexpr std::array<ChainInfo, 4> kChainInfo{{
    {Chain::BTC, "BTC (Native SegWit)", "secp256k1",
     {kHardened | 84u, kHardened | 0u, kHardened | 0u, 0u, 0u},
     5, PrivateKeyFormat::Hex},
    {Chain::ETH, "ETH/EVM", "secp256k1",
     {kHardened | 44u, kHardened | 60u, kHardened | 0u, 0u, 0u},
     5, PrivateKeyFormat::Hex},
    {Chain::SOL, "SOL", "ed25519",
     {kHardened | 44u, kHardened | 501u, kHardened | 0u, kHardened | 0u, 0u},
     4, PrivateKeyFormat::Base58Keypair},
    {Chain::TRON, "TRON", "secp256k1",
     {kHardened | 44u, kHardened | 195u, kHardened | 0u, 0u, 0u},
     5, PrivateKeyFormat::Hex},
}};

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

const ChainInfo& chain_info(Chain chain) {
  for (const auto& info : kChainInfo) {
    if (info.chain == chain) {
      return info;
    }
  }
  throw std::invalid_argument("unsupported chain");
}

std::string derivation_path(Chain chain) {
  const auto& info = chain_info(chain);
  std::string path = "m";
  for (std::size_t i = 0; i < info.path_length; ++i) {
    const std::uint32_t index = info.path[i];
    path += '/';
    path += std::to_string(index & ~kHardened);
    if ((index & kHardened) != 0) {
      path += '\'';
    }
  }
  return path;
}

Wallet::Wallet(Chain chain_value) : chain(chain_value) {
  (void)chain_info(chain);
}

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

bool derive(const std::array<std::uint8_t, 64>& seed, Wallet& out) {
  const auto& info = chain_info(out.chain);
  out.address.clear();
  if (!out.private_key_text.empty()) {
    secure_wipe(out.private_key_text.data(), out.private_key_text.size());
    out.private_key_text.clear();
  }
  secure_wipe(out.private_key.data(), out.private_key.size());
  HDNode node{};
  ClearOnExit<HDNode> clear_node(node);
  if (!hdnode_from_seed(seed.data(), seed.size(), info.curve, &node)) {
    return false;
  }
  for (std::size_t i = 0; i < info.path_length; ++i) {
    if (!hdnode_private_ckd(&node, info.path[i])) {
      return false;
    }
  }
  std::array<std::uint8_t, 32> hash{};
  ClearOnExit<decltype(hash)> clear_hash(hash);
  char address[90]{};
  ClearOnExit<decltype(address)> clear_address(address);
  if (out.chain == Chain::BTC) {
    if (hdnode_fill_public_key(&node) != 0) {
      return false;
    }
    hasher_Raw(HASHER_SHA2_RIPEMD, node.public_key,
               sizeof(node.public_key), hash.data());
    if (!segwit_addr_encode(address, "bc", 0, hash.data(), 20)) {
      return false;
    }
  } else if (out.chain == Chain::ETH) {
    if (!hdnode_get_ethereum_pubkeyhash(&node, hash.data())) {
      return false;
    }
    ethereum_address_checksum(hash.data(), address, false, 0);
  } else if (out.chain == Chain::SOL) {
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
  if (info.private_key_format == PrivateKeyFormat::Hex) {
    std::memcpy(out.private_key.data(), node.private_key, out.private_key.size());
  }
  return true;
}

}  // namespace keyforge
