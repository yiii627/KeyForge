#include "wallet.hpp"

#include <windows.h>

#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

class SecretWide {
 public:
  SecretWide() { text.reserve(4096); }
  explicit SecretWide(std::wstring value) : text(std::move(value)) {}
  ~SecretWide() { wipe(); }
  SecretWide(const SecretWide&) = delete;
  SecretWide& operator=(const SecretWide&) = delete;
  SecretWide(SecretWide&& other) noexcept : text(std::move(other.text)) {}
  SecretWide& operator=(SecretWide&&) = delete;

  std::wstring text;

 private:
  void wipe() {
    if (!text.empty()) {
      keyforge::secure_wipe(text.data(), text.size() * sizeof(wchar_t));
    }
  }
};

class SecretUtf8 {
 public:
  explicit SecretUtf8(std::string value) : text(std::move(value)) {}
  ~SecretUtf8() {
    if (!text.empty()) {
      keyforge::secure_wipe(text.data(), text.size());
    }
  }
  SecretUtf8(const SecretUtf8&) = delete;
  SecretUtf8& operator=(const SecretUtf8&) = delete;

  std::string text;
};

void write_console(HANDLE output, const std::wstring& text) {
  size_t position = 0;
  while (position < text.size()) {
    const DWORD chunk = static_cast<DWORD>(
        (text.size() - position) > 2048 ? 2048 : text.size() - position);
    DWORD written = 0;
    if (!WriteConsoleW(output, text.data() + position, chunk, &written, nullptr) ||
        written == 0) {
      throw std::runtime_error("cannot write to console");
    }
    position += written;
  }
}

std::wstring ascii_to_wide(const std::string& ascii) {
  return std::wstring(ascii.begin(), ascii.end());
}

std::wstring hex_private(const std::array<uint8_t, 32>& key) {
  constexpr wchar_t digits[] = L"0123456789abcdef";
  std::wstring hex;
  hex.reserve(64);
  for (uint8_t byte : key) {
    hex += digits[byte >> 4];
    hex += digits[byte & 0x0f];
  }
  return hex;
}

void print_wallet(HANDLE output, const wchar_t* label, const wchar_t* path,
                  const keyforge::Wallet& wallet, bool solana) {
  SecretWide private_text(solana ? ascii_to_wide(wallet.private_key_text)
                                 : hex_private(wallet.private_key));
  write_console(output, std::wstring(L"\n") + label + L"  " + path +
                            L"\n  Private key: ");
  write_console(output, private_text.text);
  write_console(output, L"\n  Address:     " + ascii_to_wide(wallet.address) + L"\n");
}

int run(HANDLE output) {
  write_console(output,
                L"KeyForge — Offline Mnemonic Generator (BTC/ETH/SOL/TRON)\n");
  SecretUtf8 mnemonic("");
  std::array<uint8_t, 16> entropy{};
  struct ClearEntropy {
    std::array<uint8_t, 16>& bytes;
    ~ClearEntropy() { keyforge::secure_wipe(bytes.data(), bytes.size()); }
  } clear{entropy};
  keyforge::secure_random(entropy.data(), entropy.size());
  if (!keyforge::mnemonic_from_entropy(entropy.data(), entropy.size(), mnemonic.text)) {
    throw std::runtime_error("could not generate mnemonic");
  }
  keyforge::secure_wipe(entropy.data(), entropy.size());
  write_console(output, L"\nMnemonic:\n");
  {
    SecretWide displayed(ascii_to_wide(mnemonic.text));
    write_console(output, displayed.text);
  }
  write_console(output, L"\n");

  std::array<uint8_t, 64> seed{};
  struct ClearSeed {
    std::array<uint8_t, 64>& bytes;
    ~ClearSeed() { keyforge::secure_wipe(bytes.data(), bytes.size()); }
  } clear_seed{seed};
  if (!keyforge::mnemonic_seed(mnemonic.text, "", seed)) {
    throw std::runtime_error("could not derive seed");
  }
  keyforge::secure_wipe(mnemonic.text.data(), mnemonic.text.size());

  keyforge::Wallet btc;
  keyforge::Wallet eth;
  keyforge::Wallet sol;
  keyforge::Wallet tron;
  if (!keyforge::derive(seed, 0, btc) ||
      !keyforge::derive(seed, 1, eth) ||
      !keyforge::derive(seed, 2, sol) ||
      !keyforge::derive(seed, 3, tron)) {
    throw std::runtime_error("wallet derivation failed");
  }
  keyforge::secure_wipe(seed.data(), seed.size());
  print_wallet(output, L"BTC (Native SegWit)", L"m/84'/0'/0'/0/0", btc, false);
  print_wallet(output, L"ETH/EVM", L"m/44'/60'/0'/0/0", eth, false);
  print_wallet(output, L"SOL", L"m/44'/501'/0'/0'", sol, true);
  print_wallet(output, L"TRON", L"m/44'/195'/0'/0/0", tron, false);
  return 0;
}

}  // namespace

int main(int argc, char*[]) {
  if (argc != 1) {
    std::fputs("KeyForge does not accept command-line arguments.\n", stderr);
    return 1;
  }
  HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  if (output == INVALID_HANDLE_VALUE || !GetConsoleMode(output, &mode)) {
    std::fputs("Run KeyForge in an interactive Windows console.\n", stderr);
    return 1;
  }
  try {
    return run(output);
  } catch (const std::exception& error) {
    try {
      write_console(output,
                    L"\nOperation failed: " + ascii_to_wide(error.what()) + L"\n");
    } catch (...) {
      std::fprintf(stderr, "Operation failed: %s\n", error.what());
    }
    return 1;
  }
}
