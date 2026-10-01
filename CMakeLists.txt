cmake_minimum_required(VERSION 3.20)
project(KeyForge LANGUAGES C CXX)

if(NOT MINGW)
  message(FATAL_ERROR "This build currently supports Windows MinGW-w64 only")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CRYPTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/trezor-crypto")

set(CRYPTO_SOURCES
  address base58 bignum bip32 bip39 bip39_english blake256 blake2b
  consteq curves ecdsa groestl hasher hmac hmac_drbg memzero nist256p1
  pbkdf2 rfc6979 ripemd160 secp256k1 segwit_addr sha2 sha3
)
list(TRANSFORM CRYPTO_SOURCES PREPEND "${CRYPTO_DIR}/")
list(TRANSFORM CRYPTO_SOURCES APPEND ".c")
list(APPEND CRYPTO_SOURCES
  "${CRYPTO_DIR}/ed25519-donna/curve25519-donna-32bit.c"
  "${CRYPTO_DIR}/ed25519-donna/curve25519-donna-helpers.c"
  "${CRYPTO_DIR}/ed25519-donna/modm-donna-32bit.c"
  "${CRYPTO_DIR}/ed25519-donna/ed25519-donna-basepoint-table.c"
  "${CRYPTO_DIR}/ed25519-donna/ed25519-donna-32bit-tables.c"
  "${CRYPTO_DIR}/ed25519-donna/ed25519-donna-impl-base.c"
  "${CRYPTO_DIR}/ed25519-donna/ed25519.c"
  "${CRYPTO_DIR}/ed25519-donna/curve25519-donna-scalarmult-base.c"
  "${CRYPTO_DIR}/ed25519-donna/ed25519-sha3.c"
  "${CRYPTO_DIR}/ed25519-donna/ed25519-keccak.c"
)

add_library(trezor_crypto STATIC ${CRYPTO_SOURCES})
target_include_directories(trezor_crypto PUBLIC "${CRYPTO_DIR}")
target_compile_definitions(trezor_crypto PUBLIC
  USE_ETHEREUM=1 USE_KECCAK=1
  USE_BIP39_CACHE=0 USE_BIP32_CACHE=0 USE_BIP32_25519_CURVES=1
  USE_CARDANO=0 USE_MONERO=0 USE_NEM=0
)
target_compile_options(trezor_crypto PRIVATE -O2 -ffunction-sections -fdata-sections)

add_library(keyforge_core STATIC
  src/wallet.cpp
  src/keyforge_platform.cpp
)
target_include_directories(keyforge_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(keyforge_core PUBLIC trezor_crypto bcrypt)
target_compile_options(keyforge_core PRIVATE -O2 -ffunction-sections -fdata-sections)

add_executable(keyforge src/main.cpp)
target_link_libraries(keyforge PRIVATE keyforge_core)
target_link_options(keyforge PRIVATE -Wl,--gc-sections -Wl,--no-undefined)
set_target_properties(keyforge PROPERTIES
  OUTPUT_NAME "KeyForge"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
