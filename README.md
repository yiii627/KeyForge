# KeyForge

[Chinese](README_zh.md)

KeyForge is a Windows console application. On launch, it generates a 12-word English BIP39 mnemonic and displays the private keys and addresses for BTC, ETH/EVM, SOL, and TRON.

## Features

- Generates 128 bits of entropy using the operating system's secure random source and converts it to a 12-word mnemonic.
- Uses an empty BIP39 passphrase and derives the seed with PBKDF2-HMAC-SHA512.
- Displays the mnemonic, derivation path, private key, and address for each chain:

| Chain | Derivation path | Address format | Private key format |
| --- | --- | --- | --- |
| BTC (Native SegWit) | `m/84'/0'/0'/0/0` | `bc1q…` | 32-byte hexadecimal |
| ETH/EVM | `m/44'/60'/0'/0/0` | EIP-55 | 32-byte hexadecimal |
| SOL | `m/44'/501'/0'/0'` | Base58 | Base58-encoded 64-byte keypair |
| TRON | `m/44'/195'/0'/0/0` | Base58Check | 32-byte hexadecimal |

## Build and Run

Windows, MinGW-w64 GCC/G++, and CMake are required. Run these commands from the project root:

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
.\build\KeyForge.exe
```

Run the application in an interactive PowerShell, Windows Terminal, or CMD console.

## Runtime Files

The executable is located at `build/KeyForge.exe`. The `dll/` directory contains `libstdc++-6.dll` and `libgcc_s_seh-1.dll`. To run the application on another 64-bit Windows computer, place these three files in the same directory:

```text
KeyForge.exe
libstdc++-6.dll
libgcc_s_seh-1.dll
```

## Directories and Licenses

- `src/`: Program entry point, wallet derivation, and Windows platform code.
- `trezor-crypto/`: Trezor cryptographic source code. Copyright and license details are in the source file headers and `trezor-crypto/LICENSE`.
- `dll/`: MinGW runtime DLLs.

The application displays the mnemonic and private keys directly in the console. They may remain in terminal scrollback, recordings, or system memory. Use and back up this information only in a trusted offline environment.
