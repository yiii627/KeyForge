# KeyForge

[English](README.md)

KeyForge 是 Windows 控制台程序。启动后自动生成 12 个英文 BIP39 助记词，并显示 BTC、ETH/EVM、SOL 和 TRON 的私钥与地址。

## 功能

- 使用操作系统安全随机源生成 128 位熵和 12 个助记词。
- 使用空 BIP39 passphrase，通过 PBKDF2-HMAC-SHA512 派生 seed。
- 显示助记词，以及以下四条链的派生路径、私钥和地址：

| 链 | 派生路径 | 地址格式 | 私钥格式 |
| --- | --- | --- | --- |
| BTC (Native SegWit) | `m/84'/0'/0'/0/0` | `bc1q…` | 32 字节十六进制 |
| ETH/EVM | `m/44'/60'/0'/0/0` | EIP-55 | 32 字节十六进制 |
| SOL | `m/44'/501'/0'/0'` | Base58 | 64 字节 keypair 的 Base58 编码 |
| TRON | `m/44'/195'/0'/0/0` | Base58Check | 32 字节十六进制 |

## 构建和运行

需要 Windows、MinGW-w64 GCC/G++ 和 CMake。在项目根目录运行：

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
.\build\KeyForge.exe
```

程序需要在 PowerShell、Windows Terminal 或 CMD 的交互式控制台中运行。

## 运行时文件

程序位于 `build/KeyForge.exe`。`dll/` 目录保存 `libstdc++-6.dll` 和 `libgcc_s_seh-1.dll`。复制到其他 64 位 Windows 电脑时，将以下文件放在同一个目录：

```text
KeyForge.exe
libstdc++-6.dll
libgcc_s_seh-1.dll
```

## 目录与许可

- `src/`：程序入口、钱包派生和 Windows 平台代码。
- `trezor-crypto/`：Trezor 密码学源码，版权和许可见各文件头及 `trezor-crypto/LICENSE`。
- `dll/`：MinGW 运行时 DLL。

程序直接在控制台显示助记词和私钥，这些内容可能留在终端滚屏、录屏或系统内存中。请在可信的离线环境中使用和备份。
