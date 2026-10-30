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

需要 64 位 Windows 10 或更新版本、64 位 MinGW-w64 GCC/G++ 工具链，以及 CMake 3.20 或更新版本。在项目根目录运行：

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
.\build\KeyForge.exe
```

## 运行时文件

程序位于 `build/KeyForge.exe`，GCC 和 C++ 运行库采用静态链接。分发时将 `KeyForge.exe` 复制到兼容的 64 位 Windows 电脑。程序依赖 Windows 系统库，包括 BCrypt 和通用 C 运行库（UCRT）；Windows 10 及更新版本自带 UCRT。

使用以下命令查看 EXE 的 DLL 依赖：

```powershell
objdump -p .\build\KeyForge.exe | Select-String "DLL Name"
```

## 目录与许可

- `src/`：程序入口、钱包派生和 Windows 平台代码。
- `trezor-crypto/`：Trezor 密码学源码，版权和许可见各文件头及 `trezor-crypto/LICENSE`。

程序直接在控制台显示助记词和私钥，这些内容可能留在终端滚屏、录屏或系统内存中。请在可信的离线环境中使用和备份。
