# AES128_For_WSPR

A self-contained AES-128 encryption library written in C++, designed for use in [WSPR](https://www.physics.princeton.edu/pulsar/k1jt/wspr.html) (Weak Signal Propagation Reporter) applications. It implements the full AES-128 cipher (NIST FIPS-197) from scratch with no external dependencies, and provides both a low-level block API and a high-level string API with PKCS#7 padding.

---

## Features

- **Pure C++ implementation** — no external crypto libraries required
- **AES-128 ECB mode** — encrypts and decrypts 16-byte aligned blocks
- **PKCS#7 padding** — high-level string wrapper handles arbitrary-length input automatically
- **Validated against NIST FIPS-197 test vectors**
- **Comprehensive test suite** — unit tests and system/integration tests included

---

## File Overview

| File | Description |
|---|---|
| `AES128_Encrypt.h` / `AES128_Encrypt.cpp` | Core AES-128 block encrypt/decrypt (raw bytes, ECB mode) |
| `AES128_StringWrapper.h` / `AES128_StringWrapper.cpp` | High-level `std::string` API with PKCS#7 padding |
| `main.cpp` | Example program demonstrating encryption and decryption |
| `tests/unit/unit_tests.cpp` | Unit tests with NIST known-answer vectors |
| `tests/system/system_tests.cpp` | System/integration tests |

---

## Building

### Requirements

- A C++17-compatible compiler (e.g., `g++`, MSVC, Clang)
- No external libraries needed

### Example build (Linux / macOS)

```bash
# Build and run the demo
g++ -std=c++17 -o demo main.cpp AES128_Encrypt.cpp AES128_StringWrapper.cpp
./demo
```

### Example build (Windows with MinGW-w64 / PowerShell)

```powershell
C:\msys64\ucrt64\bin\g++.exe -std=c++17 -o demo.exe main.cpp AES128_Encrypt.cpp AES128_StringWrapper.cpp
.\demo.exe
```

---

## API Reference

### Core API — `AES128_Encrypt.h`

These functions operate on raw byte buffers. Input must be a multiple of 16 bytes (one AES block).

```cpp
int AES128_Encrypt(const uint8_t* key,
                   uint8_t*       input,
                   size_t         in_size,
                   uint8_t*       output,
                   size_t         out_size);

int AES128_Decrypt(const uint8_t* key,
                   const uint8_t* input,
                   size_t         in_size,
                   uint8_t*       output,
                   size_t         out_size);
```

| Parameter | Description |
|---|---|
| `key` | Pointer to a 16-byte encryption key |
| `input` | Pointer to input data (plaintext for encrypt, ciphertext for decrypt) |
| `in_size` | Size of input in bytes — **must be a multiple of 16** |
| `output` | Pointer to output buffer — may be the same as `input` (in-place) |
| `out_size` | Size of output buffer in bytes — must be `>= in_size` |
| **return** | `0` on success, `-1` on error (null pointer, misaligned size, or buffer too small) |

---

### String Wrapper API — `AES128_StringWrapper.h`

These functions handle `std::string` input and apply PKCS#7 padding automatically, so input does not need to be a multiple of 16 bytes.

```cpp
int AES128_EncryptStringPKCS7(const uint8_t*          key,
                               const std::string&      plaintext,
                               std::vector<uint8_t>&   ciphertext);

int AES128_DecryptStringPKCS7(const uint8_t*              key,
                               const std::vector<uint8_t>& ciphertext,
                               std::string&                plaintext);
```

| Parameter | Description |
|---|---|
| `key` | Pointer to a 16-byte encryption key |
| `plaintext` | (encrypt) Input string of any length |
| `ciphertext` | (encrypt) Output vector that receives encrypted bytes; (decrypt) Input vector of encrypted bytes |
| `plaintext` | (decrypt) Output string that receives the recovered plaintext |
| **return** | `0` on success, `-1` on error (null key, invalid padding, or decryption failure) |

**Note:** The encrypted output is always a multiple of 16 bytes because PKCS#7 padding is always added (even when the input length is already a multiple of 16, a full 16-byte pad block is appended). This ensures the padding can be unambiguously removed on decryption.

---

## Usage Examples

### 1. Encrypt and decrypt a string (recommended for most use cases)

```cpp
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include "AES128_StringWrapper.h"

int main() {
    // 16-byte key (128 bits)
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    const std::string message = "Hello, WSPR!";
    std::vector<uint8_t> ciphertext;
    std::string recovered;

    // Encrypt
    if (AES128_EncryptStringPKCS7(key, message, ciphertext) != 0) {
        std::cerr << "Encryption failed\n";
        return 1;
    }

    // Decrypt
    if (AES128_DecryptStringPKCS7(key, ciphertext, recovered) != 0) {
        std::cerr << "Decryption failed\n";
        return 1;
    }

    std::cout << "Original:  " << message   << "\n";
    std::cout << "Recovered: " << recovered << "\n";
    std::cout << "Match: " << (message == recovered ? "YES" : "NO") << "\n";
    return 0;
}
```

### 2. Encrypt and decrypt raw 16-byte-aligned blocks

```cpp
#include <cstdint>
#include <cstring>
#include <iostream>
#include "AES128_Encrypt.h"

int main() {
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // Plaintext must be a multiple of 16 bytes
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    uint8_t ciphertext[16];
    uint8_t recovered[16];

    // Encrypt
    if (AES128_Encrypt(key, plaintext, 16, ciphertext, 16) != 0) {
        std::cerr << "Encryption failed\n";
        return 1;
    }

    // Decrypt
    if (AES128_Decrypt(key, ciphertext, 16, recovered, 16) != 0) {
        std::cerr << "Decryption failed\n";
        return 1;
    }

    std::cout << "Match: " << (memcmp(plaintext, recovered, 16) == 0 ? "YES" : "NO") << "\n";
    return 0;
}
```

---

## Error Handling

Both APIs return `0` on success and `-1` on failure. Common error conditions:

| Condition | API | Return |
|---|---|---|
| Null `key` or buffer pointer | Core & String | `-1` |
| `in_size` not a multiple of 16 | Core | `-1` |
| Output buffer smaller than input | Core | `-1` |
| Invalid or corrupted PKCS#7 padding | String (decrypt) | `-1` |

Always check return values before using the output.

---

## Running the Tests

### Unit tests (known-answer vectors, including NIST FIPS-197)

```bash
# Linux / macOS
g++ -std=c++17 -o unit_tests AES128_Encrypt.cpp tests/unit/unit_tests.cpp
./unit_tests

# Windows (PowerShell)
C:\msys64\ucrt64\bin\g++.exe -std=c++17 -g AES128_Encrypt.cpp tests\unit\unit_tests.cpp -o unit_tests.exe
.\unit_tests.exe
```

### System / integration tests

```bash
# Linux / macOS
g++ -std=c++17 -o system_tests AES128_Encrypt.cpp AES128_StringWrapper.cpp tests/system/system_tests.cpp
./system_tests

# Windows (PowerShell)
C:\msys64\ucrt64\bin\g++.exe -std=c++17 -g AES128_Encrypt.cpp AES128_StringWrapper.cpp tests\system\system_tests.cpp -o system_tests.exe
.\system_tests.exe
```

An exit code of `0` means all tests in that suite passed.

---

## Implementation Notes

- **Mode:** ECB (Electronic Codebook). Each 16-byte block is encrypted independently. For messages longer than 16 bytes, use a higher-level mode (e.g. CBC) or encrypt each block separately using this library as the primitive.
- **Key size:** 128 bits (exactly 16 bytes). AES-192 and AES-256 are not supported.
- **In-place encryption:** The core API supports using the same buffer for input and output.
- **PKCS#7 padding:** The string wrapper always adds a full pad block when the input length is already a multiple of 16, ensuring unambiguous removal on decryption.
- **No dynamic memory allocation** in the core API — all operations use caller-provided buffers.
