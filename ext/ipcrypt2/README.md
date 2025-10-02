# `ipcrypt2`

A lightweight, self-contained C implementation of the [Methods for IP Address Encryption and Obfuscation](https://ipcrypt-std.github.io/draft-denis-ipcrypt/draft-denis-ipcrypt.html) draft to encrypt (or "obfuscate") IP addresses for privacy, compliance and security purposes.

It supports both IPv4 and IPv6 addresses, and it can optionally preserve the IP format (so an IP address is still recognized as an IP address after encryption). `ipcrypt2` also provides prefix-preserving encryption (preserving network structure while encrypting host portions) and non-deterministic encryption modes, where encrypting the same address multiple times will yield different ciphertexts.

## Features

- **IPv4 and IPv6 support**
  Works seamlessly with both IP address formats.

- **Format-Preserving Encryption (FPE)**
  In "standard" mode, an address is encrypted into another valid IP address. This means that consumers of the data (e.g., logs) still see what appears to be an IP address, but without revealing the original address.

- **Prefix-Preserving Encryption (PFX)**
  IP addresses with the same prefix produce encrypted IP addresses with the same prefix. The prefix can be of any length. Useful for maintaining network topology information while anonymizing individual hosts.

- **Non-Deterministic Encryption**
  Supports non-deterministic encryption using the KIASU-BC and AES-XTX tweakable block ciphers, ensuring that repeated encryptions of the same IP produce different outputs.

- **Fast and Minimal**
  Fast and Minimal: Written in C with no external dependencies. It uses hardware-accelerated AES instructions when available for improved performance, but it also supports a software fallback on any CPU, including WebAssembly environments.

- **Convenient APIs**
  Functions are provided to encrypt/decrypt in-place (16-byte arrays for addresses) or via string-to-string conversions (e.g., `x.x.x.x` → `y.y.y.y`).

- **No Extra Heap Allocations**
  Simple usage and easy to integrate into existing projects. Just compile and link.

## Table of Contents

- [`ipcrypt2`](#ipcrypt2)
  - [Features](#features)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Building as a Static Library with Make](#building-as-a-static-library-with-make)
  - [Building as a Static Library with Zig](#building-as-a-static-library-with-zig)
  - [API Overview](#api-overview)
    - [1. `IPCrypt` Context](#1-ipcrypt-context)
    - [2. Initialization and Deinitialization](#2-initialization-and-deinitialization)
    - [3. Format-Preserving Encryption / Decryption](#3-format-preserving-encryption--decryption)
    - [4. Prefix-Preserving Encryption / Decryption](#4-prefix-preserving-encryption--decryption)
    - [5. Non-Deterministic Encryption / Decryption](#5-non-deterministic-encryption--decryption)
      - [With 8 Byte Tweaks (ND Mode)](#with-8-byte-tweaks-nd-mode)
      - [With 16 Byte Tweaks (NDX Mode)](#with-16-byte-tweaks-ndx-mode)
    - [6. Helper Functions](#6-helper-functions)
  - [Examples](#examples)
    - [Format-Preserving Example](#format-preserving-example)
    - [Prefix-Preserving Example](#prefix-preserving-example)
    - [Non-Deterministic Example](#non-deterministic-example)
  - [Security Considerations](#security-considerations)
  - [Limitations and Assumptions](#limitations-and-assumptions)
  - [Bindings and Other Implementations](#bindings-and-other-implementations)

## Getting Started

`ipcrypt2` is a single C file implementation that can be directly copied into any existing project. Simply include `src/ipcrypt2.c` and `src/include/ipcrypt2.h` in your project and you're ready to go.

1. Download/Clone this repository.
2. Copy `src/ipcrypt2.c` and `src/include/ipcrypt2.h` directly to your project.
3. Build and link them with your application.

If you are cross-compiling for ARM, make sure your toolchain targets AES-enabled ARM CPUs and sets the appropriate flags.

The `untrinsics.h` file is only required on target CPUs that lack AES hardware support. On systems with AES-NI (x86_64) or AES instructions (ARM64), this file is unnecessary.

Alternatively, you can build `ipcrypt2` as a static library. This is useful when you want to:

- Use the library across multiple projects without copying source files
- Manage dependencies more cleanly in larger codebases
- Integrate with build systems that prefer library dependencies

To force usage of `explicit_bzero` to zero-out secrets on de-initialization, define `HAVE_EXPLICIT_BZERO` in your build system.

## Building as a Static Library with Make

Set the appropriate `CFLAGS` if necessary and type:

```sh
make
```

The resulting library is called `libipcrypt2.a`. The header file will be installed from `src/include/ipcrypt2.h`.

## Building as a Static Library with Zig

Zig can compile and link C code. You can typically build the project by running:

```sh
zig build -Doptimize=ReleaseFast
```

or

```sh
zig build -Doptimize=ReleaseSmall
```

The resulting library and headers will be placed into the `zig-out` directory.

## API Overview

All user-facing declarations are in `src/include/ipcrypt2.h`. Here are the key structures and functions:

### 1. `IPCrypt` Context

```c
typedef struct IPCrypt { ... } IPCrypt;
```

- Must be initialized via `ipcrypt_init()` with a 16-byte key.
- Optionally, call `ipcrypt_deinit()` to zero out secrets in memory once done.

### 2. Initialization and Deinitialization

```c
void ipcrypt_init(IPCrypt *ipcrypt, const uint8_t key[IPCRYPT_KEYBYTES]);
void ipcrypt_deinit(IPCrypt *ipcrypt);
```

- **Initialization** loads the user-provided AES key and prepares the context.
- **Deinitialization** scrubs sensitive data from memory.

### 3. Format-Preserving Encryption / Decryption

```c
// For 16-byte (binary) representation of IP addresses:
void ipcrypt_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);
void ipcrypt_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);

// For string-based IP addresses:
size_t ipcrypt_encrypt_ip_str(const IPCrypt *ipcrypt,
                              char encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                              const char *ip_str);

size_t ipcrypt_decrypt_ip_str(const IPCrypt *ipcrypt,
                              char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                              const char *encrypted_ip_str);
```

- **`ipcrypt_encrypt_ip16`** / **`ipcrypt_decrypt_ip16`**: In-place encryption/decryption of a 16-byte buffer. An IPv4 address must be placed inside a 16-byte buffer as an IPv4-mapped IPv6.
- **`ipcrypt_encrypt_ip_str`** / **`ipcrypt_decrypt_ip_str`**: Takes an IP string (IPv4 or IPv6), encrypts it as a new IP, and returns the encrypted address as a string. Decryption reverses that process.

### 4. Prefix-Preserving Encryption / Decryption

```c
typedef struct IPCryptPFX { ... } IPCryptPFX;

void ipcrypt_pfx_init(IPCryptPFX *ipcrypt, const uint8_t key[IPCRYPT_PFX_KEYBYTES]);
void ipcrypt_pfx_deinit(IPCryptPFX *ipcrypt);

// For 16-byte (binary) representation of IP addresses:
void ipcrypt_pfx_encrypt_ip16(const IPCryptPFX *ipcrypt, uint8_t ip16[16]);
void ipcrypt_pfx_decrypt_ip16(const IPCryptPFX *ipcrypt, uint8_t ip16[16]);

// For string-based IP addresses:
size_t ipcrypt_pfx_encrypt_ip_str(const IPCryptPFX *ipcrypt,
                                  char encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                  const char *ip_str);

size_t ipcrypt_pfx_decrypt_ip_str(const IPCryptPFX *ipcrypt,
                                  char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                  const char *encrypted_ip_str);
```

- **Prefix-preserving** mode ensures that IP addresses with the same prefix produce encrypted IP addresses with the same prefix.
- The prefix can be of any length - the encryption preserves the common prefix structure.
- Requires a 32-byte key (`IPCRYPT_PFX_KEYBYTES`).
- Returns 0 on success.
- The output is still a valid IP address, maintaining network topology information.
- Useful for scenarios where you need to anonymize individual hosts while preserving network structure for analysis.

### 5. Non-Deterministic Encryption / Decryption

#### With 8 Byte Tweaks (ND Mode)

```c
void ipcrypt_nd_encrypt_ip16(const IPCrypt *ipcrypt,
                             uint8_t ndip[IPCRYPT_NDIP_BYTES],
                             const uint8_t ip16[16],
                             const uint8_t random[IPCRYPT_TWEAKBYTES]);

void ipcrypt_nd_decrypt_ip16(const IPCrypt *ipcrypt,
                             uint8_t ip16[16],
                             const uint8_t ndip[IPCRYPT_NDIP_BYTES]);

void ipcrypt_nd_encrypt_ip_str(const IPCrypt *ipcrypt,
                               char encrypted_ip_str[IPCRYPT_NDIP_STR_BYTES],
                               const char *ip_str,
                               const uint8_t random[IPCRYPT_TWEAKBYTES]);

size_t ipcrypt_nd_decrypt_ip_str(const IPCrypt *ipcrypt,
                                 char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                 const char *encrypted_ip_str);
```

- **Non-deterministic** mode takes a random 8-byte tweak (`random[IPCRYPT_TWEAKBYTES]`).
- Even if you encrypt the same IP multiple times with the same key, encrypted values will be unique, which helps mitigate traffic analysis or repeated-pattern attacks.
- This mode is _not_ format-preserving: the output is 24 bytes (or 48 hex characters).

#### With 16 Byte Tweaks (NDX Mode)

```c
typedef struct IPCryptNDX { ... } IPCryptNDX;

void ipcrypt_ndx_init(IPCryptNDX *ipcrypt,
                      const uint8_t key[IPCRYPT_NDX_KEYBYTES]);

void ipcrypt_ndx_deinit(IPCryptNDX *ipcrypt);

void ipcrypt_ndx_encrypt_ip16(const IPCryptNDX *ipcrypt,
                              uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES],
                              const uint8_t ip16[16],
                              const uint8_t random[IPCRYPT_NDX_TWEAKBYTES]);

void ipcrypt_ndx_decrypt_ip16(const IPCryptNDX *ipcrypt,
                              uint8_t ip16[16],
                              const uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES]);

void ipcrypt_ndx_encrypt_ip_str(const IPCryptNDX *ipcrypt,
                                char encrypted_ip_str[IPCRYPT_NDX_NDIP_STR_BYTES],
                                const char *ip_str,
                                const uint8_t random[IPCRYPT_NDX_TWEAKBYTES]);

size_t ipcrypt_ndx_decrypt_ip_str(const IPCryptNDX *ipcrypt,
                                  char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                  const char *encrypted_ip_str);
```

- The **NDX non-deterministic** mode takes a random 16-byte tweak (`random[IPCRYPT_NDX_TWEAKBYTES]`) and a 32-byte key (`IPCRYPT_NDX_KEYBYTES`).
- Returns 0 on success.
- Even if you encrypt the same IP multiple times with the same key, encrypted values will be unique, which helps mitigate traffic analysis or repeated-pattern attacks.
- This mode is _not_ format-preserving: the output is 32 bytes (or 64 hex characters).

The NDX mode is similar to the ND mode, but larger tweaks make it even more difficult to detect repeated IP addresses. The downside is that it runs at half the speed of ND mode and produces larger ciphertexts.

### 6. Helper Functions

```c
int ipcrypt_str_to_ip16(uint8_t ip16[16], const char *ip_str);
size_t ipcrypt_ip16_to_str(char ip_str[IPCRYPT_MAX_IP_STR_BYTES], const uint8_t ip16[16]);
int ipcrypt_sockaddr_to_ip16(uint8_t ip16[16], const struct sockaddr *sa);
void ipcrypt_ip16_to_sockaddr(struct sockaddr_storage *sa, const uint8_t ip16[16]);
int ipcrypt_key_from_hex(uint8_t *key, size_t key_len, const char *hex, size_t hex_len);
int ipcrypt_ndip_from_hex(uint8_t ndip[24], size_t key_len, const char *hex, size_t hex_len);
int ipcrypt_ndx_ndip_from_hex(uint8_t ndip[32], size_t key_len, const char *hex, size_t hex_len);
```

- **`ipcrypt_str_to_ip16`** / **`ipcrypt_ip16_to_str`**: Convert between string IP addresses and their 16-byte representation.
- **`ipcrypt_sockaddr_to_ip16`**: Convert a socket address structure to a 16-byte binary IP representation. Supports both IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) socket addresses. For IPv4 addresses, they are converted to IPv4-mapped IPv6 format. Returns `0` on success, or `-1` if the address family is not supported.
- **`ipcrypt_ip16_to_sockaddr`**: Convert a 16-byte binary IP address to a socket address structure. The socket address structure is populated based on the IP format: for IPv4-mapped IPv6 addresses, an IPv4 socket address is created; for other IPv6 addresses, an IPv6 socket address is created. The provided `sockaddr_storage` structure is guaranteed to be large enough to hold any socket address type.
- **`ipcrypt_key_from_hex`**: Convert a hexadecimal string to a secret key. The input string must be exactly 32 or 64 characters long (16 or 32 bytes in hex). Returns `0` on success, or `-1` if the input string is invalid or conversion fails.

## Examples

Below are two illustrative examples of using `ipcrypt2` in C.

### Format-Preserving Example

```c
#include <stdio.h>
#include <string.h>
#include "ipcrypt2.h"

int main(void) {
    // A 16-byte AES key (for demonstration only; keep yours secret!)
    const uint8_t key[IPCRYPT_KEYBYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Example IP (could be IPv4 or IPv6)
    const char *original_ip = "192.168.0.100";  // or "::1"

    IPCrypt ctx;
    ipcrypt_init(&ctx, key);

    // Encrypt
    char encrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_encrypt_ip_str(&ctx, encrypted_ip, original_ip);

    // Decrypt
    char decrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_decrypt_ip_str(&ctx, decrypted_ip, encrypted_ip);

    // Print results
    printf("Original IP : %s\n", original_ip);
    printf("Encrypted IP: %s\n", encrypted_ip);
    printf("Decrypted IP: %s\n", decrypted_ip);

    // Clean up
    ipcrypt_deinit(&ctx);
    return 0;
}
```

### Prefix-Preserving Example

```c
#include <stdio.h>
#include <string.h>
#include "ipcrypt2.h"

int main(void) {
    // A 32-byte AES key for PFX mode
    const uint8_t key[IPCRYPT_PFX_KEYBYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // Example IPv6 addresses
    const char *ip1 = "2001:db8:abcd:1234:5678:90ab:cdef:0123";
    const char *ip2 = "2001:db8:abcd:1234:aaaa:bbbb:cccc:dddd";
    const char *ip3 = "2001:db8:9999:5555:1111:2222:3333:4444";

    IPCryptPFX ctx;
    ipcrypt_pfx_init(&ctx, key);

    // Encrypt multiple IPs
    char encrypted_ip1[IPCRYPT_MAX_IP_STR_BYTES];
    char encrypted_ip2[IPCRYPT_MAX_IP_STR_BYTES];
    char encrypted_ip3[IPCRYPT_MAX_IP_STR_BYTES];

    ipcrypt_pfx_encrypt_ip_str(&ctx, encrypted_ip1, ip1);
    ipcrypt_pfx_encrypt_ip_str(&ctx, encrypted_ip2, ip2);
    ipcrypt_pfx_encrypt_ip_str(&ctx, encrypted_ip3, ip3);

    // Print results
    printf("Original IP1: %s\n", ip1);
    printf("Encrypted   : %s\n\n", encrypted_ip1);

    printf("Original IP2: %s\n", ip2);
    printf("Encrypted   : %s\n\n", encrypted_ip2);

    printf("Original IP3: %s\n", ip3);
    printf("Encrypted   : %s\n\n", encrypted_ip3);

    // Note: ip1 and ip2 share the same prefix (2001:db8:abcd:1234)
    // so their encrypted versions will also share the same prefix

    // Clean up
    ipcrypt_pfx_deinit(&ctx);
    return 0;
}
```

### Non-Deterministic Example

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "ipcrypt2.h"

int main(void) {
    // A 16-byte AES key
    const uint8_t key[IPCRYPT_KEYBYTES] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
    };
    IPCrypt ctx;
    ipcrypt_init(&ctx, key);

    // We'll generate a random 8-byte tweak
    uint8_t random_tweak[IPCRYPT_TWEAKBYTES];
    arc4random_buf(random_tweak, sizeof IPCRYPT_TWEAKBYTES);

    // Input IP
    const char *original_ip = "2607:f8b0:4005:805::200e"; // example IPv6

    // Encrypt string in non-deterministic mode
    char nd_encrypted_str[IPCRYPT_NDIP_STR_BYTES];
    ipcrypt_nd_encrypt_ip_str(&ctx, nd_encrypted_str, original_ip, random_tweak);

    // Decrypt
    char decrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_nd_decrypt_ip_str(&ctx, decrypted_ip, nd_encrypted_str);

    printf("Original IP : %s\n", original_ip);
    printf("ND-Encrypted: %s\n", nd_encrypted_str);
    printf("Decrypted IP: %s\n", decrypted_ip);

    ipcrypt_deinit(&ctx);
    return 0;
}
```

## Security Considerations

1. **Key Management**

   - Standard and ND modes require a secure 16-byte AES key.
   - PFX and NDX modes require a secure 32-byte AES key.
   - Protect keys and ensure they remain secret.
   - Keys should be frequently rotated.

2. **Tweak Randomness** (for non-deterministic modes)

   - **ND mode**: the 8-byte tweak does not need to be secret; however, it should be random or unique for each encryption to prevent predictable patterns. While collisions may become a statistical concern after approximately 2^32 encryptions of the same IP address with the same key, they do not directly expose the IP address without the key.
   - **NDX mode**: the 16-byte tweak does not need to be secret; however, it should be random or unique for each encryption to prevent predictable patterns. Collisions become a statistical concern after approximately 2^64 encryptions of the same IP address with the same key. They only reveal the fact that an IP address was observed multiple times, but not the IP address itself.

3. **IP Format Preservation**

   - In "standard" mode, the library encrypts a 16-byte IP buffer into another 16-byte buffer. After encryption, it _may become a valid IPv6 address even if the original address was IPv4_, or vice versa.

4. **Not a General Purpose Encryption Library**

  - This library is specialized for IP address encryption and may not be suitable for arbitrary data encryption.

## Limitations and Assumptions

- **Architecture**: Optimized for x86_64 and ARM (aarch64) with hardware AES, but fully functional on any CPU using a software fallback. WebAssembly is also supported.
- **Format-Preserving**: Standard encryption is format-preserving at the 16-byte level. However, an original IPv4 may decrypt to an IPv6 format (or vice versa) in string form.

## Bindings and Other Implementations

- [Python (reference implementation)](https://github.com/jedisct1/draft-denis-ipcrypt/tree/main/implementations/python)
- [Rust - Native implementation](https://docs.rs/ipcrypt_rs)
- [Rust - C bindings](https://docs.rs/ipcrypt2)
- [JavaScript (Browser and Node.js)](https://github.com/jedisct1/ipcrypt-js)
- [Go](https://github.com/jedisct1/go-ipcrypt)
- [Java](https://github.com/jedisct1/ipcrypt-java)
- [Lua](https://github.com/jedisct1/ipcrypt-lua)
- [Swift](https://github.com/jedisct1/ipcrypt-swift)
- [Elixir](https://github.com/jedisct1/ipcrypt-elixir)
- [Ruby](https://github.com/jedisct1/ipcrypt-ruby)
- [Kotlin](https://github.com/jedisct1/ipcrypt-kotlin)
- [AWK](https://github.com/jedisct1/ipcrypt.awk)
- [Dart](https://github.com/elliotwutingfeng/ipcrypt)

---

**Enjoy using `ipcrypt2`!** Contributions and bug reports are always welcome. Feel free to open issues or submit pull requests on GitHub to help improve the library.
