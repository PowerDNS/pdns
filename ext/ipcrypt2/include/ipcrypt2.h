#ifndef ipcrypt2_H
#define ipcrypt2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* System headers for socket structures */
#if defined(_WIN32)
#    include <winsock2.h>
#else
#    include <sys/types.h>
/* <sys/types.h> must be included before <sys/socket.h> */
#    include <sys/socket.h>
#endif

/** Size of the AES encryption key, in bytes (128 bits). */
#define IPCRYPT_KEYBYTES 16U

/** Size of the encryption tweak, in bytes (64 bits). */
#define IPCRYPT_TWEAKBYTES 8U

/** Maximum length of an IP address string, including the null terminator. */
#define IPCRYPT_MAX_IP_STR_BYTES 46U

/** Size of the binary output for non-deterministic encryption. */
#define IPCRYPT_NDIP_BYTES 24U

/** Size of the hexadecimal output for non-deterministic encryption, including null terminator. */
#define IPCRYPT_NDIP_STR_BYTES (48U + 1U)

/** Size of the NDX encryption key, in bytes (256 bits). */
#define IPCRYPT_NDX_KEYBYTES 32U

/** Size of the NDX cryption tweak, in bytes (128 bits). */
#define IPCRYPT_NDX_TWEAKBYTES 16U

/** Size of the binary output for NDX encryption. */
#define IPCRYPT_NDX_NDIP_BYTES 32U

/** Size of the hexadecimal output for NDX encryption, including null terminator. */
#define IPCRYPT_NDX_NDIP_STR_BYTES (64U + 1U)

/** Size of the PFX encryption key, in bytes (256 bits). */
#define IPCRYPT_PFX_KEYBYTES 32U

/* -------- Utility functions -------- */

/**
 * Convert an IP address string (IPv4 or IPv6) to a 16-byte binary representation.
 */
int ipcrypt_str_to_ip16(uint8_t ip16[16], const char *ip_str);

/**
 * Convert a 16-byte binary IP address into a string.
 *
 * Returns the length of the resulting string on success, or 0 on error.
 */
size_t ipcrypt_ip16_to_str(char ip_str[IPCRYPT_MAX_IP_STR_BYTES], const uint8_t ip16[16]);

/**
 * Convert a socket address structure to a 16-byte binary IP representation.
 *
 * Supports both IPv4 (AF_INET) and IPv6 (AF_INET6) socket addresses.
 * For IPv4 addresses, they are converted to IPv4-mapped IPv6 format.
 *
 * Returns 0 on success, or -1 if the address family is not supported.
 */
int ipcrypt_sockaddr_to_ip16(uint8_t ip16[16], const struct sockaddr *sa);

/**
 * Convert a 16-byte binary IP address to a socket address structure.
 *
 * The socket address structure is populated based on the IP format:
 * - For IPv4-mapped IPv6 addresses, an IPv4 socket address is created
 * - For other IPv6 addresses, an IPv6 socket address is created
 *
 * The provided sockaddr_storage structure is guaranteed to be large enough
 * to hold any socket address type.
 */
void ipcrypt_ip16_to_sockaddr(struct sockaddr_storage *sa, const uint8_t ip16[16]);

/**
 * Convert a hexadecimal string to a secret key.
 *
 * The input string must be exactly 32 or 64 characters long (IPCRYPT_KEYBYTES or
 * IPCRYPT_NDX_KEYBYTES bytes in hex). Returns 0 on success, or -1 if the input string is invalid or
 * conversion fails.
 */
int ipcrypt_key_from_hex(uint8_t *key, size_t key_len, const char *hex, size_t hex_len);

/**
 * Convert a hexadecimal string to an ipcrypt-nd ciphertext.
 *
 * The input string must be exactly 48 characters long (IPCRYPT_NDIP_BYTES bytes in hex).
 * Returns 0 on success, or -1 if the input string is invalid or conversion fails.
 */
int ipcrypt_ndip_from_hex(uint8_t ndip[IPCRYPT_NDIP_BYTES], const char *hex, size_t hex_len);

/**
 * Convert a hexadecimal string to an ipcrypt-ndx ciphertext.
 *
 * The input string must be exactly 64 characters long (IPCRYPT_NDX_NDIP_BYTES bytes in hex).
 * Returns 0 on success, or -1 if the input string is invalid or conversion fails.
 */
int ipcrypt_ndx_ndip_from_hex(uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES], const char *hex,
                              size_t hex_len);

/* -------- IP encryption -------- */

/**
 * Encryption context structure.
 * Must be initialized with ipcrypt_init() before use.
 */
typedef struct IPCrypt {
    uint8_t opaque[16U * 11];
} IPCrypt;

/**
 * Initialize the IPCrypt context with a 16-byte secret key.
 *
 * The key must:
 * - Be exactly IPCRYPT_KEYBYTES bytes.
 * - Be secret and randomly generated.
 */
void ipcrypt_init(IPCrypt *ipcrypt, const uint8_t key[IPCRYPT_KEYBYTES]);

/**
 * Securely clear and deinitialize the IPCrypt context.
 *
 * Optional: No heap allocations are used, but this ensures secrets are wiped from memory.
 */
void ipcrypt_deinit(IPCrypt *ipcrypt);

/**
 * Encrypt a 16-byte IP address in-place (format-preserving).
 */
void ipcrypt_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);

/**
 * Decrypt a 16-byte IP address in-place (format-preserving).
 */
void ipcrypt_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);

/**
 * Encrypt an IP address string (IPv4 or IPv6).
 *
 * Output is a format-preserving string written to encrypted_ip_str.
 * Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_encrypt_ip_str(const IPCrypt *ipcrypt,
                              char encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES], const char *ip_str);

/**
 * Decrypt a previously encrypted IP address string.
 *
 * Output is written to ip_str. Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_decrypt_ip_str(const IPCrypt *ipcrypt,
                              char           ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                              const char    *encrypted_ip_str);

/**
 * Non-deterministically encrypt a 16-byte IP address using an 8-byte tweak.
 *
 * Output is written to ndip. `random` must be set to a secure 8-byte random value.
 */
void ipcrypt_nd_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ndip[IPCRYPT_NDIP_BYTES],
                             const uint8_t ip16[16], const uint8_t random[IPCRYPT_TWEAKBYTES]);

/**
 * Decrypt a non-deterministically encrypted 16-byte IP address.
 *
 * Input is ndip, and output is written to ip16.
 */
void ipcrypt_nd_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16],
                             const uint8_t ndip[IPCRYPT_NDIP_BYTES]);

/**
 * Encrypt an IP address string non-deterministically.
 *
 * Output is a hex-encoded zero-terminated string written to encrypted_ip_str.
 *`random` must be an 8-byte random value.
 *
 * Returns the output length, without the null terminator.
 */
size_t ipcrypt_nd_encrypt_ip_str(const IPCrypt *ipcrypt,
                                 char           encrypted_ip_str[IPCRYPT_NDIP_STR_BYTES],
                                 const char    *ip_str,
                                 const uint8_t  random[IPCRYPT_TWEAKBYTES]);

/**
 * Decrypt a hex-encoded IP address string from non-deterministic mode.
 *
 * Output is written to ip_str. Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_nd_decrypt_ip_str(const IPCrypt *ipcrypt,
                                 char           ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                 const char    *encrypted_ip_str);

/* -------- Prefix-preserving IP encryption -------- */

/**
 * Encryption context structure for prefix-preserving IP encryption.
 * Must be initialized with ipcrypt_pfx_init() before use.
 */
typedef struct IPCryptPFX {
    uint8_t opaque[16U * 11 * 2];
} IPCryptPFX;

/**
 * Initialize the IPCryptPFX context with a 32-byte secret key.
 *
 * The key must:
 * - Be exactly IPCRYPT_PFX_KEYBYTES bytes.
 * - Be secret and randomly generated.
 *
 * Returns 0 on success.
 */
int ipcrypt_pfx_init(IPCryptPFX *ipcrypt, const uint8_t key[IPCRYPT_PFX_KEYBYTES]);

/**
 * Securely clear and deinitialize the IPCryptPFX context.
 *
 * Optional: No heap allocations are used, but this ensures secrets are wiped from memory.
 */
void ipcrypt_pfx_deinit(IPCryptPFX *ipcrypt);

/**
 * Encrypt a 16-byte IP address in-place with prefix preservation.
 *
 * IP addresses with the same prefix produce encrypted IP addresses with the same prefix.
 * The prefix can be of any length. For IPv4 addresses (stored as IPv4-mapped IPv6),
 * preserves the IPv4 prefix structure.
 */
void ipcrypt_pfx_encrypt_ip16(const IPCryptPFX *ipcrypt, uint8_t ip16[16]);

/**
 * Decrypt a 16-byte IP address in-place with prefix preservation.
 *
 * Reverses the encryption performed by ipcrypt_pfx_encrypt_ip16().
 */
void ipcrypt_pfx_decrypt_ip16(const IPCryptPFX *ipcrypt, uint8_t ip16[16]);

/**
 * Encrypt an IP address string (IPv4 or IPv6) with prefix preservation.
 *
 * Output is a format-preserving string written to encrypted_ip_str.
 * Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_pfx_encrypt_ip_str(const IPCryptPFX *ipcrypt,
                                  char              encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                  const char       *ip_str);

/**
 * Decrypt a previously encrypted IP address string with prefix preservation.
 *
 * Output is written to ip_str. Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_pfx_decrypt_ip_str(const IPCryptPFX *ipcrypt,
                                  char              ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                  const char       *encrypted_ip_str);

/* -------- IP non-deterministic encryption with a 16-byte tweak -------- */

/**
 * Encryption context structure for NDX mode (non-deterministic encryption with 16 bytes of
 * tweak and a 32-byte secret key).
 *
 * Must be initialized with ipcrypt_ndx_init() before use.
 */
typedef struct IPCryptNDX {
    uint8_t opaque[16U * 11 * 2];
} IPCryptNDX;

/**
 * Initialize the IPCryptNDX context with a 32-byte secret key.
 *
 * The key must:
 * - Be exactly IPCRYPT_NDX_KEYBYTES bytes.
 * - Be secret and randomly generated.
 *
 * Returns 0 on success.
 */
int ipcrypt_ndx_init(IPCryptNDX *ipcrypt, const uint8_t key[IPCRYPT_NDX_KEYBYTES]);

/**
 * Securely clear and deinitialize the IPCryptNDX context.
 *
 * Optional: No heap allocations are used, but this ensures secrets are wiped from memory.
 */
void ipcrypt_ndx_deinit(IPCryptNDX *ipcrypt);

/**
 * Non-deterministically encrypt a 16-byte IP address using an 16-byte tweak.
 *
 * Output is written to ndip. `random` must be set to a secure 16-byte random value.
 */
void ipcrypt_ndx_encrypt_ip16(const IPCryptNDX *ipcrypt, uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES],
                              const uint8_t ip16[16], const uint8_t random[IPCRYPT_NDX_TWEAKBYTES]);

/**
 * Decrypt a non-deterministically encrypted 16-byte IP address, previously encrypted with
 * `ipcrypt_ndx_encrypt_ip16`.
 *
 * Input is ndip, and output is written to ip16.
 */
void ipcrypt_ndx_decrypt_ip16(const IPCryptNDX *ipcrypt, uint8_t ip16[16],
                              const uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES]);

/**
 * Encrypt an IP address string non-deterministically.
 *
 * Output is a hex-encoded zero-terminated string written to encrypted_ip_str.
 *`random` must be an 16-byte random value.
 *
 * Returns the output length, without the null terminator.
 */
size_t ipcrypt_ndx_encrypt_ip_str(const IPCryptNDX *ipcrypt,
                                  char              encrypted_ip_str[IPCRYPT_NDX_NDIP_STR_BYTES],
                                  const char *ip_str, const uint8_t random[IPCRYPT_NDX_TWEAKBYTES]);

/**
 * Decrypt a hex-encoded IP address string from non-deterministic mode.
 *
 * Output is written to ip_str. Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_ndx_decrypt_ip_str(const IPCryptNDX *ipcrypt, char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                  const char *encrypted_ip_str);

#ifdef __cplusplus
}
#endif

#endif
