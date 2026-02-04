#pragma once

#include <atomic>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <optional>

#include "config.h"
#include "circular_buffer.hh"
#include "lock.hh"
#include "misc.hh"

enum class LibsslTLSVersion : uint8_t { Unknown, TLS10, TLS11, TLS12, TLS13 };

struct TLSCertKeyPair
{
  std::string d_cert;
  std::optional<std::string> d_key;
  std::optional<std::string> d_password;
  explicit TLSCertKeyPair(const std::string& cert, std::optional<std::string> key = std::nullopt, std::optional<std::string> password = std::nullopt):
    d_cert(cert), d_key(std::move(key)), d_password(std::move(password)) {
  }
};

class TLSConfig
{
public:
  std::vector<TLSCertKeyPair> d_certKeyPairs;
  std::vector<std::string> d_ocspFiles;

  std::string d_ciphers;
  std::string d_ciphers13;
  std::string d_ticketKeyFile;
  std::string d_keyLogFile;

  size_t d_maxStoredSessions{20480};
  time_t d_sessionTimeout{0};
  time_t d_ticketsKeyRotationDelay{43200};
  uint8_t d_numberOfTicketsKeys{5};
  LibsslTLSVersion d_minTLSVersion{LibsslTLSVersion::TLS10};

  bool d_preferServerCiphers{true};
  bool d_enableTickets{true};
  /* whether OpenSSL will release I/O buffers when the connection
     becomes idle, saving memory */
  bool d_releaseBuffers{true};
  /* whether so-called secure renegotiation should be allowed for TLS < 1.3 */
  bool d_enableRenegotiation{false};
  /* enable TLS async mode, if supported by any engine */
  bool d_asyncMode{false};
  /* enable kTLS mode, if supported */
  bool d_ktls{false};
  /* set read ahead mode, if supported */
  bool d_readAhead{true};
};

struct TLSErrorCounters
{
  std::atomic<uint64_t> d_dhKeyTooSmall{0}; /* the other side sent a DH value that is not large enough */
  std::atomic<uint64_t> d_inappropriateFallBack{0}; /* SCSV indicates that the client previously tried a higher version,
                                                       something bad is happening */
  std::atomic<uint64_t> d_noSharedCipher{0}; /* we could not agree on a cipher to use */
  std::atomic<uint64_t> d_unknownCipherType{0}; /* unknown cipher type */
  std::atomic<uint64_t> d_unknownKeyExchangeType{0}; /* * unknown exchange type, weird */
  std::atomic<uint64_t> d_unknownProtocol{0}; /* unknown protocol (SSLv2 or TLS 1.4, who knows? */
  std::atomic<uint64_t> d_unsupportedEC{0}; /* unsupported elliptic curve */
  std::atomic<uint64_t> d_unsupportedProtocol{0}; /* we don't accept this TLS version, sorry */
};

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>

void registerOpenSSLUser();
void unregisterOpenSSLUser();

/* From rfc5077 Section 4. Recommended Ticket Construction */
#define TLS_TICKETS_KEY_NAME_SIZE (16)

/* AES-256 */
#define TLS_TICKETS_CIPHER_KEY_SIZE (32)
#define TLS_TICKETS_CIPHER_ALGO (EVP_aes_256_cbc)

/* HMAC SHA-256 */
#define TLS_TICKETS_MAC_KEY_SIZE (32)
#define TLS_TICKETS_MAC_ALGO (EVP_sha256)

class OpenSSLTLSTicketKey
{
public:
  OpenSSLTLSTicketKey();
  OpenSSLTLSTicketKey(std::ifstream& file);
  OpenSSLTLSTicketKey(const std::string& key);
  ~OpenSSLTLSTicketKey();

  bool nameMatches(const unsigned char name[TLS_TICKETS_KEY_NAME_SIZE]) const;

#if OPENSSL_VERSION_MAJOR >= 3
  int encrypt(unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char* iv, EVP_CIPHER_CTX* ectx, EVP_MAC_CTX* hctx) const;
  bool decrypt(const unsigned char* iv, EVP_CIPHER_CTX* ectx, EVP_MAC_CTX* hctx) const;
#else
  int encrypt(unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char* iv, EVP_CIPHER_CTX* ectx, HMAC_CTX* hctx) const;
  bool decrypt(const unsigned char* iv, EVP_CIPHER_CTX* ectx, HMAC_CTX* hctx) const;
#endif

  [[nodiscard]] std::string content() const;

private:
  unsigned char d_name[TLS_TICKETS_KEY_NAME_SIZE];
  unsigned char d_cipherKey[TLS_TICKETS_CIPHER_KEY_SIZE];
  unsigned char d_hmacKey[TLS_TICKETS_MAC_KEY_SIZE];
};

class OpenSSLTLSTicketKeysRing
{
public:
  OpenSSLTLSTicketKeysRing(size_t capacity);
  ~OpenSSLTLSTicketKeysRing();
  std::shared_ptr<OpenSSLTLSTicketKey> getEncryptionKey();
  std::shared_ptr<OpenSSLTLSTicketKey> getDecryptionKey(unsigned char name[TLS_TICKETS_KEY_NAME_SIZE], bool& activeKey);
  size_t getKeysCount();
  void loadTicketsKeys(const std::string& keyFile);
  void loadTicketsKey(const std::string& key);
  void rotateTicketsKey(time_t now);

private:
  void addKey(std::shared_ptr<OpenSSLTLSTicketKey>&& newKey);
  SharedLockGuarded<boost::circular_buffer<std::shared_ptr<OpenSSLTLSTicketKey> > > d_ticketKeys;
};

void* libssl_get_ticket_key_callback_data(SSL* s);
void libssl_set_ticket_key_callback_data(SSL_CTX* ctx, void* data);

#if OPENSSL_VERSION_MAJOR >= 3
int libssl_ticket_key_callback(SSL* s, OpenSSLTLSTicketKeysRing& keyring, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char* iv, EVP_CIPHER_CTX* ectx, EVP_MAC_CTX* hctx, int enc);
#else
int libssl_ticket_key_callback(SSL* s, OpenSSLTLSTicketKeysRing& keyring, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char* iv, EVP_CIPHER_CTX* ectx, HMAC_CTX* hctx, int enc);
#endif

#ifndef DISABLE_OCSP_STAPLING
int libssl_ocsp_stapling_callback(SSL* ssl, const std::map<int, std::string>& ocspMap);
#ifdef HAVE_OCSP_BASIC_SIGN
bool libssl_generate_ocsp_response(const std::string& certFile, const std::string& caCert, const std::string& caKey, const std::string& outFile, int ndays, int nmin);
#endif
#endif /* DISABLE_OCSP_STAPLING */

void libssl_set_error_counters_callback(SSL_CTX& ctx, TLSErrorCounters* counters);

LibsslTLSVersion libssl_tls_version_from_string(const std::string& str);
const std::string& libssl_tls_version_to_string(LibsslTLSVersion version);


namespace pdns::libssl {
class ServerContext
{
public:
  using SharedContext = std::shared_ptr<SSL_CTX>;
  using SNIToContextMap  = std::map<std::string, SharedContext, std::less<>>;

  SharedContext d_defaultContext;
  SNIToContextMap d_sniMap;
  std::map<int, std::string> d_ocspResponses;
};
}

/* add a keypair to an SSL context */
void libssl_setup_context_no_sni(std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>& ctx, const TLSCertKeyPair& pair, std::vector<int>& keyTypes);

/* return the created context, and a list of warning messages for issues not severe enough
   to trigger raising an exception, like failing to load an OCSP response file */
std::pair<std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>, std::vector<std::string>> libssl_init_server_context_no_sni(const TLSConfig& config,
                                                                                                                         std::map<int, std::string>& ocspResponses);
std::pair<pdns::libssl::ServerContext, std::vector<std::string>> libssl_init_server_context(const TLSConfig& config);

pdns::UniqueFilePtr libssl_set_key_log_file(SSL_CTX* ctx, const std::string& logFile);

/* called in a server context, to select an ALPN value advertised by the client if any */
void libssl_set_alpn_select_callback(SSL_CTX* ctx, int (*callback)(SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* inPtr, unsigned int inlen, void* arg), void* arg);
/* set the supported ALPN protos in client context */
bool libssl_set_alpn_protos(SSL_CTX* ctx, const std::vector<std::vector<uint8_t>>& protos);

std::string libssl_get_error_string();

#if defined(HAVE_LIBSSL) && OPENSSL_VERSION_MAJOR >= 3 && defined(HAVE_TLS_PROVIDERS)
std::pair<bool, std::string> libssl_load_provider(const std::string& engineName);
#endif /* HAVE_LIBSSL && OPENSSL_VERSION_MAJOR >= 3 && HAVE_TLS_PROVIDERS */

#if defined(HAVE_LIBSSL) && !defined(HAVE_TLS_PROVIDERS)
std::pair<bool, std::string> libssl_load_engine(const std::string& engineName, const std::optional<std::string>& defaultString);
#endif /* HAVE_LIBSSL && !HAVE_TLS_PROVIDERS */

#endif /* HAVE_LIBSSL */
