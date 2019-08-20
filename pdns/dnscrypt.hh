/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include "config.h"

#ifndef HAVE_DNSCRYPT

/* let's just define a few types and values so that the rest of
   the code can ignore whether DNSCrypt support is available */
#define DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE (0)

class DNSCryptContext
{
};

class DNSCryptQuery
{
  DNSCryptQuery(const std::shared_ptr<DNSCryptContext>& ctx): d_ctx(ctx)
  {
  }
private:
  std::shared_ptr<DNSCryptContext> d_ctx{nullptr};
};

#else /* HAVE_DNSCRYPT */

#include <memory>
#include <string>
#include <vector>
#include <arpa/inet.h>

#include <sodium.h>

#include "dnsname.hh"

#define DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE (crypto_sign_ed25519_PUBLICKEYBYTES)
#define DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE (crypto_sign_ed25519_SECRETKEYBYTES)
#define DNSCRYPT_SIGNATURE_SIZE (crypto_sign_ed25519_BYTES)

#define DNSCRYPT_PUBLIC_KEY_SIZE (crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
#define DNSCRYPT_PRIVATE_KEY_SIZE (crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES)
#define DNSCRYPT_NONCE_SIZE (crypto_box_curve25519xsalsa20poly1305_NONCEBYTES)
#define DNSCRYPT_BEFORENM_SIZE (crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES)
#define DNSCRYPT_MAC_SIZE (crypto_box_curve25519xsalsa20poly1305_MACBYTES)

#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
static_assert(crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES == crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES, "DNSCrypt public key size should be the same for all exchange versions");
static_assert(crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES == crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES, "DNSCrypt private key size should be the same for all exchange versions");
static_assert(crypto_box_curve25519xchacha20poly1305_NONCEBYTES == crypto_box_curve25519xsalsa20poly1305_NONCEBYTES, "DNSCrypt nonce size should be the same for all exchange versions");
static_assert(crypto_box_curve25519xsalsa20poly1305_MACBYTES == crypto_box_curve25519xchacha20poly1305_MACBYTES, "DNSCrypt MAC size should be the same for all exchange versions");
static_assert(crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES == crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES, "DNSCrypt BEFORENM size should be the same for all exchange versions");
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */

#define DNSCRYPT_CERT_MAGIC_SIZE (4)
#define DNSCRYPT_CERT_MAGIC_VALUE { 0x44, 0x4e, 0x53, 0x43 }
#define DNSCRYPT_CERT_PROTOCOL_MINOR_VERSION_VALUE { 0x00, 0x00 }
#define DNSCRYPT_CLIENT_MAGIC_SIZE (8)
#define DNSCRYPT_RESOLVER_MAGIC { 0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38 }
#define DNSCRYPT_RESOLVER_MAGIC_SIZE (8)
#define DNSCRYPT_PADDED_BLOCK_SIZE (64)
#define DNSCRYPT_MAX_TCP_PADDING_SIZE (256)
#define DNSCRYPT_MAX_RESPONSE_PADDING_SIZE (256)
#define DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE (DNSCRYPT_MAX_RESPONSE_PADDING_SIZE + DNSCRYPT_MAC_SIZE)

/* "The client must check for new certificates every hour", so let's use one hour TTL */
#define DNSCRYPT_CERTIFICATE_RESPONSE_TTL (3600)

static_assert(DNSCRYPT_CLIENT_MAGIC_SIZE <= DNSCRYPT_PUBLIC_KEY_SIZE, "DNSCrypt Client Nonce size should be smaller or equal to public key size.");

#define DNSCRYPT_CERT_ES_VERSION1_VALUE { 0x00, 0x01 }
#define DNSCRYPT_CERT_ES_VERSION2_VALUE { 0x00, 0x02 }

class DNSCryptContext;

struct DNSCryptCertSignedData
{
  unsigned char resolverPK[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char clientMagic[DNSCRYPT_CLIENT_MAGIC_SIZE];
  uint32_t serial;
  uint32_t tsStart;
  uint32_t tsEnd;
};

class DNSCryptCert
{
public:
  uint32_t getSerial() const
  {
    return ntohl(signedData.serial);
  }
  uint32_t getTSStart() const
  {
    return signedData.tsStart;
  }
  uint32_t getTSEnd() const
  {
    return signedData.tsEnd;
  }
  bool isValid(time_t now) const
  {
    return ntohl(getTSStart()) <= static_cast<uint32_t>(now) && static_cast<uint32_t>(now) <= ntohl(getTSEnd());
  }
  unsigned char magic[DNSCRYPT_CERT_MAGIC_SIZE];
  unsigned char esVersion[2];
  unsigned char protocolMinorVersion[2];
  unsigned char signature[DNSCRYPT_SIGNATURE_SIZE];
  struct DNSCryptCertSignedData signedData;
};

static_assert((sizeof(DNSCryptCertSignedData) + DNSCRYPT_SIGNATURE_SIZE) == 116, "Dnscrypt cert signed data size + signature size should be 116!");
static_assert(sizeof(DNSCryptCert) == 124, "Dnscrypt cert size should be 124!");

struct DNSCryptQueryHeader
{
  unsigned char clientMagic[DNSCRYPT_CLIENT_MAGIC_SIZE];
  unsigned char clientPK[DNSCRYPT_PUBLIC_KEY_SIZE];
  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2];
};

static_assert(sizeof(DNSCryptQueryHeader) == 52, "Dnscrypt query header size should be 52!");

struct DNSCryptResponseHeader
{
  const unsigned char resolverMagic[DNSCRYPT_RESOLVER_MAGIC_SIZE] = DNSCRYPT_RESOLVER_MAGIC;
  unsigned char nonce[DNSCRYPT_NONCE_SIZE];
};

typedef enum {
  VERSION1,
  VERSION2
} DNSCryptExchangeVersion;

class DNSCryptPrivateKey
{
public:
  DNSCryptPrivateKey();
  ~DNSCryptPrivateKey();
  void loadFromFile(const std::string& keyFile);
  void saveToFile(const std::string& keyFile) const;

  unsigned char key[DNSCRYPT_PRIVATE_KEY_SIZE];
};

struct DNSCryptCertificatePair
{
  unsigned char publicKey[DNSCRYPT_PUBLIC_KEY_SIZE];
  DNSCryptCert cert;
  DNSCryptPrivateKey privateKey;
  bool active;
};

class DNSCryptQuery
{
public:
  DNSCryptQuery(const std::shared_ptr<DNSCryptContext>& ctx): d_ctx(ctx)
  {
  }
  ~DNSCryptQuery();

  bool isValid() const
  {
    return d_valid;
  }

  const DNSName& getQName() const
  {
    return d_qname;
  }

  uint16_t getID() const
  {
    return d_id;
  }

  const unsigned char* getClientMagic() const
  {
    return d_header.clientMagic;
  }

  bool isEncrypted() const
  {
    return d_encrypted;
  }

  void setCertificatePair(const std::shared_ptr<DNSCryptCertificatePair>& pair)
  {
    d_pair = pair;
  }

  void parsePacket(char* packet, uint16_t packetSize, bool tcp, uint16_t* decryptedQueryLen, time_t now);
  void getDecrypted(bool tcp, char* packet, uint16_t packetSize, uint16_t* decryptedQueryLen);
  void getCertificateResponse(time_t now, std::vector<uint8_t>& response) const;
  int encryptResponse(char* response, uint16_t responseLen, uint16_t responseSize, bool tcp, uint16_t* encryptedResponseLen);

  static const size_t s_minUDPLength = 256;

private:
  DNSCryptExchangeVersion getVersion() const;
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int computeSharedKey();
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
  void fillServerNonce(unsigned char* dest) const;
  uint16_t computePaddingSize(uint16_t unpaddedLen, size_t maxLen) const;
  bool parsePlaintextQuery(const char * packet, uint16_t packetSize);
  bool isEncryptedQuery(const char * packet, uint16_t packetSize, bool tcp, time_t now);

  DNSCryptQueryHeader d_header;
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  unsigned char d_sharedKey[crypto_box_BEFORENMBYTES];
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
  DNSName d_qname;
  std::shared_ptr<DNSCryptContext> d_ctx{nullptr};
  std::shared_ptr<DNSCryptCertificatePair> d_pair{nullptr};
  uint16_t d_id{0};
  uint16_t d_len{0};
  uint16_t d_paddedLen{0};
  bool d_encrypted{false};
  bool d_valid{false};

#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  bool d_sharedKeyComputed{false};
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
};

class DNSCryptContext
{
public:
  static void generateProviderKeys(unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE], unsigned char privateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE]);
  static std::string getProviderFingerprint(unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE]);
  static void generateCertificate(uint32_t serial, time_t begin, time_t end, const DNSCryptExchangeVersion& version, const unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE], DNSCryptPrivateKey& privateKey, DNSCryptCert& cert);
  static void saveCertFromFile(const DNSCryptCert& cert, const std::string&filename);
  static std::string certificateDateToStr(uint32_t date);
  static void generateResolverKeyPair(DNSCryptPrivateKey& privK, unsigned char pubK[DNSCRYPT_PUBLIC_KEY_SIZE]);
  static void setExchangeVersion(const DNSCryptExchangeVersion& version,  unsigned char esVersion[sizeof(DNSCryptCert::esVersion)]);
  static DNSCryptExchangeVersion getExchangeVersion(const unsigned char esVersion[sizeof(DNSCryptCert::esVersion)]);
  static DNSCryptExchangeVersion getExchangeVersion(const DNSCryptCert& cert);

  struct CertKeyPaths
  {
    std::string cert;
    std::string key;
  };

  DNSCryptContext(const std::string& pName, const std::vector<CertKeyPaths>& certKeys);
  DNSCryptContext(const std::string& pName, const DNSCryptCert& certificate, const DNSCryptPrivateKey& pKey);

  void reloadCertificates();
  void loadNewCertificate(const std::string& certFile, const std::string& keyFile, bool active=true, bool reload=false);
  void addNewCertificate(const DNSCryptCert& newCert, const DNSCryptPrivateKey& newKey, bool active=true, bool reload=false);

  void markActive(uint32_t serial);
  void markInactive(uint32_t serial);
  void removeInactiveCertificate(uint32_t serial);
  std::vector<std::shared_ptr<DNSCryptCertificatePair>> getCertificates() { return d_certs; };
  const DNSName& getProviderName() const { return providerName; }

  int encryptQuery(char* query, uint16_t queryLen, uint16_t querySize, const unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE], const DNSCryptPrivateKey& clientPrivateKey, const unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2], bool tcp, uint16_t* encryptedResponseLen, const std::shared_ptr<DNSCryptCert>& cert) const;
  bool magicMatchesAPublicKey(DNSCryptQuery& query, time_t now);
  void getCertificateResponse(time_t now, const DNSName& qname, uint16_t qid, std::vector<uint8_t>& response);

private:
  static void computePublicKeyFromPrivate(const DNSCryptPrivateKey& privK, unsigned char pubK[DNSCRYPT_PUBLIC_KEY_SIZE]);
  static void loadCertFromFile(const std::string&filename, DNSCryptCert& dest);
  static std::shared_ptr<DNSCryptCertificatePair> loadCertificatePair(const std::string& certFile, const std::string& keyFile);

  void addNewCertificate(std::shared_ptr<DNSCryptCertificatePair>& newCert, bool reload=false);

  pthread_rwlock_t d_lock;
  std::vector<std::shared_ptr<DNSCryptCertificatePair>> d_certs;
  std::vector<CertKeyPaths> d_certKeyPaths;
  DNSName providerName;
};

bool generateDNSCryptCertificate(const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, DNSCryptExchangeVersion version, DNSCryptCert& certOut, DNSCryptPrivateKey& keyOut);

#endif
