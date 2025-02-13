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
#include <memory>

#ifndef HAVE_DNSCRYPT

/* let's just define a few types and values so that the rest of
   the code can ignore whether DNSCrypt support is available */
#define DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE (0)

class DNSCryptContext
{
};

class DNSCryptQuery
{
  DNSCryptQuery(const std::shared_ptr<DNSCryptContext>& ctx) :
    d_ctx(ctx)
  {
  }

private:
  std::shared_ptr<DNSCryptContext> d_ctx{nullptr};
};

#else /* HAVE_DNSCRYPT */

#include <string>
#include <vector>
#include <arpa/inet.h>

#include <sodium.h>

#include "dnsname.hh"
#include "lock.hh"
#include "noinitvector.hh"

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
#define DNSCRYPT_CERT_MAGIC_VALUE \
  {0x44, 0x4e, 0x53, 0x43}
#define DNSCRYPT_CERT_PROTOCOL_MINOR_VERSION_VALUE \
  {0x00, 0x00}
#define DNSCRYPT_CLIENT_MAGIC_SIZE (8)
#define DNSCRYPT_RESOLVER_MAGIC \
  {0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
#define DNSCRYPT_RESOLVER_MAGIC_SIZE (8)
#define DNSCRYPT_PADDED_BLOCK_SIZE (64)
#define DNSCRYPT_MAX_TCP_PADDING_SIZE (256)
#define DNSCRYPT_MAX_RESPONSE_PADDING_SIZE (256)
#define DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE (DNSCRYPT_MAX_RESPONSE_PADDING_SIZE + DNSCRYPT_MAC_SIZE)

/* "The client must check for new certificates every hour", so let's use one hour TTL */
#define DNSCRYPT_CERTIFICATE_RESPONSE_TTL (3600)

static_assert(DNSCRYPT_CLIENT_MAGIC_SIZE <= DNSCRYPT_PUBLIC_KEY_SIZE, "DNSCrypt Client Nonce size should be smaller or equal to public key size.");

#define DNSCRYPT_CERT_ES_VERSION1_VALUE \
  {0x00, 0x01}
#define DNSCRYPT_CERT_ES_VERSION2_VALUE \
  {0x00, 0x02}

class DNSCryptContext;

struct DNSCryptCertSignedData
{
  using ResolverPublicKeyType = std::array<unsigned char, DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE>;
  using ResolverPrivateKeyType = std::array<unsigned char, DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE>;
  using ClientMagicType = std::array<unsigned char, DNSCRYPT_CLIENT_MAGIC_SIZE>;
  ResolverPublicKeyType resolverPK{};
  ClientMagicType clientMagic{};
  uint32_t serial{0};
  uint32_t tsStart{0};
  uint32_t tsEnd{0};
};

static_assert(sizeof(DNSCryptCertSignedData) == (DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE + DNSCRYPT_CLIENT_MAGIC_SIZE + 12));
static_assert(std::is_trivially_copyable_v<DNSCryptCertSignedData> == true);

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
    // coverity[store_truncates_time_t]
    return ntohl(getTSStart()) <= static_cast<uint32_t>(now) && static_cast<uint32_t>(now) <= ntohl(getTSEnd());
  }
  using ESVersionType = std::array<unsigned char, 2>;
  using ProtocolMinorVersionType = std::array<unsigned char, 2>;
  using CertMagicType = std::array<unsigned char, DNSCRYPT_CERT_MAGIC_SIZE>;
  CertMagicType magic{};
  ESVersionType esVersion{};
  ProtocolMinorVersionType protocolMinorVersion{};
  std::array<unsigned char, DNSCRYPT_SIGNATURE_SIZE> signature{};
  DNSCryptCertSignedData signedData;
};

static_assert((sizeof(DNSCryptCertSignedData) + DNSCRYPT_SIGNATURE_SIZE) == 116, "Dnscrypt cert signed data size + signature size should be 116!");
static_assert(sizeof(DNSCryptCert) == 124, "Dnscrypt cert size should be 124!");

using DNSCryptClientNonceType = std::array<unsigned char, DNSCRYPT_NONCE_SIZE / 2>;
using DNSCryptNonceType = std::array<unsigned char, DNSCRYPT_NONCE_SIZE>;
using DNSCryptPublicKeyType = std::array<unsigned char, DNSCRYPT_PUBLIC_KEY_SIZE>;
using DNSCryptClientMagicType = std::array<unsigned char, DNSCRYPT_CLIENT_MAGIC_SIZE>;

struct DNSCryptQueryHeader
{
  DNSCryptClientMagicType clientMagic;
  DNSCryptPublicKeyType clientPK;
  DNSCryptClientNonceType clientNonce;
};

static_assert(sizeof(DNSCryptQueryHeader) == 52, "Dnscrypt query header size should be 52!");
static_assert(std::is_trivially_copyable_v<DNSCryptQueryHeader> == true);

struct DNSCryptResponseHeader
{
  // a const std::array is not trivially copyable, unfortunately
  const unsigned char resolverMagic[DNSCRYPT_RESOLVER_MAGIC_SIZE] = DNSCRYPT_RESOLVER_MAGIC;
  DNSCryptNonceType nonce;
};

static_assert(sizeof(DNSCryptResponseHeader) == (DNSCRYPT_RESOLVER_MAGIC_SIZE + DNSCRYPT_NONCE_SIZE), "Dnscrypt response header size is incorrect!");
static_assert(std::is_trivially_copyable_v<DNSCryptResponseHeader> == true);

typedef enum
{
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

  using PrivateKeyType = std::array<unsigned char, DNSCRYPT_PRIVATE_KEY_SIZE>;
  PrivateKeyType key{};
};

struct DNSCryptCertificatePair
{
  using PublicKeyType = std::array<unsigned char, DNSCRYPT_PUBLIC_KEY_SIZE>;
  PublicKeyType publicKey;
  DNSCryptCert cert;
  DNSCryptPrivateKey privateKey;
  bool active{false};
};

class DNSCryptQuery
{
public:
  DNSCryptQuery(const std::shared_ptr<DNSCryptContext>& ctx) :
    d_ctx(ctx)
  {
    memset(&d_header, 0, sizeof(d_header));
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
    memset(&d_sharedKey, 0, sizeof(d_sharedKey));
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
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

  const DNSCryptClientMagicType& getClientMagic() const
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

  void parsePacket(PacketBuffer& packet, bool tcp, time_t now);
  void getDecrypted(bool tcp, PacketBuffer& packet);
  void getCertificateResponse(time_t now, PacketBuffer& response) const;
  int encryptResponse(PacketBuffer& response, size_t maxResponseSize, bool tcp);

  static constexpr size_t s_minUDPLength = 256;

private:
  static void fillServerNonce(DNSCryptNonceType& nonce);

  DNSCryptExchangeVersion getVersion() const;
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int computeSharedKey();
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
  uint16_t computePaddingSize(uint16_t unpaddedLen, size_t maxLen) const;
  bool parsePlaintextQuery(const PacketBuffer& packet);
  bool isEncryptedQuery(const PacketBuffer& packet, bool tcp, time_t now);

  DNSCryptQueryHeader d_header;
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  std::array<unsigned char, crypto_box_BEFORENMBYTES> d_sharedKey;
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
  static void generateProviderKeys(DNSCryptCertSignedData::ResolverPublicKeyType& publicKey, DNSCryptCertSignedData::ResolverPrivateKeyType& privateKey);
  static std::string getProviderFingerprint(const DNSCryptCertSignedData::ResolverPublicKeyType& publicKey);
  static void generateCertificate(uint32_t serial, time_t begin, time_t end, const DNSCryptExchangeVersion& version, const DNSCryptCertSignedData::ResolverPrivateKeyType& providerPrivateKey, DNSCryptPrivateKey& privateKey, DNSCryptCert& cert);
  static void saveCertFromFile(const DNSCryptCert& cert, const std::string& filename);
  static std::string certificateDateToStr(uint32_t date);
  static void generateResolverKeyPair(DNSCryptPrivateKey& privK, DNSCryptPublicKeyType& pubK);
  static void setExchangeVersion(const DNSCryptExchangeVersion& version, DNSCryptCert::ESVersionType& esVersion);
  static DNSCryptExchangeVersion getExchangeVersion(const DNSCryptCert::ESVersionType& esVersion);
  static DNSCryptExchangeVersion getExchangeVersion(const DNSCryptCert& cert);
  static int encryptQuery(PacketBuffer& packet, size_t maximumSize, const DNSCryptCertificatePair::PublicKeyType& clientPublicKey, const DNSCryptPrivateKey& clientPrivateKey, const DNSCryptClientNonceType& clientNonce, bool tcp, const std::shared_ptr<DNSCryptCert>& cert);

  struct CertKeyPaths
  {
    std::string cert;
    std::string key;
  };

  DNSCryptContext(const std::string& pName, const std::vector<CertKeyPaths>& certKeys);
  DNSCryptContext(const std::string& pName, const DNSCryptCert& certificate, const DNSCryptPrivateKey& pKey);
  ~DNSCryptContext();

  void reloadCertificates();
  void loadNewCertificate(const std::string& certFile, const std::string& keyFile, bool active = true, bool reload = false);
  void addNewCertificate(const DNSCryptCert& newCert, const DNSCryptPrivateKey& newKey, bool active = true, bool reload = false);

  void markActive(uint32_t serial);
  void markInactive(uint32_t serial);
  void removeInactiveCertificate(uint32_t serial);
  std::vector<std::shared_ptr<DNSCryptCertificatePair>> getCertificates();
  const DNSName& getProviderName() const { return providerName; }

  bool magicMatchesAPublicKey(DNSCryptQuery& query, time_t now);
  void getCertificateResponse(time_t now, const DNSName& qname, uint16_t qid, PacketBuffer& response);

private:
  static void computePublicKeyFromPrivate(const DNSCryptPrivateKey& privK, DNSCryptCertificatePair::PublicKeyType& pubK);
  static void loadCertFromFile(const std::string& filename, DNSCryptCert& dest);
  static std::shared_ptr<DNSCryptCertificatePair> loadCertificatePair(const std::string& certFile, const std::string& keyFile);

  void addNewCertificate(std::shared_ptr<DNSCryptCertificatePair>& newCert, bool reload = false);

  SharedLockGuarded<std::vector<std::shared_ptr<DNSCryptCertificatePair>>> d_certs;
  SharedLockGuarded<std::vector<CertKeyPaths>> d_certKeyPaths;
  DNSName providerName;
};

bool generateDNSCryptCertificate(const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, DNSCryptExchangeVersion version, DNSCryptCert& certOut, DNSCryptPrivateKey& keyOut);

#endif
