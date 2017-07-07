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

#ifdef HAVE_DNSCRYPT

#include <memory>
#include <string>
#include <vector>
#include <sodium.h>

#include "dnsname.hh"

#define DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE (crypto_sign_ed25519_PUBLICKEYBYTES)
#define DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE (crypto_sign_ed25519_SECRETKEYBYTES)
#define DNSCRYPT_PUBLIC_KEY_SIZE (crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
#define DNSCRYPT_PRIVATE_KEY_SIZE (crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES)
#define DNSCRYPT_NONCE_SIZE (crypto_box_curve25519xsalsa20poly1305_NONCEBYTES)
#define DNSCRYPT_BEFORENM_SIZE (crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES)
#define DNSCRYPT_SIGNATURE_SIZE (crypto_sign_ed25519_BYTES)
#define DNSCRYPT_MAC_SIZE (crypto_box_curve25519xsalsa20poly1305_MACBYTES)
#define DNSCRYPT_CERT_MAGIC_SIZE (4)
#define DNSCRYPT_CERT_MAGIC_VALUE { 0x44, 0x4e, 0x53, 0x43 }
#define DNSCRYPT_CERT_ES_VERSION_VALUE { 0x00, 0x01 }
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

static_assert(DNSCRYPT_CLIENT_MAGIC_SIZE <= DNSCRYPT_PUBLIC_KEY_SIZE, "Dnscrypt Client Nonce size should be smaller or equal to public key size.");

class DnsCryptContext;

struct DnsCryptCertSignedData
{
  unsigned char resolverPK[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char clientMagic[DNSCRYPT_CLIENT_MAGIC_SIZE];
  uint32_t serial;
  uint32_t tsStart;
  uint32_t tsEnd;
};

struct DnsCryptCert
{
  unsigned char magic[DNSCRYPT_CERT_MAGIC_SIZE];
  unsigned char esVersion[2];
  unsigned char protocolMinorVersion[2];
  unsigned char signature[DNSCRYPT_SIGNATURE_SIZE];
  struct DnsCryptCertSignedData signedData;
};

static_assert((sizeof(DnsCryptCertSignedData) + DNSCRYPT_SIGNATURE_SIZE) == 116, "Dnscrypt cert signed data size + signature size should be 116!");
static_assert(sizeof(DnsCryptCert) == 124, "Dnscrypt cert size should be 124!");

struct DnsCryptQueryHeader
{
  unsigned char clientMagic[DNSCRYPT_CLIENT_MAGIC_SIZE];
  unsigned char clientPK[DNSCRYPT_PUBLIC_KEY_SIZE];
  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2];
};

static_assert(sizeof(DnsCryptQueryHeader) == 52, "Dnscrypt query header size should be 52!");

struct DnsCryptResponseHeader
{
  const unsigned char resolverMagic[DNSCRYPT_RESOLVER_MAGIC_SIZE] = DNSCRYPT_RESOLVER_MAGIC;
  unsigned char nonce[DNSCRYPT_NONCE_SIZE];
};

class DnsCryptPrivateKey
{
public:
  DnsCryptPrivateKey();
  ~DnsCryptPrivateKey();
  void loadFromFile(const std::string& keyFile);
  void saveToFile(const std::string& keyFile) const;

  unsigned char key[DNSCRYPT_PRIVATE_KEY_SIZE];
};

class DnsCryptQuery
{
public:
  DnsCryptQuery()
  {
  }
  ~DnsCryptQuery();
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int computeSharedKey(const DnsCryptPrivateKey& privateKey);
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

  static const size_t minUDPLength = 256;

  DnsCryptQueryHeader header;
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  unsigned char sharedKey[crypto_box_BEFORENMBYTES];
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
  DNSName qname;
  DnsCryptContext* ctx;
  uint16_t id{0};
  uint16_t len{0};
  uint16_t paddedLen;
  bool useOldCert{false};
  bool encrypted{false};
  bool valid{false};
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  bool sharedKeyComputed{false};
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
};

class DnsCryptContext
{
public:
  static void generateProviderKeys(unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE], unsigned char privateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE]);
  static std::string getProviderFingerprint(unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE]);
  static void generateCertificate(uint32_t serial, time_t begin, time_t end, const unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE], DnsCryptPrivateKey& privateKey, DnsCryptCert& cert);
  static void saveCertFromFile(const DnsCryptCert& cert, const std::string&filename);
  static std::string certificateDateToStr(uint32_t date);
  static void generateResolverKeyPair(DnsCryptPrivateKey& privK, unsigned char pubK[DNSCRYPT_PUBLIC_KEY_SIZE]);

  DnsCryptContext(const std::string& pName, const std::string& certFile, const std::string& keyFile): providerName(pName)
  {
    loadCertFromFile(certFile, cert);
    privateKey.loadFromFile(keyFile);
    computePublicKeyFromPrivate(privateKey, publicKey);
  }

  DnsCryptContext(const std::string& pName, const DnsCryptCert& certificate, const DnsCryptPrivateKey& pKey): providerName(pName), cert(certificate), privateKey(pKey)
  {
    computePublicKeyFromPrivate(privateKey, publicKey);
  }

  void parsePacket(char* packet, uint16_t packetSize, std::shared_ptr<DnsCryptQuery> query, bool tcp, uint16_t* decryptedQueryLen) const;
  int encryptResponse(char* response, uint16_t responseLen, uint16_t responseSize, const std::shared_ptr<DnsCryptQuery> query, bool tcp, uint16_t* encryptedResponseLen) const;
  void getCertificateResponse(const std::shared_ptr<DnsCryptQuery> query, std::vector<uint8_t>& response) const;
  void loadNewCertificate(const std::string& certFile, const std::string& keyFile);
  void setNewCertificate(const DnsCryptCert& newCert, const DnsCryptPrivateKey& newKey);
  const DnsCryptCert& getCurrentCertificate() const { return cert; };
  const DnsCryptCert& getOldCertificate() const { return oldCert; };
  bool hasOldCertificate() const { return hasOldCert; };
  const std::string& getProviderName() const { return providerName; }
  int encryptQuery(char* query, uint16_t queryLen, uint16_t querySize, const unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE], const DnsCryptPrivateKey& clientPrivateKey, const unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2], bool tcp, uint16_t* encryptedResponseLen) const;


private:
  static void computePublicKeyFromPrivate(const DnsCryptPrivateKey& privK, unsigned char pubK[DNSCRYPT_PUBLIC_KEY_SIZE]);
  static void loadCertFromFile(const std::string&filename, DnsCryptCert& dest);

  void parsePlaintextQuery(const char * packet, uint16_t packetSize, std::shared_ptr<DnsCryptQuery> query) const;
  bool magicMatchesPublicKey(std::shared_ptr<DnsCryptQuery> query) const;
  void isQueryEncrypted(const char * packet, uint16_t packetSize, std::shared_ptr<DnsCryptQuery> query, bool tcp) const;
  void getDecryptedQuery(std::shared_ptr<DnsCryptQuery> query, bool tcp, char* packet, uint16_t packetSize, uint16_t* decryptedQueryLen) const;
  void fillServerNonce(unsigned char* dest) const;
  uint16_t computePaddingSize(uint16_t unpaddedLen, size_t maxLen, const unsigned char* clientNonce) const;

  std::string providerName;
  DnsCryptCert cert;
  DnsCryptCert oldCert;
  DnsCryptPrivateKey privateKey;
  unsigned char publicKey[DNSCRYPT_PUBLIC_KEY_SIZE];
  DnsCryptPrivateKey oldPrivateKey;
  bool hasOldCert{false};
};

#endif
