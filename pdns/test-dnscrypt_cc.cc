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
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnscrypt.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include <unistd.h>

bool g_verbose{true};
bool g_syslog{true};

BOOST_AUTO_TEST_SUITE(test_dnscrypt_cc)

#ifdef HAVE_DNSCRYPT

// plaintext query for cert
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQuery) {
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.name.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::TXT, QClass::IN, 0);
  pw.getHeader()->rd = 0;
  uint16_t len = plainQuery.size();

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  uint16_t decryptedLen = 0;

  query->parsePacket((char*) plainQuery.data(), len, false, &decryptedLen, now);

  BOOST_CHECK_EQUAL(query->isValid(), true);
  BOOST_CHECK_EQUAL(query->isEncrypted(), false);

  std::vector<uint8_t> response;

  query->getCertificateResponse(now, response);

  MOADNSParser mdp(false, (char*) response.data(), response.size());

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "2.name.");
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::TXT);
}

// invalid plaintext query (A)
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQueryInvalidA) {
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.name.");

  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 0;
  uint16_t len = plainQuery.size();

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  uint16_t decryptedLen = 0;

  query->parsePacket((char*) plainQuery.data(), len, false, &decryptedLen, now);

  BOOST_CHECK_EQUAL(query->isValid(), false);
}

// invalid plaintext query (wrong provider name)
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQueryInvalidProviderName) {
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.WRONG.name.");

  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::TXT, QClass::IN, 0);
  pw.getHeader()->rd = 0;
  uint16_t len = plainQuery.size();

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  uint16_t decryptedLen = 0;

  query->parsePacket((char*) plainQuery.data(), len, false, &decryptedLen, now);

  BOOST_CHECK_EQUAL(query->isValid(), false);
}

// valid encrypted query
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValid) {
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE];

  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B };

  DNSName name("www.powerdns.com.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::AAAA, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  size_t requiredSize = plainQuery.size() + sizeof(DNSCryptQueryHeader) + DNSCRYPT_MAC_SIZE;
  if (requiredSize < DNSCryptQuery::s_minUDPLength) {
    requiredSize = DNSCryptQuery::s_minUDPLength;
  }

  plainQuery.reserve(requiredSize);
  uint16_t len = plainQuery.size();
  uint16_t encryptedResponseLen = 0;

  int res = ctx->encryptQuery((char*) plainQuery.data(), len, plainQuery.capacity(), clientPublicKey, clientPrivateKey, clientNonce, false, &encryptedResponseLen, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(encryptedResponseLen > len);

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  uint16_t decryptedLen = 0;

  query->parsePacket((char*) plainQuery.data(), encryptedResponseLen, false, &decryptedLen, now);

  BOOST_CHECK_EQUAL(query->isValid(), true);
  BOOST_CHECK_EQUAL(query->isEncrypted(), true);

  MOADNSParser mdp(true, (char*) plainQuery.data(), decryptedLen);

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

  BOOST_CHECK_EQUAL(mdp.d_qname, name);
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::AAAA);
}

// valid encrypted query with not enough room
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValidButShort) {
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE];

  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B };

  DNSName name("www.powerdns.com.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::AAAA, QClass::IN, 0);
  pw.getHeader()->rd = 1;

  uint16_t len = plainQuery.size();
  uint16_t encryptedResponseLen = 0;

  int res = ctx->encryptQuery((char*) plainQuery.data(), len, plainQuery.capacity(), clientPublicKey, clientPrivateKey, clientNonce, false, &encryptedResponseLen, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, ENOBUFS);
}

// valid encrypted query with old key
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValidWithOldKey) {
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE];

  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B };

  DNSName name("www.powerdns.com.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::AAAA, QClass::IN, 0);
  pw.getHeader()->rd = 1;

  size_t requiredSize = plainQuery.size() + sizeof(DNSCryptQueryHeader) + DNSCRYPT_MAC_SIZE;
  if (requiredSize < DNSCryptQuery::s_minUDPLength) {
    requiredSize = DNSCryptQuery::s_minUDPLength;
  }

  plainQuery.reserve(requiredSize);

  uint16_t len = plainQuery.size();
  uint16_t encryptedResponseLen = 0;

  int res = ctx->encryptQuery((char*) plainQuery.data(), len, plainQuery.capacity(), clientPublicKey, clientPrivateKey, clientNonce, false, &encryptedResponseLen, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(encryptedResponseLen > len);

  DNSCryptCert newResolverCert;
  DNSCryptContext::generateCertificate(2, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, newResolverCert);
  ctx->addNewCertificate(newResolverCert, resolverPrivateKey);
  ctx->markInactive(resolverCert.getSerial());

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  uint16_t decryptedLen = 0;

  query->parsePacket((char*) plainQuery.data(), encryptedResponseLen, false, &decryptedLen, now);

  BOOST_CHECK_EQUAL(query->isValid(), true);
  BOOST_CHECK_EQUAL(query->isEncrypted(), true);

  MOADNSParser mdp(true, (char*) plainQuery.data(), decryptedLen);

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

  BOOST_CHECK_EQUAL(mdp.d_qname, name);
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::AAAA);
}

// valid encrypted query with wrong key
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryInvalidWithWrongKey) {
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE];

  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B };

  DNSName name("www.powerdns.com.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::AAAA, QClass::IN, 0);
  pw.getHeader()->rd = 1;

  size_t requiredSize = plainQuery.size() + sizeof(DNSCryptQueryHeader) + DNSCRYPT_MAC_SIZE;
  if (requiredSize < DNSCryptQuery::s_minUDPLength) {
    requiredSize = DNSCryptQuery::s_minUDPLength;
  }

  plainQuery.reserve(requiredSize);

  uint16_t len = plainQuery.size();
  uint16_t encryptedResponseLen = 0;

  int res = ctx->encryptQuery((char*) plainQuery.data(), len, plainQuery.capacity(), clientPublicKey, clientPrivateKey, clientNonce, false, &encryptedResponseLen, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(encryptedResponseLen > len);

  DNSCryptCert newResolverCert;
  DNSCryptContext::generateCertificate(2, now, now + (24 * 60 * 3600), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, newResolverCert);
  ctx->addNewCertificate(newResolverCert, resolverPrivateKey);
  ctx->markInactive(resolverCert.getSerial());
  ctx->removeInactiveCertificate(resolverCert.getSerial());

  /* we have removed the old certificate, we can't decrypt this query */

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  uint16_t decryptedLen = 0;

  query->parsePacket((char*) plainQuery.data(), encryptedResponseLen, false, &decryptedLen, now);

  BOOST_CHECK_EQUAL(query->isValid(), false);
}

#endif

BOOST_AUTO_TEST_SUITE_END();
