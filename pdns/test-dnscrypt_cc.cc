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
bool g_console{true};
bool g_syslog{true};

BOOST_AUTO_TEST_SUITE(dnscrypt_cc)

#ifdef HAVE_DNSCRYPT

// plaintext query for cert
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQuery) {
  DnsCryptPrivateKey resolverPrivateKey;
  DnsCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(NULL);
  DnsCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  DnsCryptContext ctx("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.name.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::TXT, QClass::IN, 0);
  pw.getHeader()->rd = 0;
  uint16_t len = plainQuery.size();

  std::shared_ptr<DnsCryptQuery> query = std::make_shared<DnsCryptQuery>();
  uint16_t decryptedLen = 0;

  ctx.parsePacket((char*) plainQuery.data(), len, query, false, &decryptedLen);

  BOOST_CHECK_EQUAL(query->valid, true);
  BOOST_CHECK_EQUAL(query->encrypted, false);

  std::vector<uint8_t> response;

  ctx.getCertificateResponse(query, response);

  MOADNSParser mdp(false, (char*) response.data(), response.size());

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0);

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "2.name.");
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::TXT);
}

// invalid plaintext query (A)
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQueryInvalidA) {
    DnsCryptPrivateKey resolverPrivateKey;
  DnsCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(NULL);
  DnsCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  DnsCryptContext ctx("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.name.");

  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 0;
  uint16_t len = plainQuery.size();

  std::shared_ptr<DnsCryptQuery> query = std::make_shared<DnsCryptQuery>();
  uint16_t decryptedLen = 0;

  ctx.parsePacket((char*) plainQuery.data(), len, query, false, &decryptedLen);

  BOOST_CHECK_EQUAL(query->valid, false);
}

// invalid plaintext query (wrong provider name)
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQueryInvalidProviderName) {
  DnsCryptPrivateKey resolverPrivateKey;
  DnsCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(NULL);
  DnsCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  DnsCryptContext ctx("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.WRONG.name.");

  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::TXT, QClass::IN, 0);
  pw.getHeader()->rd = 0;
  uint16_t len = plainQuery.size();

  std::shared_ptr<DnsCryptQuery> query = std::make_shared<DnsCryptQuery>();
  uint16_t decryptedLen = 0;

  ctx.parsePacket((char*) plainQuery.data(), len, query, false, &decryptedLen);

  BOOST_CHECK_EQUAL(query->valid, false);
}

// valid encrypted query
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValid) {
  DnsCryptPrivateKey resolverPrivateKey;
  DnsCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(NULL);
  DnsCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  DnsCryptContext ctx("2.name", resolverCert, resolverPrivateKey);

  DnsCryptPrivateKey clientPrivateKey;
  unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE];

  DnsCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B };

  DNSName name("www.powerdns.com.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::AAAA, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  size_t requiredSize = plainQuery.size() + sizeof(DnsCryptQueryHeader) + DNSCRYPT_MAC_SIZE;
  if (requiredSize < DnsCryptQuery::minUDPLength) {
    requiredSize = DnsCryptQuery::minUDPLength;
  }

  plainQuery.reserve(requiredSize);
  uint16_t len = plainQuery.size();
  uint16_t encryptedResponseLen = 0;

  int res = ctx.encryptQuery((char*) plainQuery.data(), len, plainQuery.capacity(), clientPublicKey, clientPrivateKey, clientNonce, false, &encryptedResponseLen);

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(encryptedResponseLen > len);

  std::shared_ptr<DnsCryptQuery> query = std::make_shared<DnsCryptQuery>();
  uint16_t decryptedLen = 0;

  ctx.parsePacket((char*) plainQuery.data(), encryptedResponseLen, query, false, &decryptedLen);

  BOOST_CHECK_EQUAL(query->valid, true);
  BOOST_CHECK_EQUAL(query->encrypted, true);

  MOADNSParser mdp(true, (char*) plainQuery.data(), decryptedLen);

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0);

  BOOST_CHECK_EQUAL(mdp.d_qname, name);
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::AAAA);
}

// valid encrypted query with not enough room
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValidButShort) {
  DnsCryptPrivateKey resolverPrivateKey;
  DnsCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(NULL);
  DnsCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  DnsCryptContext ctx("2.name", resolverCert, resolverPrivateKey);

  DnsCryptPrivateKey clientPrivateKey;
  unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE];

  DnsCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B };

  DNSName name("www.powerdns.com.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::AAAA, QClass::IN, 0);
  pw.getHeader()->rd = 1;

  uint16_t len = plainQuery.size();
  uint16_t encryptedResponseLen = 0;

  int res = ctx.encryptQuery((char*) plainQuery.data(), len, plainQuery.capacity(), clientPublicKey, clientPrivateKey, clientNonce, false, &encryptedResponseLen);

  BOOST_CHECK_EQUAL(res, ENOBUFS);
}

// valid encrypted query with old key
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValidWithOldKey) {
  DnsCryptPrivateKey resolverPrivateKey;
  DnsCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(NULL);
  DnsCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  DnsCryptContext ctx("2.name", resolverCert, resolverPrivateKey);

  DnsCryptPrivateKey clientPrivateKey;
  unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE];

  DnsCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B };

  DNSName name("www.powerdns.com.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::AAAA, QClass::IN, 0);
  pw.getHeader()->rd = 1;

  size_t requiredSize = plainQuery.size() + sizeof(DnsCryptQueryHeader) + DNSCRYPT_MAC_SIZE;
  if (requiredSize < DnsCryptQuery::minUDPLength) {
    requiredSize = DnsCryptQuery::minUDPLength;
  }

  plainQuery.reserve(requiredSize);

  uint16_t len = plainQuery.size();
  uint16_t encryptedResponseLen = 0;

  int res = ctx.encryptQuery((char*) plainQuery.data(), len, plainQuery.capacity(), clientPublicKey, clientPrivateKey, clientNonce, false, &encryptedResponseLen);

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(encryptedResponseLen > len);

  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  ctx.setNewCertificate(resolverCert, resolverPrivateKey);

  std::shared_ptr<DnsCryptQuery> query = std::make_shared<DnsCryptQuery>();
  uint16_t decryptedLen = 0;

  ctx.parsePacket((char*) plainQuery.data(), encryptedResponseLen, query, false, &decryptedLen);

  BOOST_CHECK_EQUAL(query->valid, true);
  BOOST_CHECK_EQUAL(query->encrypted, true);

  MOADNSParser mdp(true, (char*) plainQuery.data(), decryptedLen);

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0);

  BOOST_CHECK_EQUAL(mdp.d_qname, name);
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::AAAA);
}

// valid encrypted query with wrong key
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryInvalidWithWrongKey) {
  DnsCryptPrivateKey resolverPrivateKey;
  DnsCryptCert resolverCert;
  unsigned char providerPublicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  time_t now = time(NULL);
  DnsCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  DnsCryptContext ctx("2.name", resolverCert, resolverPrivateKey);

  DnsCryptPrivateKey clientPrivateKey;
  unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE];

  DnsCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B };

  DNSName name("www.powerdns.com.");
  vector<uint8_t> plainQuery;
  DNSPacketWriter pw(plainQuery, name, QType::AAAA, QClass::IN, 0);
  pw.getHeader()->rd = 1;

  size_t requiredSize = plainQuery.size() + sizeof(DnsCryptQueryHeader) + DNSCRYPT_MAC_SIZE;
  if (requiredSize < DnsCryptQuery::minUDPLength) {
    requiredSize = DnsCryptQuery::minUDPLength;
  }

  plainQuery.reserve(requiredSize);

  uint16_t len = plainQuery.size();
  uint16_t encryptedResponseLen = 0;

  int res = ctx.encryptQuery((char*) plainQuery.data(), len, plainQuery.capacity(), clientPublicKey, clientPrivateKey, clientNonce, false, &encryptedResponseLen);

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(encryptedResponseLen > len);

  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  ctx.setNewCertificate(resolverCert, resolverPrivateKey);

  DnsCryptContext::generateCertificate(1, now, now + (24 * 60 * 3600), providerPrivateKey, resolverPrivateKey, resolverCert);
  ctx.setNewCertificate(resolverCert, resolverPrivateKey);

  /* we have changed the key two times, we don't have the one used to encrypt this query */

  std::shared_ptr<DnsCryptQuery> query = std::make_shared<DnsCryptQuery>();
  uint16_t decryptedLen = 0;

  ctx.parsePacket((char*) plainQuery.data(), encryptedResponseLen, query, false, &decryptedLen);

  BOOST_CHECK_EQUAL(query->valid, false);
}

#endif

BOOST_AUTO_TEST_SUITE_END();
