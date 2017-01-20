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
#include "config.h"
#ifdef HAVE_DNSCRYPT
#include <fstream>
#include "dolog.hh"
#include "dnscrypt.hh"
#include "dnswriter.hh"

DnsCryptPrivateKey::DnsCryptPrivateKey()
{
  sodium_memzero(key, sizeof(key));
  sodium_mlock(key, sizeof(key));
}

void DnsCryptPrivateKey::loadFromFile(const std::string& keyFile)
{
  ifstream file(keyFile);
  sodium_memzero(key, sizeof(key));
  file.read((char*) key, sizeof(key));

  if (file.fail()) {
    sodium_memzero(key, sizeof(key));
    file.close();
    throw std::runtime_error("Invalid DNSCrypt key file " + keyFile);
  }

  file.close();
}

void DnsCryptPrivateKey::saveToFile(const std::string& keyFile) const
{
  ofstream file(keyFile);
  file.write((char*) key, sizeof(key));
  file.close();
}

DnsCryptPrivateKey::~DnsCryptPrivateKey()
{
  sodium_munlock(key, sizeof(key));
}

#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
DnsCryptQuery::~DnsCryptQuery()
{
  if (sharedKeyComputed) {
    sodium_munlock(sharedKey, sizeof(sharedKey));
  }
}

int DnsCryptQuery::computeSharedKey(const DnsCryptPrivateKey& privateKey)
{
  int res = 0;

  if (sharedKeyComputed) {
    return res;
  }

  sodium_mlock(sharedKey, sizeof(sharedKey));
  res = crypto_box_beforenm(sharedKey,
                            header.clientPK,
                            privateKey.key);

  if (res != 0) {
    sodium_munlock(sharedKey, sizeof(sharedKey));
    return res;
  }

  sharedKeyComputed = true;
  return res;
}
#else
DnsCryptQuery::~DnsCryptQuery()
{
}
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

void DnsCryptContext::generateProviderKeys(unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE], unsigned char privateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE])
{
  int res = crypto_sign_ed25519_keypair(publicKey, privateKey);

  if (res != 0) {
    throw std::runtime_error("Error generating DNSCrypt provider keys");
  }
}

std::string DnsCryptContext::getProviderFingerprint(unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE])
{
  boost::format fmt("%02X%02X");
  ostringstream ret;

  for (size_t idx = 0; idx < DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE; idx += 2)
  {
    ret << (fmt % static_cast<int>(publicKey[idx]) % static_cast<int>(publicKey[idx+1]));
    if (idx < (DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE - 2)) {
      ret << ":";
    }
  }

  return ret.str();
}

void DnsCryptContext::generateCertificate(uint32_t serial, time_t begin, time_t end, const unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE], DnsCryptPrivateKey& privateKey, DnsCryptCert& cert)
{
  unsigned char magic[DNSCRYPT_CERT_MAGIC_SIZE] = DNSCRYPT_CERT_MAGIC_VALUE;
  unsigned char esVersion[] = DNSCRYPT_CERT_ES_VERSION_VALUE;
  unsigned char protocolMinorVersion[] = DNSCRYPT_CERT_PROTOCOL_MINOR_VERSION_VALUE;
  unsigned char pubK[DNSCRYPT_PUBLIC_KEY_SIZE];
  generateResolverKeyPair(privateKey, pubK);

  memcpy(cert.magic, magic, sizeof(magic));
  memcpy(cert.esVersion, esVersion, sizeof(esVersion));
  memcpy(cert.protocolMinorVersion, protocolMinorVersion, sizeof(protocolMinorVersion));
  memcpy(cert.signedData.resolverPK, pubK, sizeof(cert.signedData.resolverPK));
  memcpy(cert.signedData.clientMagic, pubK, sizeof(cert.signedData.clientMagic));
  cert.signedData.serial = serial;
  cert.signedData.tsStart = htonl((uint32_t) begin);
  cert.signedData.tsEnd = htonl((uint32_t) end);

  unsigned long long signatureSize = 0;

  int res = crypto_sign_ed25519(cert.signature,
                                &signatureSize,
                                (unsigned char*) &cert.signedData,
                                sizeof(cert.signedData),
                                providerPrivateKey);

  if (res == 0) {
    assert(signatureSize == sizeof(DnsCryptCertSignedData) + DNSCRYPT_SIGNATURE_SIZE);
  }
  else {
    throw std::runtime_error("Error generating DNSCrypt certificate");
  }
}

void DnsCryptContext::loadCertFromFile(const std::string&filename, DnsCryptCert& dest)
{
  ifstream file(filename);
  file.read((char *) &dest, sizeof(dest));

  if (file.fail())
    throw std::runtime_error("Invalid dnscrypt certificate file " + filename);

  file.close();
}

void DnsCryptContext::saveCertFromFile(const DnsCryptCert& cert, const std::string&filename)
{
  ofstream file(filename);
  file.write((char *) &cert, sizeof(cert));
  file.close();
}

void DnsCryptContext::generateResolverKeyPair(DnsCryptPrivateKey& privK, unsigned char pubK[DNSCRYPT_PUBLIC_KEY_SIZE])
{
  int res = crypto_box_keypair(pubK, privK.key);

  if (res != 0) {
    throw std::runtime_error("Error generating DNSCrypt resolver keys");
  }
}

void DnsCryptContext::computePublicKeyFromPrivate(const DnsCryptPrivateKey& privK, unsigned char* pubK)
{
  int res = crypto_scalarmult_base(pubK,
                                   privK.key);

  if (res != 0) {
    throw std::runtime_error("Error computing dnscrypt public key from the private one");
  }
}

std::string DnsCryptContext::certificateDateToStr(uint32_t date)
{
  char buf[20];
  time_t tdate = (time_t) ntohl(date);
  struct tm date_tm;

  localtime_r(&tdate, &date_tm);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &date_tm);

  return string(buf);
}

void DnsCryptContext::setNewCertificate(const DnsCryptCert& newCert, const DnsCryptPrivateKey& newKey)
{
  // XXX TODO: this could use a lock
  oldPrivateKey = privateKey;
  oldCert = cert;
  hasOldCert = true;
  privateKey = newKey;
  cert = newCert;
}

void DnsCryptContext::loadNewCertificate(const std::string& certFile, const std::string& keyFile)
{
  DnsCryptCert newCert;
  DnsCryptPrivateKey newPrivateKey;

  loadCertFromFile(certFile, newCert);
  newPrivateKey.loadFromFile(keyFile);
  setNewCertificate(newCert, newPrivateKey);
}

void DnsCryptContext::parsePlaintextQuery(const char * packet, uint16_t packetSize, std::shared_ptr<DnsCryptQuery> query) const
{
  if (packetSize < sizeof(dnsheader)) {
    return;
  }

  struct dnsheader * dh = (struct dnsheader *) packet;
  if (dh->qr || ntohs(dh->qdcount) != 1 || dh->ancount != 0 || dh->nscount != 0 || dh->opcode != Opcode::Query)
    return;

  unsigned int consumed;
  uint16_t qtype, qclass;
  DNSName qname(packet, packetSize, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  if ((packetSize - sizeof(dnsheader)) < (consumed + sizeof(qtype) + sizeof(qclass)))
    return;

  if (qtype != QType::TXT || qclass != QClass::IN)
    return;

  if (qname != DNSName(providerName))
    return;

  query->qname = qname;
  query->id = dh->id;
  query->valid = true;
}

void DnsCryptContext::getCertificateResponse(const std::shared_ptr<DnsCryptQuery> query, vector<uint8_t>& response) const
{
  DNSPacketWriter pw(response, query->qname, QType::TXT, QClass::IN, Opcode::Query);
  struct dnsheader * dh = pw.getHeader();
  dh->id = query->id;
  dh->qr = true;
  dh->rcode = RCode::NoError;
  pw.startRecord(query->qname, QType::TXT, (DNSCRYPT_CERTIFICATE_RESPONSE_TTL), QClass::IN, DNSResourceRecord::ANSWER, true);
  std::string scert;
  uint8_t certSize = sizeof(cert);
  scert.assign((const char*) &certSize, sizeof(certSize));
  scert.append((const char*) &cert, certSize);

  pw.xfrBlob(scert);
  pw.commit();
}

bool DnsCryptContext::magicMatchesPublicKey(std::shared_ptr<DnsCryptQuery> query) const
{
  const unsigned char* magic = query->header.clientMagic;

  if (memcmp(magic, cert.signedData.clientMagic, DNSCRYPT_CLIENT_MAGIC_SIZE) == 0) {
    return true;
  }

  if (hasOldCert == true &&
      memcmp(magic, oldCert.signedData.clientMagic, DNSCRYPT_CLIENT_MAGIC_SIZE) == 0) {
    query->useOldCert = true;
    return true;
  }

  return false;
}

void DnsCryptContext::isQueryEncrypted(const char * packet, uint16_t packetSize, std::shared_ptr<DnsCryptQuery> query, bool tcp) const
{
  query->encrypted = false;

  if (packetSize < sizeof(DnsCryptQueryHeader)) {
    return;
  }

  if (!tcp && packetSize < DnsCryptQuery::minUDPLength) {
    return;
  }

  struct DnsCryptQueryHeader* header = (struct DnsCryptQueryHeader*) packet;

  query->header = *(header);

  if (!magicMatchesPublicKey(query)) {
    return;
  }

  query->encrypted = true;
}

void DnsCryptContext::getDecryptedQuery(std::shared_ptr<DnsCryptQuery> query, bool tcp, char* packet, uint16_t packetSize, uint16_t* decryptedQueryLen) const
{
  assert(decryptedQueryLen != NULL);
  assert(query->encrypted);
  assert(query->valid == false);

#ifdef DNSCRYPT_STRICT_PADDING_LENGTH
  if (tcp && ((packetSize - sizeof(DnsCryptQueryHeader)) % DNSCRYPT_PADDED_BLOCK_SIZE) != 0) {
    vinfolog("Dropping encrypted query with invalid size of %d (should be a multiple of %d)", (packetSize - sizeof(DnsCryptQueryHeader)), DNSCRYPT_PADDED_BLOCK_SIZE);
    return;
  }
#endif

  unsigned char nonce[DNSCRYPT_NONCE_SIZE];
  static_assert(sizeof(nonce) == (2* sizeof(query->header.clientNonce)), "Nonce should be larger than clientNonce (half)");
  static_assert(sizeof(query->header.clientPK) == DNSCRYPT_PUBLIC_KEY_SIZE, "Client Publick key size is not right");
  static_assert(sizeof(privateKey.key) == DNSCRYPT_PRIVATE_KEY_SIZE, "Private key size is not right");

  memcpy(nonce, &query->header.clientNonce, sizeof(query->header.clientNonce));
  memset(nonce + sizeof(query->header.clientNonce), 0, sizeof(nonce) - sizeof(query->header.clientNonce));

#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int res = query->computeSharedKey(query->useOldCert ? oldPrivateKey : privateKey);
  if (res != 0) {
    vinfolog("Dropping encrypted query we can't compute the shared key for");
    return;
  }

  res = crypto_box_open_easy_afternm((unsigned char*) packet,
                                     (unsigned char*) packet + sizeof(DnsCryptQueryHeader),
                                     packetSize - sizeof(DnsCryptQueryHeader),
                                     nonce,
                                     query->sharedKey);
#else
  int res = crypto_box_open_easy((unsigned char*) packet,
                                 (unsigned char*) packet + sizeof(DnsCryptQueryHeader),
                                 packetSize - sizeof(DnsCryptQueryHeader),
                                 nonce,
                                 query->header.clientPK,
                                 query->useOldCert ? oldPrivateKey.key : privateKey.key);
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

  if (res != 0) {
    vinfolog("Dropping encrypted query we can't decrypt");
    return;
  }

  *decryptedQueryLen = packetSize - sizeof(DnsCryptQueryHeader) - DNSCRYPT_MAC_SIZE;
  uint16_t pos = *decryptedQueryLen;
  assert(pos < packetSize);
  query->paddedLen = *decryptedQueryLen;

  while(pos > 0 && packet[pos - 1] == 0) pos--;

  if (pos == 0 || ((uint8_t) packet[pos - 1]) != 0x80) {
    vinfolog("Dropping encrypted query with invalid padding value");
    return;
  }

  pos--;

  size_t paddingLen = *decryptedQueryLen - pos;
  *decryptedQueryLen = pos;

  if (tcp && paddingLen > DNSCRYPT_MAX_TCP_PADDING_SIZE) {
    vinfolog("Dropping encrypted query with too long padding size");
    return;
  }

  query->len = pos;

  query->valid = true;
}

void DnsCryptContext::parsePacket(char* packet, uint16_t packetSize, std::shared_ptr<DnsCryptQuery> query, bool tcp, uint16_t* decryptedQueryLen) const
{
  assert(packet != NULL);
  assert(decryptedQueryLen != NULL);

  query->valid = false;

  /* might be a plaintext certificate request or an authenticated request */
  isQueryEncrypted(packet, packetSize, query, tcp);

  if (query->encrypted) {
    getDecryptedQuery(query, tcp, packet, packetSize, decryptedQueryLen);
  }
  else {
    parsePlaintextQuery(packet, packetSize, query);
  }
}

void DnsCryptContext::fillServerNonce(unsigned char* nonce) const
{
  uint32_t* dest = (uint32_t*) nonce;
  static const size_t nonceSize = DNSCRYPT_NONCE_SIZE / 2;

  for (size_t pos = 0; pos < (nonceSize / sizeof(*dest)); pos++)
  {
    const uint32_t value = randombytes_random();
    memcpy(dest + pos, &value, sizeof(value));
  }
}

/*
   "The length of <resolver-response-pad> must be between 0 and 256 bytes,
   and must be constant for a given (<resolver-sk>, <client-nonce>) tuple."
*/
uint16_t DnsCryptContext::computePaddingSize(uint16_t unpaddedLen, size_t maxLen, const unsigned char* clientNonce) const
{
  size_t paddedLen = 0;
  uint16_t result = 0;
  uint32_t rnd = 0;
  assert(clientNonce != NULL);
  unsigned char nonce[DNSCRYPT_NONCE_SIZE];
  memcpy(nonce, clientNonce, (DNSCRYPT_NONCE_SIZE / 2));
  memcpy(&(nonce[DNSCRYPT_NONCE_SIZE / 2]), clientNonce, (DNSCRYPT_NONCE_SIZE / 2));
  crypto_stream((unsigned char*) &rnd, sizeof(rnd), nonce, privateKey.key);

  paddedLen = unpaddedLen + rnd % (maxLen - unpaddedLen + 1);
  paddedLen += DNSCRYPT_PADDED_BLOCK_SIZE - (paddedLen % DNSCRYPT_PADDED_BLOCK_SIZE);

  if (paddedLen > maxLen)
    paddedLen = maxLen;

  result = paddedLen - unpaddedLen;

  return result;
}

int DnsCryptContext::encryptResponse(char* response, uint16_t responseLen, uint16_t responseSize, const std::shared_ptr<DnsCryptQuery> query, bool tcp, uint16_t* encryptedResponseLen) const
{
  struct DnsCryptResponseHeader header;
  assert(response != NULL);
  assert(responseLen > 0);
  assert(responseSize >= responseLen);
  assert(encryptedResponseLen != NULL);
  assert(query->encrypted == true);

  if (!tcp && query->paddedLen < responseLen) {
    struct dnsheader* dh = (struct dnsheader*) response;
    size_t questionSize = 0;

    if (responseLen > sizeof(dnsheader)) {
      unsigned int consumed = 0;
      DNSName qname(response, responseLen, sizeof(dnsheader), false, 0, 0, &consumed);
      if (consumed > 0) {
        questionSize = consumed + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
      }
    }

    responseLen = sizeof(dnsheader) + questionSize;

    if (responseLen > query->paddedLen) {
      responseLen = query->paddedLen;
    }
    dh->ancount = dh->arcount = dh->nscount = 0;
    dh->tc = 1;
  }

  size_t requiredSize = sizeof(header) + DNSCRYPT_MAC_SIZE + responseLen;
  size_t maxSize = (responseSize > (requiredSize + DNSCRYPT_MAX_RESPONSE_PADDING_SIZE)) ? (requiredSize + DNSCRYPT_MAX_RESPONSE_PADDING_SIZE) : responseSize;
  uint16_t paddingSize = computePaddingSize(requiredSize, maxSize, query->header.clientNonce);
  requiredSize += paddingSize;

  if (requiredSize > responseSize)
    return ENOBUFS;

  memcpy(&header.nonce, &query->header.clientNonce, sizeof query->header.clientNonce);
  fillServerNonce(&(header.nonce[sizeof(query->header.clientNonce)]));

  /* moving the existing response after the header + MAC */
  memmove(response + sizeof(header) + DNSCRYPT_MAC_SIZE, response, responseLen);

  uint16_t pos = 0;
  /* copying header */
  memcpy(response + pos, &header, sizeof(header));
  pos += sizeof(header);
  /* setting MAC bytes to 0 */
  memset(response + pos, 0, DNSCRYPT_MAC_SIZE);
  pos += DNSCRYPT_MAC_SIZE;
  uint16_t toEncryptPos = pos;
  /* skipping response */
  pos += responseLen;
  /* padding */
  response[pos] = (uint8_t) 0x80;
  pos++;
  memset(response + pos, 0, paddingSize - 1);
  pos += (paddingSize - 1);

  /* encrypting */
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int res = query->computeSharedKey(query->useOldCert ? oldPrivateKey : privateKey);
  if (res != 0) {
    return res;
  }

  res = crypto_box_easy_afternm((unsigned char*) (response + sizeof(header)),
                                (unsigned char*) (response + toEncryptPos),
                                responseLen + paddingSize,
                                header.nonce,
                                query->sharedKey);
#else
  int res = crypto_box_easy((unsigned char*) (response + sizeof(header)),
                            (unsigned char*) (response + toEncryptPos),
                            responseLen + paddingSize,
                            header.nonce,
                            query->header.clientPK,
                            query->useOldCert ? oldPrivateKey.key : privateKey.key);
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

  if (res == 0) {
    assert(pos == requiredSize);
    *encryptedResponseLen = requiredSize;
  }

  return res;
}

int DnsCryptContext::encryptQuery(char* query, uint16_t queryLen, uint16_t querySize, const unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE], const DnsCryptPrivateKey& clientPrivateKey, const unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2], bool tcp, uint16_t* encryptedResponseLen) const
{
  assert(query != NULL);
  assert(queryLen > 0);
  assert(querySize >= queryLen);
  assert(encryptedResponseLen != NULL);
  unsigned char nonce[DNSCRYPT_NONCE_SIZE];
  size_t requiredSize = sizeof(DnsCryptQueryHeader) + DNSCRYPT_MAC_SIZE + queryLen;
  /* this is not optimal, we should compute a random padding size, multiple of DNSCRYPT_PADDED_BLOCK_SIZE,
     DNSCRYPT_PADDED_BLOCK_SIZE <= padding size <= 4096? */
  uint16_t paddingSize = DNSCRYPT_PADDED_BLOCK_SIZE - (queryLen % DNSCRYPT_PADDED_BLOCK_SIZE);
  requiredSize += paddingSize;

  if (!tcp && requiredSize < DnsCryptQuery::minUDPLength) {
    paddingSize += (DnsCryptQuery::minUDPLength - requiredSize);
    requiredSize = DnsCryptQuery::minUDPLength;
  }

  if (requiredSize > querySize)
    return ENOBUFS;

  /* moving the existing query after the header + MAC */
  memmove(query + sizeof(DnsCryptQueryHeader) + DNSCRYPT_MAC_SIZE, query, queryLen);

  size_t pos = 0;
  /* client magic */
  memcpy(query + pos, cert.signedData.clientMagic, sizeof(cert.signedData.clientMagic));
  pos += sizeof(cert.signedData.clientMagic);

  /* client PK */
  memcpy(query + pos, clientPublicKey, DNSCRYPT_PUBLIC_KEY_SIZE);
  pos += DNSCRYPT_PUBLIC_KEY_SIZE;

  /* client nonce */
  memcpy(query + pos, clientNonce, DNSCRYPT_NONCE_SIZE / 2);
  pos += DNSCRYPT_NONCE_SIZE / 2;
  size_t encryptedPos = pos;

  /* clear the MAC bytes */
  memset(query + pos, 0, DNSCRYPT_MAC_SIZE);
  pos += DNSCRYPT_MAC_SIZE;

  /* skipping data */
  pos += queryLen;

  /* padding */
  query[pos] = (uint8_t) 0x80;
  pos++;
  memset(query + pos, 0, paddingSize - 1);
  pos += paddingSize - 1;

  memcpy(nonce, clientNonce, DNSCRYPT_NONCE_SIZE / 2);
  memset(nonce + (DNSCRYPT_NONCE_SIZE / 2), 0, DNSCRYPT_NONCE_SIZE / 2);

  int res = crypto_box_easy((unsigned char*) query + encryptedPos,
                            (unsigned char*) query + encryptedPos + DNSCRYPT_MAC_SIZE,
                            queryLen + paddingSize,
                            nonce,
                            cert.signedData.resolverPK,
                            clientPrivateKey.key);

  if (res == 0) {
    assert(pos == requiredSize);
    *encryptedResponseLen = requiredSize;
  }

  return res;
}

#endif
