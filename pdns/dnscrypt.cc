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
#include "lock.hh"

DNSCryptPrivateKey::DNSCryptPrivateKey()
{
  sodium_memzero(key, sizeof(key));
  sodium_mlock(key, sizeof(key));
}

void DNSCryptPrivateKey::loadFromFile(const std::string& keyFile)
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

void DNSCryptPrivateKey::saveToFile(const std::string& keyFile) const
{
  ofstream file(keyFile);
  file.write((char*) key, sizeof(key));
  file.close();
}

DNSCryptPrivateKey::~DNSCryptPrivateKey()
{
  sodium_munlock(key, sizeof(key));
}

DNSCryptExchangeVersion DNSCryptQuery::getVersion() const
{
  if (d_pair == nullptr) {
    throw std::runtime_error("Unable to determine the version of a DNSCrypt query if there is not associated cert");
  }

  return DNSCryptContext::getExchangeVersion(d_pair->cert);
}

#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
DNSCryptQuery::~DNSCryptQuery()
{
  if (d_sharedKeyComputed) {
    sodium_munlock(d_sharedKey, sizeof(d_sharedKey));
  }
}

int DNSCryptQuery::computeSharedKey()
{
  assert(d_pair != nullptr);

  int res = 0;

  if (d_sharedKeyComputed) {
    return res;
  }

  const DNSCryptExchangeVersion version = DNSCryptContext::getExchangeVersion(d_pair->cert);

  sodium_mlock(d_sharedKey, sizeof(d_sharedKey));

  if (version == DNSCryptExchangeVersion::VERSION1) {
    res = crypto_box_beforenm(d_sharedKey,
                              d_header.clientPK,
                              d_pair->privateKey.key);
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
    res = crypto_box_curve25519xchacha20poly1305_beforenm(d_sharedKey,
                                                          d_header.clientPK,
                                                          d_pair->privateKey.key);
#else /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
    res = -1;
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
  }
  else {
    res = -1;
  }

  if (res != 0) {
    sodium_munlock(d_sharedKey, sizeof(d_sharedKey));
    return res;
  }

  d_sharedKeyComputed = true;
  return res;
}
#else
DNSCryptQuery::~DNSCryptQuery()
{
}
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

DNSCryptContext::DNSCryptContext(const std::string& pName, const std::vector<CertKeyPaths>& certKeys): d_certKeyPaths(certKeys), providerName(pName)
{
  pthread_rwlock_init(&d_lock, 0);

  reloadCertificates();
}

DNSCryptContext::DNSCryptContext(const std::string& pName, const DNSCryptCert& certificate, const DNSCryptPrivateKey& pKey): providerName(pName)
{
  pthread_rwlock_init(&d_lock, 0);

  addNewCertificate(certificate, pKey);
}

void DNSCryptContext::generateProviderKeys(unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE], unsigned char privateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE])
{
  int res = crypto_sign_ed25519_keypair(publicKey, privateKey);

  if (res != 0) {
    throw std::runtime_error("Error generating DNSCrypt provider keys");
  }
}

std::string DNSCryptContext::getProviderFingerprint(unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE])
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

void DNSCryptContext::setExchangeVersion(const DNSCryptExchangeVersion& version,  unsigned char esVersion[sizeof(DNSCryptCert::esVersion)])
{
  esVersion[0] = 0x00;

  if (version == DNSCryptExchangeVersion::VERSION1) {
    esVersion[1] = { 0x01 };
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
    esVersion[1] = { 0x02 };
  }
  else {
    throw std::runtime_error("Unknown DNSCrypt exchange version");
  }
}

DNSCryptExchangeVersion DNSCryptContext::getExchangeVersion(const unsigned char esVersion[sizeof(DNSCryptCert::esVersion)])
{
  if (esVersion[0] != 0x00) {
    throw std::runtime_error("Unknown DNSCrypt exchange version");
  }

  if (esVersion[1] == 0x01) {
    return DNSCryptExchangeVersion::VERSION1;
  }
  else if (esVersion[1] == 0x02) {
    return DNSCryptExchangeVersion::VERSION2;
  }

  throw std::runtime_error("Unknown DNSCrypt exchange version");
}

DNSCryptExchangeVersion DNSCryptContext::getExchangeVersion(const DNSCryptCert& cert)
{
  return getExchangeVersion(cert.esVersion);
}


void DNSCryptContext::generateCertificate(uint32_t serial, time_t begin, time_t end, const DNSCryptExchangeVersion& version, const unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE], DNSCryptPrivateKey& privateKey, DNSCryptCert& cert)
{
  unsigned char magic[DNSCRYPT_CERT_MAGIC_SIZE] = DNSCRYPT_CERT_MAGIC_VALUE;
  unsigned char protocolMinorVersion[] = DNSCRYPT_CERT_PROTOCOL_MINOR_VERSION_VALUE;
  unsigned char pubK[DNSCRYPT_PUBLIC_KEY_SIZE];
  unsigned char esVersion[sizeof(DNSCryptCert::esVersion)];
  setExchangeVersion(version, esVersion);

  generateResolverKeyPair(privateKey, pubK);

  memcpy(cert.magic, magic, sizeof(magic));
  memcpy(cert.esVersion, esVersion, sizeof(esVersion));
  memcpy(cert.protocolMinorVersion, protocolMinorVersion, sizeof(protocolMinorVersion));
  memcpy(cert.signedData.resolverPK, pubK, sizeof(cert.signedData.resolverPK));
  memcpy(cert.signedData.clientMagic, pubK, sizeof(cert.signedData.clientMagic));
  cert.signedData.serial = htonl(serial);
  cert.signedData.tsStart = htonl((uint32_t) begin);
  cert.signedData.tsEnd = htonl((uint32_t) end);

  unsigned long long signatureSize = 0;

  int res = crypto_sign_ed25519(cert.signature,
                                &signatureSize,
                                (unsigned char*) &cert.signedData,
                                sizeof(cert.signedData),
                                providerPrivateKey);

  if (res == 0) {
    assert(signatureSize == sizeof(DNSCryptCertSignedData) + DNSCRYPT_SIGNATURE_SIZE);
  }
  else {
    throw std::runtime_error("Error generating DNSCrypt certificate");
  }
}

void DNSCryptContext::loadCertFromFile(const std::string&filename, DNSCryptCert& dest)
{
  ifstream file(filename);
  file.read((char *) &dest, sizeof(dest));

  if (file.fail())
    throw std::runtime_error("Invalid dnscrypt certificate file " + filename);

  file.close();
}

void DNSCryptContext::saveCertFromFile(const DNSCryptCert& cert, const std::string&filename)
{
  ofstream file(filename);
  file.write((char *) &cert, sizeof(cert));
  file.close();
}

void DNSCryptContext::generateResolverKeyPair(DNSCryptPrivateKey& privK, unsigned char pubK[DNSCRYPT_PUBLIC_KEY_SIZE])
{
  int res = crypto_box_keypair(pubK, privK.key);

  if (res != 0) {
    throw std::runtime_error("Error generating DNSCrypt resolver keys");
  }
}

void DNSCryptContext::computePublicKeyFromPrivate(const DNSCryptPrivateKey& privK, unsigned char* pubK)
{
  int res = crypto_scalarmult_base(pubK,
                                   privK.key);

  if (res != 0) {
    throw std::runtime_error("Error computing dnscrypt public key from the private one");
  }
}

std::string DNSCryptContext::certificateDateToStr(uint32_t date)
{
  char buf[20];
  time_t tdate = static_cast<time_t>(ntohl(date));
  struct tm date_tm;

  localtime_r(&tdate, &date_tm);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &date_tm);

  return string(buf);
}

void DNSCryptContext::addNewCertificate(std::shared_ptr<DNSCryptCertificatePair>& newCert, bool reload)
{
  WriteLock w(&d_lock);

  for (auto pair : d_certs) {
    if (pair->cert.getSerial() == newCert->cert.getSerial()) {
      if (reload) {
        /* on reload we just assume that this is the same certificate */
        return;
      }
      else {
        throw std::runtime_error("Error adding a new certificate: we already have a certificate with the same serial");
      }
    }
  }

  d_certs.push_back(newCert);
}

void DNSCryptContext::addNewCertificate(const DNSCryptCert& newCert, const DNSCryptPrivateKey& newKey, bool active, bool reload)
{
  auto pair = std::make_shared<DNSCryptCertificatePair>();
  pair->cert = newCert;
  pair->privateKey = newKey;
  computePublicKeyFromPrivate(pair->privateKey, pair->publicKey);
  pair->active = active;

  addNewCertificate(pair, reload);
}

std::shared_ptr<DNSCryptCertificatePair> DNSCryptContext::loadCertificatePair(const std::string& certFile, const std::string& keyFile)
{
  auto pair = std::make_shared<DNSCryptCertificatePair>();
  loadCertFromFile(certFile, pair->cert);
  pair->privateKey.loadFromFile(keyFile);
  pair->active = true;
  computePublicKeyFromPrivate(pair->privateKey, pair->publicKey);
  return pair;
}

void DNSCryptContext::loadNewCertificate(const std::string& certFile, const std::string& keyFile, bool active, bool reload)
{
  auto newPair = DNSCryptContext::loadCertificatePair(certFile, keyFile);
  newPair->active = active;
  addNewCertificate(newPair, reload);
  d_certKeyPaths.push_back({certFile, keyFile});
}

void DNSCryptContext::reloadCertificates()
{
  std::vector<std::shared_ptr<DNSCryptCertificatePair>> newCerts;
  for (const auto& pair : d_certKeyPaths) {
    newCerts.push_back(DNSCryptContext::loadCertificatePair(pair.cert, pair.key));
  }

  {
    WriteLock w(&d_lock);
    d_certs = std::move(newCerts);
  }
}

void DNSCryptContext::markActive(uint32_t serial)
{
  WriteLock w(&d_lock);

  for (auto pair : d_certs) {
    if (pair->active == false && pair->cert.getSerial() == serial) {
      pair->active = true;
      return;
    }
  }
  throw std::runtime_error("No inactive certificate found with this serial");
}

void DNSCryptContext::markInactive(uint32_t serial)
{
  WriteLock w(&d_lock);

  for (auto pair : d_certs) {
    if (pair->active == true && pair->cert.getSerial() == serial) {
      pair->active = false;
      return;
    }
  }
  throw std::runtime_error("No active certificate found with this serial");
}

void DNSCryptContext::removeInactiveCertificate(uint32_t serial)
{
  WriteLock w(&d_lock);

  for (auto it = d_certs.begin(); it != d_certs.end(); ) {
    if ((*it)->active == false && (*it)->cert.getSerial() == serial) {
      it = d_certs.erase(it);
      return;
    } else {
      it++;
    }
  }
  throw std::runtime_error("No inactive certificate found with this serial");
}

bool DNSCryptQuery::parsePlaintextQuery(const char * packet, uint16_t packetSize)
{
  assert(d_ctx != nullptr);

  if (packetSize < sizeof(dnsheader)) {
    return false;
  }

  const struct dnsheader * dh = reinterpret_cast<const struct dnsheader *>(packet);
  if (dh->qr || ntohs(dh->qdcount) != 1 || dh->ancount != 0 || dh->nscount != 0 || dh->opcode != Opcode::Query)
    return false;

  unsigned int consumed;
  uint16_t qtype, qclass;
  DNSName qname(packet, packetSize, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  if ((packetSize - sizeof(dnsheader)) < (consumed + sizeof(qtype) + sizeof(qclass)))
    return false;

  if (qtype != QType::TXT || qclass != QClass::IN)
    return false;

  if (qname != d_ctx->getProviderName())
    return false;

  d_qname = qname;
  d_id = dh->id;
  d_valid = true;

  return true;
}

void DNSCryptContext::getCertificateResponse(time_t now, const DNSName& qname, uint16_t qid, std::vector<uint8_t>& response)
{
  DNSPacketWriter pw(response, qname, QType::TXT, QClass::IN, Opcode::Query);
  struct dnsheader * dh = pw.getHeader();
  dh->id = qid;
  dh->qr = true;
  dh->rcode = RCode::NoError;

  ReadLock r(&d_lock);
  for (const auto pair : d_certs) {
    if (!pair->active || !pair->cert.isValid(now)) {
      continue;
    }

    pw.startRecord(qname, QType::TXT, (DNSCRYPT_CERTIFICATE_RESPONSE_TTL), QClass::IN, DNSResourceRecord::ANSWER, true);
    std::string scert;
    uint8_t certSize = sizeof(pair->cert);
    scert.assign((const char*) &certSize, sizeof(certSize));
    scert.append((const char*) &pair->cert, certSize);

    pw.xfrBlob(scert);
    pw.commit();
  }
}

bool DNSCryptContext::magicMatchesAPublicKey(DNSCryptQuery& query, time_t now)
{
  const unsigned char* magic = query.getClientMagic();

  ReadLock r(&d_lock);
  for (const auto& pair : d_certs) {
    if (pair->cert.isValid(now) && memcmp(magic, pair->cert.signedData.clientMagic, DNSCRYPT_CLIENT_MAGIC_SIZE) == 0) {
      query.setCertificatePair(pair);
      return true;
    }
  }

  return false;
}

bool DNSCryptQuery::isEncryptedQuery(const char * packet, uint16_t packetSize, bool tcp, time_t now)
{
  assert(d_ctx != nullptr);

  d_encrypted = false;

  if (packetSize < sizeof(DNSCryptQueryHeader)) {
    return false;
  }

  if (!tcp && packetSize < DNSCryptQuery::s_minUDPLength) {
    return false;
  }

  const struct DNSCryptQueryHeader* header = reinterpret_cast<const struct DNSCryptQueryHeader*>(packet);

  d_header = *header;

  if (!d_ctx->magicMatchesAPublicKey(*this, now)) {
    return false;
  }

  d_encrypted = true;

  return true;
}

void DNSCryptQuery::getDecrypted(bool tcp, char* packet, uint16_t packetSize, uint16_t* decryptedQueryLen)
{
  assert(decryptedQueryLen != nullptr);
  assert(d_encrypted);
  assert(d_pair != nullptr);
  assert(d_valid == false);

#ifdef DNSCRYPT_STRICT_PADDING_LENGTH
  if (tcp && ((packetSize - sizeof(DNSCryptQueryHeader)) % DNSCRYPT_PADDED_BLOCK_SIZE) != 0) {
    vinfolog("Dropping encrypted query with invalid size of %d (should be a multiple of %d)", (packetSize - sizeof(DNSCryptQueryHeader)), DNSCRYPT_PADDED_BLOCK_SIZE);
    return;
  }
#endif

  unsigned char nonce[DNSCRYPT_NONCE_SIZE];
  static_assert(sizeof(nonce) == (2* sizeof(d_header.clientNonce)), "Nonce should be larger than clientNonce (half)");
  static_assert(sizeof(d_header.clientPK) == DNSCRYPT_PUBLIC_KEY_SIZE, "Client Publick key size is not right");
  static_assert(sizeof(d_pair->privateKey.key) == DNSCRYPT_PRIVATE_KEY_SIZE, "Private key size is not right");

  memcpy(nonce, &d_header.clientNonce, sizeof(d_header.clientNonce));
  memset(nonce + sizeof(d_header.clientNonce), 0, sizeof(nonce) - sizeof(d_header.clientNonce));

#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int res = computeSharedKey();
  if (res != 0) {
    vinfolog("Dropping encrypted query we can't compute the shared key for");
    return;
  }

  const DNSCryptExchangeVersion version = getVersion();

  if (version == DNSCryptExchangeVersion::VERSION1) {
    res = crypto_box_open_easy_afternm(reinterpret_cast<unsigned char*>(packet),
                                       reinterpret_cast<unsigned char*>(packet + sizeof(DNSCryptQueryHeader)),
                                       packetSize - sizeof(DNSCryptQueryHeader),
                                       nonce,
                                       d_sharedKey);
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
    res = crypto_box_curve25519xchacha20poly1305_open_easy_afternm(reinterpret_cast<unsigned char*>(packet),
                                                                   reinterpret_cast<unsigned char*>(packet + sizeof(DNSCryptQueryHeader)),
                                                                   packetSize - sizeof(DNSCryptQueryHeader),
                                                                   nonce,
                                                                   d_sharedKey);
#else /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
    res = -1;
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
  } else {
    res = -1;
  }

#else /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
  int res = crypto_box_open_easy(reinterpret_cast<unsigned char*>(packet),
                                 reinterpret_cast<unsigned char*>(packet + sizeof(DNSCryptQueryHeader)),
                                 packetSize - sizeof(DNSCryptQueryHeader),
                                 nonce,
                                 d_header.clientPK,
                                 d_pair->privateKey.key);
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

  if (res != 0) {
    vinfolog("Dropping encrypted query we can't decrypt");
    return;
  }

  *decryptedQueryLen = packetSize - sizeof(DNSCryptQueryHeader) - DNSCRYPT_MAC_SIZE;
  uint16_t pos = *decryptedQueryLen;
  assert(pos < packetSize);
  d_paddedLen = *decryptedQueryLen;

  while(pos > 0 && packet[pos - 1] == 0) pos--;

  if (pos == 0 || static_cast<uint8_t>(packet[pos - 1]) != 0x80) {
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

  d_len = pos;
  d_valid = true;
}

void DNSCryptQuery::getCertificateResponse(time_t now, std::vector<uint8_t>& response) const
{
  assert(d_ctx != nullptr);
  d_ctx->getCertificateResponse(now, d_qname, d_id, response);
}

void DNSCryptQuery::parsePacket(char* packet, uint16_t packetSize, bool tcp, uint16_t* decryptedQueryLen, time_t now)
{
  assert(packet != nullptr);
  assert(decryptedQueryLen != nullptr);

  d_valid = false;

  /* might be a plaintext certificate request or an authenticated request */
  if (isEncryptedQuery(packet, packetSize, tcp, now)) {
    getDecrypted(tcp, packet, packetSize, decryptedQueryLen);
  }
  else {
    parsePlaintextQuery(packet, packetSize);
  }
}

void DNSCryptQuery::fillServerNonce(unsigned char* nonce) const
{
  uint32_t* dest = reinterpret_cast<uint32_t*>(nonce);
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
uint16_t DNSCryptQuery::computePaddingSize(uint16_t unpaddedLen, size_t maxLen) const
{
  size_t paddedSize = 0;
  uint16_t result = 0;
  uint32_t rnd = 0;
  assert(d_header.clientNonce);
  assert(d_pair != nullptr);

  unsigned char nonce[DNSCRYPT_NONCE_SIZE];
  memcpy(nonce, d_header.clientNonce, (DNSCRYPT_NONCE_SIZE / 2));
  memcpy(&(nonce[DNSCRYPT_NONCE_SIZE / 2]), d_header.clientNonce, (DNSCRYPT_NONCE_SIZE / 2));
  crypto_stream((unsigned char*) &rnd, sizeof(rnd), nonce, d_pair->privateKey.key);

  paddedSize = unpaddedLen + rnd % (maxLen - unpaddedLen + 1);
  paddedSize += DNSCRYPT_PADDED_BLOCK_SIZE - (paddedSize % DNSCRYPT_PADDED_BLOCK_SIZE);

  if (paddedSize > maxLen)
    paddedSize = maxLen;

  result = paddedSize - unpaddedLen;

  return result;
}

int DNSCryptQuery::encryptResponse(char* response, uint16_t responseLen, uint16_t responseSize, bool tcp, uint16_t* encryptedResponseLen)
{
  struct DNSCryptResponseHeader responseHeader;
  assert(response != nullptr);
  assert(responseLen > 0);
  assert(responseSize >= responseLen);
  assert(encryptedResponseLen != nullptr);
  assert(d_encrypted == true);
  assert(d_pair != nullptr);

  if (!tcp && d_paddedLen < responseLen) {
    struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(response);
    size_t questionSize = 0;

    if (responseLen > sizeof(dnsheader)) {
      unsigned int consumed = 0;
      DNSName tempQName(response, responseLen, sizeof(dnsheader), false, 0, 0, &consumed);
      if (consumed > 0) {
        questionSize = consumed + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
      }
    }

    responseLen = sizeof(dnsheader) + questionSize;

    if (responseLen > d_paddedLen) {
      responseLen = d_paddedLen;
    }
    dh->ancount = dh->arcount = dh->nscount = 0;
    dh->tc = 1;
  }

  size_t requiredSize = sizeof(responseHeader) + DNSCRYPT_MAC_SIZE + responseLen;
  size_t maxSize = (responseSize > (requiredSize + DNSCRYPT_MAX_RESPONSE_PADDING_SIZE)) ? (requiredSize + DNSCRYPT_MAX_RESPONSE_PADDING_SIZE) : responseSize;
  uint16_t paddingSize = computePaddingSize(requiredSize, maxSize);
  requiredSize += paddingSize;

  if (requiredSize > responseSize)
    return ENOBUFS;

  memcpy(&responseHeader.nonce, &d_header.clientNonce, sizeof d_header.clientNonce);
  fillServerNonce(&(responseHeader.nonce[sizeof(d_header.clientNonce)]));

  /* moving the existing response after the header + MAC */
  memmove(response + sizeof(responseHeader) + DNSCRYPT_MAC_SIZE, response, responseLen);

  uint16_t pos = 0;
  /* copying header */
  memcpy(response + pos, &responseHeader, sizeof(responseHeader));
  pos += sizeof(responseHeader);
  /* setting MAC bytes to 0 */
  memset(response + pos, 0, DNSCRYPT_MAC_SIZE);
  pos += DNSCRYPT_MAC_SIZE;
  uint16_t toEncryptPos = pos;
  /* skipping response */
  pos += responseLen;
  /* padding */
  response[pos] = static_cast<uint8_t>(0x80);
  pos++;
  memset(response + pos, 0, paddingSize - 1);
  pos += (paddingSize - 1);

  /* encrypting */
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int res = computeSharedKey();
  if (res != 0) {
    return res;
  }

  const DNSCryptExchangeVersion version = getVersion();

  if (version == DNSCryptExchangeVersion::VERSION1) {
    res = crypto_box_easy_afternm(reinterpret_cast<unsigned char*>(response + sizeof(responseHeader)),
                                  reinterpret_cast<unsigned char*>(response + toEncryptPos),
                                  responseLen + paddingSize,
                                  responseHeader.nonce,
                                  d_sharedKey);
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
    res = crypto_box_curve25519xchacha20poly1305_easy_afternm(reinterpret_cast<unsigned char*>(response + sizeof(responseHeader)),
                                                              reinterpret_cast<unsigned char*>(response + toEncryptPos),
                                                              responseLen + paddingSize,
                                                              responseHeader.nonce,
                                                              d_sharedKey);
#else /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
    res = -1;
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
  }
  else {
    res = -1;
  }
#else
  int res = crypto_box_easy(reinterpret_cast<unsigned char*>(response + sizeof(responseHeader)),
                            reinterpret_cast<unsigned char*>(response + toEncryptPos),
                            responseLen + paddingSize,
                            responseHeader.nonce,
                            d_header.clientPK,
                            d_pair->privateKey.key);
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

  if (res == 0) {
    assert(pos == requiredSize);
    *encryptedResponseLen = requiredSize;
  }

  return res;
}

int DNSCryptContext::encryptQuery(char* query, uint16_t queryLen, uint16_t querySize, const unsigned char clientPublicKey[DNSCRYPT_PUBLIC_KEY_SIZE], const DNSCryptPrivateKey& clientPrivateKey, const unsigned char clientNonce[DNSCRYPT_NONCE_SIZE / 2], bool tcp, uint16_t* encryptedResponseLen, const std::shared_ptr<DNSCryptCert>& cert) const
{
  assert(query != nullptr);
  assert(queryLen > 0);
  assert(querySize >= queryLen);
  assert(encryptedResponseLen != nullptr);
  assert(cert != nullptr);

  unsigned char nonce[DNSCRYPT_NONCE_SIZE];
  size_t requiredSize = sizeof(DNSCryptQueryHeader) + DNSCRYPT_MAC_SIZE + queryLen;
  /* this is not optimal, we should compute a random padding size, multiple of DNSCRYPT_PADDED_BLOCK_SIZE,
     DNSCRYPT_PADDED_BLOCK_SIZE <= padding size <= 4096? */
  uint16_t paddingSize = DNSCRYPT_PADDED_BLOCK_SIZE - (queryLen % DNSCRYPT_PADDED_BLOCK_SIZE);
  requiredSize += paddingSize;

  if (!tcp && requiredSize < DNSCryptQuery::s_minUDPLength) {
    paddingSize += (DNSCryptQuery::s_minUDPLength - requiredSize);
    requiredSize = DNSCryptQuery::s_minUDPLength;
  }

  if (requiredSize > querySize)
    return ENOBUFS;

  /* moving the existing query after the header + MAC */
  memmove(query + sizeof(DNSCryptQueryHeader) + DNSCRYPT_MAC_SIZE, query, queryLen);

  size_t pos = 0;
  /* client magic */
  memcpy(query + pos, cert->signedData.clientMagic, sizeof(cert->signedData.clientMagic));
  pos += sizeof(cert->signedData.clientMagic);

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
  query[pos] = static_cast<uint8_t>(0x80);
  pos++;
  memset(query + pos, 0, paddingSize - 1);
  pos += paddingSize - 1;

  memcpy(nonce, clientNonce, DNSCRYPT_NONCE_SIZE / 2);
  memset(nonce + (DNSCRYPT_NONCE_SIZE / 2), 0, DNSCRYPT_NONCE_SIZE / 2);

  const DNSCryptExchangeVersion version = getExchangeVersion(*cert);
  int res = -1;

  if (version == DNSCryptExchangeVersion::VERSION1) {
    res = crypto_box_easy(reinterpret_cast<unsigned char*>(query + encryptedPos),
                          reinterpret_cast<unsigned char*>(query + encryptedPos + DNSCRYPT_MAC_SIZE),
                          queryLen + paddingSize,
                          nonce,
                          cert->signedData.resolverPK,
                          clientPrivateKey.key);
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
    res = crypto_box_curve25519xchacha20poly1305_easy(reinterpret_cast<unsigned char*>(query + encryptedPos),
                                                      reinterpret_cast<unsigned char*>(query + encryptedPos + DNSCRYPT_MAC_SIZE),
                                                      queryLen + paddingSize,
                                                      nonce,
                                                      cert->signedData.resolverPK,
                                                      clientPrivateKey.key);
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
  }
  else {
    throw std::runtime_error("Unknown DNSCrypt exchange version");
  }

  if (res == 0) {
    assert(pos == requiredSize);
    *encryptedResponseLen = requiredSize;
  }

  return res;
}

bool generateDNSCryptCertificate(const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, DNSCryptExchangeVersion version, DNSCryptCert& certOut, DNSCryptPrivateKey& keyOut)
{
  bool success = false;
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  sodium_mlock(providerPrivateKey, sizeof(providerPrivateKey));
  sodium_memzero(providerPrivateKey, sizeof(providerPrivateKey));

  try {
    ifstream providerKStream(providerPrivateKeyFile);
    providerKStream.read((char*) providerPrivateKey, sizeof(providerPrivateKey));
    if (providerKStream.fail()) {
      providerKStream.close();
      throw std::runtime_error("Invalid DNSCrypt provider key file " + providerPrivateKeyFile);
    }

    DNSCryptContext::generateCertificate(serial, begin, end, version, providerPrivateKey, keyOut, certOut);
    success = true;
  }
  catch(const std::exception& e) {
    errlog(e.what());
  }

  sodium_memzero(providerPrivateKey, sizeof(providerPrivateKey));
  sodium_munlock(providerPrivateKey, sizeof(providerPrivateKey));
  return success;
}

#endif
