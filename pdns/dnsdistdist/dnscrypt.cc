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
#include <boost/format.hpp>
#include "dolog.hh"
#include "dnscrypt.hh"
#include "dnsdist-dnsparser.hh"
#include "dnswriter.hh"

DNSCryptPrivateKey::DNSCryptPrivateKey()
{
  sodium_memzero(key.data(), key.size());
  sodium_mlock(key.data(), key.size());
}

void DNSCryptPrivateKey::loadFromFile(const std::string& keyFile)
{
  ifstream file(keyFile);
  sodium_memzero(key.data(), key.size());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  file.read(reinterpret_cast<char*>(key.data()), static_cast<std::streamsize>(key.size()));

  if (file.fail()) {
    sodium_memzero(key.data(), key.size());
    file.close();
    throw std::runtime_error("Invalid DNSCrypt key file " + keyFile);
  }

  file.close();
}

void DNSCryptPrivateKey::saveToFile(const std::string& keyFile) const
{
  ofstream file(keyFile);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  file.write(reinterpret_cast<const char*>(key.data()), static_cast<std::streamsize>(key.size()));
  file.close();
}

DNSCryptPrivateKey::~DNSCryptPrivateKey()
{
  sodium_munlock(key.data(), key.size());
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
    sodium_munlock(d_sharedKey.data(), d_sharedKey.size());
  }
}

int DNSCryptQuery::computeSharedKey()
{
  int res = 0;
  if (d_sharedKeyComputed) {
    return res;
  }
  if (d_pair == nullptr) {
    throw std::runtime_error("Asked to compute a DNSCrypt shared key without the certificate key set");
  }

  const DNSCryptExchangeVersion version = DNSCryptContext::getExchangeVersion(d_pair->cert);

  sodium_mlock(d_sharedKey.data(), d_sharedKey.size());

  if (version == DNSCryptExchangeVersion::VERSION1) {
    res = crypto_box_beforenm(d_sharedKey.data(),
                              d_header.clientPK.data(),
                              d_pair->privateKey.key.data());
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
    res = crypto_box_curve25519xchacha20poly1305_beforenm(d_sharedKey.data(),
                                                          d_header.clientPK.data(),
                                                          d_pair->privateKey.key.data());
#else /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
    res = -1;
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
  }
  else {
    res = -1;
  }

  if (res != 0) {
    sodium_munlock(d_sharedKey.data(), d_sharedKey.size());
    return res;
  }

  d_sharedKeyComputed = true;
  return res;
}
#else
DNSCryptQuery::~DNSCryptQuery() = default;
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

DNSCryptContext::~DNSCryptContext() = default;

DNSCryptContext::DNSCryptContext(const std::string& pName, const std::vector<CertKeyPaths>& certKeys) :
  d_certKeyPaths(certKeys), providerName(pName)
{
  reloadCertificates();
}

DNSCryptContext::DNSCryptContext(const std::string& pName, const DNSCryptCert& certificate, const DNSCryptPrivateKey& pKey) :
  providerName(pName)
{
  addNewCertificate(certificate, pKey);
}

void DNSCryptContext::generateProviderKeys(DNSCryptCertSignedData::ResolverPublicKeyType& publicKey, DNSCryptCertSignedData::ResolverPrivateKeyType& privateKey)
{
  int res = crypto_sign_ed25519_keypair(publicKey.data(), privateKey.data());

  if (res != 0) {
    throw std::runtime_error("Error generating DNSCrypt provider keys");
  }
}

std::string DNSCryptContext::getProviderFingerprint(const DNSCryptCertSignedData::ResolverPublicKeyType& publicKey)
{
  boost::format fmt("%02X%02X");
  ostringstream ret;

  for (size_t idx = 0; idx < DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE; idx += 2) {
    ret << (fmt % static_cast<int>(publicKey.at(idx)) % static_cast<int>(publicKey.at(idx + 1)));
    if (idx < (DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE - 2)) {
      ret << ":";
    }
  }

  return ret.str();
}

void DNSCryptContext::setExchangeVersion(const DNSCryptExchangeVersion& version, DNSCryptCert::ESVersionType& esVersion)
{
  esVersion.at(0) = 0x00;

  if (version == DNSCryptExchangeVersion::VERSION1) {
    esVersion.at(1) = {0x01};
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
    esVersion.at(1) = {0x02};
  }
  else {
    throw std::runtime_error("Unknown DNSCrypt exchange version");
  }
}

DNSCryptExchangeVersion DNSCryptContext::getExchangeVersion(const DNSCryptCert::ESVersionType& esVersion)
{
  if (esVersion.at(0) != 0x00) {
    throw std::runtime_error("Unknown DNSCrypt exchange version");
  }

  if (esVersion.at(1) == 0x01) {
    return DNSCryptExchangeVersion::VERSION1;
  }
  if (esVersion.at(1) == 0x02) {
    return DNSCryptExchangeVersion::VERSION2;
  }

  throw std::runtime_error("Unknown DNSCrypt exchange version");
}

DNSCryptExchangeVersion DNSCryptContext::getExchangeVersion(const DNSCryptCert& cert)
{
  return getExchangeVersion(cert.esVersion);
}

void DNSCryptContext::generateCertificate(uint32_t serial, time_t begin, time_t end, const DNSCryptExchangeVersion& version, const DNSCryptCertSignedData::ResolverPrivateKeyType& providerPrivateKey, DNSCryptPrivateKey& privateKey, DNSCryptCert& cert)
{
  setExchangeVersion(version, cert.esVersion);
  DNSCryptPublicKeyType pubKey;
  generateResolverKeyPair(privateKey, pubKey);

  cert.magic = DNSCRYPT_CERT_MAGIC_VALUE;
  cert.protocolMinorVersion = DNSCRYPT_CERT_PROTOCOL_MINOR_VERSION_VALUE;
  memcpy(cert.signedData.clientMagic.data(), pubKey.data(), cert.signedData.clientMagic.size());
  memcpy(cert.signedData.resolverPK.data(), pubKey.data(), cert.signedData.resolverPK.size());
  cert.signedData.serial = htonl(serial);
  // coverity[store_truncates_time_t]
  cert.signedData.tsStart = htonl(static_cast<uint32_t>(begin));
  // coverity[store_truncates_time_t]
  cert.signedData.tsEnd = htonl(static_cast<uint32_t>(end));

  unsigned long long signatureSize = 0;

  int res = crypto_sign_ed25519(cert.signature.data(),
                                &signatureSize,
                                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                                reinterpret_cast<unsigned char*>(&cert.signedData),
                                sizeof(cert.signedData),
                                providerPrivateKey.data());

  if (res != 0 || signatureSize != (sizeof(DNSCryptCertSignedData) + DNSCRYPT_SIGNATURE_SIZE)) {
    throw std::runtime_error("Error generating DNSCrypt certificate");
  }
}

void DNSCryptContext::loadCertFromFile(const std::string& filename, DNSCryptCert& dest)
{
  ifstream file(filename);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  file.read(reinterpret_cast<char*>(&dest), sizeof(dest));

  if (file.fail()) {
    throw std::runtime_error("Invalid dnscrypt certificate file " + filename);
  }

  file.close();
}

void DNSCryptContext::saveCertFromFile(const DNSCryptCert& cert, const std::string& filename)
{
  ofstream file(filename);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  file.write(reinterpret_cast<const char*>(&cert), sizeof(cert));
  file.close();
}

void DNSCryptContext::generateResolverKeyPair(DNSCryptPrivateKey& privK, DNSCryptPublicKeyType& pubK)
{
  int res = crypto_box_keypair(pubK.data(), privK.key.data());

  if (res != 0) {
    throw std::runtime_error("Error generating DNSCrypt resolver keys");
  }
}

void DNSCryptContext::computePublicKeyFromPrivate(const DNSCryptPrivateKey& privK, DNSCryptCertificatePair::PublicKeyType& pubK)
{
  int res = crypto_scalarmult_base(pubK.data(),
                                   privK.key.data());

  if (res != 0) {
    throw std::runtime_error("Error computing dnscrypt public key from the private one");
  }
}

std::string DNSCryptContext::certificateDateToStr(uint32_t date)
{
  std::string result;
  auto tdate = static_cast<time_t>(ntohl(date));
  tm date_tm{};
  localtime_r(&tdate, &date_tm);
  result.resize(20);
  auto got = strftime(result.data(), result.size(), "%Y-%m-%d %H:%M:%S", &date_tm);
  result.resize(got);
  return result;
}

void DNSCryptContext::addNewCertificate(std::shared_ptr<DNSCryptCertificatePair>& newCert, bool reload)
{
  auto certs = d_certs.write_lock();

  for (const auto& pair : *certs) {
    if (pair->cert.getSerial() == newCert->cert.getSerial()) {
      if (reload) {
        /* on reload we just assume that this is the same certificate */
        return;
      }
      throw std::runtime_error("Error adding a new certificate: we already have a certificate with the same serial");
    }
  }

  certs->push_back(newCert);
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
  d_certKeyPaths.write_lock()->push_back({certFile, keyFile});
}

void DNSCryptContext::reloadCertificates()
{
  std::vector<std::shared_ptr<DNSCryptCertificatePair>> newCerts;
  {
    auto paths = d_certKeyPaths.read_lock();
    newCerts.reserve(paths->size());
    for (const auto& pair : *paths) {
      newCerts.push_back(DNSCryptContext::loadCertificatePair(pair.cert, pair.key));
    }
  }

  {
    *(d_certs.write_lock()) = std::move(newCerts);
  }
}

std::vector<std::shared_ptr<DNSCryptCertificatePair>> DNSCryptContext::getCertificates()
{
  std::vector<std::shared_ptr<DNSCryptCertificatePair>> ret = *(d_certs.read_lock());
  return ret;
};

void DNSCryptContext::markActive(uint32_t serial)
{
  for (const auto& pair : *d_certs.write_lock()) {
    if (!pair->active && pair->cert.getSerial() == serial) {
      pair->active = true;
      return;
    }
  }
  throw std::runtime_error("No inactive certificate found with this serial");
}

void DNSCryptContext::markInactive(uint32_t serial)
{
  for (const auto& pair : *d_certs.write_lock()) {
    if (pair->active && pair->cert.getSerial() == serial) {
      pair->active = false;
      return;
    }
  }
  throw std::runtime_error("No active certificate found with this serial");
}

void DNSCryptContext::removeInactiveCertificate(uint32_t serial)
{
  auto certs = d_certs.write_lock();

  for (auto it = certs->begin(); it != certs->end();) {
    if (!(*it)->active && (*it)->cert.getSerial() == serial) {
      it = certs->erase(it);
      return;
    }
    it++;
  }
  throw std::runtime_error("No inactive certificate found with this serial");
}

bool DNSCryptQuery::parsePlaintextQuery(const PacketBuffer& packet)
{
  if (packet.size() < sizeof(dnsheader)) {
    return false;
  }

  const dnsheader_aligned dnsHeader(packet.data());
  if (dnsHeader->qr || ntohs(dnsHeader->qdcount) != 1 || dnsHeader->ancount != 0 || dnsHeader->nscount != 0 || static_cast<uint8_t>(dnsHeader->opcode) != Opcode::Query) {
    return false;
  }

  unsigned int qnameWireLength{0};
  uint16_t qtype{0};
  uint16_t qclass{0};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &qnameWireLength);
  if ((packet.size() - sizeof(dnsheader)) < (qnameWireLength + sizeof(qtype) + sizeof(qclass))) {
    return false;
  }

  if (qtype != QType::TXT || qclass != QClass::IN) {
    return false;
  }

  if (d_ctx == nullptr || qname != d_ctx->getProviderName()) {
    return false;
  }

  d_qname = std::move(qname);
  d_id = dnsHeader->id;
  d_valid = true;

  return true;
}

void DNSCryptContext::getCertificateResponse(time_t now, const DNSName& qname, uint16_t qid, PacketBuffer& response)
{
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, qname, QType::TXT, QClass::IN, Opcode::Query);
  struct dnsheader* dnsHeader = packetWriter.getHeader();
  dnsHeader->id = qid;
  dnsHeader->qr = true;
  dnsHeader->rcode = RCode::NoError;

  auto certs = d_certs.read_lock();
  for (const auto& pair : *certs) {
    if (!pair->active || !pair->cert.isValid(now)) {
      continue;
    }

    packetWriter.startRecord(qname, QType::TXT, (DNSCRYPT_CERTIFICATE_RESPONSE_TTL), QClass::IN, DNSResourceRecord::ANSWER, true);
    std::string scert;
    uint8_t certSize = sizeof(pair->cert);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    scert.assign(reinterpret_cast<const char*>(&certSize), sizeof(certSize));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    scert.append(reinterpret_cast<const char*>(&pair->cert), certSize);

    packetWriter.xfrBlob(scert);
    packetWriter.commit();
  }
}

bool DNSCryptContext::magicMatchesAPublicKey(DNSCryptQuery& query, time_t now)
{
  const auto& magic = query.getClientMagic();

  auto certs = d_certs.read_lock();
  for (const auto& pair : *certs) {
    if (pair->cert.isValid(now) && magic == pair->cert.signedData.clientMagic) {
      query.setCertificatePair(pair);
      return true;
    }
  }

  return false;
}

bool DNSCryptQuery::isEncryptedQuery(const PacketBuffer& packet, bool tcp, time_t now)
{
  d_encrypted = false;

  if (packet.size() < sizeof(DNSCryptQueryHeader)) {
    return false;
  }

  if (!tcp && packet.size() < DNSCryptQuery::s_minUDPLength) {
    return false;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  const auto* header = reinterpret_cast<const DNSCryptQueryHeader*>(packet.data());

  d_header = *header;

  if (d_ctx == nullptr || !d_ctx->magicMatchesAPublicKey(*this, now)) {
    return false;
  }

  d_encrypted = true;

  return true;
}

void DNSCryptQuery::getDecrypted(bool tcp, PacketBuffer& packet)
{
  if (!d_encrypted || d_valid || d_pair == nullptr) {
    throw std::runtime_error("Trying to decrypt a DNSCrypt query in an invalid state");
  }

#ifdef DNSCRYPT_STRICT_PADDING_LENGTH
  if (tcp && ((packet.size() - sizeof(DNSCryptQueryHeader)) % DNSCRYPT_PADDED_BLOCK_SIZE) != 0) {
    VERBOSESLOG(infolog("Dropping encrypted query with invalid size of %d (should be a multiple of %d)", (packet.size() - sizeof(DNSCryptQueryHeader)), DNSCRYPT_PADDED_BLOCK_SIZE),
                dnsdist::logging::getTopLogger()->info("Dropping DNSCrypt-encrypted query with invalid size (should be a multiple of " DNSCRYPT_PADDED_BLOCK_SIZE, "dns.question.size", Logging::Loggable(packet.size() - sizeof(DNSCryptQueryHeader))));
    return;
  }
#endif

  DNSCryptNonceType nonce;
  memcpy(nonce.data(), d_header.clientNonce.data(), d_header.clientNonce.size());
  memset(&nonce.at(d_header.clientNonce.size()), 0, nonce.size() - d_header.clientNonce.size());

#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int res = computeSharedKey();
  if (res != 0) {
    VERBOSESLOG(infolog("Dropping encrypted query we can't compute the shared key for"),
                dnsdist::logging::getTopLogger()->info("Dropping DNSCrypt-encrypted query we can't compute the shared key for"));
    return;
  }

  const DNSCryptExchangeVersion version = getVersion();

  if (version == DNSCryptExchangeVersion::VERSION1) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    res = crypto_box_open_easy_afternm(reinterpret_cast<unsigned char*>(packet.data()),
                                       // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                                       reinterpret_cast<unsigned char*>(&packet.at(sizeof(DNSCryptQueryHeader))),
                                       packet.size() - sizeof(DNSCryptQueryHeader),
                                       nonce.data(),
                                       d_sharedKey.data());
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    res = crypto_box_curve25519xchacha20poly1305_open_easy_afternm(reinterpret_cast<unsigned char*>(packet.data()),
                                                                   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                                                                   reinterpret_cast<unsigned char*>(&packet.at(sizeof(DNSCryptQueryHeader))),
                                                                   packet.size() - sizeof(DNSCryptQueryHeader),
                                                                   nonce.data(),
                                                                   d_sharedKey.data());
#else /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
    res = -1;
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
  }
  else {
    res = -1;
  }

#else /* HAVE_CRYPTO_BOX_EASY_AFTERNM */
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  int res = crypto_box_open_easy(reinterpret_cast<unsigned char*>(packet.data()),
                                 // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                                 reinterpret_cast<unsigned char*>(&packet.at(sizeof(DNSCryptQueryHeader))),
                                 packet.size() - sizeof(DNSCryptQueryHeader),
                                 nonce.data(),
                                 d_header.clientPK.data(),
                                 d_pair->privateKey.key.data());
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

  if (res != 0) {
    VERBOSESLOG(infolog("Dropping encrypted query we can't decrypt"),
                dnsdist::logging::getTopLogger()->error(Logr::Info, res, "Dropping DNSCrypt-encrypted query we couldn't decrypt"));
    return;
  }

  uint16_t decryptedQueryLen = packet.size() - sizeof(DNSCryptQueryHeader) - DNSCRYPT_MAC_SIZE;
  uint16_t pos = decryptedQueryLen;
  if (pos >= packet.size()) {
    VERBOSESLOG(infolog("Dropping encrypted query we can't decrypt (invalid position)"),
                dnsdist::logging::getTopLogger()->info("Dropping DNSCrypt-encrypted we couldn't decrypt because of an invalid position", "position", Logging::Loggable(pos), "dns.question.size", Logging::Loggable(packet.size())));
    return;
  }

  d_paddedLen = decryptedQueryLen;

  while (pos > 0 && packet.at(pos - 1) == 0) {
    pos--;
  }

  if (pos == 0 || packet.at(pos - 1) != 0x80) {
    VERBOSESLOG(infolog("Dropping encrypted query with invalid padding value"),
                dnsdist::logging::getTopLogger()->info("Dropping DNSCrypt-encrypted query with invalid padding value"));
    return;
  }

  pos--;

  size_t paddingLen = decryptedQueryLen - pos;
  packet.resize(pos);

  if (tcp && paddingLen > DNSCRYPT_MAX_TCP_PADDING_SIZE) {
    VERBOSESLOG(infolog("Dropping encrypted query with too long padding size"),
                dnsdist::logging::getTopLogger()->info("Dropping DNSCrypt-encrypted query withtoo long padding size"));
    return;
  }

  d_len = pos;
  d_valid = true;
}

void DNSCryptQuery::getCertificateResponse(time_t now, PacketBuffer& response) const
{
  if (d_ctx == nullptr) {
    throw std::runtime_error("Trying to get a certificate response from a DNSCrypt query lacking context");
  }
  d_ctx->getCertificateResponse(now, d_qname, d_id, response);
}

void DNSCryptQuery::parsePacket(PacketBuffer& packet, bool tcp, time_t now)
{
  d_valid = false;

  /* might be a plaintext certificate request or an authenticated request */
  if (isEncryptedQuery(packet, tcp, now)) {
    getDecrypted(tcp, packet);
  }
  else {
    parsePlaintextQuery(packet);
  }
}

void DNSCryptQuery::fillServerNonce(DNSCryptNonceType& nonce)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  auto* dest = reinterpret_cast<uint32_t*>(&nonce.at(DNSCRYPT_NONCE_SIZE / 2));
  static const size_t nonceSize = DNSCRYPT_NONCE_SIZE / 2;

  for (size_t pos = 0; pos < (nonceSize / sizeof(*dest)); pos++) {
    const uint32_t value = randombytes_random();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): sorry
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
  if (d_pair == nullptr) {
    throw std::runtime_error("Trying to compute the padding size from an invalid DNSCrypt query");
  }

  DNSCryptNonceType nonce;
  memcpy(nonce.data(), d_header.clientNonce.data(), d_header.clientNonce.size());
  memcpy(&(nonce.at(d_header.clientNonce.size())), d_header.clientNonce.data(), d_header.clientNonce.size());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  crypto_stream(reinterpret_cast<unsigned char*>(&rnd), sizeof(rnd), nonce.data(), d_pair->privateKey.key.data());

  paddedSize = unpaddedLen + rnd % (maxLen - unpaddedLen + 1);
  paddedSize += DNSCRYPT_PADDED_BLOCK_SIZE - (paddedSize % DNSCRYPT_PADDED_BLOCK_SIZE);

  if (paddedSize > maxLen) {
    paddedSize = maxLen;
  }

  result = paddedSize - unpaddedLen;

  return result;
}

int DNSCryptQuery::encryptResponse(PacketBuffer& response, size_t maxResponseSize, bool tcp)
{
  if (response.empty() || response.size() > maxResponseSize || !d_encrypted || d_pair == nullptr) {
    throw std::runtime_error("Trying to encrypt a DNSCrypt response from an invalid state");
  }

  DNSCryptResponseHeader responseHeader{};
  /* a DNSCrypt UDP response can't be larger than the (padded) DNSCrypt query */
  if (!tcp && d_paddedLen < response.size()) {
    /* so we need to truncate it */
    size_t questionSize = 0;

    if (response.size() > sizeof(dnsheader)) {
      unsigned int qnameWireLength = 0;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
      DNSName tempQName(reinterpret_cast<const char*>(response.data()), response.size(), sizeof(dnsheader), false, nullptr, nullptr, &qnameWireLength);
      if (qnameWireLength > 0) {
        questionSize = qnameWireLength + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
      }
    }

    response.resize(sizeof(dnsheader) + questionSize);

    if (response.size() > d_paddedLen) {
      /* that does not seem right but let's truncate even more */
      response.resize(d_paddedLen);
    }
    dnsdist::PacketMangling::editDNSHeaderFromPacket(response, [](dnsheader& header) {
      header.ancount = 0;
      header.arcount = 0;
      header.nscount = 0;
      header.tc = 1;
      return true;
    });
  }

  size_t requiredSize = sizeof(responseHeader) + DNSCRYPT_MAC_SIZE + response.size();
  size_t maxSize = std::min(maxResponseSize, requiredSize + DNSCRYPT_MAX_RESPONSE_PADDING_SIZE);
  uint16_t paddingSize = computePaddingSize(requiredSize, maxSize);
  requiredSize += paddingSize;

  if (requiredSize > maxResponseSize) {
    return ENOBUFS;
  }

  memcpy(responseHeader.nonce.data(), d_header.clientNonce.data(), d_header.clientNonce.size());
  fillServerNonce(responseHeader.nonce);

  size_t responseLen = response.size();
  /* moving the existing response after the header + MAC */
  response.resize(requiredSize);
  std::copy_backward(response.begin(), response.begin() + static_cast<ssize_t>(responseLen), response.begin() + static_cast<ssize_t>(responseLen + sizeof(responseHeader) + DNSCRYPT_MAC_SIZE));

  uint16_t pos = 0;
  /* copying header */
  memcpy(&response.at(pos), &responseHeader, sizeof(responseHeader));
  pos += sizeof(responseHeader);
  /* setting MAC bytes to 0 */
  memset(&response.at(pos), 0, DNSCRYPT_MAC_SIZE);
  pos += DNSCRYPT_MAC_SIZE;
  uint16_t toEncryptPos = pos;
  /* skipping response */
  pos += responseLen;
  /* padding */
  response.at(pos) = static_cast<uint8_t>(0x80);
  pos++;
  memset(&response.at(pos), 0, paddingSize - 1);
  pos += (paddingSize - 1);

  /* encrypting */
#ifdef HAVE_CRYPTO_BOX_EASY_AFTERNM
  int res = computeSharedKey();
  if (res != 0) {
    return res;
  }

  const DNSCryptExchangeVersion version = getVersion();

  if (version == DNSCryptExchangeVersion::VERSION1) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    res = crypto_box_easy_afternm(reinterpret_cast<unsigned char*>(&response.at(sizeof(responseHeader))),
                                  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                                  reinterpret_cast<unsigned char*>(&response.at(toEncryptPos)),
                                  responseLen + paddingSize,
                                  responseHeader.nonce.data(),
                                  d_sharedKey.data());
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    res = crypto_box_curve25519xchacha20poly1305_easy_afternm(reinterpret_cast<unsigned char*>(&response.at(sizeof(responseHeader))),
                                                              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                                                              reinterpret_cast<unsigned char*>(&response.at(toEncryptPos)),
                                                              responseLen + paddingSize,
                                                              responseHeader.nonce.data(),
                                                              d_sharedKey.data());
#else /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
    res = -1;
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
  }
  else {
    res = -1;
  }
#else
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  int res = crypto_box_easy(reinterpret_cast<unsigned char*>(&response.at(sizeof(responseHeader))),
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                            reinterpret_cast<unsigned char*>(&response.at(toEncryptPos)),
                            responseLen + paddingSize,
                            responseHeader.nonce.data(),
                            d_header.clientPK.data(),
                            d_pair->privateKey.key.data());
#endif /* HAVE_CRYPTO_BOX_EASY_AFTERNM */

  if (res == 0) {
    if (pos != requiredSize) {
      throw std::runtime_error("Unexpected size for encrypted DNSCrypt response");
    }
  }

  return res;
}

int DNSCryptContext::encryptQuery(PacketBuffer& packet, size_t maximumSize, const DNSCryptCertificatePair::PublicKeyType& clientPublicKey, const DNSCryptPrivateKey& clientPrivateKey, const DNSCryptClientNonceType& clientNonce, bool tcp, const std::shared_ptr<DNSCryptCert>& cert)
{
  if (packet.empty() || cert == nullptr) {
    throw std::runtime_error("Trying to encrypt a DNSCrypt query with an invalid state");
  }

  size_t queryLen = packet.size();
  DNSCryptNonceType nonce;
  size_t requiredSize = sizeof(DNSCryptQueryHeader) + DNSCRYPT_MAC_SIZE + queryLen;
  /* this is not optimal, we should compute a random padding size, multiple of DNSCRYPT_PADDED_BLOCK_SIZE,
     DNSCRYPT_PADDED_BLOCK_SIZE <= padding size <= 4096? */
  uint16_t paddingSize = DNSCRYPT_PADDED_BLOCK_SIZE - (queryLen % DNSCRYPT_PADDED_BLOCK_SIZE);
  requiredSize += paddingSize;

  if (!tcp && requiredSize < DNSCryptQuery::s_minUDPLength) {
    paddingSize += (DNSCryptQuery::s_minUDPLength - requiredSize);
    requiredSize = DNSCryptQuery::s_minUDPLength;
  }

  if (requiredSize > maximumSize) {
    return ENOBUFS;
  }

  /* moving the existing query after the header + MAC */
  packet.resize(requiredSize);
  std::copy_backward(packet.begin(), packet.begin() + static_cast<ssize_t>(queryLen), packet.begin() + static_cast<ssize_t>(queryLen + sizeof(DNSCryptQueryHeader) + DNSCRYPT_MAC_SIZE));

  size_t pos = 0;
  /* client magic */
  memcpy(&packet.at(pos), cert->signedData.clientMagic.data(), sizeof(cert->signedData.clientMagic));
  pos += cert->signedData.clientMagic.size();

  /* client PK */
  memcpy(&packet.at(pos), clientPublicKey.data(), clientPublicKey.size());
  pos += DNSCRYPT_PUBLIC_KEY_SIZE;

  /* client nonce */
  memcpy(&packet.at(pos), clientNonce.data(), clientNonce.size());
  pos += clientNonce.size();
  size_t encryptedPos = pos;

  /* clear the MAC bytes */
  memset(&packet.at(pos), 0, DNSCRYPT_MAC_SIZE);
  pos += DNSCRYPT_MAC_SIZE;

  /* skipping data */
  pos += queryLen;

  /* padding */
  packet.at(pos) = static_cast<uint8_t>(0x80);
  pos++;
  memset(&packet.at(pos), 0, paddingSize - 1);
  pos += paddingSize - 1;

  memcpy(nonce.data(), clientNonce.data(), clientNonce.size());
  memset(&nonce.at(clientNonce.size()), 0, DNSCRYPT_NONCE_SIZE / 2);

  const DNSCryptExchangeVersion version = getExchangeVersion(*cert);
  int res = -1;

  if (version == DNSCryptExchangeVersion::VERSION1) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    res = crypto_box_easy(reinterpret_cast<unsigned char*>(&packet.at(encryptedPos)),
                          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                          reinterpret_cast<unsigned char*>(&packet.at(encryptedPos + DNSCRYPT_MAC_SIZE)),
                          queryLen + paddingSize,
                          nonce.data(),
                          cert->signedData.resolverPK.data(),
                          clientPrivateKey.key.data());
  }
  else if (version == DNSCryptExchangeVersion::VERSION2) {
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    res = crypto_box_curve25519xchacha20poly1305_easy(reinterpret_cast<unsigned char*>(&packet.at(encryptedPos)),
                                                      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
                                                      reinterpret_cast<unsigned char*>(&packet.at(encryptedPos + DNSCRYPT_MAC_SIZE)),
                                                      queryLen + paddingSize,
                                                      nonce.data(),
                                                      cert->signedData.resolverPK.data(),
                                                      clientPrivateKey.key.data());
#endif /* HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_EASY */
  }
  else {
    throw std::runtime_error("Unknown DNSCrypt exchange version");
  }

  if (res == 0) {
    if (pos != requiredSize) {
      throw std::runtime_error("Unexpected size for encrypted DNSCrypt query");
    }
  }

  return res;
}

bool generateDNSCryptCertificate(const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, DNSCryptExchangeVersion version, DNSCryptCert& certOut, DNSCryptPrivateKey& keyOut)
{
  bool success = false;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey{};
  sodium_mlock(providerPrivateKey.data(), providerPrivateKey.size());
  sodium_memzero(providerPrivateKey.data(), providerPrivateKey.size());

  try {
    ifstream providerKStream(providerPrivateKeyFile);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    providerKStream.read(reinterpret_cast<char*>(providerPrivateKey.data()), providerPrivateKey.size());
    if (providerKStream.fail()) {
      providerKStream.close();
      throw std::runtime_error("Invalid DNSCrypt provider key file " + providerPrivateKeyFile);
    }

    DNSCryptContext::generateCertificate(serial, begin, end, version, providerPrivateKey, keyOut, certOut);
    success = true;
  }
  catch (const std::exception& e) {
    SLOG(errlog(e.what()),
         dnsdist::logging::getTopLogger()->error(e.what(), "Error while generating DNSCrypt certificate"));
  }

  sodium_memzero(providerPrivateKey.data(), providerPrivateKey.size());
  sodium_munlock(providerPrivateKey.data(), providerPrivateKey.size());
  return success;
}

#endif
