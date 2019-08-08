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
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"

/* when we add EDNS to a query, we don't want to advertise
   a large buffer size */
size_t g_EdnsUDPPayloadSize = 512;
uint16_t g_PayloadSizeSelfGenAnswers{s_udpIncomingBufferSize};

/* draft-ietf-dnsop-edns-client-subnet-04 "11.1.  Privacy" */
uint16_t g_ECSSourcePrefixV4 = 24;
uint16_t g_ECSSourcePrefixV6 = 56;

bool g_ECSOverride{false};
bool g_addEDNSToSelfGeneratedResponses{true};

int rewriteResponseWithoutEDNS(const std::string& initialPacket, vector<uint8_t>& newContent)
{
  assert(initialPacket.size() >= sizeof(dnsheader));
  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(initialPacket.data());

  if (ntohs(dh->arcount) == 0)
    return ENOENT;

  if (ntohs(dh->qdcount) == 0)
    return ENOENT;

  PacketReader pr(initialPacket);

  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t nscount = ntohs(dh->nscount);
  uint16_t arcount = ntohs(dh->arcount);
  uint16_t rrtype;
  uint16_t rrclass;
  string blob;
  struct dnsrecordheader ah;

  rrname = pr.getName();
  rrtype = pr.get16BitInt();
  rrclass = pr.get16BitInt();

  DNSPacketWriter pw(newContent, rrname, rrtype, rrclass, dh->opcode);
  pw.getHeader()->id=dh->id;
  pw.getHeader()->qr=dh->qr;
  pw.getHeader()->aa=dh->aa;
  pw.getHeader()->tc=dh->tc;
  pw.getHeader()->rd=dh->rd;
  pw.getHeader()->ra=dh->ra;
  pw.getHeader()->ad=dh->ad;
  pw.getHeader()->cd=dh->cd;
  pw.getHeader()->rcode=dh->rcode;

  /* consume remaining qd if any */
  if (qdcount > 1) {
    for(idx = 1; idx < qdcount; idx++) {
      rrname = pr.getName();
      rrtype = pr.get16BitInt();
      rrclass = pr.get16BitInt();
      (void) rrtype;
      (void) rrclass;
    }
  }

  /* copy AN and NS */
  for (idx = 0; idx < ancount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ANSWER, true);
    pr.xfrBlob(blob);
    pw.xfrBlob(blob);
  }

  for (idx = 0; idx < nscount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::AUTHORITY, true);
    pr.xfrBlob(blob);
    pw.xfrBlob(blob);
  }
  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type != QType::OPT) {
      pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ADDITIONAL, true);
      pr.xfrBlob(blob);
      pw.xfrBlob(blob);
    } else {
      pr.skip(ah.d_clen);
    }
  }
  pw.commit();

  return 0;
}

int locateEDNSOptRR(const std::string& packet, uint16_t * optStart, size_t * optLen, bool * last)
{
  assert(optStart != NULL);
  assert(optLen != NULL);
  assert(last != NULL);
  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(packet.data());

  if (ntohs(dh->arcount) == 0)
    return ENOENT;

  PacketReader pr(packet);
  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t nscount = ntohs(dh->nscount);
  uint16_t arcount = ntohs(dh->arcount);
  uint16_t rrtype;
  uint16_t rrclass;
  struct dnsrecordheader ah;

  /* consume qd */
  for(idx = 0; idx < qdcount; idx++) {
    rrname = pr.getName();
    rrtype = pr.get16BitInt();
    rrclass = pr.get16BitInt();
    (void) rrtype;
    (void) rrclass;
  }

  /* consume AN and NS */
  for (idx = 0; idx < ancount + nscount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);
    pr.skip(ah.d_clen);
  }

  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    uint16_t start = pr.getPosition();
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type == QType::OPT) {
      *optStart = start;
      *optLen = (pr.getPosition() - start) + ah.d_clen;

      if (packet.size() < (*optStart + *optLen)) {
        throw std::range_error("Opt record overflow");
      }

      if (idx == ((size_t) arcount - 1)) {
        *last = true;
      }
      else {
        *last = false;
      }
      return 0;
    }
    pr.skip(ah.d_clen);
  }

  return ENOENT;
}

/* extract the start of the OPT RR in a QUERY packet if any */
int getEDNSOptionsStart(const char* packet, const size_t offset, const size_t len, uint16_t* optRDPosition, size_t * remaining)
{
  assert(packet != nullptr);
  assert(optRDPosition != nullptr);
  assert(remaining != nullptr);
  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(packet);

  if (offset >= len) {
    return ENOENT;
  }

  if (ntohs(dh->qdcount) != 1 || ntohs(dh->ancount) != 0 || ntohs(dh->arcount) != 1 || ntohs(dh->nscount) != 0)
    return ENOENT;

  size_t pos = sizeof(dnsheader) + offset;
  pos += DNS_TYPE_SIZE + DNS_CLASS_SIZE;

  if (pos >= len)
    return ENOENT;

  if ((pos + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE) >= len) {
    return ENOENT;
  }

  if (packet[pos] != 0) {
    /* not the root so not an OPT record */
    return ENOENT;
  }
  pos += 1;

  uint16_t qtype = (reinterpret_cast<const unsigned char*>(packet)[pos])*256 + reinterpret_cast<const unsigned char*>(packet)[pos+1];
  pos += DNS_TYPE_SIZE;
  pos += DNS_CLASS_SIZE;

  if(qtype != QType::OPT || (len - pos) < (DNS_TTL_SIZE + DNS_RDLENGTH_SIZE))
    return ENOENT;

  pos += DNS_TTL_SIZE;
  *optRDPosition = pos;
  *remaining = len - pos;

  return 0;
}

void generateECSOption(const ComboAddress& source, string& res, uint16_t ECSPrefixLength)
{
  Netmask sourceNetmask(source, ECSPrefixLength);
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = sourceNetmask;
  string payload = makeEDNSSubnetOptsString(ecsOpts);
  generateEDNSOption(EDNSOptionCode::ECS, payload, res);
}

void generateOptRR(const std::string& optRData, string& res, uint16_t udpPayloadSize, uint8_t ednsrcode, bool dnssecOK)
{
  const uint8_t name = 0;
  dnsrecordheader dh;
  EDNS0Record edns0;
  edns0.extRCode = ednsrcode;
  edns0.version = 0;
  edns0.extFlags = dnssecOK ? htons(EDNS_HEADER_FLAG_DO) : 0;

  dh.d_type = htons(QType::OPT);
  dh.d_class = htons(udpPayloadSize);
  static_assert(sizeof(EDNS0Record) == sizeof(dh.d_ttl), "sizeof(EDNS0Record) must match sizeof(dnsrecordheader.d_ttl)");
  memcpy(&dh.d_ttl, &edns0, sizeof edns0);
  dh.d_clen = htons(static_cast<uint16_t>(optRData.length()));
  res.reserve(sizeof(name) + sizeof(dh) + optRData.length());
  res.assign(reinterpret_cast<const char *>(&name), sizeof name);
  res.append(reinterpret_cast<const char *>(&dh), sizeof(dh));
  res.append(optRData.c_str(), optRData.length());
}

static bool replaceEDNSClientSubnetOption(char * const packet, const size_t packetSize, uint16_t * const len, char * const oldEcsOptionStart, size_t const oldEcsOptionSize, unsigned char * const optRDLen, const string& newECSOption)
{
  assert(packet != NULL);
  assert(len != NULL);
  assert(oldEcsOptionStart != NULL);
  assert(optRDLen != NULL);

  if (newECSOption.size() == oldEcsOptionSize) {
    /* same size as the existing option */
    memcpy(oldEcsOptionStart, newECSOption.c_str(), oldEcsOptionSize);
  }
  else {
    /* different size than the existing option */
    const unsigned int newPacketLen = *len + (newECSOption.length() - oldEcsOptionSize);
    const size_t beforeOptionLen = oldEcsOptionStart - packet;
    const size_t dataBehindSize = *len - beforeOptionLen - oldEcsOptionSize;

    /* check that it fits in the existing buffer */
    if (newPacketLen > packetSize) {
      return false;
    }

    /* fix the size of ECS Option RDLen */
    uint16_t newRDLen = (optRDLen[0] * 256) + optRDLen[1];
    newRDLen += (newECSOption.size() - oldEcsOptionSize);
    optRDLen[0] = newRDLen / 256;
    optRDLen[1] = newRDLen % 256;

    if (dataBehindSize > 0) {
      memmove(oldEcsOptionStart, oldEcsOptionStart + oldEcsOptionSize, dataBehindSize);
    }
    memcpy(oldEcsOptionStart + dataBehindSize, newECSOption.c_str(), newECSOption.size());
    *len = newPacketLen;
  }

  return true;
}

/* This function looks for an OPT RR, return true if a valid one was found (even if there was no options)
   and false otherwise. */
bool parseEDNSOptions(DNSQuestion& dq)
{
  assert(dq.dh != nullptr);
  assert(dq.consumed <= dq.len);
  assert(dq.len <= dq.size);

  if (dq.ednsOptions != nullptr) {
    return true;
  }

  dq.ednsOptions = std::make_shared<std::map<uint16_t, EDNSOptionView> >();
  const char* packet = reinterpret_cast<const char*>(dq.dh);

  size_t remaining = 0;
  uint16_t optRDPosition;
  int res = getEDNSOptionsStart(packet, dq.consumed, dq.len, &optRDPosition, &remaining);

  if (res == 0) {
    res = getEDNSOptions(packet + optRDPosition, remaining, *dq.ednsOptions);
    return (res == 0);
  }

  return false;
}

static bool addECSToExistingOPT(char* const packet, size_t const packetSize, uint16_t* const len, const string& newECSOption, unsigned char* optRDLen, bool* const ecsAdded)
{
  /* we need to add one EDNS0 ECS option, fixing the size of EDNS0 RDLENGTH */
  /* getEDNSOptionsStart has already checked that there is exactly one AR,
     no NS and no AN */

  /* check if the existing buffer is large enough */
  const size_t newECSOptionSize = newECSOption.size();
  if (packetSize - *len <= newECSOptionSize) {
    return false;
  }

  uint16_t newRDLen = (optRDLen[0] * 256) + optRDLen[1];
  newRDLen += newECSOptionSize;
  optRDLen[0] = newRDLen / 256;
  optRDLen[1] = newRDLen % 256;

  memcpy(packet + *len, newECSOption.c_str(), newECSOptionSize);
  *len += newECSOptionSize;
  *ecsAdded = true;

  return true;
}

static bool addEDNSWithECS(char* const packet, size_t const packetSize, uint16_t* const len, const string& newECSOption, bool* const ednsAdded, bool preserveTrailingData)
{
  /* we need to add a EDNS0 RR with one EDNS0 ECS option, fixing the AR count */
  string EDNSRR;
  struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(packet);
  generateOptRR(newECSOption, EDNSRR, g_EdnsUDPPayloadSize, 0, false);

  /* does it fit in the existing buffer? */
  if (packetSize - *len <= EDNSRR.size()) {
    return false;
  }

  uint32_t realPacketLen = getDNSPacketLength(packet, *len);
  if (realPacketLen < *len && preserveTrailingData) {
    size_t toMove = *len - realPacketLen;
    memmove(packet + realPacketLen + EDNSRR.size(), packet + realPacketLen, toMove);
    *len += EDNSRR.size();
  }
  else {
    *len = realPacketLen + EDNSRR.size();
  }

  uint16_t arcount = ntohs(dh->arcount);
  arcount++;
  dh->arcount = htons(arcount);
  *ednsAdded = true;

  memcpy(packet + realPacketLen, EDNSRR.c_str(), EDNSRR.size());

  return true;
}

bool handleEDNSClientSubnet(char* const packet, const size_t packetSize, const unsigned int consumed, uint16_t* const len, bool* const ednsAdded, bool* const ecsAdded, bool overrideExisting, const string& newECSOption, bool preserveTrailingData)
{
  assert(packet != nullptr);
  assert(len != nullptr);
  assert(consumed <= (size_t) *len);
  assert(ednsAdded != nullptr);
  assert(ecsAdded != nullptr);
  uint16_t optRDPosition = 0;
  size_t remaining = 0;

  int res = getEDNSOptionsStart(packet, consumed, *len, &optRDPosition, &remaining);

  if (res != 0) {
    return addEDNSWithECS(packet, packetSize, len, newECSOption, ednsAdded, preserveTrailingData);
  }

  unsigned char* optRDLen = reinterpret_cast<unsigned char*>(packet) + optRDPosition;
  char * ecsOptionStart = nullptr;
  size_t ecsOptionSize = 0;

  res = getEDNSOption(reinterpret_cast<char*>(optRDLen), remaining, EDNSOptionCode::ECS, &ecsOptionStart, &ecsOptionSize);

  if (res == 0) {
    /* there is already an ECS value */
    if (!overrideExisting) {
      return true;
    }

    return replaceEDNSClientSubnetOption(packet, packetSize, len, ecsOptionStart, ecsOptionSize, optRDLen, newECSOption);
  } else {
    /* we have an EDNS OPT RR but no existing ECS option */
    return addECSToExistingOPT(packet, packetSize, len, newECSOption, optRDLen, ecsAdded);
  }

  return true;
}

bool handleEDNSClientSubnet(DNSQuestion& dq, bool* ednsAdded, bool* ecsAdded, bool preserveTrailingData)
{
  assert(dq.remote != nullptr);
  string newECSOption;
  generateECSOption(dq.ecsSet ? dq.ecs.getNetwork() : *dq.remote, newECSOption, dq.ecsSet ? dq.ecs.getBits() : dq.ecsPrefixLength);
  char* packet = reinterpret_cast<char*>(dq.dh);

  return handleEDNSClientSubnet(packet, dq.size, dq.consumed, &dq.len, ednsAdded, ecsAdded, dq.ecsOverride, newECSOption, preserveTrailingData);
}

static int removeEDNSOptionFromOptions(unsigned char* optionsStart, const uint16_t optionsLen, const uint16_t optionCodeToRemove, uint16_t* newOptionsLen)
{
  unsigned char* p = optionsStart;
  size_t pos = 0;
  while ((pos + 4) <= optionsLen) {
    unsigned char* optionBegin = p;
    const uint16_t optionCode = 0x100*p[0] + p[1];
    p += sizeof(optionCode);
    pos += sizeof(optionCode);
    const uint16_t optionLen = 0x100*p[0] + p[1];
    p += sizeof(optionLen);
    pos += sizeof(optionLen);
    if ((pos + optionLen) > optionsLen) {
      return EINVAL;
    }
    if (optionCode == optionCodeToRemove) {
      if (pos + optionLen < optionsLen) {
        /* move remaining options over the removed one,
           if any */
        memmove(optionBegin, p + optionLen, optionsLen - (pos + optionLen));
      }
      *newOptionsLen = optionsLen - (sizeof(optionCode) + sizeof(optionLen) + optionLen);
      return 0;
    }
    p += optionLen;
    pos += optionLen;
  }
  return ENOENT;
}

int removeEDNSOptionFromOPT(char* optStart, size_t* optLen, const uint16_t optionCodeToRemove)
{
  if (*optLen < optRecordMinimumSize) {
    return EINVAL;
  }
  const unsigned char* end = (const unsigned char*) optStart + *optLen;
  unsigned char* p = (unsigned char*) optStart + 9;
  unsigned char* rdLenPtr = p;
  uint16_t rdLen = (0x100*p[0] + p[1]);
  p += sizeof(rdLen);
  if (p + rdLen != end) {
    return EINVAL;
  }
  uint16_t newRdLen = 0;
  int res = removeEDNSOptionFromOptions(p, rdLen, optionCodeToRemove, &newRdLen);
  if (res != 0) {
    return res;
  }
  *optLen -= (rdLen - newRdLen);
  rdLenPtr[0] = newRdLen / 0x100;
  rdLenPtr[1] = newRdLen % 0x100;
  return 0;
}

bool isEDNSOptionInOpt(const std::string& packet, const size_t optStart, const size_t optLen, const uint16_t optionCodeToFind, size_t* optContentStart, uint16_t* optContentLen)
{
  if (optLen < optRecordMinimumSize) {
    return false;
  }
  size_t p = optStart + 9;
  uint16_t rdLen = (0x100*static_cast<unsigned char>(packet.at(p)) + static_cast<unsigned char>(packet.at(p+1)));
  p += sizeof(rdLen);
  if (rdLen > (optLen - optRecordMinimumSize)) {
    return false;
  }

  size_t rdEnd = p + rdLen;
  while ((p + 4) <= rdEnd) {
    const uint16_t optionCode = 0x100*static_cast<unsigned char>(packet.at(p)) + static_cast<unsigned char>(packet.at(p+1));
    p += sizeof(optionCode);
    const uint16_t optionLen = 0x100*static_cast<unsigned char>(packet.at(p)) + static_cast<unsigned char>(packet.at(p+1));
    p += sizeof(optionLen);

    if ((p + optionLen) > rdEnd) {
      return false;
    }

    if (optionCode == optionCodeToFind) {
      if (optContentStart != nullptr) {
        *optContentStart = p;
      }

      if (optContentLen != nullptr) {
        *optContentLen = optionLen;
      }

      return true;
    }
    p += optionLen;
  }
  return false;
}

int rewriteResponseWithoutEDNSOption(const std::string& initialPacket, const uint16_t optionCodeToSkip, vector<uint8_t>& newContent)
{
  assert(initialPacket.size() >= sizeof(dnsheader));
  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(initialPacket.data());

  if (ntohs(dh->arcount) == 0)
    return ENOENT;

  if (ntohs(dh->qdcount) == 0)
    return ENOENT;

  PacketReader pr(initialPacket);

  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t nscount = ntohs(dh->nscount);
  uint16_t arcount = ntohs(dh->arcount);
  uint16_t rrtype;
  uint16_t rrclass;
  string blob;
  struct dnsrecordheader ah;

  rrname = pr.getName();
  rrtype = pr.get16BitInt();
  rrclass = pr.get16BitInt();

  DNSPacketWriter pw(newContent, rrname, rrtype, rrclass, dh->opcode);
  pw.getHeader()->id=dh->id;
  pw.getHeader()->qr=dh->qr;
  pw.getHeader()->aa=dh->aa;
  pw.getHeader()->tc=dh->tc;
  pw.getHeader()->rd=dh->rd;
  pw.getHeader()->ra=dh->ra;
  pw.getHeader()->ad=dh->ad;
  pw.getHeader()->cd=dh->cd;
  pw.getHeader()->rcode=dh->rcode;

  /* consume remaining qd if any */
  if (qdcount > 1) {
    for(idx = 1; idx < qdcount; idx++) {
      rrname = pr.getName();
      rrtype = pr.get16BitInt();
      rrclass = pr.get16BitInt();
      (void) rrtype;
      (void) rrclass;
    }
  }

  /* copy AN and NS */
  for (idx = 0; idx < ancount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ANSWER, true);
    pr.xfrBlob(blob);
    pw.xfrBlob(blob);
  }

  for (idx = 0; idx < nscount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::AUTHORITY, true);
    pr.xfrBlob(blob);
    pw.xfrBlob(blob);
  }

  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type != QType::OPT) {
      pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ADDITIONAL, true);
      pr.xfrBlob(blob);
      pw.xfrBlob(blob);
    } else {
      pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ADDITIONAL, false);
      pr.xfrBlob(blob);
      uint16_t rdLen = blob.length();
      removeEDNSOptionFromOptions((unsigned char*)blob.c_str(), rdLen, optionCodeToSkip, &rdLen);
      /* xfrBlob(string, size) completely ignores size.. */
      if (rdLen > 0) {
        blob.resize((size_t)rdLen);
        pw.xfrBlob(blob);
      } else {
        pw.commit();
      }
    }
  }
  pw.commit();

  return 0;
}

bool addEDNS(dnsheader* dh, uint16_t& len, const size_t size, bool dnssecOK, uint16_t payloadSize, uint8_t ednsrcode)
{
  if (dh->arcount != 0) {
    return false;
  }

  std::string optRecord;
  generateOptRR(std::string(), optRecord, payloadSize, ednsrcode, dnssecOK);

  if (optRecord.size() >= size || (size - optRecord.size()) < len) {
    return false;
  }

  char * optPtr = reinterpret_cast<char*>(dh) + len;
  memcpy(optPtr, optRecord.data(), optRecord.size());
  len += optRecord.size();
  dh->arcount = htons(1);

  return true;
}

bool addEDNSToQueryTurnedResponse(DNSQuestion& dq)
{
  uint16_t optRDPosition;
  /* remaining is at least the size of the rdlen + the options if any + the following records if any */
  size_t remaining = 0;

  int res = getEDNSOptionsStart(reinterpret_cast<char*>(dq.dh), dq.consumed, dq.len, &optRDPosition, &remaining);

  if (res != 0) {
    /* if the initial query did not have EDNS0, we are done */
    return true;
  }

  const size_t existingOptLen = /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + /* Z */ 2 + remaining;
  if (existingOptLen >= dq.len) {
    /* something is wrong, bail out */
    return false;
  }

  char* optRDLen = reinterpret_cast<char*>(dq.dh) + optRDPosition;
  char * optPtr = (optRDLen - (/* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + /* Z */ 2));

  const uint8_t* zPtr = reinterpret_cast<const uint8_t*>(optPtr) + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE;
  uint16_t z = 0x100 * (*zPtr) + *(zPtr + 1);
  bool dnssecOK = z & EDNS_HEADER_FLAG_DO;

  /* remove the existing OPT record, and everything else that follows (any SIG or TSIG would be useless anyway) */
  dq.len -= existingOptLen;
  dq.dh->arcount = 0;

  if (g_addEDNSToSelfGeneratedResponses) {
    /* now we need to add a new OPT record */
    return addEDNS(dq.dh, dq.len, dq.size, dnssecOK, g_PayloadSizeSelfGenAnswers, dq.ednsRCode);
  }

  /* otherwise we are just fine */
  return true;
}

// goal in life - if you send us a reasonably normal packet, we'll get Z for you, otherwise 0
int getEDNSZ(const DNSQuestion& dq)
try
{
  if (ntohs(dq.dh->qdcount) != 1 || dq.dh->ancount != 0 || ntohs(dq.dh->arcount) != 1 || dq.dh->nscount != 0) {
    return 0;
  }

  if (dq.len <= sizeof(dnsheader)) {
    return 0;
  }

  size_t pos = sizeof(dnsheader) + dq.consumed + DNS_TYPE_SIZE + DNS_CLASS_SIZE;

  if (dq.len <= (pos + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE)) {
    return 0;
  }

  const char* packet = reinterpret_cast<const char*>(dq.dh);

  if (packet[pos] != 0) {
    /* not root, so not a valid OPT record */
    return 0;
  }

  pos++;

  uint16_t qtype = (reinterpret_cast<const unsigned char*>(packet)[pos])*256 + reinterpret_cast<const unsigned char*>(packet)[pos+1];
  pos += DNS_TYPE_SIZE;
  pos += DNS_CLASS_SIZE;

  if (qtype != QType::OPT || (pos + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + 1) >= dq.len) {
    return 0;
  }

  const uint8_t* z = reinterpret_cast<const uint8_t*>(packet) + pos + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE;
  return 0x100 * (*z) + *(z+1);
}
catch(...)
{
  return 0;
}

bool queryHasEDNS(const DNSQuestion& dq)
{
  uint16_t optRDPosition;
  size_t ecsRemaining = 0;

  int res = getEDNSOptionsStart(reinterpret_cast<char*>(dq.dh), dq.consumed, dq.len, &optRDPosition, &ecsRemaining);
  if (res == 0) {
    return true;
  }

  return false;
}

bool getEDNS0Record(const DNSQuestion& dq, EDNS0Record& edns0)
{
  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;
  const char * packet = reinterpret_cast<const char*>(dq.dh);
  std::string packetStr(packet, dq.len);
  int res = locateEDNSOptRR(packetStr, &optStart, &optLen, &last);
  if (res != 0) {
    // no EDNS OPT RR
    return false;
  }

  if (optLen < optRecordMinimumSize) {
    return false;
  }

  if (optStart < dq.len && packetStr.at(optStart) != 0) {
    // OPT RR Name != '.'
    return false;
  }

  static_assert(sizeof(EDNS0Record) == sizeof(uint32_t), "sizeof(EDNS0Record) must match sizeof(uint32_t) AKA RR TTL size");
  // copy out 4-byte "ttl" (really the EDNS0 record), after root label (1) + type (2) + class (2).
  memcpy(&edns0, packet + optStart + 5, sizeof edns0);
  return true;
}
