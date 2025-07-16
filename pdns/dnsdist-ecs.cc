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
#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"

/* when we add EDNS to a query, we don't want to advertise
   a large buffer size */
size_t g_EdnsUDPPayloadSize = 512;
static const uint16_t defaultPayloadSizeSelfGenAnswers = 1232;
static_assert(defaultPayloadSizeSelfGenAnswers < s_udpIncomingBufferSize, "The UDP responder's payload size should be smaller or equal to our incoming buffer size");
uint16_t g_PayloadSizeSelfGenAnswers{defaultPayloadSizeSelfGenAnswers};

/* draft-ietf-dnsop-edns-client-subnet-04 "11.1.  Privacy" */
uint16_t g_ECSSourcePrefixV4 = 24;
uint16_t g_ECSSourcePrefixV6 = 56;

bool g_ECSOverride{false};
bool g_addEDNSToSelfGeneratedResponses{true};

int rewriteResponseWithoutEDNS(const PacketBuffer& initialPacket, PacketBuffer& newContent)
{
  assert(initialPacket.size() >= sizeof(dnsheader));
  const dnsheader_aligned dh(initialPacket.data());

  if (ntohs(dh->arcount) == 0) {
    return ENOENT;
  }

  if (ntohs(dh->qdcount) == 0) {
    return ENOENT;
  }

  PacketReader pr(std::string_view(reinterpret_cast<const char*>(initialPacket.data()), initialPacket.size()));

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

  GenericDNSPacketWriter<PacketBuffer> pw(newContent, rrname, rrtype, rrclass, dh->opcode);
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

static bool addOrReplaceEDNSOption(std::vector<std::pair<uint16_t, std::string>>& options, uint16_t optionCode, bool& optionAdded, bool overrideExisting, const string& newOptionContent)
{
  for (auto it = options.begin(); it != options.end(); ) {
    if (it->first == optionCode) {
      optionAdded = false;

      if (!overrideExisting) {
        return false;
      }

      it = options.erase(it);
    }
    else {
      ++it;
    }
  }

  options.emplace_back(optionCode, std::string(&newOptionContent.at(EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), newOptionContent.size() - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)));
  return true;
}

bool slowRewriteEDNSOptionInQueryWithRecords(const PacketBuffer& initialPacket, PacketBuffer& newContent, bool& ednsAdded, uint16_t optionToReplace, bool& optionAdded, bool overrideExisting, const string& newOptionContent)
{
  assert(initialPacket.size() >= sizeof(dnsheader));
  const dnsheader_aligned dh(initialPacket.data());

  if (ntohs(dh->qdcount) == 0) {
    return false;
  }

  if (ntohs(dh->ancount) == 0 && ntohs(dh->nscount) == 0 && ntohs(dh->arcount) == 0) {
    throw std::runtime_error(std::string(__PRETTY_FUNCTION__) + " should not be called for queries that have no records");
  }

  optionAdded = false;
  ednsAdded = true;

  PacketReader pr(std::string_view(reinterpret_cast<const char*>(initialPacket.data()), initialPacket.size()));

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

  GenericDNSPacketWriter<PacketBuffer> pw(newContent, rrname, rrtype, rrclass, dh->opcode);
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

      ednsAdded = false;
      pr.xfrBlob(blob);

      std::vector<std::pair<uint16_t, std::string>> options;
      getEDNSOptionsFromContent(blob, options);

      /* getDnsrecordheader() has helpfully converted the TTL for us, which we do not want in that case */
      uint32_t ttl = htonl(ah.d_ttl);
      EDNS0Record edns0;
      static_assert(sizeof(edns0) == sizeof(ttl), "sizeof(EDNS0Record) must match sizeof(uint32_t) AKA RR TTL size");
      memcpy(&edns0, &ttl, sizeof(edns0));

      /* addOrReplaceEDNSOption will set it to false if there is already an existing option */
      optionAdded = true;
      addOrReplaceEDNSOption(options, optionToReplace, optionAdded, overrideExisting, newOptionContent);
      pw.addOpt(ah.d_class, edns0.extRCode, edns0.extFlags, options, edns0.version);
    }
  }

  if (ednsAdded) {
    pw.addOpt(g_EdnsUDPPayloadSize, 0, 0, {{optionToReplace, std::string(&newOptionContent.at(EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), newOptionContent.size() - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE))}}, 0);
    optionAdded = true;
  }

  pw.commit();

  return true;
}

int locateEDNSOptRR(const PacketBuffer& packet, uint16_t * optStart, size_t * optLen, bool * last)
{
  assert(optStart != NULL);
  assert(optLen != NULL);
  assert(last != NULL);
  const dnsheader_aligned dh(packet.data());

  if (ntohs(dh->arcount) == 0) {
    return ENOENT;
  }

  PacketReader pr(std::string_view(reinterpret_cast<const char*>(packet.data()), packet.size()));

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
int getEDNSOptionsStart(const PacketBuffer& packet, const size_t offset, uint16_t* optRDPosition, size_t* remaining)
{
  assert(optRDPosition != nullptr);
  assert(remaining != nullptr);
  const dnsheader_aligned dh(packet.data());

  if (offset >= packet.size()) {
    return ENOENT;
  }

  if (ntohs(dh->qdcount) != 1 || ntohs(dh->ancount) != 0 || ntohs(dh->arcount) != 1 || ntohs(dh->nscount) != 0) {
    return ENOENT;
  }

  size_t pos = sizeof(dnsheader) + offset;
  pos += DNS_TYPE_SIZE + DNS_CLASS_SIZE;

  if (pos >= packet.size())
    return ENOENT;

  if ((pos + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE) >= packet.size()) {
    return ENOENT;
  }

  if (packet[pos] != 0) {
    /* not the root so not an OPT record */
    return ENOENT;
  }
  pos += 1;

  uint16_t qtype = packet.at(pos)*256 + packet.at(pos+1);
  pos += DNS_TYPE_SIZE;
  pos += DNS_CLASS_SIZE;

  if (qtype != QType::OPT || (packet.size() - pos) < (DNS_TTL_SIZE + DNS_RDLENGTH_SIZE)) {
    return ENOENT;
  }

  pos += DNS_TTL_SIZE;
  *optRDPosition = pos;
  *remaining = packet.size() - pos;

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

bool generateOptRR(const std::string& optRData, PacketBuffer& res, size_t maximumSize, uint16_t udpPayloadSize, uint8_t ednsrcode, bool dnssecOK)
{
  const uint8_t name = 0;
  dnsrecordheader dh;
  EDNS0Record edns0;
  edns0.extRCode = ednsrcode;
  edns0.version = 0;
  edns0.extFlags = dnssecOK ? htons(EDNS_HEADER_FLAG_DO) : 0;

  if ((maximumSize - res.size()) < (sizeof(name) + sizeof(dh) + optRData.length())) {
    return false;
  }

  dh.d_type = htons(QType::OPT);
  dh.d_class = htons(udpPayloadSize);
  static_assert(sizeof(EDNS0Record) == sizeof(dh.d_ttl), "sizeof(EDNS0Record) must match sizeof(dnsrecordheader.d_ttl)");
  memcpy(&dh.d_ttl, &edns0, sizeof edns0);
  dh.d_clen = htons(static_cast<uint16_t>(optRData.length()));

  res.reserve(res.size() + sizeof(name) + sizeof(dh) + optRData.length());
  res.insert(res.end(), reinterpret_cast<const uint8_t*>(&name), reinterpret_cast<const uint8_t*>(&name) + sizeof(name));
  res.insert(res.end(), reinterpret_cast<const uint8_t*>(&dh), reinterpret_cast<const uint8_t*>(&dh) + sizeof(dh));
  res.insert(res.end(), reinterpret_cast<const uint8_t*>(optRData.data()), reinterpret_cast<const uint8_t*>(optRData.data()) + optRData.length());

  return true;
}

static bool replaceEDNSClientSubnetOption(PacketBuffer& packet, size_t maximumSize, size_t const oldEcsOptionStartPosition, size_t const oldEcsOptionSize, size_t const optRDLenPosition, const string& newECSOption)
{
  assert(oldEcsOptionStartPosition < packet.size());
  assert(optRDLenPosition < packet.size());

  if (newECSOption.size() == oldEcsOptionSize) {
    /* same size as the existing option */
    memcpy(&packet.at(oldEcsOptionStartPosition), newECSOption.c_str(), oldEcsOptionSize);
  }
  else {
    /* different size than the existing option */
    const unsigned int newPacketLen = packet.size() + (newECSOption.length() - oldEcsOptionSize);
    const size_t beforeOptionLen = oldEcsOptionStartPosition;
    const size_t dataBehindSize = packet.size() - beforeOptionLen - oldEcsOptionSize;

    /* check that it fits in the existing buffer */
    if (newPacketLen > packet.size()) {
      if (newPacketLen > maximumSize) {
        return false;
      }

      packet.resize(newPacketLen);
    }

    /* fix the size of ECS Option RDLen */
    uint16_t newRDLen = (packet.at(optRDLenPosition) * 256) + packet.at(optRDLenPosition + 1);
    newRDLen += (newECSOption.size() - oldEcsOptionSize);
    packet.at(optRDLenPosition) = newRDLen / 256;
    packet.at(optRDLenPosition + 1) = newRDLen % 256;

    if (dataBehindSize > 0) {
      memmove(&packet.at(oldEcsOptionStartPosition), &packet.at(oldEcsOptionStartPosition + oldEcsOptionSize), dataBehindSize);
    }
    memcpy(&packet.at(oldEcsOptionStartPosition + dataBehindSize), newECSOption.c_str(), newECSOption.size());
    packet.resize(newPacketLen);
  }

  return true;
}

/* This function looks for an OPT RR, return true if a valid one was found (even if there was no options)
   and false otherwise. */
bool parseEDNSOptions(const DNSQuestion& dq)
{
  const auto dh = dq.getHeader();
  if (dq.ednsOptions != nullptr) {
    return true;
  }

  // dq.ednsOptions is mutable
  dq.ednsOptions = std::make_unique<EDNSOptionViewMap>();

  if (ntohs(dh->arcount) == 0) {
    /* nothing in additional so no EDNS */
    return false;
  }

  if (ntohs(dh->ancount) != 0 || ntohs(dh->nscount) != 0 || ntohs(dh->arcount) > 1) {
    return slowParseEDNSOptions(dq.getData(), *dq.ednsOptions);
  }

  size_t remaining = 0;
  uint16_t optRDPosition;
  int res = getEDNSOptionsStart(dq.getData(), dq.ids.qname.wirelength(), &optRDPosition, &remaining);

  if (res == 0) {
    res = getEDNSOptions(reinterpret_cast<const char*>(&dq.getData().at(optRDPosition)), remaining, *dq.ednsOptions);
    return (res == 0);
  }

  return false;
}

static bool addECSToExistingOPT(PacketBuffer& packet, size_t maximumSize, const string& newECSOption, size_t optRDLenPosition, bool& ecsAdded)
{
  /* we need to add one EDNS0 ECS option, fixing the size of EDNS0 RDLENGTH */
  /* getEDNSOptionsStart has already checked that there is exactly one AR,
     no NS and no AN */
  uint16_t oldRDLen = (packet.at(optRDLenPosition) * 256) + packet.at(optRDLenPosition + 1);
  if (packet.size() != (optRDLenPosition + sizeof(uint16_t) + oldRDLen)) {
    /* we are supposed to be the last record, do we have some trailing data to remove? */
    uint32_t realPacketLen = getDNSPacketLength(reinterpret_cast<const char*>(packet.data()), packet.size());
    packet.resize(realPacketLen);
  }

  if ((maximumSize - packet.size()) < newECSOption.size()) {
    return false;
  }

  uint16_t newRDLen = oldRDLen + newECSOption.size();
  packet.at(optRDLenPosition) = newRDLen / 256;
  packet.at(optRDLenPosition + 1) = newRDLen % 256;

  packet.insert(packet.end(), newECSOption.begin(), newECSOption.end());
  ecsAdded = true;

  return true;
}

static bool addEDNSWithECS(PacketBuffer& packet, size_t maximumSize, const string& newECSOption, bool& ednsAdded, bool& ecsAdded)
{
  if (!generateOptRR(newECSOption, packet, maximumSize, g_EdnsUDPPayloadSize, 0, false)) {
    return false;
  }

  dnsdist::PacketMangling::editDNSHeaderFromPacket(packet, [](dnsheader& header) {
    uint16_t arcount = ntohs(header.arcount);
    arcount++;
    header.arcount = htons(arcount);
    return true;
  });
  ednsAdded = true;
  ecsAdded = true;

  return true;
}

bool handleEDNSClientSubnet(PacketBuffer& packet, const size_t maximumSize, const size_t qnameWireLength, bool& ednsAdded, bool& ecsAdded, bool overrideExisting, const string& newECSOption)
{
  assert(qnameWireLength <= packet.size());

  const dnsheader_aligned dh(packet.data());

  if (ntohs(dh->ancount) != 0 || ntohs(dh->nscount) != 0 || (ntohs(dh->arcount) != 0 && ntohs(dh->arcount) != 1)) {
    PacketBuffer newContent;
    newContent.reserve(packet.size());

    if (!slowRewriteEDNSOptionInQueryWithRecords(packet, newContent, ednsAdded, EDNSOptionCode::ECS, ecsAdded, overrideExisting, newECSOption)) {
      return false;
    }

    if (newContent.size() > maximumSize) {
      ednsAdded = false;
      ecsAdded = false;
      return false;
    }

    packet = std::move(newContent);
    return true;
  }

  uint16_t optRDPosition = 0;
  size_t remaining = 0;

  int res = getEDNSOptionsStart(packet, qnameWireLength, &optRDPosition, &remaining);

  if (res != 0) {
    /* no EDNS but there might be another record in additional (TSIG?) */
    /* Careful, this code assumes that ANCOUNT == 0 && NSCOUNT == 0 */
    size_t minimumPacketSize = sizeof(dnsheader) + qnameWireLength + sizeof(uint16_t) + sizeof(uint16_t);
    if (packet.size() > minimumPacketSize) {
      if (ntohs(dh->arcount) == 0) {
        /* well now.. */
        packet.resize(minimumPacketSize);
      }
      else {
        uint32_t realPacketLen = getDNSPacketLength(reinterpret_cast<const char*>(packet.data()), packet.size());
        packet.resize(realPacketLen);
      }
    }

    return addEDNSWithECS(packet, maximumSize, newECSOption, ednsAdded, ecsAdded);
  }

  size_t ecsOptionStartPosition = 0;
  size_t ecsOptionSize = 0;

  res = getEDNSOption(reinterpret_cast<const char*>(&packet.at(optRDPosition)), remaining, EDNSOptionCode::ECS, &ecsOptionStartPosition, &ecsOptionSize);

  if (res == 0) {
    /* there is already an ECS value */
    if (!overrideExisting) {
      return true;
    }

    return replaceEDNSClientSubnetOption(packet, maximumSize, optRDPosition + ecsOptionStartPosition, ecsOptionSize, optRDPosition, newECSOption);
  } else {
    /* we have an EDNS OPT RR but no existing ECS option */
    return addECSToExistingOPT(packet, maximumSize, newECSOption, optRDPosition, ecsAdded);
  }

  return true;
}

bool handleEDNSClientSubnet(DNSQuestion& dq, bool& ednsAdded, bool& ecsAdded)
{
  string newECSOption;
  generateECSOption(dq.ecs ? dq.ecs->getNetwork() : dq.ids.origRemote, newECSOption, dq.ecs ? dq.ecs->getBits() : dq.ecsPrefixLength);

  return handleEDNSClientSubnet(dq.getMutableData(), dq.getMaximumSize(), dq.ids.qname.wirelength(), ednsAdded, ecsAdded, dq.ecsOverride, newECSOption);
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

bool isEDNSOptionInOpt(const PacketBuffer& packet, const size_t optStart, const size_t optLen, const uint16_t optionCodeToFind, size_t* optContentStart, uint16_t* optContentLen)
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

int rewriteResponseWithoutEDNSOption(const PacketBuffer& initialPacket, const uint16_t optionCodeToSkip, PacketBuffer& newContent)
{
  assert(initialPacket.size() >= sizeof(dnsheader));
  const dnsheader_aligned dh(initialPacket.data());

  if (ntohs(dh->arcount) == 0)
    return ENOENT;

  if (ntohs(dh->qdcount) == 0)
    return ENOENT;

  PacketReader pr(std::string_view(reinterpret_cast<const char*>(initialPacket.data()), initialPacket.size()));

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

  GenericDNSPacketWriter<PacketBuffer> pw(newContent, rrname, rrtype, rrclass, dh->opcode);
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

bool addEDNS(PacketBuffer& packet, size_t maximumSize, bool dnssecOK, uint16_t payloadSize, uint8_t ednsrcode)
{
  if (!generateOptRR(std::string(), packet, maximumSize, payloadSize, ednsrcode, dnssecOK)) {
    return false;
  }

  dnsdist::PacketMangling::editDNSHeaderFromPacket(packet, [](dnsheader& header) {
    header.arcount = htons(ntohs(header.arcount) + 1);
    return true;
  });

  return true;
}

/*
  This function keeps the existing header and DNSSECOK bit (if any) but wipes anything else,
  generating a NXD or NODATA answer with a SOA record in the additional section (or optionally the authority section for a full cacheable NXDOMAIN/NODATA).
*/
bool setNegativeAndAdditionalSOA(DNSQuestion& dq, bool nxd, const DNSName& zone, uint32_t ttl, const DNSName& mname, const DNSName& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum, bool soaInAuthoritySection)
{
  auto& packet = dq.getMutableData();
  auto dh = dq.getHeader();
  if (ntohs(dh->qdcount) != 1) {
    return false;
  }

  size_t queryPartSize = sizeof(dnsheader) + dq.ids.qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
  if (packet.size() < queryPartSize) {
    /* something is already wrong, don't build on flawed foundations */
    return false;
  }

  uint16_t qtype = htons(QType::SOA);
  uint16_t qclass = htons(QClass::IN);
  uint16_t rdLength = mname.wirelength() + rname.wirelength() + sizeof(serial) + sizeof(refresh) + sizeof(retry) + sizeof(expire) + sizeof(minimum);
  size_t soaSize = zone.wirelength() + sizeof(qtype) + sizeof(qclass) + sizeof(ttl) + sizeof(rdLength) + rdLength;
  bool hadEDNS = false;
  bool dnssecOK = false;

  if (g_addEDNSToSelfGeneratedResponses) {
    uint16_t payloadSize = 0;
    uint16_t z = 0;
    hadEDNS = getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(packet.data()), packet.size(), &payloadSize, &z);
    if (hadEDNS) {
      dnssecOK = z & EDNS_HEADER_FLAG_DO;
    }
  }

  /* chop off everything after the question */
  packet.resize(queryPartSize);
  dnsdist::PacketMangling::editDNSHeaderFromPacket(packet, [nxd](dnsheader& header) {
    if (nxd) {
      header.rcode = RCode::NXDomain;
    }
    else {
      header.rcode = RCode::NoError;
    }
    header.qr = true;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    return true;
  });

  rdLength = htons(rdLength);
  ttl = htonl(ttl);
  serial = htonl(serial);
  refresh = htonl(refresh);
  retry = htonl(retry);
  expire = htonl(expire);
  minimum = htonl(minimum);

  std::string soa;
  soa.reserve(soaSize);
  soa.append(zone.toDNSString());
  soa.append(reinterpret_cast<const char*>(&qtype), sizeof(qtype));
  soa.append(reinterpret_cast<const char*>(&qclass), sizeof(qclass));
  soa.append(reinterpret_cast<const char*>(&ttl), sizeof(ttl));
  soa.append(reinterpret_cast<const char*>(&rdLength), sizeof(rdLength));
  soa.append(mname.toDNSString());
  soa.append(rname.toDNSString());
  soa.append(reinterpret_cast<const char*>(&serial), sizeof(serial));
  soa.append(reinterpret_cast<const char*>(&refresh), sizeof(refresh));
  soa.append(reinterpret_cast<const char*>(&retry), sizeof(retry));
  soa.append(reinterpret_cast<const char*>(&expire), sizeof(expire));
  soa.append(reinterpret_cast<const char*>(&minimum), sizeof(minimum));

  if (soa.size() != soaSize) {
    throw std::runtime_error("Unexpected SOA response size: " + std::to_string(soa.size()) + " vs " + std::to_string(soaSize));
  }

  packet.insert(packet.end(), soa.begin(), soa.end());

  /* We are populating a response with only the query in place, order of sections is QD,AN,NS,AR
     NS (authority) is before AR (additional) so we can just decide which section the SOA record is in here
     and have EDNS added to AR afterwards */
  dnsdist::PacketMangling::editDNSHeaderFromPacket(packet, [soaInAuthoritySection](dnsheader& header) {
    if (soaInAuthoritySection) {
      header.nscount = htons(1);
    } else {
      header.arcount = htons(1);
    }
    return true;
  });

  if (hadEDNS) {
    /* now we need to add a new OPT record */
    return addEDNS(packet, dq.getMaximumSize(), dnssecOK, g_PayloadSizeSelfGenAnswers, dq.ednsRCode);
  }

  return true;
}

bool addEDNSToQueryTurnedResponse(DNSQuestion& dq)
{
  uint16_t optRDPosition;
  /* remaining is at least the size of the rdlen + the options if any + the following records if any */
  size_t remaining = 0;

  auto& packet = dq.getMutableData();
  int res = getEDNSOptionsStart(packet, dq.ids.qname.wirelength(), &optRDPosition, &remaining);

  if (res != 0) {
    /* if the initial query did not have EDNS0, we are done */
    return true;
  }

  const size_t existingOptLen = /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + /* Z */ 2 + remaining;
  if (existingOptLen >= packet.size()) {
    /* something is wrong, bail out */
    return false;
  }

  uint8_t* optRDLen = &packet.at(optRDPosition);
  uint8_t* optPtr = (optRDLen - (/* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + /* Z */ 2));

  const uint8_t* zPtr = optPtr + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE;
  uint16_t z = 0x100 * (*zPtr) + *(zPtr + 1);
  bool dnssecOK = z & EDNS_HEADER_FLAG_DO;

  /* remove the existing OPT record, and everything else that follows (any SIG or TSIG would be useless anyway) */
  packet.resize(packet.size() - existingOptLen);
  dnsdist::PacketMangling::editDNSHeaderFromPacket(packet, [](dnsheader& header) {
    header.arcount = 0;
    return true;
  });

  if (g_addEDNSToSelfGeneratedResponses) {
    /* now we need to add a new OPT record */
    return addEDNS(packet, dq.getMaximumSize(), dnssecOK, g_PayloadSizeSelfGenAnswers, dq.ednsRCode);
  }

  /* otherwise we are just fine */
  return true;
}

// goal in life - if you send us a reasonably normal packet, we'll get Z for you, otherwise 0
int getEDNSZ(const DNSQuestion& dq)
{
  try
  {
    const auto& dh = dq.getHeader();
    if (ntohs(dh->qdcount) != 1 || dh->ancount != 0 || ntohs(dh->arcount) != 1 || dh->nscount != 0) {
      return 0;
    }

    if (dq.getData().size() <= sizeof(dnsheader)) {
      return 0;
    }

    size_t pos = sizeof(dnsheader) + dq.ids.qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE;

    if (dq.getData().size() <= (pos + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE)) {
      return 0;
    }

    auto& packet = dq.getData();

    if (packet.at(pos) != 0) {
      /* not root, so not a valid OPT record */
      return 0;
    }

    pos++;

    uint16_t qtype = packet.at(pos)*256 + packet.at(pos+1);
    pos += DNS_TYPE_SIZE;
    pos += DNS_CLASS_SIZE;

    if (qtype != QType::OPT || (pos + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + 1) >= packet.size()) {
      return 0;
    }

    const uint8_t* z = &packet.at(pos + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE);
    return 0x100 * (*z) + *(z+1);
  }
  catch(...)
  {
    return 0;
  }
}

bool queryHasEDNS(const DNSQuestion& dq)
{
  uint16_t optRDPosition;
  size_t ecsRemaining = 0;

  int res = getEDNSOptionsStart(dq.getData(), dq.ids.qname.wirelength(), &optRDPosition, &ecsRemaining);
  if (res == 0) {
    return true;
  }

  return false;
}

bool getEDNS0Record(const PacketBuffer& packet, EDNS0Record& edns0)
{
  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;
  int res = locateEDNSOptRR(packet, &optStart, &optLen, &last);
  if (res != 0) {
    // no EDNS OPT RR
    return false;
  }

  if (optLen < optRecordMinimumSize) {
    return false;
  }

  if (optStart < packet.size() && packet.at(optStart) != 0) {
    // OPT RR Name != '.'
    return false;
  }

  static_assert(sizeof(EDNS0Record) == sizeof(uint32_t), "sizeof(EDNS0Record) must match sizeof(uint32_t) AKA RR TTL size");
  // copy out 4-byte "ttl" (really the EDNS0 record), after root label (1) + type (2) + class (2).
  memcpy(&edns0, &packet.at(optStart + 5), sizeof edns0);
  return true;
}

bool setEDNSOption(DNSQuestion& dq, uint16_t ednsCode, const std::string& ednsData)
{
  std::string optRData;
  generateEDNSOption(ednsCode, ednsData, optRData);

  if (dq.getHeader()->arcount) {
    bool ednsAdded = false;
    bool optionAdded = false;
    PacketBuffer newContent;
    newContent.reserve(dq.getData().size());

    if (!slowRewriteEDNSOptionInQueryWithRecords(dq.getData(), newContent, ednsAdded, ednsCode, optionAdded, true, optRData)) {
      return false;
    }

    if (newContent.size() > dq.getMaximumSize()) {
      return false;
    }

    dq.getMutableData() = std::move(newContent);
    if (!dq.ids.ednsAdded && ednsAdded) {
      dq.ids.ednsAdded = true;
    }

    return true;
  }

  auto& data = dq.getMutableData();
  if (generateOptRR(optRData, data, dq.getMaximumSize(), g_EdnsUDPPayloadSize, 0, false)) {
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dq.getMutableData(), [](dnsheader& header) {
      header.arcount = htons(1);
      return true;
    });
    // make sure that any EDNS sent by the backend is removed before forwarding the response to the client
    dq.ids.ednsAdded = true;
  }

  return true;
}

namespace dnsdist {
bool setInternalQueryRCode(InternalQueryState& state, PacketBuffer& buffer,  uint8_t rcode, bool clearAnswers)
{
  const auto qnameLength = state.qname.wirelength();
  if (buffer.size() < sizeof(dnsheader) + qnameLength + sizeof(uint16_t) + sizeof(uint16_t)) {
    return false;
  }

  EDNS0Record edns0;
  bool hadEDNS = false;
  if (clearAnswers) {
    hadEDNS = getEDNS0Record(buffer, edns0);
  }

  dnsdist::PacketMangling::editDNSHeaderFromPacket(buffer, [rcode,clearAnswers](dnsheader& header) {
    header.rcode = rcode;
    header.ad = false;
    header.aa = false;
    header.ra = header.rd;
    header.qr = true;

    if (clearAnswers) {
      header.ancount = 0;
      header.nscount = 0;
      header.arcount = 0;
    }
    return true;
  });

  if (clearAnswers) {
    buffer.resize(sizeof(dnsheader) + qnameLength + sizeof(uint16_t) + sizeof(uint16_t));
    if (hadEDNS) {
      DNSQuestion dq(state, buffer);
      if (!addEDNS(buffer, dq.getMaximumSize(), edns0.extFlags & htons(EDNS_HEADER_FLAG_DO), g_PayloadSizeSelfGenAnswers, 0)) {
        return false;
      }
    }
  }

  return true;
}
}
