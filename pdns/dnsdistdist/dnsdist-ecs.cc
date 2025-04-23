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
  if (initialPacket.size() < sizeof(dnsheader)) {
    return ENOENT;
  }

  const dnsheader_aligned dnsHeader(initialPacket.data());

  if (ntohs(dnsHeader->arcount) == 0) {
    return ENOENT;
  }

  if (ntohs(dnsHeader->qdcount) == 0) {
    return ENOENT;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  PacketReader packetReader(std::string_view(reinterpret_cast<const char*>(initialPacket.data()), initialPacket.size()));

  size_t idx = 0;
  uint16_t qdcount = ntohs(dnsHeader->qdcount);
  uint16_t ancount = ntohs(dnsHeader->ancount);
  uint16_t nscount = ntohs(dnsHeader->nscount);
  uint16_t arcount = ntohs(dnsHeader->arcount);
  string blob;
  dnsrecordheader recordHeader{};

  auto rrname = packetReader.getName();
  auto rrtype = packetReader.get16BitInt();
  auto rrclass = packetReader.get16BitInt();

  GenericDNSPacketWriter<PacketBuffer> packetWriter(newContent, rrname, rrtype, rrclass, dnsHeader->opcode);
  packetWriter.getHeader()->id = dnsHeader->id;
  packetWriter.getHeader()->qr = dnsHeader->qr;
  packetWriter.getHeader()->aa = dnsHeader->aa;
  packetWriter.getHeader()->tc = dnsHeader->tc;
  packetWriter.getHeader()->rd = dnsHeader->rd;
  packetWriter.getHeader()->ra = dnsHeader->ra;
  packetWriter.getHeader()->ad = dnsHeader->ad;
  packetWriter.getHeader()->cd = dnsHeader->cd;
  packetWriter.getHeader()->rcode = dnsHeader->rcode;

  /* consume remaining qd if any */
  if (qdcount > 1) {
    for (idx = 1; idx < qdcount; idx++) {
      rrname = packetReader.getName();
      rrtype = packetReader.get16BitInt();
      rrclass = packetReader.get16BitInt();
      (void)rrtype;
      (void)rrclass;
    }
  }

  /* copy AN and NS */
  for (idx = 0; idx < ancount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::ANSWER, true);
    packetReader.xfrBlob(blob);
    packetWriter.xfrBlob(blob);
  }

  for (idx = 0; idx < nscount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::AUTHORITY, true);
    packetReader.xfrBlob(blob);
    packetWriter.xfrBlob(blob);
  }
  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    if (recordHeader.d_type != QType::OPT) {
      packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::ADDITIONAL, true);
      packetReader.xfrBlob(blob);
      packetWriter.xfrBlob(blob);
    }
    else {

      packetReader.skip(recordHeader.d_clen);
    }
  }
  packetWriter.commit();

  return 0;
}

static bool addOrReplaceEDNSOption(std::vector<std::pair<uint16_t, std::string>>& options, uint16_t optionCode, bool& optionAdded, bool overrideExisting, const string& newOptionContent)
{
  for (auto it = options.begin(); it != options.end();) {
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
  if (initialPacket.size() < sizeof(dnsheader)) {
    return false;
  }

  const dnsheader_aligned dnsHeader(initialPacket.data());

  if (ntohs(dnsHeader->qdcount) == 0) {
    return false;
  }

  if (ntohs(dnsHeader->ancount) == 0 && ntohs(dnsHeader->nscount) == 0 && ntohs(dnsHeader->arcount) == 0) {
    throw std::runtime_error("slowRewriteEDNSOptionInQueryWithRecords should not be called for queries that have no records");
  }

  optionAdded = false;
  ednsAdded = true;

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  PacketReader packetReader(std::string_view(reinterpret_cast<const char*>(initialPacket.data()), initialPacket.size()));

  size_t idx = 0;
  uint16_t qdcount = ntohs(dnsHeader->qdcount);
  uint16_t ancount = ntohs(dnsHeader->ancount);
  uint16_t nscount = ntohs(dnsHeader->nscount);
  uint16_t arcount = ntohs(dnsHeader->arcount);
  string blob;
  dnsrecordheader recordHeader{};

  auto rrname = packetReader.getName();
  auto rrtype = packetReader.get16BitInt();
  auto rrclass = packetReader.get16BitInt();

  GenericDNSPacketWriter<PacketBuffer> packetWriter(newContent, rrname, rrtype, rrclass, dnsHeader->opcode);
  packetWriter.getHeader()->id = dnsHeader->id;
  packetWriter.getHeader()->qr = dnsHeader->qr;
  packetWriter.getHeader()->aa = dnsHeader->aa;
  packetWriter.getHeader()->tc = dnsHeader->tc;
  packetWriter.getHeader()->rd = dnsHeader->rd;
  packetWriter.getHeader()->ra = dnsHeader->ra;
  packetWriter.getHeader()->ad = dnsHeader->ad;
  packetWriter.getHeader()->cd = dnsHeader->cd;
  packetWriter.getHeader()->rcode = dnsHeader->rcode;

  /* consume remaining qd if any */
  if (qdcount > 1) {
    for (idx = 1; idx < qdcount; idx++) {
      rrname = packetReader.getName();
      rrtype = packetReader.get16BitInt();
      rrclass = packetReader.get16BitInt();
      (void)rrtype;
      (void)rrclass;
    }
  }

  /* copy AN and NS */
  for (idx = 0; idx < ancount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::ANSWER, true);
    packetReader.xfrBlob(blob);
    packetWriter.xfrBlob(blob);
  }

  for (idx = 0; idx < nscount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::AUTHORITY, true);
    packetReader.xfrBlob(blob);
    packetWriter.xfrBlob(blob);
  }

  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    if (recordHeader.d_type != QType::OPT) {
      packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::ADDITIONAL, true);
      packetReader.xfrBlob(blob);
      packetWriter.xfrBlob(blob);
    }
    else {

      ednsAdded = false;
      packetReader.xfrBlob(blob);

      std::vector<std::pair<uint16_t, std::string>> options;
      getEDNSOptionsFromContent(blob, options);

      /* getDnsrecordheader() has helpfully converted the TTL for us, which we do not want in that case */
      uint32_t ttl = htonl(recordHeader.d_ttl);
      EDNS0Record edns0{};
      static_assert(sizeof(edns0) == sizeof(ttl), "sizeof(EDNS0Record) must match sizeof(uint32_t) AKA RR TTL size");
      memcpy(&edns0, &ttl, sizeof(edns0));

      /* addOrReplaceEDNSOption will set it to false if there is already an existing option */
      optionAdded = true;
      addOrReplaceEDNSOption(options, optionToReplace, optionAdded, overrideExisting, newOptionContent);
      packetWriter.addOpt(recordHeader.d_class, edns0.extRCode, edns0.extFlags, options, edns0.version);
    }
  }

  if (ednsAdded) {
    packetWriter.addOpt(g_EdnsUDPPayloadSize, 0, 0, {{optionToReplace, std::string(&newOptionContent.at(EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), newOptionContent.size() - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE))}}, 0);
    optionAdded = true;
  }

  packetWriter.commit();

  return true;
}

int locateEDNSOptRR(const PacketBuffer& packet, uint16_t* optStart, size_t* optLen, bool* last)
{
  if (optStart == nullptr || optLen == nullptr || last == nullptr) {
    throw std::runtime_error("Invalid values passed to locateEDNSOptRR");
  }

  const dnsheader_aligned dnsHeader(packet.data());

  if (ntohs(dnsHeader->arcount) == 0) {
    return ENOENT;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  PacketReader packetReader(std::string_view(reinterpret_cast<const char*>(packet.data()), packet.size()));

  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dnsHeader->qdcount);
  uint16_t ancount = ntohs(dnsHeader->ancount);
  uint16_t nscount = ntohs(dnsHeader->nscount);
  uint16_t arcount = ntohs(dnsHeader->arcount);
  uint16_t rrtype{};
  uint16_t rrclass{};
  dnsrecordheader recordHeader{};

  /* consume qd */
  for (idx = 0; idx < qdcount; idx++) {
    rrname = packetReader.getName();
    rrtype = packetReader.get16BitInt();
    rrclass = packetReader.get16BitInt();
    (void)rrtype;
    (void)rrclass;
  }

  /* consume AN and NS */
  for (idx = 0; idx < ancount + nscount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);
    packetReader.skip(recordHeader.d_clen);
  }

  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    uint16_t start = packetReader.getPosition();
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    if (recordHeader.d_type == QType::OPT) {
      *optStart = start;
      *optLen = (packetReader.getPosition() - start) + recordHeader.d_clen;

      if (packet.size() < (*optStart + *optLen)) {
        throw std::range_error("Opt record overflow");
      }

      if (idx == ((size_t)arcount - 1)) {
        *last = true;
      }
      else {
        *last = false;
      }
      return 0;
    }
    packetReader.skip(recordHeader.d_clen);
  }

  return ENOENT;
}

/* extract the start of the OPT RR in a QUERY packet if any */
int getEDNSOptionsStart(const PacketBuffer& packet, const size_t offset, uint16_t* optRDPosition, size_t* remaining)
{
  if (optRDPosition == nullptr || remaining == nullptr) {
    throw std::runtime_error("Invalid values passed to getEDNSOptionsStart");
  }

  const dnsheader_aligned dnsHeader(packet.data());

  if (offset >= packet.size()) {
    return ENOENT;
  }

  if (ntohs(dnsHeader->qdcount) != 1 || ntohs(dnsHeader->ancount) != 0 || ntohs(dnsHeader->arcount) != 1 || ntohs(dnsHeader->nscount) != 0) {
    return ENOENT;
  }

  size_t pos = sizeof(dnsheader) + offset;
  pos += DNS_TYPE_SIZE + DNS_CLASS_SIZE;

  if (pos >= packet.size()) {
    return ENOENT;
  }

  if ((pos + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE) >= packet.size()) {
    return ENOENT;
  }

  if (packet[pos] != 0) {
    /* not the root so not an OPT record */
    return ENOENT;
  }
  pos += 1;

  uint16_t qtype = packet.at(pos) * 256 + packet.at(pos + 1);
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
  dnsrecordheader dnsHeader{};
  EDNS0Record edns0{};
  edns0.extRCode = ednsrcode;
  edns0.version = 0;
  edns0.extFlags = dnssecOK ? htons(EDNS_HEADER_FLAG_DO) : 0;

  if ((maximumSize - res.size()) < (sizeof(name) + sizeof(dnsHeader) + optRData.length())) {
    return false;
  }

  dnsHeader.d_type = htons(QType::OPT);
  dnsHeader.d_class = htons(udpPayloadSize);
  static_assert(sizeof(EDNS0Record) == sizeof(dnsHeader.d_ttl), "sizeof(EDNS0Record) must match sizeof(dnsrecordheader.d_ttl)");
  memcpy(&dnsHeader.d_ttl, &edns0, sizeof edns0);
  dnsHeader.d_clen = htons(static_cast<uint16_t>(optRData.length()));

  res.reserve(res.size() + sizeof(name) + sizeof(dnsHeader) + optRData.length());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
  res.insert(res.end(), reinterpret_cast<const uint8_t*>(&name), reinterpret_cast<const uint8_t*>(&name) + sizeof(name));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
  res.insert(res.end(), reinterpret_cast<const uint8_t*>(&dnsHeader), reinterpret_cast<const uint8_t*>(&dnsHeader) + sizeof(dnsHeader));
  res.insert(res.end(), optRData.begin(), optRData.end());

  return true;
}

static bool replaceEDNSClientSubnetOption(PacketBuffer& packet, size_t maximumSize, size_t const oldEcsOptionStartPosition, size_t const oldEcsOptionSize, size_t const optRDLenPosition, const string& newECSOption)
{
  if (oldEcsOptionStartPosition >= packet.size() || optRDLenPosition >= packet.size()) {
    throw std::runtime_error("Invalid values passed to replaceEDNSClientSubnetOption");
  }

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
bool parseEDNSOptions(const DNSQuestion& dnsQuestion)
{
  const auto dnsHeader = dnsQuestion.getHeader();
  if (dnsQuestion.ednsOptions != nullptr) {
    return true;
  }

  // dnsQuestion.ednsOptions is mutable
  dnsQuestion.ednsOptions = std::make_unique<EDNSOptionViewMap>();

  if (ntohs(dnsHeader->arcount) == 0) {
    /* nothing in additional so no EDNS */
    return false;
  }

  if (ntohs(dnsHeader->ancount) != 0 || ntohs(dnsHeader->nscount) != 0 || ntohs(dnsHeader->arcount) > 1) {
    return slowParseEDNSOptions(dnsQuestion.getData(), *dnsQuestion.ednsOptions);
  }

  size_t remaining = 0;
  uint16_t optRDPosition{};
  int res = getEDNSOptionsStart(dnsQuestion.getData(), dnsQuestion.ids.qname.wirelength(), &optRDPosition, &remaining);

  if (res == 0) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    res = getEDNSOptions(reinterpret_cast<const char*>(&dnsQuestion.getData().at(optRDPosition)), remaining, *dnsQuestion.ednsOptions);
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
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
  if (qnameWireLength > packet.size()) {
    throw std::runtime_error("Invalid value passed to handleEDNSClientSubnet");
  }

  const dnsheader_aligned dnsHeader(packet.data());

  if (ntohs(dnsHeader->ancount) != 0 || ntohs(dnsHeader->nscount) != 0 || (ntohs(dnsHeader->arcount) != 0 && ntohs(dnsHeader->arcount) != 1)) {
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
      if (ntohs(dnsHeader->arcount) == 0) {
        /* well now.. */
        packet.resize(minimumPacketSize);
      }
      else {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        uint32_t realPacketLen = getDNSPacketLength(reinterpret_cast<const char*>(packet.data()), packet.size());
        packet.resize(realPacketLen);
      }
    }

    return addEDNSWithECS(packet, maximumSize, newECSOption, ednsAdded, ecsAdded);
  }

  size_t ecsOptionStartPosition = 0;
  size_t ecsOptionSize = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  res = getEDNSOption(reinterpret_cast<const char*>(&packet.at(optRDPosition)), remaining, EDNSOptionCode::ECS, &ecsOptionStartPosition, &ecsOptionSize);

  if (res == 0) {
    /* there is already an ECS value */
    if (!overrideExisting) {
      return true;
    }

    return replaceEDNSClientSubnetOption(packet, maximumSize, optRDPosition + ecsOptionStartPosition, ecsOptionSize, optRDPosition, newECSOption);
  }

  /* we have an EDNS OPT RR but no existing ECS option */
  return addECSToExistingOPT(packet, maximumSize, newECSOption, optRDPosition, ecsAdded);
}

bool handleEDNSClientSubnet(DNSQuestion& dnsQuestion, bool& ednsAdded, bool& ecsAdded)
{
  string newECSOption;
  generateECSOption(dnsQuestion.ecs ? dnsQuestion.ecs->getNetwork() : dnsQuestion.ids.origRemote, newECSOption, dnsQuestion.ecs ? dnsQuestion.ecs->getBits() : dnsQuestion.ecsPrefixLength);

  return handleEDNSClientSubnet(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnsQuestion.ids.qname.wirelength(), ednsAdded, ecsAdded, dnsQuestion.ecsOverride, newECSOption);
}

static int removeEDNSOptionFromOptions(unsigned char* optionsStart, const uint16_t optionsLen, const uint16_t optionCodeToRemove, uint16_t* newOptionsLen)
{
  const pdns::views::UnsignedCharView view(optionsStart, optionsLen);
  size_t pos = 0;
  while ((pos + 4) <= view.size()) {
    size_t optionBeginPos = pos;
    const uint16_t optionCode = 0x100 * view.at(pos) + view.at(pos + 1);
    pos += sizeof(optionCode);
    const uint16_t optionLen = 0x100 * view.at(pos) + view.at(pos + 1);
    pos += sizeof(optionLen);
    if ((pos + optionLen) > view.size()) {
      return EINVAL;
    }
    if (optionCode == optionCodeToRemove) {
      if (pos + optionLen < view.size()) {
        /* move remaining options over the removed one,
           if any */
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        memmove(optionsStart + optionBeginPos, optionsStart + pos + optionLen, optionsLen - (pos + optionLen));
      }
      *newOptionsLen = optionsLen - (sizeof(optionCode) + sizeof(optionLen) + optionLen);
      return 0;
    }
    pos += optionLen;
  }
  return ENOENT;
}

int removeEDNSOptionFromOPT(char* optStart, size_t* optLen, const uint16_t optionCodeToRemove)
{
  if (*optLen < optRecordMinimumSize) {
    return EINVAL;
  }
  const pdns::views::UnsignedCharView view(optStart, *optLen);
  /* skip the root label, qtype, qclass and TTL */
  size_t position = 9;
  uint16_t rdLen = (0x100 * view.at(position) + view.at(position + 1));
  position += sizeof(rdLen);
  if (position + rdLen != view.size()) {
    return EINVAL;
  }
  uint16_t newRdLen = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
  int res = removeEDNSOptionFromOptions(reinterpret_cast<unsigned char*>(optStart + position), rdLen, optionCodeToRemove, &newRdLen);
  if (res != 0) {
    return res;
  }
  *optLen -= (rdLen - newRdLen);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
  auto* rdLenPtr = reinterpret_cast<unsigned char*>(optStart + 9);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  rdLenPtr[0] = newRdLen / 0x100;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  rdLenPtr[1] = newRdLen % 0x100;
  return 0;
}

bool isEDNSOptionInOpt(const PacketBuffer& packet, const size_t optStart, const size_t optLen, const uint16_t optionCodeToFind, size_t* optContentStart, uint16_t* optContentLen)
{
  if (optLen < optRecordMinimumSize) {
    return false;
  }
  size_t position = optStart + 9;
  uint16_t rdLen = (0x100 * static_cast<unsigned char>(packet.at(position)) + static_cast<unsigned char>(packet.at(position + 1)));
  position += sizeof(rdLen);
  if (rdLen > (optLen - optRecordMinimumSize)) {
    return false;
  }

  size_t rdEnd = position + rdLen;
  while ((position + 4) <= rdEnd) {
    const uint16_t optionCode = 0x100 * static_cast<unsigned char>(packet.at(position)) + static_cast<unsigned char>(packet.at(position + 1));
    position += sizeof(optionCode);
    const uint16_t optionLen = 0x100 * static_cast<unsigned char>(packet.at(position)) + static_cast<unsigned char>(packet.at(position + 1));
    position += sizeof(optionLen);

    if ((position + optionLen) > rdEnd) {
      return false;
    }

    if (optionCode == optionCodeToFind) {
      if (optContentStart != nullptr) {
        *optContentStart = position;
      }

      if (optContentLen != nullptr) {
        *optContentLen = optionLen;
      }

      return true;
    }
    position += optionLen;
  }
  return false;
}

int rewriteResponseWithoutEDNSOption(const PacketBuffer& initialPacket, const uint16_t optionCodeToSkip, PacketBuffer& newContent)
{
  if (initialPacket.size() < sizeof(dnsheader)) {
    return ENOENT;
  }

  const dnsheader_aligned dnsHeader(initialPacket.data());

  if (ntohs(dnsHeader->arcount) == 0) {
    return ENOENT;
  }

  if (ntohs(dnsHeader->qdcount) == 0) {
    return ENOENT;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  PacketReader packetReader(std::string_view(reinterpret_cast<const char*>(initialPacket.data()), initialPacket.size()));

  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dnsHeader->qdcount);
  uint16_t ancount = ntohs(dnsHeader->ancount);
  uint16_t nscount = ntohs(dnsHeader->nscount);
  uint16_t arcount = ntohs(dnsHeader->arcount);
  uint16_t rrtype = 0;
  uint16_t rrclass = 0;
  string blob;
  dnsrecordheader recordHeader{};

  rrname = packetReader.getName();
  rrtype = packetReader.get16BitInt();
  rrclass = packetReader.get16BitInt();

  GenericDNSPacketWriter<PacketBuffer> packetWriter(newContent, rrname, rrtype, rrclass, dnsHeader->opcode);
  packetWriter.getHeader()->id = dnsHeader->id;
  packetWriter.getHeader()->qr = dnsHeader->qr;
  packetWriter.getHeader()->aa = dnsHeader->aa;
  packetWriter.getHeader()->tc = dnsHeader->tc;
  packetWriter.getHeader()->rd = dnsHeader->rd;
  packetWriter.getHeader()->ra = dnsHeader->ra;
  packetWriter.getHeader()->ad = dnsHeader->ad;
  packetWriter.getHeader()->cd = dnsHeader->cd;
  packetWriter.getHeader()->rcode = dnsHeader->rcode;

  /* consume remaining qd if any */
  if (qdcount > 1) {
    for (idx = 1; idx < qdcount; idx++) {
      rrname = packetReader.getName();
      rrtype = packetReader.get16BitInt();
      rrclass = packetReader.get16BitInt();
      (void)rrtype;
      (void)rrclass;
    }
  }

  /* copy AN and NS */
  for (idx = 0; idx < ancount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::ANSWER, true);
    packetReader.xfrBlob(blob);
    packetWriter.xfrBlob(blob);
  }

  for (idx = 0; idx < nscount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::AUTHORITY, true);
    packetReader.xfrBlob(blob);
    packetWriter.xfrBlob(blob);
  }

  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    if (recordHeader.d_type != QType::OPT) {
      packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::ADDITIONAL, true);
      packetReader.xfrBlob(blob);
      packetWriter.xfrBlob(blob);
    }
    else {
      packetWriter.startRecord(rrname, recordHeader.d_type, recordHeader.d_ttl, recordHeader.d_class, DNSResourceRecord::ADDITIONAL, false);
      packetReader.xfrBlob(blob);
      uint16_t rdLen = blob.length();
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      removeEDNSOptionFromOptions(reinterpret_cast<unsigned char*>(blob.data()), rdLen, optionCodeToSkip, &rdLen);
      /* xfrBlob(string, size) completely ignores size.. */
      if (rdLen > 0) {
        blob.resize((size_t)rdLen);
        packetWriter.xfrBlob(blob);
      }
      else {
        packetWriter.commit();
      }
    }
  }
  packetWriter.commit();

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
bool setNegativeAndAdditionalSOA(DNSQuestion& dnsQuestion, bool nxd, const DNSName& zone, uint32_t ttl, const DNSName& mname, const DNSName& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum, bool soaInAuthoritySection)
{
  auto& packet = dnsQuestion.getMutableData();
  auto dnsHeader = dnsQuestion.getHeader();
  if (ntohs(dnsHeader->qdcount) != 1) {
    return false;
  }

  size_t queryPartSize = sizeof(dnsheader) + dnsQuestion.ids.qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
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
    uint16_t zValue = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    hadEDNS = getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(packet.data()), packet.size(), &payloadSize, &zValue);
    if (hadEDNS) {
      dnssecOK = (zValue & EDNS_HEADER_FLAG_DO) != 0;
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
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  soa.append(reinterpret_cast<const char*>(&qtype), sizeof(qtype));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  soa.append(reinterpret_cast<const char*>(&qclass), sizeof(qclass));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  soa.append(reinterpret_cast<const char*>(&ttl), sizeof(ttl));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  soa.append(reinterpret_cast<const char*>(&rdLength), sizeof(rdLength));
  soa.append(mname.toDNSString());
  soa.append(rname.toDNSString());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  soa.append(reinterpret_cast<const char*>(&serial), sizeof(serial));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  soa.append(reinterpret_cast<const char*>(&refresh), sizeof(refresh));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  soa.append(reinterpret_cast<const char*>(&retry), sizeof(retry));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  soa.append(reinterpret_cast<const char*>(&expire), sizeof(expire));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
    }
    else {
      header.arcount = htons(1);
    }
    return true;
  });

  if (hadEDNS) {
    /* now we need to add a new OPT record */
    return addEDNS(packet, dnsQuestion.getMaximumSize(), dnssecOK, g_PayloadSizeSelfGenAnswers, dnsQuestion.ednsRCode);
  }

  return true;
}

bool addEDNSToQueryTurnedResponse(DNSQuestion& dnsQuestion)
{
  uint16_t optRDPosition{};
  /* remaining is at least the size of the rdlen + the options if any + the following records if any */
  size_t remaining = 0;

  auto& packet = dnsQuestion.getMutableData();
  int res = getEDNSOptionsStart(packet, dnsQuestion.ids.qname.wirelength(), &optRDPosition, &remaining);

  if (res != 0) {
    /* if the initial query did not have EDNS0, we are done */
    return true;
  }

  const size_t existingOptLen = /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + /* Z */ 2 + remaining;
  if (existingOptLen >= packet.size()) {
    /* something is wrong, bail out */
    return false;
  }

  const size_t optPosition = (optRDPosition - (/* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + /* Z */ 2));

  size_t zPosition = optPosition + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE;
  uint16_t zValue = 0x100 * packet.at(zPosition) + packet.at(zPosition + 1);
  bool dnssecOK = (zValue & EDNS_HEADER_FLAG_DO) != 0;

  /* remove the existing OPT record, and everything else that follows (any SIG or TSIG would be useless anyway) */
  packet.resize(packet.size() - existingOptLen);
  dnsdist::PacketMangling::editDNSHeaderFromPacket(packet, [](dnsheader& header) {
    header.arcount = 0;
    return true;
  });

  if (g_addEDNSToSelfGeneratedResponses) {
    /* now we need to add a new OPT record */
    return addEDNS(packet, dnsQuestion.getMaximumSize(), dnssecOK, g_PayloadSizeSelfGenAnswers, dnsQuestion.ednsRCode);
  }

  /* otherwise we are just fine */
  return true;
}

// goal in life - if you send us a reasonably normal packet, we'll get Z for you, otherwise 0
int getEDNSZ(const DNSQuestion& dnsQuestion)
{
  try {
    const auto& dnsHeader = dnsQuestion.getHeader();
    if (ntohs(dnsHeader->qdcount) != 1 || dnsHeader->ancount != 0 || ntohs(dnsHeader->arcount) != 1 || dnsHeader->nscount != 0) {
      return 0;
    }

    if (dnsQuestion.getData().size() <= sizeof(dnsheader)) {
      return 0;
    }

    size_t pos = sizeof(dnsheader) + dnsQuestion.ids.qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE;

    if (dnsQuestion.getData().size() <= (pos + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE)) {
      return 0;
    }

    const auto& packet = dnsQuestion.getData();
    if (packet.at(pos) != 0) {
      /* not root, so not a valid OPT record */
      return 0;
    }

    pos++;

    uint16_t qtype = packet.at(pos) * 256 + packet.at(pos + 1);
    pos += DNS_TYPE_SIZE;
    pos += DNS_CLASS_SIZE;

    if (qtype != QType::OPT || (pos + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + 1) >= packet.size()) {
      return 0;
    }

    return 0x100 * packet.at(pos + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE) + packet.at(pos + EDNS_EXTENDED_RCODE_SIZE + EDNS_VERSION_SIZE + 1);
  }
  catch (...) {
    return 0;
  }
}

bool queryHasEDNS(const DNSQuestion& dnsQuestion)
{
  uint16_t optRDPosition = 0;
  size_t ecsRemaining = 0;

  int res = getEDNSOptionsStart(dnsQuestion.getData(), dnsQuestion.ids.qname.wirelength(), &optRDPosition, &ecsRemaining);
  return res == 0;
}

bool getEDNS0Record(const PacketBuffer& packet, EDNS0Record& edns0)
{
  uint16_t optStart = 0;
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

bool setEDNSOption(DNSQuestion& dnsQuestion, uint16_t ednsCode, const std::string& ednsData)
{
  std::string optRData;
  generateEDNSOption(ednsCode, ednsData, optRData);

  if (dnsQuestion.getHeader()->arcount != 0) {
    bool ednsAdded = false;
    bool optionAdded = false;
    PacketBuffer newContent;
    newContent.reserve(dnsQuestion.getData().size());

    if (!slowRewriteEDNSOptionInQueryWithRecords(dnsQuestion.getData(), newContent, ednsAdded, ednsCode, optionAdded, true, optRData)) {
      return false;
    }

    if (newContent.size() > dnsQuestion.getMaximumSize()) {
      return false;
    }

    dnsQuestion.getMutableData() = std::move(newContent);
    if (!dnsQuestion.ids.ednsAdded && ednsAdded) {
      dnsQuestion.ids.ednsAdded = true;
    }

    return true;
  }

  auto& data = dnsQuestion.getMutableData();
  if (generateOptRR(optRData, data, dnsQuestion.getMaximumSize(), g_EdnsUDPPayloadSize, 0, false)) {
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
      header.arcount = htons(1);
      return true;
    });
    // make sure that any EDNS sent by the backend is removed before forwarding the response to the client
    dnsQuestion.ids.ednsAdded = true;
  }

  return true;
}

namespace dnsdist
{
bool setInternalQueryRCode(InternalQueryState& state, PacketBuffer& buffer, uint8_t rcode, bool clearAnswers)
{
  const auto qnameLength = state.qname.wirelength();
  if (buffer.size() < sizeof(dnsheader) + qnameLength + sizeof(uint16_t) + sizeof(uint16_t)) {
    return false;
  }

  EDNS0Record edns0{};
  bool hadEDNS = false;
  if (clearAnswers) {
    hadEDNS = getEDNS0Record(buffer, edns0);
  }

  dnsdist::PacketMangling::editDNSHeaderFromPacket(buffer, [rcode, clearAnswers](dnsheader& header) {
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
      DNSQuestion dnsQuestion(state, buffer);
      if (!addEDNS(buffer, dnsQuestion.getMaximumSize(), (edns0.extFlags & htons(EDNS_HEADER_FLAG_DO)) != 0, g_PayloadSizeSelfGenAnswers, 0)) {
        return false;
      }
    }
  }

  return true;
}
}
