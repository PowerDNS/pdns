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
#include "dnsdist-dnsparser.hh"
#include "dnsparser.hh"
#include "iputils.hh"

namespace dnsdist
{
DNSPacketOverlay::DNSPacketOverlay(const std::string_view& packet)
{
  if (packet.size() < sizeof(dnsheader)) {
    throw std::runtime_error("Packet is too small for a DNS packet");
  }

  memcpy(&d_header, packet.data(), sizeof(dnsheader));
  uint64_t numRecords = ntohs(d_header.ancount) + ntohs(d_header.nscount) + ntohs(d_header.arcount);
  d_records.reserve(numRecords);

  try {
    PacketReader reader(std::string_view(reinterpret_cast<const char*>(packet.data()), packet.size()));

    for (uint16_t n = 0; n < ntohs(d_header.qdcount); ++n) {
      reader.xfrName(d_qname);
      reader.xfrType(d_qtype);
      reader.xfrType(d_qclass);
    }

    for (uint64_t n = 0; n < numRecords; ++n) {
      Record rec;
      reader.xfrName(rec.d_name);
      rec.d_place = n < ntohs(d_header.ancount) ? DNSResourceRecord::ANSWER : (n < (ntohs(d_header.ancount) + ntohs(d_header.nscount)) ? DNSResourceRecord::AUTHORITY : DNSResourceRecord::ADDITIONAL);
      reader.xfrType(rec.d_type);
      reader.xfrType(rec.d_class);
      reader.xfr32BitInt(rec.d_ttl);
      reader.xfr16BitInt(rec.d_contentLength);
      rec.d_contentOffset = reader.getPosition();
      reader.skip(rec.d_contentLength);
      d_records.push_back(std::move(rec));
    }
  }
  catch (const std::exception& e) {
    throw std::runtime_error("Unable to parse DNS packet: " + std::string(e.what()));
  }
  catch (...) {
    throw std::runtime_error("Unable to parse DNS packet");
  }
}

bool changeNameInDNSPacket(PacketBuffer& initialPacket, const DNSName& from, const DNSName& to)
{
  if (initialPacket.size() < sizeof(dnsheader)) {
    return false;
  }

  PacketReader pr(std::string_view(reinterpret_cast<const char*>(initialPacket.data()), initialPacket.size()));

  dnsheader dh;
  memcpy(&dh, initialPacket.data(), sizeof(dh));
  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh.qdcount);
  uint16_t ancount = ntohs(dh.ancount);
  uint16_t nscount = ntohs(dh.nscount);
  uint16_t arcount = ntohs(dh.arcount);
  uint16_t rrtype;
  uint16_t rrclass;
  string blob;

  size_t recordsCount = ancount + nscount + arcount;
  struct dnsrecordheader ah;

  rrname = pr.getName();
  if (rrname == from) {
    rrname = to;
  }

  rrtype = pr.get16BitInt();
  rrclass = pr.get16BitInt();

  PacketBuffer newContent;
  newContent.reserve(initialPacket.size());
  GenericDNSPacketWriter<PacketBuffer> pw(newContent, rrname, rrtype, rrclass, dh.opcode);
  /* we want to copy the flags and ID but not the counts since we recreate the records below */
  pw.getHeader()->id = dh.id;
  pw.getHeader()->qr = dh.qr;
  pw.getHeader()->aa = dh.aa;
  pw.getHeader()->tc = dh.tc;
  pw.getHeader()->rd = dh.rd;
  pw.getHeader()->ra = dh.ra;
  pw.getHeader()->ad = dh.ad;
  pw.getHeader()->cd = dh.cd;
  pw.getHeader()->rcode = dh.rcode;

  /* consume remaining qd if any, but do not copy it */
  for (idx = 1; idx < qdcount; idx++) {
    rrname = pr.getName();
    (void)pr.get16BitInt();
    (void)pr.get16BitInt();
  }

  static const std::unordered_set<QType> nameOnlyTypes{QType::NS, QType::PTR, QType::CNAME, QType::DNAME};
  static const std::unordered_set<QType> noNameTypes{QType::A, QType::AAAA, QType::DHCID, QType::TXT, QType::OPT, QType::HINFO, QType::DNSKEY, QType::CDNSKEY, QType::DS, QType::CDS, QType::DLV, QType::SSHFP, QType::KEY, QType::CERT, QType::TLSA, QType::SMIMEA, QType::OPENPGPKEY, QType::NSEC, QType::NSEC3, QType::CSYNC, QType::NSEC3PARAM, QType::LOC, QType::NID, QType::L32, QType::L64, QType::EUI48, QType::EUI64, QType::URI, QType::CAA};

  /* copy AN, NS and AR */
  for (idx = 0; idx < recordsCount; idx++) {
    rrname = pr.getName();
    if (rrname == from) {
      rrname = to;
    }
    pr.getDnsrecordheader(ah);

    auto place = idx < ancount ? DNSResourceRecord::ANSWER : (idx < (ancount + nscount) ? DNSResourceRecord::AUTHORITY : DNSResourceRecord::ADDITIONAL);
    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, place, true);
    if (nameOnlyTypes.count(ah.d_type)) {
      rrname = pr.getName();
      pw.xfrName(rrname);
    }
    else if (noNameTypes.count(ah.d_type)) {
      pr.xfrBlob(blob);
      pw.xfrBlob(blob);
    }
    else if (ah.d_type == QType::RRSIG) {
      /* good luck */
      pr.xfrBlob(blob);
      pw.xfrBlob(blob);
    }
    else if (ah.d_type == QType::MX) {
      auto prio = pr.get16BitInt();
      rrname = pr.getName();
      pw.xfr16BitInt(prio);
      pw.xfrName(rrname);
    }
    else if (ah.d_type == QType::SOA) {
      auto mname = pr.getName();
      pw.xfrName(mname);
      auto rname = pr.getName();
      pw.xfrName(rname);
      /* serial */
      pw.xfr32BitInt(pr.get32BitInt());
      /* refresh */
      pw.xfr32BitInt(pr.get32BitInt());
      /* retry */
      pw.xfr32BitInt(pr.get32BitInt());
      /* expire */
      pw.xfr32BitInt(pr.get32BitInt());
      /* minimal */
      pw.xfr32BitInt(pr.get32BitInt());
    }
    else if (ah.d_type == QType::SRV) {
      /* preference */
      pw.xfr16BitInt(pr.get16BitInt());
      /* weight */
      pw.xfr16BitInt(pr.get16BitInt());
      /* port */
      pw.xfr16BitInt(pr.get16BitInt());
      auto target = pr.getName();
      pw.xfrName(target);
    }
    else {
      /* sorry, unsafe type */
      return false;
    }
  }

  pw.commit();
  initialPacket = std::move(newContent);

  return true;
}

namespace PacketMangling
{
  bool editDNSHeaderFromPacket(PacketBuffer& packet, const std::function<bool(dnsheader& header)>& editFunction)
  {
    if (packet.size() < sizeof(dnsheader)) {
      throw std::runtime_error("Trying to edit the DNS header of a too small packet");
    }

    return editDNSHeaderFromRawPacket(packet.data(), editFunction);
  }

  bool editDNSHeaderFromRawPacket(void* packet, const std::function<bool(dnsheader& header)>& editFunction)
  {
    if (dnsheader_aligned::isMemoryAligned(packet)) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      auto* header = reinterpret_cast<dnsheader*>(packet);
      return editFunction(*header);
    }

    dnsheader header{};
    memcpy(&header, packet, sizeof(header));
    if (!editFunction(header)) {
      return false;
    }
    memcpy(packet, &header, sizeof(header));
    return true;
  }

  void restrictDNSPacketTTLs(PacketBuffer& packet, uint32_t minimumValue, uint32_t maximumValue, const std::unordered_set<QType>& types)
  {
    auto visitor = [minimumValue, maximumValue, types](uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl) {
      (void)section;
      if (!types.empty() && qclass == QClass::IN && types.count(qtype) == 0) {
        return ttl;
      }

      if (minimumValue > 0) {
        if (ttl < minimumValue) {
          ttl = minimumValue;
        }
      }
      if (ttl > maximumValue) {
        ttl = maximumValue;
      }
      return ttl;
    };
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    editDNSPacketTTL(reinterpret_cast<char*>(packet.data()), packet.size(), visitor);
  }

}

namespace RecordParsers
{
  std::optional<ComboAddress> parseARecord(const std::string_view& packet, const DNSPacketOverlay::Record& record)
  {
    if (record.d_type != QType::A || record.d_contentLength != 4) {
      return {};
    }

    // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): length is passed in and used to read data
    return makeComboAddressFromRaw(4, packet.substr(record.d_contentOffset, record.d_contentOffset + 4).data(), record.d_contentLength);
  }

  std::optional<ComboAddress> parseAAAARecord(const std::string_view& packet, const DNSPacketOverlay::Record& record)
  {
    if (record.d_type != QType::AAAA || record.d_contentLength != 16) {
      return {};
    }

    // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): length is passed in and used to read data
    return makeComboAddressFromRaw(6, packet.substr(record.d_contentOffset, record.d_contentOffset + 16).data(), record.d_contentLength);
  }

  std::optional<ComboAddress> parseAddressRecord(const std::string_view& packet, const DNSPacketOverlay::Record& record)
  {
    if (record.d_type == QType::A && record.d_contentLength == 4) {
      // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): length is passed in and used to read data
      return makeComboAddressFromRaw(4, packet.substr(record.d_contentOffset, record.d_contentOffset + 4).data(), record.d_contentLength);
    }

    if (record.d_type == QType::AAAA && record.d_contentLength == 16) {
      // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): length is passed in and used to read data
      return makeComboAddressFromRaw(6, packet.substr(record.d_contentOffset, record.d_contentOffset + 16).data(), record.d_contentLength);
    }

    return {};
  }

  std::optional<DNSName> parseCNAMERecord(const std::string_view& packet, const DNSPacketOverlay::Record& record)
  {
    if (record.d_type != QType::CNAME) {
      return {};
    }

    // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): length is passed in and used to read data
    return DNSName(packet.data(), record.d_contentOffset + record.d_contentLength, record.d_contentOffset, true);
  }
}

void setResponseHeadersFromConfig(dnsheader& dnsheader, const ResponseConfig& config)
{
  if (config.setAA) {
    dnsheader.aa = *config.setAA;
  }
  if (config.setAD) {
    dnsheader.ad = *config.setAD;
  }
  else {
    dnsheader.ad = false;
  }
  if (config.setRA) {
    dnsheader.ra = *config.setRA;
  }
  else {
    dnsheader.ra = dnsheader.rd; // for good measure
  }
}
}
