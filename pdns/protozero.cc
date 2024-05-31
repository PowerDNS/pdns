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

#include "protozero.hh"

#ifndef DISABLE_PROTOBUF
#include "dnsparser.hh"

void pdns::ProtoZero::Message::encodeComboAddress(const protozero::pbf_tag_type type, const ComboAddress& address)
{
  if (address.sin4.sin_family == AF_INET) {
    d_message.add_bytes(type, reinterpret_cast<const char*>(&address.sin4.sin_addr.s_addr), sizeof(address.sin4.sin_addr.s_addr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
  }
  else if (address.sin4.sin_family == AF_INET6) {
    d_message.add_bytes(type, reinterpret_cast<const char*>(&address.sin6.sin6_addr.s6_addr), sizeof(address.sin6.sin6_addr.s6_addr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
  }
}

void pdns::ProtoZero::Message::encodeNetmask(const protozero::pbf_tag_type type, const Netmask& subnet, uint8_t mask)
{
  if (!subnet.empty()) {
    ComboAddress address(subnet.getNetwork());
    address.truncate(mask);
    if (address.sin4.sin_family == AF_INET) {
      d_message.add_bytes(type, reinterpret_cast<const char*>(&address.sin4.sin_addr.s_addr), sizeof(address.sin4.sin_addr.s_addr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
    }
    else if (address.sin4.sin_family == AF_INET6) {
      d_message.add_bytes(type, reinterpret_cast<const char*>(&address.sin6.sin6_addr.s6_addr), sizeof(address.sin6.sin6_addr.s6_addr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
    }
  }
}

void pdns::ProtoZero::Message::encodeDNSName(protozero::pbf_writer& pbf, std::string& buffer, const protozero::pbf_tag_type type, const DNSName& name)
{
  // this will append the tag, mark the current position then reserve enough place to write the size
  protozero::pbf_writer pbf_name{pbf, type};
  // we append the name to the buffer
  name.toString(buffer);
  // leaving the block will cause the sub writer to compute how much was written based on the new size and update the size accordingly
}

void pdns::ProtoZero::Message::setRequest(const boost::uuids::uuid& uniqueId, const ComboAddress& requestor, const ComboAddress& local, const DNSName& qname, uint16_t qtype, uint16_t qclass, uint16_t qid, pdns::ProtoZero::Message::TransportProtocol proto, size_t len)
{
  setMessageIdentity(uniqueId);
  setSocketFamily(requestor.sin4.sin_family);
  setSocketProtocol(proto);
  setFrom(requestor);
  setTo(local);
  setInBytes(len);
  setTime();
  setId(qid);
  setQuestion(qname, qtype, qclass);
  setFromPort(requestor.getPort());
  setToPort(local.getPort());
}

void pdns::ProtoZero::Message::setResponse(const DNSName& qname, uint16_t qtype, uint16_t qclass)
{
  setType(pdns::ProtoZero::Message::MessageType::DNSResponseType);
  setQuestion(qname, qtype, qclass);
}

void pdns::ProtoZero::Message::addRRsFromPacket(const char* packet, const size_t len, bool includeCNAME)
{
  if (len < sizeof(struct dnsheader)) {
    return;
  }

  const dnsheader_aligned header(packet);

  if (ntohs(header->ancount) == 0) {
    return;
  }

  if (ntohs(header->qdcount) == 0) {
    return;
  }

  PacketReader packetReader(std::string_view(packet, len));

  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(header->qdcount);
  uint16_t ancount = ntohs(header->ancount);
  uint16_t rrtype{};
  uint16_t rrclass{};
  string blob;
  dnsrecordheader recordHeader{};

  rrname = packetReader.getName();
  rrtype = packetReader.get16BitInt();
  rrclass = packetReader.get16BitInt();
  (void)rrtype;
  (void)rrclass;

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

  /* parse AN */
  for (idx = 0; idx < ancount; idx++) {
    rrname = packetReader.getName();
    packetReader.getDnsrecordheader(recordHeader);

    if (recordHeader.d_type == QType::A || recordHeader.d_type == QType::AAAA) {
      packetReader.xfrBlob(blob);

      addRR(rrname, recordHeader.d_type, recordHeader.d_class, recordHeader.d_ttl, blob);
    }
    else if (recordHeader.d_type == QType::CNAME && includeCNAME) {
      protozero::pbf_writer pbf_rr{d_response, static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::ResponseField::rrs)};

      encodeDNSName(pbf_rr, d_buffer, static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::name), rrname);
      pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::type), recordHeader.d_type);
      pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::class_), recordHeader.d_class);
      pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::ttl), recordHeader.d_ttl);
      DNSName target;
      packetReader.xfrName(target, true);
      encodeDNSName(pbf_rr, d_buffer, static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), target);
    }
    else {
      packetReader.xfrBlob(blob);
    }
  }
}

void pdns::ProtoZero::Message::addRR(const DNSName& name, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& blob)
{
  protozero::pbf_writer pbf_rr{d_response, static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::ResponseField::rrs)};
  encodeDNSName(pbf_rr, d_buffer, static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::name), name);
  pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::type), uType);
  pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::class_), uClass);
  pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::ttl), uTTL);
  pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), blob);
}

#endif /* DISABLE_PROTOBUF */
