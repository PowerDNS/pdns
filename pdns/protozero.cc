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
#include "dnsrecords.hh"


void pdns::ProtoZero::Message::encodeComboAddress(const protozero::pbf_tag_type type, const ComboAddress& ca)
{
  if (ca.sin4.sin_family == AF_INET) {
    d_pbf.add_bytes(type, reinterpret_cast<const char*>(&ca.sin4.sin_addr.s_addr), sizeof(ca.sin4.sin_addr.s_addr));
  }
  else if (ca.sin4.sin_family == AF_INET6) {
    d_pbf.add_bytes(type, reinterpret_cast<const char*>(&ca.sin6.sin6_addr.s6_addr), sizeof(ca.sin6.sin6_addr.s6_addr));
  }
}

void pdns::ProtoZero::Message::encodeNetmask(const protozero::pbf_tag_type type, const Netmask& subnet, uint8_t mask)
{
  if (!subnet.empty()) {
    ComboAddress ca(subnet.getNetwork());
    ca.truncate(mask);
    if (ca.sin4.sin_family == AF_INET) {
      d_pbf.add_bytes(type, reinterpret_cast<const char*>(&ca.sin4.sin_addr.s_addr), sizeof(ca.sin4.sin_addr.s_addr));
    }
    else if (ca.sin4.sin_family == AF_INET6) {
      d_pbf.add_bytes(type, reinterpret_cast<const char*>(&ca.sin6.sin6_addr.s6_addr), sizeof(ca.sin6.sin6_addr.s6_addr));
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

void pdns::ProtoZero::Message::request(const boost::uuids::uuid& uniqueId, const ComboAddress& requestor, const ComboAddress& local, const DNSName& qname, uint16_t qtype, uint16_t qclass, uint16_t id, bool tcp, size_t len)
{
  setType(1);
  setMessageIdentity(uniqueId);
  setSocketFamily(requestor.sin4.sin_family);
  setSocketProtocol(tcp);
  setFrom(requestor);
  setTo(local);
  setInBytes(len);
  setTime();
  setId(id);
  setQuestion(qname, qtype, qclass);
  setFromPort(requestor.getPort());
  setToPort(local.getPort());
}

void pdns::ProtoZero::Message::response(const DNSName& qname, uint16_t qtype, uint16_t qclass)
{
  setType(2);
  setQuestion(qname, qtype, qclass);
}


#ifdef NOD_ENABLED
void pdns::ProtoZero::Message::addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes, bool udr)
#else
void pdns::ProtoZero::Message::addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes)
#endif /* NOD_ENABLED */
{
  if (record.d_place != DNSResourceRecord::ANSWER || record.d_class != QClass::IN) {
    return;
  }

  if (exportTypes.count(record.d_type) == 0) {
    return;
  }

  protozero::pbf_writer pbf_rr{*d_response, 2};

  encodeDNSName(pbf_rr, d_buffer, 1, record.d_name);
  pbf_rr.add_uint32(2, record.d_type);
  pbf_rr.add_uint32(3, record.d_class);
  pbf_rr.add_uint32(4, record.d_ttl);

  switch(record.d_type) {
  case QType::A:
  {
    const auto& content = dynamic_cast<const ARecordContent&>(*(record.d_content));
    ComboAddress data = content.getCA();
    pbf_rr.add_bytes(5, reinterpret_cast<const char*>(&data.sin4.sin_addr.s_addr), sizeof(data.sin4.sin_addr.s_addr));
    break;
  }
  case QType::AAAA:
  {
    const auto& content = dynamic_cast<const AAAARecordContent&>(*(record.d_content));
    ComboAddress data = content.getCA();
    pbf_rr.add_bytes(5, reinterpret_cast<const char*>(&data.sin6.sin6_addr.s6_addr), sizeof(data.sin6.sin6_addr.s6_addr));
    break;
  }
  case QType::CNAME:
  {
    const auto& content = dynamic_cast<const CNAMERecordContent&>(*(record.d_content));
    pbf_rr.add_string(5, content.getTarget().toString());
    break;
  }
  case QType::TXT:
  {
    const auto& content = dynamic_cast<const TXTRecordContent&>(*(record.d_content));
    pbf_rr.add_string(5, content.d_text);
    break;
  }
  case QType::NS:
  {
    const auto& content = dynamic_cast<const NSRecordContent&>(*(record.d_content));
    pbf_rr.add_string(5, content.getNS().toString());
    break;
  }
  case QType::PTR:
  {
    const auto& content = dynamic_cast<const PTRRecordContent&>(*(record.d_content));
    pbf_rr.add_string(5, content.getContent().toString());
    break;
  }
  case QType::MX:
  {
    const auto& content = dynamic_cast<const MXRecordContent&>(*(record.d_content));
    pbf_rr.add_string(5, content.d_mxname.toString());
    break;
  }
  case QType::SPF:
  {
    const auto& content = dynamic_cast<const SPFRecordContent&>(*(record.d_content));
    pbf_rr.add_string(5, content.getText());
    break;
  }
  case QType::SRV:
  {
    const auto& content = dynamic_cast<const SRVRecordContent&>(*(record.d_content));
    pbf_rr.add_string(5, content.d_target.toString());
    break;
  }
  default:
    break;
  }
#ifdef NOD_ENABLED
  pbf_rr.add_bool(6, udr);
#endif
}
