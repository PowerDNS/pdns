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

#include "dnsrecords.hh"
#include "rec-protozero.hh"
#include <variant>

void pdns::ProtoZero::RecMessage::addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes, bool udr)
{
  if (record.d_place != DNSResourceRecord::ANSWER || record.d_class != QClass::IN) {
    return;
  }

  if (exportTypes.count(record.d_type) == 0) {
    return;
  }

  protozero::pbf_writer pbf_rr{d_response, static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::ResponseField::rrs)};

  encodeDNSName(pbf_rr, d_rspbuf, static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::name), record.d_name);
  pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::type), record.d_type);
  pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::class_), record.d_class);
  pbf_rr.add_uint32(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::ttl), record.d_ttl);

  switch (record.d_type) {
  case QType::A: {
    const auto& content = dynamic_cast<const ARecordContent&>(*(record.d_content));
    ComboAddress data = content.getCA();
    pbf_rr.add_bytes(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), reinterpret_cast<const char*>(&data.sin4.sin_addr.s_addr), sizeof(data.sin4.sin_addr.s_addr));
    break;
  }
  case QType::AAAA: {
    const auto& content = dynamic_cast<const AAAARecordContent&>(*(record.d_content));
    ComboAddress data = content.getCA();
    pbf_rr.add_bytes(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), reinterpret_cast<const char*>(&data.sin6.sin6_addr.s6_addr), sizeof(data.sin6.sin6_addr.s6_addr));
    break;
  }
  case QType::CNAME: {
    const auto& content = dynamic_cast<const CNAMERecordContent&>(*(record.d_content));
    pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), content.getTarget().toString());
    break;
  }
  case QType::TXT: {
    const auto& content = dynamic_cast<const TXTRecordContent&>(*(record.d_content));
    pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), content.d_text);
    break;
  }
  case QType::NS: {
    const auto& content = dynamic_cast<const NSRecordContent&>(*(record.d_content));
    pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), content.getNS().toString());
    break;
  }
  case QType::PTR: {
    const auto& content = dynamic_cast<const PTRRecordContent&>(*(record.d_content));
    pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), content.getContent().toString());
    break;
  }
  case QType::MX: {
    const auto& content = dynamic_cast<const MXRecordContent&>(*(record.d_content));
    pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), content.d_mxname.toString());
    break;
  }
  case QType::SPF: {
    const auto& content = dynamic_cast<const SPFRecordContent&>(*(record.d_content));
    pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), content.getText());
    break;
  }
  case QType::SRV: {
    const auto& content = dynamic_cast<const SRVRecordContent&>(*(record.d_content));
    pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), content.d_target.toString());
    break;
  }
  default:
    break;
  }
#ifdef NOD_ENABLED
  pbf_rr.add_bool(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::udr), udr);
  pbf_rr.commit();

  // Save the offset of the byte containing the just added bool. We can do this since
  // we know a bit about how protobuf's encoding works.
  offsets.push_back(d_rspbuf.length() - 1);
#endif
}

#ifdef NOD_ENABLED
void pdns::ProtoZero::RecMessage::clearUDR(std::string& str)
{
  for (auto i : offsets) {
    str.at(i) = 0;
  }
}
#endif

void pdns::ProtoZero::RecMessage::addEvents(const RecEventTrace& trace)
{
  for (const auto& t : trace.getEvents()) {
    protozero::pbf_writer pbf_trace{d_message, static_cast<protozero::pbf_tag_type>(Field::trace)};
    pbf_trace.add_uint64(static_cast<protozero::pbf_tag_type>(Event::ts), t.d_ts);
    pbf_trace.add_uint32(static_cast<protozero::pbf_tag_type>(Event::event), t.d_event);
    pbf_trace.add_bool(static_cast<protozero::pbf_tag_type>(Event::start), t.d_start);

    const auto& v = t.d_value;
    if (std::holds_alternative<std::nullopt_t>(v)) {
    }
    else if (std::holds_alternative<bool>(v)) {
      pbf_trace.add_bool(static_cast<protozero::pbf_tag_type>(Event::boolVal), std::get<bool>(v));
    }
    else if (std::holds_alternative<int64_t>(v)) {
      pbf_trace.add_int64(static_cast<protozero::pbf_tag_type>(Event::intVal), std::get<int64_t>(v));
    }
    else if (std::holds_alternative<std::string>(v)) {
      pbf_trace.add_string(static_cast<protozero::pbf_tag_type>(Event::stringVal), std::get<std::string>(v));
    }
    else if (std::holds_alternative<PacketBuffer>(v)) {
      const PacketBuffer& p = std::get<PacketBuffer>(v);
      pbf_trace.add_bytes(static_cast<protozero::pbf_tag_type>(Event::bytesVal), reinterpret_cast<const char*>(p.data()), p.size());
    }
  }
}

