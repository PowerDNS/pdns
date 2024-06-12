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

void pdns::ProtoZero::RecMessage::addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes, [[maybe_unused]] std::optional<bool> udr)
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

  auto add = [&](const std::string& str) {
    if (size() + str.length() < std::numeric_limits<uint16_t>::max() / 2) {
      pbf_rr.add_string(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), str);
    }
  };

  switch (record.d_type) {
  case QType::A: {
    const auto& content = getRR<ARecordContent>(record);
    if (!content) {
      return;
    }
    ComboAddress data = content->getCA();
    pbf_rr.add_bytes(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), reinterpret_cast<const char*>(&data.sin4.sin_addr.s_addr), sizeof(data.sin4.sin_addr.s_addr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
    break;
  }
  case QType::AAAA: {
    const auto& content = getRR<AAAARecordContent>(record);
    if (!content) {
      return;
    }
    ComboAddress data = content->getCA();
    pbf_rr.add_bytes(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::rdata), reinterpret_cast<const char*>(&data.sin6.sin6_addr.s6_addr), sizeof(data.sin6.sin6_addr.s6_addr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
    break;
  }
  case QType::CNAME: {
    const auto& content = getRR<CNAMERecordContent>(record);
    if (!content) {
      return;
    }
    add(content->getTarget().toString());
    break;
  }
  case QType::TXT: {
    const auto& content = getRR<TXTRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->d_text);
    break;
  }
  case QType::NS: {
    const auto& content = getRR<NSRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->getNS().toString());
    break;
  }
  case QType::PTR: {
    const auto& content = getRR<PTRRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->getContent().toString());
    break;
  }
  case QType::MX: {
    const auto& content = getRR<MXRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->d_mxname.toString());
    break;
  }
  case QType::SPF: {
    const auto& content = getRR<SPFRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->getText());
    break;
  }
  case QType::SRV: {
    const auto& content = getRR<SRVRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->d_target.toString());
    break;
  }
  case QType::SVCB: {
    const auto& content = getRR<SVCBRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->getZoneRepresentation());
    break;
  }
  case QType::HTTPS: {
    const auto& content = getRR<HTTPSRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->getZoneRepresentation());
    break;
  }
  case QType::NAPTR: {
    const auto& content = getRR<NAPTRRecordContent>(record);
    if (!content) {
      return;
    }
    add(content->getZoneRepresentation());
    break;
  }
  default:
    break;
  }
#ifdef NOD_ENABLED
  if (udr) {
    pbf_rr.add_bool(static_cast<protozero::pbf_tag_type>(pdns::ProtoZero::Message::RRField::udr), *udr);
    pbf_rr.commit();

    // Save the offset of the byte containing the just added bool. We can do this since
    // we know a bit about how protobuf's encoding works.
    offsets.push_back(d_rspbuf.length() - 1);
  }
#endif
}

#ifdef NOD_ENABLED
void pdns::ProtoZero::RecMessage::clearUDR(std::string& str)
{
  for (auto offset : offsets) {
    str.at(offset) = 0;
  }
}
#endif

void pdns::ProtoZero::RecMessage::addEvents(const RecEventTrace& trace)
{
  for (const auto& event : trace.getEvents()) {
    protozero::pbf_writer pbf_trace{d_message, static_cast<protozero::pbf_tag_type>(Field::trace)};
    pbf_trace.add_int64(static_cast<protozero::pbf_tag_type>(Event::ts), event.d_ts);
    pbf_trace.add_uint32(static_cast<protozero::pbf_tag_type>(Event::event), event.d_event);
    pbf_trace.add_bool(static_cast<protozero::pbf_tag_type>(Event::start), event.d_start);

    const auto& value = event.d_value;
    if (std::holds_alternative<std::nullopt_t>(value)) {
    }
    else if (std::holds_alternative<bool>(value)) {
      pbf_trace.add_bool(static_cast<protozero::pbf_tag_type>(Event::boolVal), std::get<bool>(value));
    }
    else if (std::holds_alternative<int64_t>(value)) {
      pbf_trace.add_int64(static_cast<protozero::pbf_tag_type>(Event::intVal), std::get<int64_t>(value));
    }
    else if (std::holds_alternative<std::string>(value)) {
      pbf_trace.add_string(static_cast<protozero::pbf_tag_type>(Event::stringVal), std::get<std::string>(value));
    }
    else if (std::holds_alternative<PacketBuffer>(value)) {
      const auto& packetBuffer = std::get<PacketBuffer>(value);
      pbf_trace.add_bytes(static_cast<protozero::pbf_tag_type>(Event::bytesVal), reinterpret_cast<const char*>(packetBuffer.data()), packetBuffer.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
    }
    if (!event.d_custom.empty()) {
      pbf_trace.add_string(static_cast<protozero::pbf_tag_type>(Event::custom), event.d_custom);
    }
  }
}
