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
#include "dnsdist.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-lua.hh"

void setupLuaBindingsDNSParser(LuaContext& luaCtx)
{
#ifndef DISABLE_DNSPACKET_BINDINGS
  luaCtx.writeFunction("newDNSPacketOverlay", [](const std::string& packet) {
    dnsdist::DNSPacketOverlay dpo(packet);
    return dpo;
  });

  luaCtx.registerMember<DNSName(dnsdist::DNSPacketOverlay::*)>(std::string("qname"), [](const dnsdist::DNSPacketOverlay& overlay) -> const DNSName& { return overlay.d_qname; });
  luaCtx.registerMember<uint16_t(dnsdist::DNSPacketOverlay::*)>(std::string("qtype"), [](const dnsdist::DNSPacketOverlay& overlay) { return overlay.d_qtype; });
  luaCtx.registerMember<uint16_t(dnsdist::DNSPacketOverlay::*)>(std::string("qclass"), [](const dnsdist::DNSPacketOverlay& overlay) { return overlay.d_qclass; });
  luaCtx.registerMember<dnsheader(dnsdist::DNSPacketOverlay::*)>(std::string("dh"), [](const dnsdist::DNSPacketOverlay& overlay) { return overlay.d_header; });

  luaCtx.registerFunction<uint16_t (dnsdist::DNSPacketOverlay::*)(uint8_t) const>("getRecordsCountInSection", [](const dnsdist::DNSPacketOverlay& overlay, uint8_t section) -> uint16_t {
    if (section > DNSResourceRecord::ADDITIONAL) {
      return 0;
    }
    uint16_t count = 0;
    for (const auto& record : overlay.d_records) {
      if (record.d_place == section) {
        count++;
      }
    }

    return count;
  });

  luaCtx.registerFunction<dnsdist::DNSPacketOverlay::Record (dnsdist::DNSPacketOverlay::*)(size_t) const>("getRecord", [](const dnsdist::DNSPacketOverlay& overlay, size_t idx) {
    return overlay.d_records.at(idx);
  });

  luaCtx.registerMember<DNSName(dnsdist::DNSPacketOverlay::Record::*)>(std::string("name"), [](const dnsdist::DNSPacketOverlay::Record& record) { return record.d_name; });
  luaCtx.registerMember<uint16_t(dnsdist::DNSPacketOverlay::Record::*)>(std::string("type"), [](const dnsdist::DNSPacketOverlay::Record& record) { return record.d_type; });
  luaCtx.registerMember<uint16_t(dnsdist::DNSPacketOverlay::Record::*)>(std::string("class"), [](const dnsdist::DNSPacketOverlay::Record& record) { return record.d_class; });
  luaCtx.registerMember<uint32_t(dnsdist::DNSPacketOverlay::Record::*)>(std::string("ttl"), [](const dnsdist::DNSPacketOverlay::Record& record) { return record.d_ttl; });
  luaCtx.registerMember<uint8_t(dnsdist::DNSPacketOverlay::Record::*)>(std::string("place"), [](const dnsdist::DNSPacketOverlay::Record& record) { return record.d_place; });
  luaCtx.registerMember<uint16_t(dnsdist::DNSPacketOverlay::Record::*)>(std::string("contentLength"), [](const dnsdist::DNSPacketOverlay::Record& record) { return record.d_contentLength; });
  luaCtx.registerMember<uint16_t(dnsdist::DNSPacketOverlay::Record::*)>(std::string("contentOffset"), [](const dnsdist::DNSPacketOverlay::Record& record) { return record.d_contentOffset; });

  luaCtx.writeFunction("parseARecord", [](const std::string& packet, const dnsdist::DNSPacketOverlay::Record& record) {
    return dnsdist::RecordParsers::parseARecord(packet, record);
  });
  luaCtx.writeFunction("parseAAAARecord", [](const std::string& packet, const dnsdist::DNSPacketOverlay::Record& record) {
    return dnsdist::RecordParsers::parseAAAARecord(packet, record);
  });
  luaCtx.writeFunction("parseAddressRecord", [](const std::string& packet, const dnsdist::DNSPacketOverlay::Record& record) {
    return dnsdist::RecordParsers::parseAddressRecord(packet, record);
  });
  luaCtx.writeFunction("parseCNAMERecord", [](const std::string& packet, const dnsdist::DNSPacketOverlay::Record& record) {
    return dnsdist::RecordParsers::parseCNAMERecord(packet, record);
  });
#endif /* DISABLE_DNSPACKET_BINDINGS */
}
