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

#include <array>

#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "dnswriter.hh"
#include "dnsname.hh"
#include "ednsoptions.hh"
#include "qtype.hh"
#include "statbag.hh"

// NOLINTNEXTLINE(readability-identifier-length,bugprone-throwing-static-initialization)
StatBag S;

bool g_slogStructured{false};

static void init()
{
  reportAllTypes();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  static bool initialized = false;

  if (!initialized) {
    init();
    initialized = true;
  }

  if (size > std::numeric_limits<uint16_t>::max()) {
    return 0;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const char* chars = reinterpret_cast<const char*>(data);

  try {
    // 1) Feed the raw, untrusted bytes straight to the EDNS OPT option parsers:
    //    the option TLV decoder in ednsoptions.cc is otherwise unreached.
    EDNSOptionViewMap viewOptions;
    (void)getEDNSOptions(chars, size, viewOptions);

    std::vector<std::pair<uint16_t, std::string>> options;
    (void)getEDNSOptionsFromContent(std::string(chars, size), options);

    // 2) Drive DNSPacketWriter with attacker-controlled structures (several
    //    records, attacker rdata, name compression, EDNS OPT writing), the
    //    full-packet writer paths that the parse/record fuzzers never reach.
    size_t pos = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const auto getU8 = [&]() -> uint8_t { return pos < size ? data[pos++] : 0; };
    const auto getU16 = [&]() -> uint16_t {
      const uint16_t highV = getU8();
      return static_cast<uint16_t>((highV << 8) | getU8());
    };

    const uint16_t qtype = getU16();
    const DNSName qname(".");
    std::vector<uint8_t> packet;
    DNSPacketWriter writer(packet, qname, qtype);

    static const std::array<const char*, 4> suffixes{".", "example.com.", "a.example.com.", "powerdns.com."};

    const unsigned int records = getU8() % 8U;
    for (unsigned int i = 0; i < records && pos < size; ++i) {
      // A valid name sharing one of a few suffixes (so the name-compression
      // paths fire) with an attacker-controlled first label.
      const uint8_t labelLen = getU8() % 32U;
      std::string label;
      for (uint8_t j = 0; j < labelLen && pos < size; ++j) {
        label.push_back(static_cast<char>('a' + (getU8() % 26)));
      }
      const std::string suffix = suffixes.at(getU8() % suffixes.size());
      DNSName name{};
      try {
        if (label.empty()) {
          name = DNSName(suffix);
        }
        else {
          label.append(".");
          label.append(suffix);
          name = DNSName(label);
        }
      }
      catch (...) {
        name = qname;
      }

      const uint16_t rtype = getU16();
      const uint16_t rdlen = getU16();
      std::string rdata;
      for (uint16_t j = 0; j < rdlen && pos < size; ++j) {
        rdata.push_back(static_cast<char>(getU8()));
      }

      writer.startRecord(name, rtype);
      writer.xfrBlob(rdata);
    }

    // EDNS OPT writing fed with the attacker-parsed option vector.
    if (!options.empty()) {
      DNSPacketWriter::optvect_t optvect;
      for (const auto& option : options) {
        optvect.emplace_back(option.first, option.second);
      }
      writer.addOpt(1232, 0, 0, optvect);
    }
    writer.commit();

    // Re-parse the writer's own output.
    if (!packet.empty()) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      MOADNSParser reparse(false, reinterpret_cast<const char*>(packet.data()), packet.size());
    }
  }
  // NOLINTNEXTLINE(bugprone-empty-catch)
  catch (const std::exception& e) {
  }
  // NOLINTNEXTLINE(bugprone-empty-catch)
  catch (const PDNSException& e) {
  }

  return 0;
}
