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

#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "qtype.hh"
#include "statbag.hh"

StatBag S{};

bool g_slogStructured{false};

static const std::array<uint16_t, 48> g_qtypes{
  QType::A,
  QType::AAAA,
  QType::NS,
  QType::CNAME,
  QType::SOA,
  QType::MX,
  QType::TXT,
  QType::SRV,
  QType::PTR,
  QType::HINFO,
  QType::RP,
  QType::AFSDB,
  QType::RRSIG,
  QType::SIG,
  QType::KEY,
  QType::DNSKEY,
  QType::CDNSKEY,
  QType::DS,
  QType::CDS,
  QType::DLV,
  QType::NSEC,
  QType::NSEC3,
  QType::NSEC3PARAM,
  QType::TLSA,
  QType::SMIMEA,
  QType::SVCB,
  QType::HTTPS,
  QType::CAA,
  QType::NAPTR,
  QType::LOC,
  QType::APL,
  QType::CERT,
  QType::SSHFP,
  QType::IPSECKEY,
  QType::DHCID,
  QType::OPENPGPKEY,
  QType::CSYNC,
  QType::ZONEMD,
  QType::URI,
  QType::DNAME,
  QType::KX,
  QType::SPF,
  QType::EUI48,
  QType::EUI64,
  QType::NID,
  QType::L32,
  QType::L64,
  QType::LP,
};

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

  if (size < 2 || size > std::numeric_limits<uint16_t>::max()) {
    return 0;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  const uint16_t selector = (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
  const uint16_t qtype = g_qtypes.at(selector % g_qtypes.size());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast, cppcoreguidelines-pro-bounds-pointer-arithmetic)
  const std::string rest(reinterpret_cast<const char*>(data + 2), size - 2);
  const DNSName qname(".");

  try {
    const auto content = DNSRecordContent::make(qtype, QClass::IN, rest);
    if (content) {
      const auto wire = content->serialize(qname, true);
      (void)content->getZoneRepresentation();
      try {
        const auto reparsed = DNSRecordContent::deserialize(qname, qtype, wire);
        if (reparsed) {
          (void)reparsed->getZoneRepresentation();
        }
      }
      // NOLINTNEXTLINE(bugprone-empty-catch)
      catch (const std::exception& e) {
      }
      // NOLINTNEXTLINE(bugprone-empty-catch)
      catch (const PDNSException& e) {
      }
    }
  }
  // NOLINTNEXTLINE(bugprone-empty-catch)
  catch (const std::exception& e) {
  }
  // NOLINTNEXTLINE(bugprone-empty-catch)
  catch (const PDNSException& e) {
  }

  try {
    const auto content = DNSRecordContent::deserialize(qname, qtype, rest);
    if (content) {
      (void)content->getZoneRepresentation();
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
