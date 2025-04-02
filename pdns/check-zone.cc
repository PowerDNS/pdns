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

#include "dns.hh"
#include "dnsrecords.hh"

#include "check-zone.hh"

namespace Check
{

static void rejectRecord(const DNSResourceRecord& rec, const std::string& why)
{
  throw CheckException("RRset " + rec.qname.toString() + " IN " + rec.qtype.toString() + why);
}

void checkRRSet(vector<DNSResourceRecord>& records, const ZoneName& zone)
{
  // QTypes that MUST NOT have multiple records of the same type in a given RRset.
  static const std::set<uint16_t> onlyOneEntryTypes = {QType::CNAME, QType::DNAME, QType::SOA};
  // QTypes that MUST be at apex.
  static const std::set<uint16_t> atApexTypes = {QType::SOA, QType::DNSKEY};
  // QTypes that are NOT allowed at apex.
  static const std::set<uint16_t> nonApexTypes = {QType::DS};

  sort(records.begin(), records.end(),
       [](const DNSResourceRecord& rec_a, const DNSResourceRecord& rec_b) -> bool {
         /* we need _strict_ weak ordering */
         return std::tie(rec_a.qname, rec_a.qtype, rec_a.content) < std::tie(rec_b.qname, rec_b.qtype, rec_b.content);
       });

  DNSResourceRecord previous;
  for (const auto& rec : records) {
    if (previous.qname == rec.qname) {
      if (previous.qtype == rec.qtype) {
        if (onlyOneEntryTypes.count(rec.qtype.getCode()) != 0) {
          rejectRecord(rec, " has more than one record");
        }
        if (previous.content == rec.content) {
          throw CheckException("Duplicate record in RRset " + rec.qname.toString() + " IN " + rec.qtype.toString() + " with content \"" + rec.content + "\"");
        }
      }
      else if (QType::exclusiveEntryTypes.count(rec.qtype.getCode()) != 0 || QType::exclusiveEntryTypes.count(previous.qtype.getCode()) != 0) {
        rejectRecord(rec, ": Conflicts with another RRset");
      }
    }

    if (rec.qname == zone.operator const DNSName&()) {
      if (nonApexTypes.count(rec.qtype.getCode()) != 0) {
        rejectRecord(rec, " is not allowed at apex");
      }
    }
    else if (atApexTypes.count(rec.qtype.getCode()) != 0) {
      rejectRecord(rec, " is only allowed at apex");
    }

    // Check if the DNSNames that should be hostnames, are hostnames
    try {
      checkHostnameCorrectness(rec);
    }
    catch (const std::exception& e) {
      rejectRecord(rec, std::string{": "} + e.what());
    }

    previous = rec;
  }
}

} // namespace Check
