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

bool validateViewName(std::string_view name, std::string& error)
{
  if (name.empty()) {
    error = "Empty view names are not allowed";
    return false;
  }

  if (auto pos = name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 _-."); pos != std::string_view::npos) {
    error = std::string("View name contains forbidden character '") + name[pos] + "' at position " + std::to_string(pos);
    return false;
  }

  if (name[0] == '.') {
    error = "View names are not allowed to start with a dot";
    return false;
  }

  if (name[0] == ' ') {
    error = "View names are not allowed to start with a space";
    return false;
  }

  return true;
}

void checkRRSet(const vector<DNSResourceRecord>& oldrrs, vector<DNSResourceRecord>& allrrs, const ZoneName& zone, bool allowUnderscores, vector<pair<DNSResourceRecord, string>>& errors)
{
  // QTypes that MUST NOT have multiple records of the same type in a given RRset.
  static const std::set<uint16_t> onlyOneEntryTypes = {QType::CNAME, QType::DNAME, QType::SOA};
  // QTypes that MUST be at apex.
  static const std::set<uint16_t> atApexTypes = {QType::SOA, QType::DNSKEY};
  // QTypes that are NOT allowed at apex.
  static const std::set<uint16_t> nonApexTypes = {QType::DS};

  sort(allrrs.begin(), allrrs.end(),
       [](const DNSResourceRecord& rec_a, const DNSResourceRecord& rec_b) -> bool {
         /* we need _strict_ weak ordering */
         return std::tie(rec_a.qname, rec_a.qtype, rec_a.content) < std::tie(rec_b.qname, rec_b.qtype, rec_b.content);
       });

  DNSResourceRecord previous;
  for (const auto& rec : allrrs) {
    if (previous.qname == rec.qname) {
      if (previous.qtype == rec.qtype) {
        if (onlyOneEntryTypes.count(rec.qtype.getCode()) != 0) {
          errors.emplace_back(std::make_pair(rec, "only one such record allowed"));
        }
        if (previous.content == rec.content) {
          errors.emplace_back(std::make_pair(rec, std::string{"duplicate record with content \""} + rec.content + "\""));
        }
      }
      else {
        if (QType::exclusiveEntryTypes.count(rec.qtype.getCode()) != 0
            || QType::exclusiveEntryTypes.count(previous.qtype.getCode()) != 0) {
          // The `rec' record can't be added because of `previous'. However
          // `rec' might be one of the existing records, and `previous' the
          // added one. Or they might both be new records.
          // We thus check if `rec' appears in the existing records in
          // order to decide which record to blame in order to make the error
          // message as less confusing as possible.
          if (std::find(oldrrs.begin(), oldrrs.end(), rec) != oldrrs.end()) {
            errors.emplace_back(std::make_pair(previous, std::string{"conflicts with existing "} + rec.qtype.toString() + " RRset of the same name"));
          }
          else {
            errors.emplace_back(std::make_pair(rec, std::string{"conflicts with existing "} + previous.qtype.toString() + " RRset of the same name"));
          }
        }
      }
    }

    if (rec.qname == zone.operator const DNSName&()) {
      if (nonApexTypes.count(rec.qtype.getCode()) != 0) {
        errors.emplace_back(std::make_pair(rec, "is not allowed at apex"));
      }
    }
    else if (atApexTypes.count(rec.qtype.getCode()) != 0) {
      errors.emplace_back(std::make_pair(rec, "is only allowed at apex"));
    }

    // Check if the DNSNames that should be hostnames, are hostnames
    try {
      checkHostnameCorrectness(rec, allowUnderscores);
    }
    catch (const std::exception& e) {
      errors.emplace_back(std::make_pair(rec, e.what()));
    }

    previous = rec;
  }
}

} // namespace Check
