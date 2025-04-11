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
#pragma once

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dnsname.hh"
#include "qtype.hh"
#include "dnsrecords.hh"
#include "validate.hh"

class ZoneParserTNG;

namespace pdns
{
class ZoneMD
{
public:
  enum class Config : uint8_t
  {
    Ignore,
    Validate,
    Require
  };
  enum class Result : uint8_t
  {
    OK,
    NoValidationDone,
    ValidationFailure
  };

  ZoneMD(ZoneName zone) :
    d_zone(std::move(zone))
  {}
  void readRecords(ZoneParserTNG& zpt);
  void readRecords(const std::vector<DNSRecord>& records);
  void readRecord(const DNSRecord& record);
  void processRecord(const DNSRecord& record);
  void verify(bool& validationDone, bool& validationOK);

  // Return the zone's apex DNSKEYs
  [[nodiscard]] const std::set<shared_ptr<const DNSKEYRecordContent>>& getDNSKEYs() const
  {
    return d_dnskeys;
  }

  // Return the zone's apex RRSIGs
  [[nodiscard]] const std::vector<shared_ptr<const RRSIGRecordContent>>& getRRSIGs(QType requestedType)
  {
    if (d_rrsigs.count(requestedType) == 0) {
      d_rrsigs[requestedType] = {};
    }
    return d_rrsigs[requestedType];
  }

  // Return the zone's apex ZONEMDs
  [[nodiscard]] std::vector<shared_ptr<const ZONEMDRecordContent>> getZONEMDs() const
  {
    std::vector<shared_ptr<const ZONEMDRecordContent>> ret;
    ret.reserve(d_zonemdRecords.size());
    for (const auto& zonemd : d_zonemdRecords) {
      ret.emplace_back(zonemd.second.record);
    }
    return ret;
  }

  // Return the zone's apex NSECs with signatures
  [[nodiscard]] const ContentSigPair& getNSECs() const
  {
    return d_nsecs;
  }

  // Return the zone's apex NSEC3s with signatures
  [[nodiscard]] const ContentSigPair& getNSEC3s() const
  {
    const auto item = d_nsec3s.find(d_nsec3label);
    return item == d_nsec3s.end() ? empty : d_nsec3s.at(d_nsec3label);
  }

  [[nodiscard]] const DNSName& getNSEC3Label() const
  {
    return d_nsec3label;
  }

  [[nodiscard]] const std::vector<shared_ptr<const NSEC3PARAMRecordContent>>& getNSEC3Params() const
  {
    return d_nsec3params;
  }

private:
  using RRSetKey_t = std::pair<DNSName, QType>;
  using RRVector_t = std::vector<std::shared_ptr<const DNSRecordContent>>;

  struct CanonRRSetKeyCompare
  {
    bool operator()(const RRSetKey_t& lhs, const RRSetKey_t& rhs) const
    {
      // FIXME surely we can be smarter here
      if (lhs.first.canonCompare(rhs.first)) {
        return true;
      }
      if (rhs.first.canonCompare(lhs.first)) {
        return false;
      }
      return lhs.second < rhs.second;
    }
  };

  using RRSetMap_t = std::map<RRSetKey_t, RRVector_t, CanonRRSetKeyCompare>;

  struct ZoneMDAndDuplicateFlag
  {
    const std::shared_ptr<const ZONEMDRecordContent> record;
    bool duplicate;
  };

  // scheme,hashalgo -> zonemdrecord,duplicate
  std::map<pair<uint8_t, uint8_t>, ZoneMDAndDuplicateFlag> d_zonemdRecords;

  RRSetMap_t d_resourceRecordSets;
  std::map<RRSetKey_t, uint32_t> d_resourceRecordSetTTLs;

  std::shared_ptr<const SOARecordContent> d_soaRecordContent;
  std::set<shared_ptr<const DNSKEYRecordContent>> d_dnskeys;
  std::map<QType, std::vector<shared_ptr<const RRSIGRecordContent>>> d_rrsigs;
  std::vector<shared_ptr<const NSEC3PARAMRecordContent>> d_nsec3params;
  ContentSigPair d_nsecs;
  map<DNSName, ContentSigPair> d_nsec3s;
  DNSName d_nsec3label;
  const ZoneName d_zone;
  const ContentSigPair empty;
};

}
