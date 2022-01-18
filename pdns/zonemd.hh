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

class ZoneParserTNG;

namespace pdns
{
class ZoneMD
{
public:
  enum class Config : uint8_t
  {
    Ignore,
    Process,
    LogOnly,
    Required,
    RequiredWithDNSSEC,
    RequiredIgnoreDNSSEC,
  };
  enum class Result : uint8_t
  {
    OK,
    NoValidationDone,
    ValidationFailure
  };

  ZoneMD(const DNSName& zone) :
    d_zone(zone)
  {}
  void readRecords(ZoneParserTNG& zpt);
  void readRecords(const std::vector<DNSRecord>& records);
  void readRecord(const DNSRecord& record);
  void verify(bool& validationDone, bool& validationOK);

  static bool validationRequired(Config config)
  {
    return config == Config::Required || config == Config::RequiredWithDNSSEC || config == Config::RequiredIgnoreDNSSEC;
  }

private:
  typedef std::pair<DNSName, QType> RRSetKey_t;
  typedef std::vector<std::shared_ptr<DNSRecordContent>> RRVector_t;

  struct CanonRRSetKeyCompare : public std::binary_function<RRSetKey_t, RRSetKey_t, bool>
  {
    bool operator()(const RRSetKey_t& a, const RRSetKey_t& b) const
    {
      // FIXME surely we can be smarter here
      if (a.first.canonCompare(b.first)) {
        return true;
      }
      if (b.first.canonCompare(a.first)) {
        return false;
      }
      return a.second < b.second;
    }
  };

  typedef std::map<RRSetKey_t, RRVector_t, CanonRRSetKeyCompare> RRSetMap_t;

  struct ZoneMDAndDuplicateFlag
  {
    std::shared_ptr<ZONEMDRecordContent> record;
    bool duplicate;
  };

  // scheme,hashalgo -> zonemdrecord,duplicate
  std::map<pair<uint8_t, uint8_t>, ZoneMDAndDuplicateFlag> d_zonemdRecords;

  RRSetMap_t d_resourceRecordSets;
  std::map<RRSetKey_t, uint32_t> d_resourceRecordSetTTLs;

  std::shared_ptr<SOARecordContent> d_soaRecordContent;
  const DNSName d_zone;
};

}
