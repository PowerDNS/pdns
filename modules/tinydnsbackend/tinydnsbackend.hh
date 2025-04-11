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
#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"
#include "pdns/iputils.hh"
#include "pdns/dnspacket.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "pdns/cdb.hh"
#include "pdns/lock.hh"
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>

using namespace ::boost;
using namespace ::boost::multi_index;

struct TinyDomainInfo
{
  uint32_t id;
  uint32_t notified_serial;
  ZoneName zone;

  bool operator<(const TinyDomainInfo& tdi) const
  {
    return zone < tdi.zone;
  }
};

struct TDI_SerialModifier
{
  TDI_SerialModifier(const int newSerial) :
    d_newSerial(newSerial) {}

  void operator()(TinyDomainInfo& tdi)
  {
    tdi.notified_serial = d_newSerial;
  }

private:
  int d_newSerial;
};

class TinyDNSBackend : public DNSBackend
{
public:
  // Methods for simple operation
  TinyDNSBackend(const string& suffix);

  unsigned int getCapabilities() override { return CAP_LIST; }
  void lookup(const QType& qtype, const DNSName& qdomain, int zoneId, DNSPacket* pkt_p = nullptr) override;
  bool list(const ZoneName& target, int domain_id, bool include_disabled = false) override;
  bool get(DNSResourceRecord& rr) override;
  bool getDomainInfo(const ZoneName& domain, DomainInfo& di, bool getSerial = true) override;
  void getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled) override;

  // Primary mode operation
  void getUpdatedPrimaries(vector<DomainInfo>& domains, std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes) override;
  void setNotified(uint32_t id, uint32_t serial) override;

private:
  //TypeDefs
  struct tag_zone
  {
  };
  struct tag_domainid
  {
  };
  typedef multi_index_container<
    TinyDomainInfo,
    indexed_by<
      hashed_unique<tag<tag_zone>, member<TinyDomainInfo, ZoneName, &TinyDomainInfo::zone>>,
      hashed_unique<tag<tag_domainid>, member<TinyDomainInfo, uint32_t, &TinyDomainInfo::id>>>>
    TDI_t;
  typedef map<string, TDI_t> TDI_suffix_t;
  typedef TDI_t::index<tag_zone>::type TDIByZone_t;
  typedef TDI_t::index<tag_domainid>::type TDIById_t;

  vector<string> getLocations();
  static TDI_t::iterator updateState(DomainInfo& domain, TDI_t* state);
  void getAllDomains_locked(vector<DomainInfo>* domains, bool getSerial);

  //data member variables
  uint64_t d_taiepoch;
  QType d_qtype;
  std::unique_ptr<CDB> d_cdbReader;
  DNSPacket* d_dnspacket; // used for location and edns-client support.
  bool d_isWildcardQuery; // Indicate if the query received was a wildcard query.
  bool d_isAxfr; // Indicate if we received a list() and not a lookup().
  bool d_isGetDomains{false};
  bool d_locations;
  bool d_ignorebogus;
  string d_suffix;

  // Statics
  static LockGuarded<TDI_suffix_t> s_domainInfo;
  static uint32_t s_lastId; // used to give a domain an id.
};
