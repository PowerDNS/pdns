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
#include "pdns/namespaces.hh"

#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>

#include "pdns/dnspacket.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/lock.hh"

namespace YAML
{
class Node;
};

struct GeoIPDomain;

class GeoIPInterface;

struct GeoIPNetmask
{
  int netmask;
};

class GeoIPBackend : public DNSBackend
{
public:
  GeoIPBackend(const std::string& suffix = "");
  ~GeoIPBackend() override;

  using filevec_t = std::vector<std::unique_ptr<GeoIPInterface>>;
  using state_t = struct
  {
    unsigned int instance_count{0};
    std::vector<GeoIPDomain> domains;
    filevec_t geoip_files;
  };

  // Needs to be public, for the Lua interface needs to access this outside
  // of a backend instance.
  static SharedLockGuarded<state_t> s_state;

  unsigned int getCapabilities() override
  {
    unsigned int caps = 0;
    if (d_dnssec) {
      caps |= CAP_DNSSEC;
    }
    return caps;
  }

  void lookup(const QType& qtype, const DNSName& qdomain, domainid_t zoneId, DNSPacket* pkt_p = nullptr) override;
  bool list(const ZoneName& /* target */, domainid_t /* domain_id */, bool /* include_disabled */ = false) override { return false; } // not supported
  bool get(DNSResourceRecord& r) override;
  void lookupEnd() override;
  void reload() override;
  void rediscover(string* status = nullptr) override;
  bool getDomainInfo(const ZoneName& domain, DomainInfo& info, bool getSerial = true) override;
  void getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled) override;

  // dnssec support
  bool getAllDomainMetadata(const ZoneName& name, std::map<std::string, std::vector<std::string>>& meta) override;
  bool getDomainMetadata(const ZoneName& name, const std::string& kind, std::vector<std::string>& meta) override;
  bool getDomainKeys(const ZoneName& name, std::vector<DNSBackend::KeyData>& keys) override;
  bool removeDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool addDomainKey(const ZoneName& name, const KeyData& key, int64_t& keyId) override;
  bool activateDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool deactivateDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool publishDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool unpublishDomainKey(const ZoneName& name, unsigned int keyId) override;

private:
  void initialize(state_t& state);
  string format2str(const filevec_t& geoip_files, string format, const Netmask& addr, GeoIPNetmask& gl, const GeoIPDomain& dom);
  bool d_dnssec{};
  bool hasDNSSECkey(const ZoneName& name);
  bool lookup_static(const filevec_t& geoip_files, const GeoIPDomain& dom, const DNSName& search, const QType& qtype, const DNSName& qdomain, const Netmask& addr, GeoIPNetmask& gl);
  void setupNetmasks(const YAML::Node& domain, GeoIPDomain& dom);
  bool loadDomain(const std::string& origin, const YAML::Node& domain, domainid_t domainID, GeoIPDomain& dom);
  void loadDomainsFromDirectory(const std::string& dir, vector<GeoIPDomain>& domains);

  vector<DNSResourceRecord> d_result;
  std::vector<std::string> d_global_mapping_lookup_formats;
  std::map<std::string, std::string> d_global_custom_mapping;
};
