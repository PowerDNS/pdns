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
#ifndef PDNS_GEOIPBACKEND_HH
#define PDNS_GEOIPBACKEND_HH

#include "pdns/namespaces.hh"

#include <vector>
#include <map>
#include <string>
#include <fstream>
#include <yaml-cpp/yaml.h>
#include <pthread.h>

#include <GeoIP.h>
#include <GeoIPCity.h>
#include <sys/types.h>
#include <dirent.h>

#include "pdns/dnspacket.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/lock.hh"

struct geoip_deleter;

class GeoIPDomain;

class GeoIPBackend: public DNSBackend {
public:
  typedef pair<int,unique_ptr<GeoIP,geoip_deleter> > geoip_file_t;
  GeoIPBackend(const std::string& suffix="");
  ~GeoIPBackend();

  virtual void lookup(const QType &qtype, const DNSName &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
  virtual bool list(const DNSName &target, int domain_id, bool include_disabled=false) { return false; } // not supported
  virtual bool get(DNSResourceRecord &r);
  virtual void reload();
  virtual void rediscover(string *status = 0);
  virtual bool getDomainInfo(const DNSName& domain, DomainInfo &di);

  // dnssec support
  virtual bool doesDNSSEC() { return d_dnssec; };
  virtual bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta);
  virtual bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta);
  virtual bool getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys);
  virtual bool removeDomainKey(const DNSName& name, unsigned int id);
  virtual bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id);
  virtual bool activateDomainKey(const DNSName& name, unsigned int id);
  virtual bool deactivateDomainKey(const DNSName& name, unsigned int id);

  enum GeoIPQueryAttribute {
    ASn,
    City,
    Continent,
    Country,
    Name,
    Region
  };

private:
  static pthread_rwlock_t s_state_lock;

  void initialize();
  void ip2geo(const GeoIPDomain& dom, const string& qname, const string& ip);
  string queryGeoIP(const string &ip, bool v6, GeoIPQueryAttribute attribute, GeoIPLookup* gl);
  bool queryCountry(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryCountryV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryContinent(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryContinentV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryName(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryNameV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryASnum(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryASnumV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryRegion(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryRegionV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryCity(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  bool queryCityV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi);
  string format2str(string format, const string& ip, bool v6, GeoIPLookup* gl);
  bool d_dnssec; 
  bool hasDNSSECkey(const DNSName& name);

  vector<DNSResourceRecord> d_result;
};

#endif /* PDNS_GEOIPBACKEND_HH */
