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
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>

#include "pdns/dnspacket.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/lock.hh"

class GeoIPInterface;

struct GeoIPDomain;

struct GeoIPNetmask {
  int netmask;
};

class GeoIPBackend: public DNSBackend {
public:
  GeoIPBackend(const std::string& suffix="");
  ~GeoIPBackend();

  void lookup(const QType &qtype, const DNSName &qdomain, int zoneId, DNSPacket *pkt_p=nullptr) override;
  bool list(const DNSName &target, int domain_id, bool include_disabled=false) override { return false; } // not supported
  bool get(DNSResourceRecord &r) override;
  void reload() override;
  void rediscover(string *status = 0) override;
  bool getDomainInfo(const DNSName& domain, DomainInfo &di, bool getSerial=true) override;

  // dnssec support
  bool doesDNSSEC() override { return d_dnssec; };
  bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta) override;
  bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) override;
  bool getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys) override;
  bool removeDomainKey(const DNSName& name, unsigned int id) override;
  bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) override;
  bool activateDomainKey(const DNSName& name, unsigned int id) override;
  bool deactivateDomainKey(const DNSName& name, unsigned int id) override;

private:
  static pthread_rwlock_t s_state_lock;

  void initialize();
  string format2str(string format, const Netmask &addr, GeoIPNetmask& gl);
  bool d_dnssec;
  bool hasDNSSECkey(const DNSName& name);
  bool lookup_static(const GeoIPDomain &dom, const DNSName &search, const QType &qtype, const DNSName& qdomain, const Netmask &addr, GeoIPNetmask& gl);
  vector<DNSResourceRecord> d_result;
  vector<GeoIPInterface> d_files;
};

#endif /* PDNS_GEOIPBACKEND_HH */
