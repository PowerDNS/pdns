#include "config.h"
#include "pdns/namespaces.hh"

#include <vector>
#include <map>
#include <string>
#include <fstream>
#include <yaml-cpp/yaml.h>
#include <pthread.h>
#include <boost/foreach.hpp>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include <sys/types.h>
#include <dirent.h>

#include "pdns/dnspacket.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/lock.hh"

class GeoIPDomain;

class GeoIPBackend: public DNSBackend {
public:
  GeoIPBackend(const std::string& suffix="");
  ~GeoIPBackend();

  virtual void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
  virtual bool list(const string &target, int domain_id, bool include_disabled=false) { return false; } // not supported
  virtual bool get(DNSResourceRecord &r);
  virtual void reload();
  virtual void rediscover(string *status = 0);
  virtual bool getDomainInfo(const string &domain, DomainInfo &di);

  // dnssec support
  virtual bool doesDNSSEC() { return d_dnssec; };
  virtual bool getAllDomainMetadata(const string& name, std::map<std::string, std::vector<std::string> >& meta);
  virtual bool getDomainMetadata(const std::string& name, const std::string& kind, std::vector<std::string>& meta);
  virtual bool getDomainKeys(const std::string& name, unsigned int kind, std::vector<DNSBackend::KeyData>& keys);
  virtual bool removeDomainKey(const string& name, unsigned int id);
  virtual int addDomainKey(const string& name, const KeyData& key);
  virtual bool activateDomainKey(const string& name, unsigned int id);
  virtual bool deactivateDomainKey(const string& name, unsigned int id);

  enum GeoIPQueryAttribute {
    Afi,
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
  string queryGeoIP(const string &ip, bool v6, GeoIPQueryAttribute attribute);
  string format2str(string format, const string& ip, bool v6);  
  int d_dbmode;
  bool d_dnssec; 
  bool hasDNSSECkey(const string &domain);

  vector<DNSResourceRecord> d_result;
};
