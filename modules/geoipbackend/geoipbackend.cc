#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "geoipbackend.hh"
#include <sstream>
#include <regex.h>
#include <glob.h>

pthread_rwlock_t GeoIPBackend::s_state_lock=PTHREAD_RWLOCK_INITIALIZER;

class GeoIPDomain {
public:
  int id;
  DNSName domain;
  int ttl;
  map<DNSName, NetmaskTree<string> > services;
  map<DNSName, vector<DNSResourceRecord> > records;
};

static vector<GeoIPDomain> s_domains;
static GeoIP *s_gi = 0; // geoip database
static GeoIP *s_gi6 = 0; // geoip database
static int s_rc = 0; // refcount

static string GeoIP_WEEKDAYS[] = { "mon", "tue", "wed", "thu", "fri", "sat", "sun" };
static string GeoIP_MONTHS[] = { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };

/* So how does it work - we have static records and services. Static records "win".
   We also insert empty non terminals for records and services.

   If a service makes an internal reference to a domain also hosted within geoip, we give a direct
   answers, no CNAMEs involved.

   If the reference is external, we spoof up a CNAME, and good luck with that
*/

GeoIPBackend::GeoIPBackend(const string& suffix) {
  WriteLock wl(&s_state_lock);
  d_dnssec = false;
  setArgPrefix("geoip" + suffix);
  if (getArg("dnssec-keydir").empty() == false) {
    DIR *d = opendir(getArg("dnssec-keydir").c_str());
    if (d == NULL) {
      throw PDNSException("dnssec-keydir " + getArg("dnssec-keydir") + " does not exist");
    }
    d_dnssec = true;
    closedir(d);
  }
  if (s_rc == 0) { // first instance gets to open everything
    initialize();
  }
  d_dbmode = GeoIP_database_edition(s_gi);
  s_rc++;
}

void GeoIPBackend::initialize() {
  YAML::Node config;
  vector<GeoIPDomain> tmp_domains;
  GeoIP *gi;

  string mode = getArg("database-cache");
  int flags;
  if (mode == "standard") 
    flags = GEOIP_STANDARD;
  else if (mode == "memory")
    flags = GEOIP_MEMORY_CACHE;
  else if (mode == "index") 
    flags = GEOIP_INDEX_CACHE;
#ifdef HAVE_MMAP
  else if (mode == "mmap")
    flags = GEOIP_MMAP_CACHE;
#endif
  else
    throw PDNSException("Invalid cache mode " + mode + " for GeoIP backend");

  if (getArg("database-file").empty() == false) {
    gi = GeoIP_open(getArg("database-file").c_str(), flags);
    if (gi == NULL)
      throw PDNSException("Cannot open GeoIP database " + getArg("database-file"));
    if (s_gi) GeoIP_delete(s_gi);
    s_gi = gi;
  }
  if (getArg("database-file6").empty() == false) {
    gi = GeoIP_open(getArg("database-file6").c_str(), flags);
    if (gi == NULL)
      throw PDNSException("Cannot open GeoIP database " + getArg("database-file6"));
    if (s_gi6) GeoIP_delete(s_gi6);
    s_gi6 = gi;
  }

  if (s_gi == NULL && s_gi6 == NULL) 
    throw PDNSException("You need to specify one database at least");

  config = YAML::LoadFile(getArg("zones-file"));

  BOOST_FOREACH(YAML::Node domain, config["domains"]) {
    GeoIPDomain dom;
    dom.id = s_domains.size();
    dom.domain = DNSName(domain["domain"].as<string>());
    dom.ttl = domain["ttl"].as<int>();

    for(YAML::const_iterator recs = domain["records"].begin(); recs != domain["records"].end(); recs++) {
      DNSName qname = DNSName(recs->first.as<string>());
      vector<DNSResourceRecord> rrs;

      BOOST_FOREACH(YAML::Node item, recs->second) {
        YAML::const_iterator rec = item.begin();
        DNSResourceRecord rr;
        rr.domain_id = dom.id;
        rr.ttl = dom.ttl;
        rr.qname = qname;
        if (rec->first.IsNull()) { 
          rr.qtype = QType(0);
        } else {
          string qtype = boost::to_upper_copy(rec->first.as<string>());
          rr.qtype = qtype;
        }
        if (rec->second.IsNull()) {
          rr.content = "";
        } else {
          string content=rec->second.as<string>();
          rr.content = content;
        } 
                
        rr.auth = 1;
        rr.d_place = DNSResourceRecord::ANSWER;
        rrs.push_back(rr);
      }
      std::swap(dom.records[qname], rrs);
    }

    for(YAML::const_iterator service = domain["services"].begin(); service != domain["services"].end(); service++) {
      NetmaskTree<string> nmt;

      // if it's an another map, we need to iterate it again, otherwise we just add two root entries.
      if (service->second.IsMap()) {
        for(YAML::const_iterator net = service->second.begin(); net != service->second.end(); net++) {
          if (net->first.as<string>() == "default") {
            nmt[Netmask("0.0.0.0/0")] = net->second.as<string>();
            nmt[Netmask("::/0")] = net->second.as<string>();
          } else {
            nmt[Netmask(net->first.as<string>())] = net->second.as<string>();
          }
        }
      } else {
        nmt[Netmask("0.0.0.0/0")] = service->second.as<string>();
        nmt[Netmask("::/0")] = service->second.as<string>();
      }

      dom.services[DNSName(service->first.as<string>())].swap(nmt);
    }

    // rectify the zone, first static records
    for(auto &item : dom.records) {
      // ensure we have parent in records
      DNSName name = item.first;
      while(name.chopOff() && name.isPartOf(dom.domain)) {
        if (dom.records.find(name) == dom.records.end() && !dom.services.count(name)) { // don't ENT out a service!
          DNSResourceRecord rr;
          vector<DNSResourceRecord> rrs;
          rr.domain_id = dom.id;
          rr.ttl = dom.ttl;
          rr.qname = name;
          rr.qtype = QType(0); // empty non terminal
          rr.content = "";
          rr.auth = 1;
          rr.d_place = DNSResourceRecord::ANSWER;
          rrs.push_back(rr);
          std::swap(dom.records[name], rrs);
        }
      }
    }

    // then services
    for(auto &item : dom.services) {
      // ensure we have parent in records
      DNSName name = item.first;
      while(name.chopOff() && name.isPartOf(dom.domain)) {
        if (dom.records.find(name) == dom.records.end()) {
          DNSResourceRecord rr;
          vector<DNSResourceRecord> rrs;
          rr.domain_id = dom.id;
          rr.ttl = dom.ttl;
          rr.qname = name;
          rr.qtype = QType(0);
          rr.content = "";
          rr.auth = 1;
          rr.d_place = DNSResourceRecord::ANSWER;
          rrs.push_back(rr);
          std::swap(dom.records[name], rrs);
        }
      }
    }

    tmp_domains.push_back(dom);
  }

  s_domains.clear();
  std::swap(s_domains, tmp_domains);
}

GeoIPBackend::~GeoIPBackend() {
  WriteLock wl(&s_state_lock);
  s_rc--;
  if (s_rc == 0) { // last instance gets to cleanup
    if (s_gi)
      GeoIP_delete(s_gi);
    if (s_gi6)
      GeoIP_delete(s_gi6);
    s_gi = NULL;
    s_gi6 = NULL;
    s_domains.clear();
  }
}

void GeoIPBackend::lookup(const QType &qtype, const DNSName& qdomain, DNSPacket *pkt_p, int zoneId) {
  ReadLock rl(&s_state_lock);
  GeoIPDomain dom;
  GeoIPLookup gl;
  bool found = false;

  if (d_result.size()>0) 
    throw PDNSException("Cannot perform lookup while another is running");

  DNSName search = qdomain;

  d_result.clear();

  if (zoneId > -1 && zoneId < static_cast<int>(s_domains.size())) 
    dom = s_domains[zoneId];
  else {
    for(const GeoIPDomain& i : s_domains) {   // this is arguably wrong, we should probably find the most specific match
      if (search.isPartOf(i.domain)) {
        dom = i;
        found = true;
        break;
      }
    }
    if (!found) return; // not found
  }

  auto i = dom.records.find(search);
  if (i != dom.records.end()) { // return static value
    for(const DNSResourceRecord& rr : i->second) {
      if (qtype == QType::ANY || rr.qtype == qtype) {
	d_result.push_back(rr);
	d_result.back().qname = qdomain;
      }
    }
  }

  string ip = "0.0.0.0";
  bool v6 = false;
  if (pkt_p != NULL) {
    ip = pkt_p->getRealRemote().toStringNoMask();
    v6 = pkt_p->getRealRemote().isIpv6();
  }

  auto target = dom.services.find(search);
  if (target == dom.services.end()) return; // no hit

  const NetmaskTree<string>::node_type* node = target->second.lookup(ComboAddress(ip));
  if (node == NULL) return; // no hit, again.

  string format = node->second;
  gl.netmask = node->first.getBits();

  format = format2str(format, ip, v6, &gl);

  // see if the record can be found
  auto ri = dom.records.find(DNSName(format));
  if (ri != dom.records.end()) { // return static value
    for(DNSResourceRecord& rr : ri->second) {
      if (qtype == QType::ANY || rr.qtype == qtype) {
        rr.scopeMask = gl.netmask;
        d_result.push_back(rr);
        d_result.back().qname = qdomain;
      }
    }
    return;
  }
  // we need this line since we otherwise claim to have NS records etc
  if (!(qtype == QType::ANY || qtype == QType::CNAME)) return;

  DNSResourceRecord rr;
  rr.domain_id = dom.id;
  rr.qtype = QType::CNAME;
  rr.qname = qdomain;
  rr.content = format;
  rr.auth = 1;
  rr.ttl = dom.ttl;
  rr.scopeMask = gl.netmask;
  d_result.push_back(rr);
}

bool GeoIPBackend::get(DNSResourceRecord &r) {
  if (d_result.empty()) return false;

  r = d_result.back();
  d_result.pop_back();

  return true;
}

string GeoIPBackend::queryGeoIP(const string &ip, bool v6, GeoIPQueryAttribute attribute, GeoIPLookup* gl) {
  string ret = "unknown";
  const char *val = NULL;
  GeoIPRegion *gir = NULL;
  GeoIPRecord *gir2 = NULL;
  int id;
  vector<string> asnr;

  if (v6 && s_gi6) {
    if (attribute == Afi) {
      return "v6";
    } else if (d_dbmode == GEOIP_ISP_EDITION_V6 || d_dbmode == GEOIP_ORG_EDITION_V6) {
      if (attribute == Name) {
        val = GeoIP_name_by_addr_v6_gl(s_gi6, ip.c_str(), gl);
      }
    } else if (d_dbmode == GEOIP_ASNUM_EDITION_V6) {
      if (attribute == ASn) {
        val = GeoIP_name_by_addr_v6_gl(s_gi6, ip.c_str(), gl);
        if (val) {
          stringtok(asnr, val);
          if(asnr.size()>0) {
            val = asnr[0].c_str();
          }
        }
      }
    } else if (d_dbmode == GEOIP_COUNTRY_EDITION_V6 ||
        d_dbmode == GEOIP_LARGE_COUNTRY_EDITION_V6 ||
        d_dbmode == GEOIP_COUNTRY_EDITION) {
      id = GeoIP_id_by_addr_v6_gl(s_gi6, ip.c_str(), gl);
      if (attribute == Country) {
        val = GeoIP_code3_by_id(id);
      } else if (attribute == Continent) {
        val = GeoIP_continent_by_id(id);
      }
    } else if (d_dbmode == GEOIP_REGION_EDITION_REV0 ||
        d_dbmode == GEOIP_REGION_EDITION_REV1) {
      gir = GeoIP_region_by_addr_v6_gl(s_gi6, ip.c_str(), gl);
      if (gir) {
        if (attribute == Country) {
          id = GeoIP_id_by_code(gir->country_code);
          val = GeoIP_code3_by_id(id);
        } else if (attribute == Region) {
          val = gir->region;
        } else if (attribute == Continent) {
          id = GeoIP_id_by_code(gir->country_code);
          val = GeoIP_continent_by_id(id);
        }
      }
    } else if (d_dbmode == GEOIP_CITY_EDITION_REV0_V6 ||
               d_dbmode == GEOIP_CITY_EDITION_REV1_V6) {
      gir2 = GeoIP_record_by_addr_v6(s_gi6, ip.c_str());
      if (gir2) {
        if (attribute == Country) {
          val = gir2->country_code3;
        } else if (attribute == Region) {
          val = gir2->region;
        } else if (attribute == Continent) {
          id = GeoIP_id_by_code(gir2->country_code);
          val = GeoIP_continent_by_id(id);
        } else if (attribute == City) {
          val = gir2->city;
        }
        gl->netmask = gir2->netmask;
      }
    }
  } else if (!v6 && s_gi) {
    if (attribute == Afi) {
      return "v4";
    } else if (d_dbmode == GEOIP_ISP_EDITION || d_dbmode == GEOIP_ORG_EDITION) {
      if (attribute == Name) {
        val = GeoIP_name_by_addr_v6_gl(s_gi, ip.c_str(), gl);
      }
    } else if (d_dbmode == GEOIP_ASNUM_EDITION) {
      if (attribute == ASn) {
        val = GeoIP_name_by_addr_gl(s_gi, ip.c_str(), gl);
        if (val) {
          stringtok(asnr, val);
          if(asnr.size()>0) {
            val = asnr[0].c_str();
          }
        }
      }
    } else if (d_dbmode == GEOIP_COUNTRY_EDITION ||
        d_dbmode == GEOIP_LARGE_COUNTRY_EDITION) {
      id = GeoIP_id_by_addr_gl(s_gi, ip.c_str(), gl);
      if (attribute == Country) {
        val = GeoIP_code3_by_id(id);
      } else if (attribute == Continent) {
        val = GeoIP_continent_by_id(id);
      }
    } else if (d_dbmode == GEOIP_REGION_EDITION_REV0 ||
        d_dbmode == GEOIP_REGION_EDITION_REV1) {
      gir = GeoIP_region_by_addr_gl(s_gi, ip.c_str(), gl);
      if (gir) {
        if (attribute == Country) {
          id = GeoIP_id_by_code(gir->country_code);
          val = GeoIP_code3_by_id(id);
        } else if (attribute == Region) {
          val = gir->region;
        } else if (attribute == Continent) {
          id = GeoIP_id_by_code(gir->country_code);
          val = GeoIP_continent_by_id(id);
        }
      }
    } else if (d_dbmode == GEOIP_CITY_EDITION_REV0 ||
               d_dbmode == GEOIP_CITY_EDITION_REV1) {
      gir2 = GeoIP_record_by_addr(s_gi, ip.c_str());
      if (gir2) {
        if (attribute == Country) {
          val = gir2->country_code3;
        } else if (attribute == Region) {
          val = gir2->region;
        } else if (attribute == Continent) {
          id = GeoIP_id_by_code(gir2->country_code);
          val = GeoIP_continent_by_id(id);
        } else if (attribute == City) {
          val = gir2->city;
        }
        gl->netmask = gir2->netmask;
      }
    }
  }
  if (val) {
    ret = val;
    if (ret == "--") ret = "unknown";
    std::transform(ret.begin(), ret.end(), ret.begin(), ::tolower);
  }
  return ret;
}

string GeoIPBackend::format2str(string format, const string& ip, bool v6, GeoIPLookup* gl) {
  string::size_type cur,last;
  time_t t = time((time_t*)NULL);
  GeoIPLookup tmp_gl; // largest wins
  struct tm gtm;
  gmtime_r(&t, &gtm);
  gl->netmask = 0;
  last=0;

  while((cur = format.find("%", last)) != string::npos) {
    string rep;
    int nrep=3;
    tmp_gl.netmask = 0;
    if (!format.compare(cur,3,"%co")) {
      rep = queryGeoIP(ip, v6, Continent, &tmp_gl);
    } else if (!format.compare(cur,3,"%cn")) {
      rep = queryGeoIP(ip, v6, Country, &tmp_gl);
    } else if (!format.compare(cur,3,"%af")) {
      rep = queryGeoIP(ip, v6, Afi, &tmp_gl);
    } else if (!format.compare(cur,3,"%as")) {
      rep = queryGeoIP(ip, v6, ASn, &tmp_gl);
    } else if (!format.compare(cur,3,"%re")) {
      rep = queryGeoIP(ip, v6, Region, &tmp_gl);
    } else if (!format.compare(cur,3,"%na")) {
      rep = queryGeoIP(ip, v6, Name, &tmp_gl);
    } else if (!format.compare(cur,3,"%ci")) {
      rep = queryGeoIP(ip, v6, City, &tmp_gl);
    } else if (!format.compare(cur,3,"%hh")) {
      rep = boost::str(boost::format("%02d") % gtm.tm_hour);
      tmp_gl.netmask = (v6?128:32);
    } else if (!format.compare(cur,3,"%yy")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_year + 1900));
      tmp_gl.netmask = (v6?128:32);
    } else if (!format.compare(cur,3,"%dd")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_yday + 1));
      tmp_gl.netmask = (v6?128:32);
    } else if (!format.compare(cur,4,"%wds")) {
      nrep=4;
      rep = GeoIP_WEEKDAYS[gtm.tm_wday];
      tmp_gl.netmask = (v6?128:32);
    } else if (!format.compare(cur,4,"%mos")) {
      nrep=4;
      rep = GeoIP_MONTHS[gtm.tm_mon];
      tmp_gl.netmask = (v6?128:32);
    } else if (!format.compare(cur,3,"%wd")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_wday + 1));
      tmp_gl.netmask = (v6?128:32);
    } else if (!format.compare(cur,3,"%mo")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_mon + 1));
      tmp_gl.netmask = (v6?128:32);
    } else if (!format.compare(cur,2,"%%")) {
      last = cur + 2; continue;
    } else {
      last = cur + 1; continue; 
    }
    if (tmp_gl.netmask > gl->netmask) gl->netmask = tmp_gl.netmask;
    format.replace(cur, nrep, rep);
    last = cur + rep.size(); // move to next attribute
  }
  return format;
}

void GeoIPBackend::reload() {
  WriteLock wl(&s_state_lock);
  
  try {
    initialize();
  } catch (PDNSException &pex) {
    L<<Logger::Error<<"GeoIP backend reload failed: " << pex.reason << endl;
  } catch (std::exception &stex) {
    L<<Logger::Error<<"GeoIP backend reload failed: " << stex.what() << endl;
  } catch (...) {
    L<<Logger::Error<<"GeoIP backend reload failed" << endl;
  }
}

void GeoIPBackend::rediscover(string* status) {
  reload();
}

bool GeoIPBackend::getDomainInfo(const DNSName& domain, DomainInfo &di) {
  ReadLock rl(&s_state_lock);

  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (dom.domain == domain) {
      SOAData sd;
      this->getSOA(domain, sd);
      di.id = dom.id;
      di.zone = dom.domain;
      di.serial = sd.serial;
      di.kind = DomainInfo::Native;
      di.backend = this;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta) {
  if (!d_dnssec) return false;

  ReadLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (dom.domain == name) {
      if (hasDNSSECkey(dom.domain)) {
        meta[string("NSEC3NARROW")].push_back("1");
        meta[string("NSEC3PARAM")].push_back("1 0 1 f95a");
      }
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) {
  if (!d_dnssec) return false;

  ReadLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (dom.domain == name) {
      if (hasDNSSECkey(dom.domain)) {
        if (kind == "NSEC3NARROW")
          meta.push_back(string("1"));
        if (kind == "NSEC3PARAM")
          meta.push_back(string("1 0 1 f95a"));
      }
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::getDomainKeys(const DNSName& name, unsigned int kind, std::vector<DNSBackend::KeyData>& keys) {
  if (!d_dnssec) return false;
  ReadLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (dom.domain == name) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "*.key";
      glob_t glob_result;
      if (glob(pathname.str().c_str(),GLOB_ERR,NULL,&glob_result) == 0) {
        for(size_t i=0;i<glob_result.gl_pathc;i++) {
          if (regexec(&reg, glob_result.gl_pathv[i], 5, regm, 0) == 0) {
            DNSBackend::KeyData kd;
            kd.id = atoi(glob_result.gl_pathv[i]+regm[3].rm_so);
            kd.active = atoi(glob_result.gl_pathv[i]+regm[4].rm_so);
            kd.flags = atoi(glob_result.gl_pathv[i]+regm[2].rm_so);
            ifstream ifs(glob_result.gl_pathv[i]);
            ostringstream content;
            char buffer[1024];
            while(ifs.good()) {
              ifs.read(buffer, sizeof buffer);
              if (ifs.gcount()>0) {
                content << string(buffer, ifs.gcount());
              }
            }
            ifs.close();
            kd.content = content.str();
            keys.push_back(kd);
          }
        }
      }
      regfree(&reg);
      globfree(&glob_result);
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::removeDomainKey(const DNSName& name, unsigned int id) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  ostringstream path;

  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (dom.domain == name) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "*.key";
      glob_t glob_result;
      if (glob(pathname.str().c_str(),GLOB_ERR,NULL,&glob_result) == 0) {
        for(size_t i=0;i<glob_result.gl_pathc;i++) {
          if (regexec(&reg, glob_result.gl_pathv[i], 5, regm, 0) == 0) {
            unsigned int kid = atoi(glob_result.gl_pathv[i]+regm[3].rm_so);
            if (kid == id) {
              if (unlink(glob_result.gl_pathv[i])) {
                cerr << "Cannot delete key:" << strerror(errno) << endl;
              }
              break;
            }
          }
        }
      }
      regfree(&reg);
      globfree(&glob_result);
      return true;
    }
  }
  return false;
}

int GeoIPBackend::addDomainKey(const DNSName& name, const KeyData& key) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  int nextid=1;

  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (dom.domain == name) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "*.key";
      glob_t glob_result;
      if (glob(pathname.str().c_str(),GLOB_ERR,NULL,&glob_result) == 0) {
        for(size_t i=0;i<glob_result.gl_pathc;i++) {
          if (regexec(&reg, glob_result.gl_pathv[i], 5, regm, 0) == 0) {
            int kid = atoi(glob_result.gl_pathv[i]+regm[3].rm_so);
            if (kid >= nextid) nextid = kid+1;
          }
        }
      }
      regfree(&reg);
      globfree(&glob_result);
      pathname.str("");
      pathname << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "." << key.flags << "." << nextid << "." << (key.active?"1":"0") << ".key";
      ofstream ofs(pathname.str().c_str());
      ofs.write(key.content.c_str(), key.content.size());
      ofs.close();
      return nextid;
    }
  }
  return false;

}

bool GeoIPBackend::activateDomainKey(const DNSName& name, unsigned int id) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (dom.domain == name) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "*.key";
      glob_t glob_result;
      if (glob(pathname.str().c_str(),GLOB_ERR,NULL,&glob_result) == 0) {
        for(size_t i=0;i<glob_result.gl_pathc;i++) {
          if (regexec(&reg, glob_result.gl_pathv[i], 5, regm, 0) == 0) {
            unsigned int kid = atoi(glob_result.gl_pathv[i]+regm[3].rm_so);
            if (kid == id && atoi(glob_result.gl_pathv[i]+regm[4].rm_so) == 0) {
              ostringstream newpath; 
              newpath << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "." << atoi(glob_result.gl_pathv[i]+regm[2].rm_so) << "." << kid << ".1.key";
              if (rename(glob_result.gl_pathv[i], newpath.str().c_str())) {
                cerr << "Cannot active key: " << strerror(errno) << endl;
              }
            }
          }
        }
      }
      globfree(&glob_result);
      regfree(&reg); 
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::deactivateDomainKey(const DNSName& name, unsigned int id) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (dom.domain == name) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "*.key";
      glob_t glob_result;
      if (glob(pathname.str().c_str(),GLOB_ERR,NULL,&glob_result) == 0) {
        for(size_t i=0;i<glob_result.gl_pathc;i++) {
          if (regexec(&reg, glob_result.gl_pathv[i], 5, regm, 0) == 0) {
            unsigned int kid = atoi(glob_result.gl_pathv[i]+regm[3].rm_so);
            if (kid == id && atoi(glob_result.gl_pathv[i]+regm[4].rm_so) == 1) {
              ostringstream newpath;
              newpath << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "." << atoi(glob_result.gl_pathv[i]+regm[2].rm_so) << "." << kid << ".0.key";
              if (rename(glob_result.gl_pathv[i], newpath.str().c_str())) {
                cerr << "Cannot deactive key: " << strerror(errno) << endl;
              }
            }
          }
        }
      }
      globfree(&glob_result);
      regfree(&reg);
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::hasDNSSECkey(const DNSName& name) {
  ostringstream pathname;
  pathname << getArg("dnssec-keydir") << "/" << name.toStringNoDot() << "*.key";
  glob_t glob_result;
  if (glob(pathname.str().c_str(),GLOB_ERR,NULL,&glob_result) == 0) {
    globfree(&glob_result);
    return true;
  }
  return false;
}

class GeoIPFactory : public BackendFactory{
public:
  GeoIPFactory() : BackendFactory("geoip") {}

  void declareArguments(const string &suffix = "") {
    declare(suffix, "zones-file", "YAML file to load zone(s) configuration", "");
    declare(suffix, "database-file6", "File to load IPv6 geoip data from", "/usr/share/GeoIP/GeoIPv6.dat");
    declare(suffix, "database-file", "File to load IPv4 geoip data from", "/usr/share/GeoIP/GeoIP.dat");
    declare(suffix, "database-cache", "Cache mode (standard, memory, index, mmap)", "standard");
    declare(suffix, "dnssec-keydir", "Directory to hold dnssec keys (also turns DNSSEC on)", "");
  }

  DNSBackend *make(const string &suffix) {
    return new GeoIPBackend(suffix);
  }
};

class GeoIPLoader {
public:
  GeoIPLoader() {
    BackendMakers().report(new GeoIPFactory);
    L << Logger::Info << "[geobackend] This is the geo backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};

static GeoIPLoader geoloader;
