#include "geoipbackend.hh"
#include <sstream>
#include <regex.h>
#include <glob.h>

pthread_rwlock_t GeoIPBackend::s_state_lock=PTHREAD_RWLOCK_INITIALIZER;

class GeoIPDomain {
public:
  int id;
  string domain;
  int ttl;
  map<string, string> services;
  map<string, vector<DNSResourceRecord> > records;
};

static vector<GeoIPDomain> s_domains;
static GeoIP *s_gi = 0; // geoip database
static GeoIP *s_gi6 = 0; // geoip database
static int s_rc = 0; // refcount

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
    dom.domain = domain["domain"].as<string>();
    std::transform(dom.domain.begin(), dom.domain.end(), dom.domain.begin(), dns_tolower);
    dom.ttl = domain["ttl"].as<int>();

    for(YAML::const_iterator recs = domain["records"].begin(); recs != domain["records"].end(); recs++) {
      string qname = recs->first.as<string>();
      std::transform(qname.begin(), qname.end(), qname.begin(), dns_tolower);
      vector<DNSResourceRecord> rrs;

      BOOST_FOREACH(YAML::Node item, recs->second) {
        YAML::const_iterator rec = item.begin();
        DNSResourceRecord rr;
        rr.domain_id = dom.id;
        rr.ttl = dom.ttl;
        rr.qname = qname;
        if (rec->first.IsNull()) {
          rr.qtype = "NULL";
        } else {
          string qtype = boost::to_upper_copy(rec->first.as<string>());
          rr.qtype = qtype;
        }
        if (rec->second.IsNull()) {
          rr.content = "";
        } else {
          string content=rec->second.as<string>();
          if (rr.qtype == QType::MX || rr.qtype == QType::SRV) {
            // extract priority
            rr.priority=atoi(content.c_str());
            string::size_type pos = content.find_first_not_of("0123456789");
            if(pos != string::npos)
               boost::erase_head(content, pos);
            trim_left(content);
          }
          rr.content = content;
        } 
                
        rr.auth = 1;
        rr.d_place = DNSResourceRecord::ANSWER;
        rrs.push_back(rr);
      }
      std::swap(dom.records[qname], rrs);
    }

    for(YAML::const_iterator service = domain["services"].begin(); service != domain["services"].end(); service++) {
      dom.services[service->first.as<string>()] = service->second.as<string>();
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

void GeoIPBackend::lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p, int zoneId) {
  ReadLock rl(&s_state_lock);
  GeoIPDomain dom;
  bool found = false;

  //cerr << qtype.getName() << " " << qdomain << " " << zoneId << std::endl;

  if (d_result.size()>0) 
    throw PDNSException("Cannot perform lookup while another is running");

  string search = qdomain;
  std::transform(search.begin(), search.end(), search.begin(), dns_tolower);

  d_result.clear();

  if (zoneId > -1 && zoneId < static_cast<int>(s_domains.size())) 
    dom = s_domains[zoneId];
  else {
    BOOST_FOREACH(GeoIPDomain i, s_domains) {
      if (endsOn(search, dom.domain)) {
        dom = i; 
        found = true;
        break;
      }
    }
    if (!found) return; // not found
  }

  if (dom.records.count(search)) { // return static value
    map<string, vector<DNSResourceRecord> >::iterator i = dom.records.find(search);
    BOOST_FOREACH(DNSResourceRecord rr, i->second) {
      if (qtype == QType::ANY || rr.qtype == qtype) {
        d_result.push_back(rr);
        d_result.back().qname = qdomain;
      }
    }
    return;
  }

  if (!(qtype == QType::ANY || qtype == QType::CNAME)) return;

  string ip = "0.0.0.0";
  bool v6 = false;
  if (pkt_p != NULL) {
    ip = pkt_p->getRealRemote().toStringNoMask();
    v6 = pkt_p->getRealRemote().isIpv6();
  }

  if (dom.services.count(search) == 0) return; // no hit
  map<string, string>::const_iterator target = dom.services.find(search);
  string format = target->second;
  
  format = format2str(format, ip, v6);

  DNSResourceRecord rr;
  rr.domain_id = dom.id;
  rr.qtype = QType::CNAME;
  rr.qname = qdomain;
  rr.content = format;
  rr.auth = 1;
  rr.ttl = dom.ttl;
  rr.scopeMask = (v6 ? 128 : 32);
  d_result.push_back(rr);
}

bool GeoIPBackend::get(DNSResourceRecord &r) {
  if (d_result.empty()) return false;

  r = d_result.back();
  d_result.pop_back();

  //cerr << "get " << r.qname << " IN " << r.qtype.getName() << " " << r.content << endl;

  return true;
}

string GeoIPBackend::queryGeoIP(const string &ip, bool v6, GeoIPQueryAttribute attribute) {
  string ret = "unknown";
  const char *val = NULL;
  GeoIPRegion *gir = NULL;
  GeoIPRecord *gir2 = NULL;
  int id;


  if (v6 && s_gi6) {
    if (attribute == Afi) {
      return "v6";
    } else if (d_dbmode == GEOIP_ISP_EDITION_V6 || d_dbmode == GEOIP_ORG_EDITION_V6) {
      if (attribute == Name) {
        val = GeoIP_name_by_addr_v6(s_gi6, ip.c_str());
      }
    } else if (d_dbmode == GEOIP_COUNTRY_EDITION_V6 ||
        d_dbmode == GEOIP_LARGE_COUNTRY_EDITION_V6 ||
        d_dbmode == GEOIP_COUNTRY_EDITION) {
      id = GeoIP_id_by_addr_v6(s_gi6, ip.c_str());
      if (attribute == Country) {
        val = GeoIP_code3_by_id(id);
      } else if (attribute == Continent) {
        val = GeoIP_continent_by_id(id);
      }
    } else if (d_dbmode == GEOIP_REGION_EDITION_REV0 ||
        d_dbmode == GEOIP_REGION_EDITION_REV1) {
      gir = GeoIP_region_by_addr_v6(s_gi6, ip.c_str());
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
      }
    }
  } else if (!v6 && s_gi) {
    if (attribute == Afi) {
      return "v4";
    } else if (d_dbmode == GEOIP_ISP_EDITION || d_dbmode == GEOIP_ORG_EDITION) {
      if (attribute == Name) {
        val = GeoIP_name_by_addr_v6(s_gi, ip.c_str());
      }
    } else if (d_dbmode == GEOIP_COUNTRY_EDITION ||
        d_dbmode == GEOIP_LARGE_COUNTRY_EDITION) {
      id = GeoIP_id_by_addr(s_gi, ip.c_str());
      if (attribute == Country) {
        val = GeoIP_code3_by_id(id);
      } else if (attribute == Continent) {
        val = GeoIP_continent_by_id(id);
      }
    } else if (d_dbmode == GEOIP_REGION_EDITION_REV0 ||
        d_dbmode == GEOIP_REGION_EDITION_REV1) {
      gir = GeoIP_region_by_addr(s_gi, ip.c_str());
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

string GeoIPBackend::format2str(string format, const string& ip, bool v6) {
  string::size_type cur,last;
  GeoIPQueryAttribute attr;
  last=0;
  while((cur = format.find("%", last)) != string::npos) {
    if (!format.compare(cur,3,"%co")) {
      attr = Country;
    } else if (!format.compare(cur,3,"%cn")) {
      attr = Continent;
    } else if (!format.compare(cur,3,"%af")) {
      attr = Afi;
    } else if (!format.compare(cur,3,"%re")) {
      attr = Region;
    } else if (!format.compare(cur,3,"%na")) {
      attr = Name;
    } else if (!format.compare(cur,3,"%ci")) {
      attr = City;
    } else if (!format.compare(cur,2,"%%")) {
      last = cur + 2; continue; 
    } else { 
      last = cur + 1; continue; 
    }

    string rep = queryGeoIP(ip, v6, attr);

    format.replace(cur, 3, rep);
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

bool GeoIPBackend::getDomainInfo(const string &domain, DomainInfo &di) {
  ReadLock rl(&s_state_lock);
  cerr << "looking for " << domain << endl;

  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (pdns_iequals(dom.domain, domain)) {
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

bool GeoIPBackend::getAllDomainMetadata(const string& name, std::map<std::string, std::vector<std::string> >& meta) {
  if (!d_dnssec) return false;

  ReadLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (pdns_iequals(dom.domain, name)) {
      if (hasDNSSECkey(dom.domain)) {
        meta[string("NSEC3NARROW")].push_back("1");
        meta[string("NSEC3PARAM")].push_back("1 0 1 f95a");
      }
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::getDomainMetadata(const std::string& name, const std::string& kind, std::vector<std::string>& meta) {
  if (!d_dnssec) return false;

  ReadLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (pdns_iequals(dom.domain, name)) {
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

bool GeoIPBackend::getDomainKeys(const std::string& name, unsigned int kind, std::vector<DNSBackend::KeyData>& keys) {
  if (!d_dnssec) return false;
  ReadLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (pdns_iequals(dom.domain, name)) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain << "*.key";
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

bool GeoIPBackend::removeDomainKey(const string& name, unsigned int id) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  ostringstream path;

  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (pdns_iequals(dom.domain, name)) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain << "*.key";
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

int GeoIPBackend::addDomainKey(const string& name, const KeyData& key) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  int nextid=1;

  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (pdns_iequals(dom.domain, name)) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain << "*.key";
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
      pathname << getArg("dnssec-keydir") << "/" << dom.domain << "." << key.flags << "." << nextid << "." << (key.active?"1":"0") << ".key";
      ofstream ofs(pathname.str().c_str());
      ofs.write(key.content.c_str(), key.content.size());
      ofs.close();
      return nextid;
    }
  }
  return false;

}

bool GeoIPBackend::activateDomainKey(const string& name, unsigned int id) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (pdns_iequals(dom.domain, name)) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain << "*.key";
      glob_t glob_result;
      if (glob(pathname.str().c_str(),GLOB_ERR,NULL,&glob_result) == 0) {
        for(size_t i=0;i<glob_result.gl_pathc;i++) {
          if (regexec(&reg, glob_result.gl_pathv[i], 5, regm, 0) == 0) {
            unsigned int kid = atoi(glob_result.gl_pathv[i]+regm[3].rm_so);
            if (kid == id && atoi(glob_result.gl_pathv[i]+regm[4].rm_so) == 0) {
              ostringstream newpath; 
              newpath << getArg("dnssec-keydir") << "/" << dom.domain << "." << atoi(glob_result.gl_pathv[i]+regm[2].rm_so) << "." << kid << ".1.key";
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

bool GeoIPBackend::deactivateDomainKey(const string& name, unsigned int id) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  BOOST_FOREACH(GeoIPDomain dom, s_domains) {
    if (pdns_iequals(dom.domain, name)) {
      regex_t reg;
      regmatch_t regm[5];
      regcomp(&reg, "(.*)[.]([0-9]+)[.]([0-9]+)[.]([01])[.]key$", REG_ICASE|REG_EXTENDED);
      ostringstream pathname;
      pathname << getArg("dnssec-keydir") << "/" << dom.domain << "*.key";
      glob_t glob_result;
      if (glob(pathname.str().c_str(),GLOB_ERR,NULL,&glob_result) == 0) {
        for(size_t i=0;i<glob_result.gl_pathc;i++) {
          if (regexec(&reg, glob_result.gl_pathv[i], 5, regm, 0) == 0) {
            unsigned int kid = atoi(glob_result.gl_pathv[i]+regm[3].rm_so);
            if (kid == id && atoi(glob_result.gl_pathv[i]+regm[4].rm_so) == 1) {
              ostringstream newpath;
              newpath << getArg("dnssec-keydir") << "/" << dom.domain << "." << atoi(glob_result.gl_pathv[i]+regm[2].rm_so) << "." << kid << ".0.key";
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

bool GeoIPBackend::hasDNSSECkey(const string& name) {
  ostringstream pathname;
  pathname << getArg("dnssec-keydir") << "/" << name << "*.key";
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
    L << Logger::Info << "[geobackend] This is the geo backend version " VERSION " reporting" << endl;
  }
};

static GeoIPLoader geoloader;
