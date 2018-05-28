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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "geoipbackend.hh"
#include "pdns/dns_random.hh"
#include <sstream>
#include <regex.h>
#include <glob.h>
#include <boost/algorithm/string/replace.hpp>

pthread_rwlock_t GeoIPBackend::s_state_lock=PTHREAD_RWLOCK_INITIALIZER;

struct GeoIPDNSResourceRecord: DNSResourceRecord {
  int weight;
  bool has_weight;
};

struct GeoIPService {
  NetmaskTree<vector<string> > masks;
  unsigned int netmask4;
  unsigned int netmask6;
};

struct GeoIPDomain {
  int id;
  DNSName domain;
  int ttl;
  map<DNSName, GeoIPService> services;
  map<DNSName, vector<GeoIPDNSResourceRecord> > records;
};

static vector<GeoIPDomain> s_domains;
static int s_rc = 0; // refcount

struct geoip_deleter {
  void operator()(GeoIP* ptr) {
    if (ptr) GeoIP_delete(ptr);
  };
};

static vector<GeoIPBackend::geoip_file_t> s_geoip_files;

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
  s_rc++;
}

void GeoIPBackend::initialize() {
  YAML::Node config;
  vector<GeoIPDomain> tmp_domains;

  string modeStr = getArg("database-cache");
  int flags;
  if (modeStr == "standard")
    flags = GEOIP_STANDARD;
  else if (modeStr == "memory")
    flags = GEOIP_MEMORY_CACHE;
  else if (modeStr == "index")
    flags = GEOIP_INDEX_CACHE;
#ifdef HAVE_MMAP
  else if (modeStr == "mmap")
    flags = GEOIP_MMAP_CACHE;
#endif
  else
    throw PDNSException("Invalid cache mode " + modeStr + " for GeoIP backend");

  s_geoip_files.clear(); // reset pointers

  if (getArg("database-files").empty() == false) {
    vector<string> files;
    stringtok(files, getArg("database-files"), " ,\t\r\n");
    for(auto const& file: files) {
      GeoIP *fptr;
      int mode;
      fptr = GeoIP_open(file.c_str(), flags);
      if (!fptr)
        throw PDNSException("Cannot open GeoIP database " + file);
      mode = GeoIP_database_edition(fptr);
      s_geoip_files.emplace_back(geoip_file_t(mode, unique_ptr<GeoIP,geoip_deleter>(fptr)));
    }
  }

  if (s_geoip_files.empty())
    L<<Logger::Warning<<"No GeoIP database files loaded!"<<endl;

  config = YAML::LoadFile(getArg("zones-file"));

  for(YAML::Node domain :  config["domains"]) {
    GeoIPDomain dom;
    dom.id = tmp_domains.size();
    dom.domain = DNSName(domain["domain"].as<string>());
    dom.ttl = domain["ttl"].as<int>();

    for(YAML::const_iterator recs = domain["records"].begin(); recs != domain["records"].end(); recs++) {
      DNSName qname = DNSName(recs->first.as<string>());
      vector<GeoIPDNSResourceRecord> rrs;

      for(YAML::Node item :  recs->second) {
        YAML::const_iterator rec = item.begin();
        GeoIPDNSResourceRecord rr;
        rr.domain_id = dom.id;
        rr.ttl = dom.ttl;
        rr.qname = qname;
        if (rec->first.IsNull()) { 
          rr.qtype = QType(0);
        } else {
          string qtype = boost::to_upper_copy(rec->first.as<string>());
          rr.qtype = qtype;
        }
        rr.has_weight = false;
        rr.weight = 100;
        if (rec->second.IsNull()) {
          rr.content = "";
        } else if (rec->second.IsMap()) {
           for(YAML::const_iterator iter = rec->second.begin(); iter != rec->second.end(); iter++) {
             string attr = iter->first.as<string>();
             if (attr == "content") {
	       string content = iter->second.as<string>();
               rr.content = content;
             } else if (attr == "weight") {
               rr.weight = iter->second.as<int>();
               if (rr.weight < 0) {
                 L<<Logger::Error<<"Weight cannot be negative for " << rr.qname << endl;
                 throw PDNSException(string("Weight cannot be negative for ") + rr.qname.toLogString());
               }
               rr.has_weight = true;
             } else if (attr == "ttl") {
               rr.ttl = iter->second.as<int>();
             } else {
               L<<Logger::Error<<"Unsupported record attribute " << attr << " for " << rr.qname << endl;
               throw PDNSException(string("Unsupported record attribute ") + attr + string(" for ") + rr.qname.toLogString());
             }
           }
	} else {
          string content=rec->second.as<string>();
          rr.content = content;
          rr.weight = 100;
        } 
        rr.auth = 1;
        rrs.push_back(rr);
      }
      std::swap(dom.records[qname], rrs);
    }

    for(YAML::const_iterator service = domain["services"].begin(); service != domain["services"].end(); service++) {
      unsigned int netmask4 = 0, netmask6 = 0;
      DNSName srvName{service->first.as<string>()};
      NetmaskTree<vector<string> > nmt;

      // if it's an another map, we need to iterate it again, otherwise we just add two root entries.
      if (service->second.IsMap()) {
        for(YAML::const_iterator net = service->second.begin(); net != service->second.end(); net++) {
          vector<string> value;
          if (net->second.IsSequence()) {
            value = net->second.as<vector<string> >();
          } else {
            value.push_back(net->second.as<string>());
          }
          if (net->first.as<string>() == "default") {
            nmt.insert(Netmask("0.0.0.0/0")).second.assign(value.begin(),value.end());
            nmt.insert(Netmask("::/0")).second.swap(value);
          } else {
            Netmask nm{net->first.as<string>()};
            nmt.insert(nm).second.swap(value);
            if (nm.isIpv6() == true && netmask6 < nm.getBits())
              netmask6 = nm.getBits();
            if (nm.isIpv6() == false && netmask4 < nm.getBits())
              netmask4 = nm.getBits();
          }
        }
      } else {
        vector<string> value;
        if (service->second.IsSequence()) {
          value = service->second.as<vector<string> >();
        } else {
          value.push_back(service->second.as<string>());
        }
        nmt.insert(Netmask("0.0.0.0/0")).second.assign(value.begin(),value.end());
        nmt.insert(Netmask("::/0")).second.swap(value);
      }

      dom.services[srvName].netmask4 = netmask4;
      dom.services[srvName].netmask6 = netmask6;
      dom.services[srvName].masks.swap(nmt);
    }

    // rectify the zone, first static records
    for(auto &item : dom.records) {
      // ensure we have parent in records
      DNSName name = item.first;
      while(name.chopOff() && name.isPartOf(dom.domain)) {
        if (dom.records.find(name) == dom.records.end() && !dom.services.count(name)) { // don't ENT out a service!
          GeoIPDNSResourceRecord rr;
          vector<GeoIPDNSResourceRecord> rrs;
          rr.domain_id = dom.id;
          rr.ttl = dom.ttl;
          rr.qname = name;
          rr.qtype = QType(0); // empty non terminal
          rr.content = "";
          rr.auth = 1;
          rr.weight = 100;
          rr.has_weight = false;
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
          GeoIPDNSResourceRecord rr;
          vector<GeoIPDNSResourceRecord> rrs;
          rr.domain_id = dom.id;
          rr.ttl = dom.ttl;
          rr.qname = name;
          rr.qtype = QType(0);
          rr.content = "";
          rr.auth = 1;
          rr.weight = 100;
          rr.has_weight = false;
          rrs.push_back(rr);
          std::swap(dom.records[name], rrs);
        }
      }
    }

    // finally fix weights
    for(auto &item: dom.records) {
      float weight=0;
      float sum=0;
      bool has_weight=false;
      // first we look for used weight
      for(const auto &rr: item.second) {
        weight+=rr.weight;
        if (rr.has_weight) has_weight = true;
      }
      if (has_weight) {
        // put them back as probabilities and values..
        for(auto &rr: item.second) {
          rr.weight=static_cast<int>((static_cast<float>(rr.weight) / weight)*1000.0);
          sum += rr.weight;
          rr.has_weight = has_weight;
        }
        // remove rounding gap
        if (sum < 1000)
          item.second.back().weight += (1000-sum);
      }
    }

    tmp_domains.push_back(std::move(dom));
  }

  s_domains.clear();
  std::swap(s_domains, tmp_domains);
}

GeoIPBackend::~GeoIPBackend() {
  try {
    WriteLock wl(&s_state_lock);
    s_rc--;
    if (s_rc == 0) { // last instance gets to cleanup
      s_geoip_files.clear();
      s_domains.clear();
    }
  }
  catch(...) {
  }
}

bool GeoIPBackend::lookup_static(const GeoIPDomain &dom, const DNSName &search, const QType &qtype, const DNSName& qdomain, const std::string &ip, GeoIPLookup &gl, bool v6) {
  const auto& i = dom.records.find(search);
  int cumul_probability = 0;
  int probability_rnd = 1+(dns_random(1000)); // setting probability=0 means it never is used

  if (i != dom.records.end()) { // return static value
    for(const auto& rr : i->second) {
      if (rr.has_weight) {
        gl.netmask = (v6?128:32);
        int comp = cumul_probability;
        cumul_probability += rr.weight;
        if (rr.weight == 0 || probability_rnd < comp || probability_rnd > (comp + rr.weight))
          continue;
      }
      if (qtype == QType::ANY || rr.qtype == qtype) {
        d_result.push_back(rr);
        d_result.back().content = format2str(rr.content, ip, v6, &gl);
        d_result.back().qname = qdomain;
      }
    }
    // ensure we get most strict netmask
    for(DNSResourceRecord& rr: d_result) {
      rr.scopeMask = gl.netmask;
    }
    return true; // no need to go further
  }

  return false;
};

void GeoIPBackend::lookup(const QType &qtype, const DNSName& qdomain, DNSPacket *pkt_p, int zoneId) {
  ReadLock rl(&s_state_lock);
  const GeoIPDomain *dom;
  GeoIPLookup gl;
  bool found = false;

  if (d_result.size()>0) 
    throw PDNSException("Cannot perform lookup while another is running");

  d_result.clear();

  if (zoneId > -1 && zoneId < static_cast<int>(s_domains.size())) 
    dom = &(s_domains[zoneId]);
  else {
    for(const GeoIPDomain& i : s_domains) {   // this is arguably wrong, we should probably find the most specific match
      if (qdomain.isPartOf(i.domain)) {
        dom = &i;
        found = true;
        break;
      }
    }
    if (!found) return; // not found
  }

  string ip = "0.0.0.0";
  bool v6 = false;
  if (pkt_p != NULL) {
    ip = pkt_p->getRealRemote().toStringNoMask();
    v6 = pkt_p->getRealRemote().isIpv6();
  }

  gl.netmask = 0;

  (void)this->lookup_static(*dom, qdomain, qtype, qdomain, ip, gl, v6);

  const auto& target = (*dom).services.find(qdomain);
  if (target == (*dom).services.end()) return; // no hit

  const NetmaskTree<vector<string> >::node_type* node = target->second.masks.lookup(ComboAddress(ip));
  if (node == NULL) return; // no hit, again.

  DNSName sformat;
  gl.netmask = node->first.getBits();
  // figure out smallest sensible netmask
  if (gl.netmask == 0) {
    GeoIPLookup tmp_gl;
    tmp_gl.netmask = 0;
    // get netmask from geoip backend
    if (queryGeoIP(ip, v6, GeoIPQueryAttribute::Name, &tmp_gl) == "unknown") {
      if (v6)
        gl.netmask = target->second.netmask6;
      else
        gl.netmask = target->second.netmask4;
    }
  } else {
    if (v6)
      gl.netmask = target->second.netmask6;
    else
      gl.netmask = target->second.netmask4;
  }

  // note that this means the array format won't work with indirect
  for(auto it = node->second.begin(); it != node->second.end(); it++) {
    sformat = DNSName(format2str(*it, ip, v6, &gl));

    // see if the record can be found
    if (this->lookup_static((*dom), sformat, qtype, qdomain, ip, gl, v6))
      return;
  }

  if (!d_result.empty()) {
    L<<Logger::Error<<
       "Cannot have static record and CNAME at the same time" <<
       "Please fix your configuration for \"" << qdomain << "\", so that" <<
       "it can be resolved by GeoIP backend directly."<< std::endl;
    d_result.clear();
    return;
  }

  // we need this line since we otherwise claim to have NS records etc
  if (!(qtype == QType::ANY || qtype == QType::CNAME)) return;

  DNSResourceRecord rr;
  rr.domain_id = dom->id;
  rr.qtype = QType::CNAME;
  rr.qname = qdomain;
  rr.content = sformat.toString();
  rr.auth = 1;
  rr.ttl = dom->ttl;
  rr.scopeMask = gl.netmask;
  d_result.push_back(rr);
}

bool GeoIPBackend::get(DNSResourceRecord &r) {
  if (d_result.empty()) return false;

  r = d_result.back();
  d_result.pop_back();

  return true;
}

bool GeoIPBackend::queryCountry(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_COUNTRY_EDITION ||
      gi.first == GEOIP_LARGE_COUNTRY_EDITION) {
    int id;
    if ((id = GeoIP_id_by_addr_gl(gi.second.get(), ip.c_str(), gl)) > 0) {
      ret = GeoIP_code3_by_id(id);
      return true;
    }
  } else if (gi.first == GEOIP_REGION_EDITION_REV0 ||
             gi.first == GEOIP_REGION_EDITION_REV1) {
    GeoIPRegion* gir = GeoIP_region_by_addr_gl(gi.second.get(), ip.c_str(), gl);
    if (gir) {
      ret = GeoIP_code3_by_id(GeoIP_id_by_code(gir->country_code));
      return true;
    }
  } else if (gi.first == GEOIP_CITY_EDITION_REV0 ||
             gi.first == GEOIP_CITY_EDITION_REV1) {
    GeoIPRecord *gir = GeoIP_record_by_addr(gi.second.get(), ip.c_str());
    if (gir) {
      ret = gir->country_code3;
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryCountryV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_COUNTRY_EDITION_V6 ||
      gi.first == GEOIP_LARGE_COUNTRY_EDITION_V6) {
    int id;
    if ((id = GeoIP_id_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl)) > 0) {
      ret = GeoIP_code3_by_id(id);
      return true;
    }
  } else if (gi.first == GEOIP_REGION_EDITION_REV0 ||
             gi.first == GEOIP_REGION_EDITION_REV1) {
    GeoIPRegion* gir = GeoIP_region_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl);
    if (gir) {
      ret = GeoIP_code3_by_id(GeoIP_id_by_code(gir->country_code));
      return true;
    }
  } else if (gi.first == GEOIP_CITY_EDITION_REV0_V6 ||
             gi.first == GEOIP_CITY_EDITION_REV1_V6) {
    GeoIPRecord *gir = GeoIP_record_by_addr_v6(gi.second.get(), ip.c_str());
    if (gir) {
      ret = gir->country_code3;
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryCountry2(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_COUNTRY_EDITION ||
      gi.first == GEOIP_LARGE_COUNTRY_EDITION) {
    int id;
    if ((id = GeoIP_id_by_addr_gl(gi.second.get(), ip.c_str(), gl)) > 0) {
      ret = GeoIP_code_by_id(id);
      return true;
    }
  } else if (gi.first == GEOIP_REGION_EDITION_REV0 ||
             gi.first == GEOIP_REGION_EDITION_REV1) {
    GeoIPRegion* gir = GeoIP_region_by_addr_gl(gi.second.get(), ip.c_str(), gl);
    if (gir) {
      ret = GeoIP_code_by_id(GeoIP_id_by_code(gir->country_code));
      return true;
    }
  } else if (gi.first == GEOIP_CITY_EDITION_REV0 ||
             gi.first == GEOIP_CITY_EDITION_REV1) {
    GeoIPRecord *gir = GeoIP_record_by_addr(gi.second.get(), ip.c_str());
    if (gir) {
      ret = gir->country_code;
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryCountry2V6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_COUNTRY_EDITION_V6 ||
      gi.first == GEOIP_LARGE_COUNTRY_EDITION_V6) {
    int id;
    if ((id = GeoIP_id_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl)) > 0) {
      ret = GeoIP_code_by_id(id);
      return true;
    }
    return true;
  } else if (gi.first == GEOIP_REGION_EDITION_REV0 ||
             gi.first == GEOIP_REGION_EDITION_REV1) {
    GeoIPRegion* gir = GeoIP_region_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl);
    if (gir) {
      ret = GeoIP_code_by_id(GeoIP_id_by_code(gir->country_code));
      return true;
    }
  } else if (gi.first == GEOIP_CITY_EDITION_REV0_V6 ||
             gi.first == GEOIP_CITY_EDITION_REV1_V6) {
    GeoIPRecord *gir = GeoIP_record_by_addr_v6(gi.second.get(), ip.c_str());
    if (gir) {
      ret = gir->country_code;
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryContinent(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_COUNTRY_EDITION ||
      gi.first == GEOIP_LARGE_COUNTRY_EDITION) {
    int id;
    if ((id = GeoIP_id_by_addr_gl(gi.second.get(), ip.c_str(), gl)) > 0) {
      ret = GeoIP_continent_by_id(id);
      return true;
    }
  } else if (gi.first == GEOIP_REGION_EDITION_REV0 ||
             gi.first == GEOIP_REGION_EDITION_REV1) {
    GeoIPRegion* gir = GeoIP_region_by_addr_gl(gi.second.get(), ip.c_str(), gl);
    if (gir) {
      ret = GeoIP_continent_by_id(GeoIP_id_by_code(gir->country_code));
      return true;
    }
  } else if (gi.first == GEOIP_CITY_EDITION_REV0 ||
             gi.first == GEOIP_CITY_EDITION_REV1) {
    GeoIPRecord *gir = GeoIP_record_by_addr(gi.second.get(), ip.c_str());
    if (gir) {
      ret =  ret = GeoIP_continent_by_id(GeoIP_id_by_code(gir->country_code));
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryContinentV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_COUNTRY_EDITION_V6 ||
      gi.first == GEOIP_LARGE_COUNTRY_EDITION_V6) {
    int id;
    if ((id = GeoIP_id_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl)) > 0) {
      ret = GeoIP_continent_by_id(id);
      return true;
    }
  } else if (gi.first == GEOIP_REGION_EDITION_REV0 ||
             gi.first == GEOIP_REGION_EDITION_REV1) {
    GeoIPRegion* gir = GeoIP_region_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl);
    if (gir) {
      ret = GeoIP_continent_by_id(GeoIP_id_by_code(gir->country_code));
      return true;
    }
  } else if (gi.first == GEOIP_CITY_EDITION_REV0_V6 ||
             gi.first == GEOIP_CITY_EDITION_REV1_V6) {
    GeoIPRecord *gir = GeoIP_record_by_addr_v6(gi.second.get(), ip.c_str());
    if (gir) {
      ret = GeoIP_continent_by_id(GeoIP_id_by_code(gir->country_code));
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryName(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_ISP_EDITION ||
      gi.first == GEOIP_ORG_EDITION) {
    string val = valueOrEmpty<char*,string>(GeoIP_name_by_addr_gl(gi.second.get(), ip.c_str(), gl));
    if (!val.empty()) {
      // reduce space to dash
      ret = boost::replace_all_copy(val, " ", "-");
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryNameV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_ISP_EDITION_V6 ||
      gi.first == GEOIP_ORG_EDITION_V6) {
    string val = valueOrEmpty<char*,string>(GeoIP_name_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl));
    if (!val.empty()) {
      // reduce space to dash
      ret = boost::replace_all_copy(val, " ", "-");
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryASnum(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_ASNUM_EDITION) {
    string val = valueOrEmpty<char*,string>(GeoIP_name_by_addr_gl(gi.second.get(), ip.c_str(), gl));
    if (!val.empty()) {
      vector<string> asnr;
      stringtok(asnr, val);
      if(asnr.size()>0) {
        ret = asnr[0];
        return true;
      }
    }
  }
  return false;
}

bool GeoIPBackend::queryASnumV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_ASNUM_EDITION_V6) {
    string val = valueOrEmpty<char*,string>(GeoIP_name_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl));
    if (!val.empty()) {
      vector<string> asnr;
      stringtok(asnr, val);
      if(asnr.size()>0) {
        ret = asnr[0];
        return true;
      }
    }
  }
  return false;
}

bool GeoIPBackend::queryRegion(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_REGION_EDITION_REV0 ||
      gi.first == GEOIP_REGION_EDITION_REV1) {
    GeoIPRegion *gir = GeoIP_region_by_addr_gl(gi.second.get(), ip.c_str(), gl);
    if (gir) {
      ret = valueOrEmpty<char*,string>(gir->region);
      return true;
    }
  } else if (gi.first == GEOIP_CITY_EDITION_REV0 ||
             gi.first == GEOIP_CITY_EDITION_REV1) {
    GeoIPRecord *gir = GeoIP_record_by_addr(gi.second.get(), ip.c_str());
    if (gir) {
      ret = valueOrEmpty<char*,string>(gir->region);
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryRegionV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_REGION_EDITION_REV0 ||
      gi.first == GEOIP_REGION_EDITION_REV1) {
    GeoIPRegion *gir = GeoIP_region_by_addr_v6_gl(gi.second.get(), ip.c_str(), gl);
    if (gir) {
      ret = valueOrEmpty<char*,string>(gir->region);
      return true;
    }
  } else if (gi.first == GEOIP_CITY_EDITION_REV0_V6 ||
             gi.first == GEOIP_CITY_EDITION_REV1_V6) {
    GeoIPRecord *gir = GeoIP_record_by_addr_v6(gi.second.get(), ip.c_str());
    if (gir) {
      ret = valueOrEmpty<char*,string>(gir->region);
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryCity(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_CITY_EDITION_REV0 ||
      gi.first == GEOIP_CITY_EDITION_REV1) {
    GeoIPRecord *gir = GeoIP_record_by_addr(gi.second.get(), ip.c_str());
    if (gir) {
      ret = valueOrEmpty<char*,string>(gir->city);
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}

bool GeoIPBackend::queryCityV6(string &ret, GeoIPLookup* gl, const string &ip, const geoip_file_t& gi) {
  if (gi.first == GEOIP_CITY_EDITION_REV0_V6 ||
      gi.first == GEOIP_CITY_EDITION_REV1_V6) {
    GeoIPRecord *gir = GeoIP_record_by_addr_v6(gi.second.get(), ip.c_str());
    if (gir) {
      ret = valueOrEmpty<char*,string>(gir->city);
      gl->netmask = gir->netmask;
      return true;
    }
  }
  return false;
}


string GeoIPBackend::queryGeoIP(const string &ip, bool v6, GeoIPQueryAttribute attribute, GeoIPLookup* gl) {
  string ret = "unknown";

  for(auto const& gi: s_geoip_files) {
    string val;
    bool found = false;

    switch(attribute) {
    case ASn:
      if (v6) found = queryASnumV6(val, gl, ip, gi);
      else found = queryASnum(val, gl, ip, gi);
      break;
    case Name:
      if (v6) found = queryNameV6(val, gl, ip, gi);
      else found = queryName(val, gl, ip, gi);
      break;
    case Continent:
      if (v6) found = queryContinentV6(val, gl, ip, gi);
      else found = queryContinent(val, gl, ip, gi);
      break;
    case Region:
      if (v6) found = queryRegionV6(val, gl, ip, gi);
      else found = queryRegion(val, gl, ip, gi);
      break;
    case Country:
      if (v6) found = queryCountryV6(val, gl, ip, gi);
      else found = queryCountry(val, gl, ip, gi);
      break;
    case Country2:
      if (v6) found = queryCountry2V6(val, gl, ip, gi);
      else found = queryCountry2(val, gl, ip, gi);
      break;
    case City:
      if (v6) found = queryCityV6(val, gl, ip, gi);
      else found = queryCity(val, gl, ip, gi);
      break;
    }

    if (!found || val.empty() || val == "--") continue; // try next database
    ret = val;
    std::transform(ret.begin(), ret.end(), ret.begin(), ::tolower);
    break;
  }

  if (ret == "unknown") gl->netmask = (v6?128:32); // prevent caching
  return ret;
}

string GeoIPBackend::format2str(string sformat, const string& ip, bool v6, GeoIPLookup* gl) {
  string::size_type cur,last;
  time_t t = time((time_t*)NULL);
  GeoIPLookup tmp_gl; // largest wins
  struct tm gtm;
  gmtime_r(&t, &gtm);
  last=0;

  while((cur = sformat.find("%", last)) != string::npos) {
    string rep;
    int nrep=3;
    tmp_gl.netmask = 0;
    if (!sformat.compare(cur,3,"%cn")) {
      rep = queryGeoIP(ip, v6, Continent, &tmp_gl);
    } else if (!sformat.compare(cur,3,"%co")) {
      rep = queryGeoIP(ip, v6, Country, &tmp_gl);
    } else if (!sformat.compare(cur,3,"%cc")) {
      rep = queryGeoIP(ip, v6, Country2, &tmp_gl);
    } else if (!sformat.compare(cur,3,"%af")) {
      rep = (v6?"v6":"v4");
    } else if (!sformat.compare(cur,3,"%as")) {
      rep = queryGeoIP(ip, v6, ASn, &tmp_gl);
    } else if (!sformat.compare(cur,3,"%re")) {
      rep = queryGeoIP(ip, v6, Region, &tmp_gl);
    } else if (!sformat.compare(cur,3,"%na")) {
      rep = queryGeoIP(ip, v6, Name, &tmp_gl);
    } else if (!sformat.compare(cur,3,"%ci")) {
      rep = queryGeoIP(ip, v6, City, &tmp_gl);
    } else if (!sformat.compare(cur,3,"%hh")) {
      rep = boost::str(boost::format("%02d") % gtm.tm_hour);
      tmp_gl.netmask = (v6?128:32);
    } else if (!sformat.compare(cur,3,"%yy")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_year + 1900));
      tmp_gl.netmask = (v6?128:32);
    } else if (!sformat.compare(cur,3,"%dd")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_yday + 1));
      tmp_gl.netmask = (v6?128:32);
    } else if (!sformat.compare(cur,4,"%wds")) {
      nrep=4;
      rep = GeoIP_WEEKDAYS[gtm.tm_wday];
      tmp_gl.netmask = (v6?128:32);
    } else if (!sformat.compare(cur,4,"%mos")) {
      nrep=4;
      rep = GeoIP_MONTHS[gtm.tm_mon];
      tmp_gl.netmask = (v6?128:32);
    } else if (!sformat.compare(cur,3,"%wd")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_wday + 1));
      tmp_gl.netmask = (v6?128:32);
    } else if (!sformat.compare(cur,3,"%mo")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_mon + 1));
      tmp_gl.netmask = (v6?128:32);
    } else if (!sformat.compare(cur,3,"%ip")) {
      rep = ip;
      tmp_gl.netmask = (v6?128:32);
    } else if (!sformat.compare(cur,2,"%%")) {
      last = cur + 2; continue;
    } else {
      last = cur + 1; continue; 
    }
    if (tmp_gl.netmask > gl->netmask) gl->netmask = tmp_gl.netmask;
    sformat.replace(cur, nrep, rep);
    last = cur + rep.size(); // move to next attribute
  }
  return sformat;
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

  for(GeoIPDomain dom :  s_domains) {
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
  for(GeoIPDomain dom :  s_domains) {
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
  for(GeoIPDomain dom :  s_domains) {
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

bool GeoIPBackend::getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys) {
  if (!d_dnssec) return false;
  ReadLock rl(&s_state_lock);
  for(GeoIPDomain dom :  s_domains) {
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
            kd.id = pdns_stou(glob_result.gl_pathv[i]+regm[3].rm_so);
            kd.active = !strncmp(glob_result.gl_pathv[i]+regm[4].rm_so, "1", 1);
            kd.flags = pdns_stou(glob_result.gl_pathv[i]+regm[2].rm_so);
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

  for(GeoIPDomain dom :  s_domains) {
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
            unsigned int kid = pdns_stou(glob_result.gl_pathv[i]+regm[3].rm_so);
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

bool GeoIPBackend::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  unsigned int nextid=1;

  for(GeoIPDomain dom :  s_domains) {
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
            unsigned int kid = pdns_stou(glob_result.gl_pathv[i]+regm[3].rm_so);
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
      id = nextid;
      return true;
    }
  }
  return false;

}

bool GeoIPBackend::activateDomainKey(const DNSName& name, unsigned int id) {
  if (!d_dnssec) return false;
  WriteLock rl(&s_state_lock);
  for(GeoIPDomain dom :  s_domains) {
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
            unsigned int kid = pdns_stou(glob_result.gl_pathv[i]+regm[3].rm_so);
            if (kid == id && !strcmp(glob_result.gl_pathv[i]+regm[4].rm_so,"0")) {
              ostringstream newpath; 
              newpath << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "." << pdns_stou(glob_result.gl_pathv[i]+regm[2].rm_so) << "." << kid << ".1.key";
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
  for(GeoIPDomain dom :  s_domains) {
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
            unsigned int kid = pdns_stou(glob_result.gl_pathv[i]+regm[3].rm_so);
            if (kid == id && !strcmp(glob_result.gl_pathv[i]+regm[4].rm_so,"1")) {
              ostringstream newpath;
              newpath << getArg("dnssec-keydir") << "/" << dom.domain.toStringNoDot() << "." << pdns_stou(glob_result.gl_pathv[i]+regm[2].rm_so) << "." << kid << ".0.key";
              if (rename(glob_result.gl_pathv[i], newpath.str().c_str())) {
                cerr << "Cannot deactivate key: " << strerror(errno) << endl;
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
    declare(suffix, "database-files", "File(s) to load geoip data from", "");
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
    L << Logger::Info << "[geoipbackend] This is the geoip backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};

static GeoIPLoader geoiploader;
