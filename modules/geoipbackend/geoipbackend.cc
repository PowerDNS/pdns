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
#include "geoipinterface.hh"
#include "pdns/dns_random.hh"
#include <sstream>
#include <regex.h>
#include <glob.h>
#include <boost/algorithm/string/replace.hpp>
#include <fstream>
#include <yaml-cpp/yaml.h>

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
static int s_rc = 0; // refcount - always accessed under lock

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

static vector<std::unique_ptr<GeoIPInterface> > s_geoip_files;

string getGeoForLua(const std::string& ip, int qaint);
static string queryGeoIP(const Netmask& addr, GeoIPInterface::GeoIPQueryAttribute attribute, GeoIPNetmask& gl);

void GeoIPBackend::initialize() {
  YAML::Node config;
  vector<GeoIPDomain> tmp_domains;

  s_geoip_files.clear(); // reset pointers

  if (getArg("database-files").empty() == false) {
    vector<string> files;
    stringtok(files, getArg("database-files"), " ,\t\r\n");
    for(auto const& file: files) {
      s_geoip_files.push_back(GeoIPInterface::makeInterface(file));
    }
  }

  if (s_geoip_files.empty())
    g_log<<Logger::Warning<<"No GeoIP database files loaded!"<<endl;

  if(!getArg("zones-file").empty()) {
    try {
       config = YAML::LoadFile(getArg("zones-file"));
    } catch (YAML::Exception &ex) {
       throw PDNSException(string("Cannot read config file ") + ex.msg);
    }
  }

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
               if (rr.weight <= 0) {
                 g_log<<Logger::Error<<"Weight must be positive for " << rr.qname << endl;
                 throw PDNSException(string("Weight must be positive for ") + rr.qname.toLogString());
               }
               rr.has_weight = true;
             } else if (attr == "ttl") {
               rr.ttl = iter->second.as<int>();
             } else {
               g_log<<Logger::Error<<"Unsupported record attribute " << attr << " for " << rr.qname << endl;
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
      map<uint16_t, float> weights;
      map<uint16_t, float> sums;
      map<uint16_t, GeoIPDNSResourceRecord> lasts;
      bool has_weight=false;
      // first we look for used weight
      for(const auto &rr: item.second) {
        weights[rr.qtype.getCode()] += rr.weight;
        if (rr.has_weight) has_weight = true;
      }
      if (has_weight) {
        // put them back as probabilities and values..
        for(auto &rr: item.second) {
          uint16_t rr_type = rr.qtype.getCode();
          rr.weight=static_cast<int>((static_cast<float>(rr.weight) / weights[rr_type])*1000.0);
          sums[rr_type] += rr.weight;
          rr.has_weight = has_weight;
          lasts[rr_type] = rr;
        }
        // remove rounding gap
        for(auto &x: lasts) {
          float sum = sums[x.first];
          if (sum < 1000)
            x.second.weight += (1000-sum);
        }
      }
    }

    tmp_domains.push_back(std::move(dom));
  }

  s_domains.clear();
  std::swap(s_domains, tmp_domains);

  extern std::function<std::string(const std::string& ip, int)> g_getGeo;
  g_getGeo = getGeoForLua;
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

bool GeoIPBackend::lookup_static(const GeoIPDomain &dom, const DNSName &search, const QType &qtype, const DNSName& qdomain, const Netmask& addr, GeoIPNetmask &gl) {
  const auto& i = dom.records.find(search);
  map<uint16_t,int> cumul_probabilities;
  int probability_rnd = 1+(dns_random(1000)); // setting probability=0 means it never is used

  if (i != dom.records.end()) { // return static value
    for(const auto& rr : i->second) {
      if (qtype != QType::ANY && rr.qtype != qtype) continue;

      if (rr.has_weight) {
        gl.netmask = (addr.isIpv6()?128:32);
        int comp = cumul_probabilities[rr.qtype.getCode()];
        cumul_probabilities[rr.qtype.getCode()] += rr.weight;
        if (rr.weight == 0 || probability_rnd < comp || probability_rnd > (comp + rr.weight))
          continue;
      }
      const string& content = format2str(rr.content, addr, gl);
      if (rr.qtype != QType::ENT && rr.qtype != QType::TXT && content.empty()) continue;
      d_result.push_back(rr);
      d_result.back().content = content;
      d_result.back().qname = qdomain;
    }
    // ensure we get most strict netmask
    for(DNSResourceRecord& rr: d_result) {
      rr.scopeMask = gl.netmask;
    }
    return true; // no need to go further
  }

  return false;
};

void GeoIPBackend::lookup(const QType &qtype, const DNSName& qdomain, int zoneId, DNSPacket *pkt_p) {
  ReadLock rl(&s_state_lock);
  const GeoIPDomain* dom;
  GeoIPNetmask gl;
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

  Netmask addr{"0.0.0.0/0"};
  if (pkt_p != NULL)
    addr = Netmask(pkt_p->getRealRemote());

  gl.netmask = 0;

  (void)this->lookup_static(*dom, qdomain, qtype, qdomain, addr, gl);

  const auto& target = (*dom).services.find(qdomain);
  if (target == (*dom).services.end()) return; // no hit

  const NetmaskTree<vector<string> >::node_type* node = target->second.masks.lookup(addr);
  if (node == NULL) return; // no hit, again.

  DNSName sformat;
  gl.netmask = node->first.getBits();
  // figure out smallest sensible netmask
  if (gl.netmask == 0) {
    GeoIPNetmask tmp_gl;
    tmp_gl.netmask = 0;
    // get netmask from geoip backend
    if (queryGeoIP(addr, GeoIPInterface::Name, tmp_gl) == "unknown") {
      if (addr.isIpv6())
        gl.netmask = target->second.netmask6;
      else
        gl.netmask = target->second.netmask4;
    }
  } else {
    if (addr.isIpv6())
      gl.netmask = target->second.netmask6;
    else
      gl.netmask = target->second.netmask4;
  }

  // note that this means the array format won't work with indirect
  for(auto it = node->second.begin(); it != node->second.end(); it++) {
    sformat = DNSName(format2str(*it, addr, gl));

    // see if the record can be found
    if (this->lookup_static((*dom), sformat, qtype, qdomain, addr, gl))
      return;
  }

  if (!d_result.empty()) {
    g_log<<Logger::Error<<
       "Cannot have static record and CNAME at the same time." <<
       "Please fix your configuration for \"" << qdomain << "\", so that " <<
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

static string queryGeoIP(const Netmask& addr, GeoIPInterface::GeoIPQueryAttribute attribute, GeoIPNetmask& gl) {
  string ret = "unknown";

  for(auto const& gi: s_geoip_files) {
    string val;
    const string ip = addr.toStringNoMask();
    bool found = false;

    switch(attribute) {
    case GeoIPInterface::ASn:
      if (addr.isIpv6()) found = gi->queryASnumV6(val, gl, ip);
      else found =gi->queryASnum(val, gl, ip);
      break;
    case GeoIPInterface::Name:
      if (addr.isIpv6()) found = gi->queryNameV6(val, gl, ip);
      else found = gi->queryName(val, gl, ip);
      break;
    case GeoIPInterface::Continent:
      if (addr.isIpv6()) found = gi->queryContinentV6(val, gl, ip);
      else found = gi->queryContinent(val, gl, ip);
      break;
    case GeoIPInterface::Region:
      if (addr.isIpv6()) found = gi->queryRegionV6(val, gl, ip);
      else found = gi->queryRegion(val, gl, ip);
      break;
    case GeoIPInterface::Country:
      if (addr.isIpv6()) found = gi->queryCountryV6(val, gl, ip);
      else found = gi->queryCountry(val, gl, ip);
      break;
    case GeoIPInterface::Country2:
      if (addr.isIpv6()) found = gi->queryCountry2V6(val, gl, ip);
      else found = gi->queryCountry2(val, gl, ip);
      break;
    case GeoIPInterface::City:
      if (addr.isIpv6()) found = gi->queryCityV6(val, gl, ip);
      else found = gi->queryCity(val, gl, ip);
      break;
    case GeoIPInterface::Location:
      double lat=0, lon=0;
      boost::optional<int> alt, prec;
      if (addr.isIpv6()) found = gi->queryLocationV6(gl, ip, lat, lon, alt, prec);
      else found = gi->queryLocation(gl, ip, lat, lon, alt, prec);
      val = std::to_string(lat)+" "+std::to_string(lon);
      break;
    }

    if (!found || val.empty() || val == "--") continue; // try next database
    ret = val;
    std::transform(ret.begin(), ret.end(), ret.begin(), ::tolower);
    break;
  }

  if (ret == "unknown") gl.netmask = (addr.isIpv6()?128:32); // prevent caching
  return ret;
}

string getGeoForLua(const std::string& ip, int qaint)
{
  GeoIPInterface::GeoIPQueryAttribute qa((GeoIPInterface::GeoIPQueryAttribute)qaint);
  try {
    const Netmask addr{ip};
    GeoIPNetmask gl;
    string res=queryGeoIP(addr, qa, gl);
    //    cout<<"Result for "<<ip<<" lookup: "<<res<<endl;
    if(qa==GeoIPInterface::ASn && boost::starts_with(res, "as"))
      return res.substr(2);
    return res;
  }
  catch(std::exception& e) {
    cout<<"Error: "<<e.what()<<endl;
  }
  catch(PDNSException& e) {
    cout<<"Error: "<<e.reason<<endl;
  }
  return "";
}

bool queryGeoLocation(const Netmask& addr, GeoIPNetmask& gl, double& lat, double& lon,
                      boost::optional<int>& alt, boost::optional<int>& prec)
{
  for(auto const& gi: s_geoip_files) {
    string val;
    if (addr.isIpv6()) {
      if (gi->queryLocationV6(gl, addr.toStringNoMask(), lat, lon, alt, prec))
        return true;
     } else if (gi->queryLocation(gl, addr.toStringNoMask(), lat, lon, alt, prec))
        return true;
  }
  return false;
}

string GeoIPBackend::format2str(string sformat, const Netmask& addr, GeoIPNetmask& gl) {
  string::size_type cur,last;
  boost::optional<int> alt, prec;
  double lat, lon;
  time_t t = time((time_t*)NULL);
  GeoIPNetmask tmp_gl; // largest wins
  struct tm gtm;
  gmtime_r(&t, &gtm);
  last=0;

  while((cur = sformat.find("%", last)) != string::npos) {
    string rep;
    int nrep=3;
    tmp_gl.netmask = 0;
    if (!sformat.compare(cur,3,"%cn")) {
      rep = queryGeoIP(addr, GeoIPInterface::Continent, tmp_gl);
    } else if (!sformat.compare(cur,3,"%co")) {
      rep = queryGeoIP(addr, GeoIPInterface::Country, tmp_gl);
    } else if (!sformat.compare(cur,3,"%cc")) {
      rep = queryGeoIP(addr, GeoIPInterface::Country2, tmp_gl);
    } else if (!sformat.compare(cur,3,"%af")) {
      rep = (addr.isIpv6()?"v6":"v4");
    } else if (!sformat.compare(cur,3,"%as")) {
      rep = queryGeoIP(addr, GeoIPInterface::ASn, tmp_gl);
    } else if (!sformat.compare(cur,3,"%re")) {
      rep = queryGeoIP(addr, GeoIPInterface::Region, tmp_gl);
    } else if (!sformat.compare(cur,3,"%na")) {
      rep = queryGeoIP(addr, GeoIPInterface::Name, tmp_gl);
    } else if (!sformat.compare(cur,3,"%ci")) {
      rep = queryGeoIP(addr, GeoIPInterface::City, tmp_gl);
    } else if (!sformat.compare(cur,4,"%loc")) {
      char ns, ew;
      int d1, d2, m1, m2;
      double s1, s2;
      if (!queryGeoLocation(addr, gl, lat, lon, alt, prec)) {
        rep = "";
      } else {
        ns = (lat>0) ? 'N' : 'S';
        ew = (lon>0) ? 'E' : 'W';
        /* remove sign */
        lat = fabs(lat);
        lon = fabs(lon);
        d1 = static_cast<int>(lat);
        d2 = static_cast<int>(lon);
        m1 = static_cast<int>((lat - d1)*60.0);
        m2 = static_cast<int>((lon - d2)*60.0);
        s1 = static_cast<double>(lat - d1 - m1/60.0)*3600.0;
        s2 = static_cast<double>(lon - d2 - m2/60.0)*3600.0;
        rep = str(boost::format("%d %d %0.3f %c %d %d %0.3f %c") %
                                d1 % m1 % s1 % ns % d2 % m2 % s2 % ew);
        if (alt)
          rep = rep + str(boost::format(" %d.00") % *alt);
        else
          rep = rep + string(" 0.00");
        if (prec)
          rep = rep + str(boost::format(" %dm") % *prec);
      }
      nrep = 4;
    } else if (!sformat.compare(cur,4,"%lat")) {
      if (!queryGeoLocation(addr, gl, lat, lon, alt, prec)) {
        rep = "";
      } else {
        rep = str(boost::format("%lf") % lat);
      }
      nrep = 4;
    } else if (!sformat.compare(cur,4,"%lon")) {
      if (!queryGeoLocation(addr, gl, lat, lon, alt, prec)) {
        rep = "";
      } else {
        rep = str(boost::format("%lf") % lon);
      }
      nrep = 4;
    } else if (!sformat.compare(cur,3,"%hh")) {
      rep = boost::str(boost::format("%02d") % gtm.tm_hour);
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,3,"%yy")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_year + 1900));
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,3,"%dd")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_yday + 1));
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,4,"%wds")) {
      nrep=4;
      rep = GeoIP_WEEKDAYS[gtm.tm_wday];
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,4,"%mos")) {
      nrep=4;
      rep = GeoIP_MONTHS[gtm.tm_mon];
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,3,"%wd")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_wday + 1));
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,3,"%mo")) {
      rep = boost::str(boost::format("%02d") % (gtm.tm_mon + 1));
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,4,"%ip6")) {
      nrep = 4;
      if (addr.isIpv6())
        rep = addr.toStringNoMask();
      else
        rep = "";
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,4,"%ip4")) {
      nrep = 4;
      if (!addr.isIpv6())
        rep = addr.toStringNoMask();
      else
        rep = "";
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,3,"%ip")) {
      rep = addr.toStringNoMask();
      tmp_gl.netmask = (addr.isIpv6()?128:32);
    } else if (!sformat.compare(cur,2,"%%")) {
      last = cur + 2; continue;
    } else {
      last = cur + 1; continue;
    }
    if (tmp_gl.netmask > gl.netmask) gl.netmask = tmp_gl.netmask;
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
    g_log<<Logger::Error<<"GeoIP backend reload failed: " << pex.reason << endl;
  } catch (std::exception &stex) {
    g_log<<Logger::Error<<"GeoIP backend reload failed: " << stex.what() << endl;
  } catch (...) {
    g_log<<Logger::Error<<"GeoIP backend reload failed" << endl;
  }
}

void GeoIPBackend::rediscover(string* status) {
  reload();
}

bool GeoIPBackend::getDomainInfo(const DNSName& domain, DomainInfo &di, bool getSerial) {
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
    declare(suffix, "database-files", "File(s) to load geoip data from ([driver:]path[;opt=value]", "");
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
    g_log << Logger::Info << "[geoipbackend] This is the geoip backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};

static GeoIPLoader geoiploader;
