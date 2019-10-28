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
#include "syncres.hh"
#include "arguments.hh"
#include "zoneparser-tng.hh"
#include "logger.hh"
#include "dnsrecords.hh"
#include "root-addresses.hh"

extern int g_argc;
extern char** g_argv;

static thread_local set<DNSName> t_rootNSZones;

static void insertIntoRootNSZones(const DNSName &name) {
  // do not insert dot, wiping dot's NS records from the cache in primeRootNSZones()
  // will cause infinite recursion
  if (!name.isRoot()) {
    t_rootNSZones.insert(name);
  }
}

void primeHints(void)
{
  // prime root cache
  const vState validationState = Insecure;
  vector<DNSRecord> nsset;
  t_rootNSZones.clear();
  if(!t_RC)
    t_RC = std::unique_ptr<MemRecursorCache>(new MemRecursorCache());

  if(::arg()["hint-file"].empty()) {
    DNSRecord arr, aaaarr, nsrr;
    nsrr.d_name=g_rootdnsname;
    arr.d_type=QType::A;
    aaaarr.d_type=QType::AAAA;
    nsrr.d_type=QType::NS;
    arr.d_ttl=aaaarr.d_ttl=nsrr.d_ttl=time(0)+3600000;
    
    for(char c='a';c<='m';++c) {
      char templ[40];
      strncpy(templ,"a.root-servers.net.", sizeof(templ) - 1);
      templ[sizeof(templ)-1] = '\0';
      *templ=c;
      aaaarr.d_name=arr.d_name=DNSName(templ);
      insertIntoRootNSZones(arr.d_name.getLastLabel());
      nsrr.d_content=std::make_shared<NSRecordContent>(DNSName(templ));
      arr.d_content=std::make_shared<ARecordContent>(ComboAddress(rootIps4[c-'a']));
      vector<DNSRecord> aset;
      aset.push_back(arr);
      t_RC->replace(time(0), DNSName(templ), QType(QType::A), aset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), true, boost::none, validationState); // auth, nuke it all
      if (rootIps6[c-'a'] != NULL) {
        aaaarr.d_content=std::make_shared<AAAARecordContent>(ComboAddress(rootIps6[c-'a']));

        vector<DNSRecord> aaaaset;
        aaaaset.push_back(aaaarr);
        t_RC->replace(time(0), DNSName(templ), QType(QType::AAAA), aaaaset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), true, boost::none, validationState);
      }
      
      nsset.push_back(nsrr);
    }
  }
  else {
    ZoneParserTNG zpt(::arg()["hint-file"]);
    DNSResourceRecord rr;

    while(zpt.get(rr)) {
      rr.ttl+=time(0);
      if(rr.qtype.getCode()==QType::A) {
        vector<DNSRecord> aset;
        aset.push_back(DNSRecord(rr));
        t_RC->replace(time(0), rr.qname, QType(QType::A), aset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), true, boost::none, validationState); // auth, etc see above
      } else if(rr.qtype.getCode()==QType::AAAA) {
        vector<DNSRecord> aaaaset;
        aaaaset.push_back(DNSRecord(rr));
        t_RC->replace(time(0), rr.qname, QType(QType::AAAA), aaaaset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), true, boost::none, validationState);
      } else if(rr.qtype.getCode()==QType::NS) {
        rr.content=toLower(rr.content);
        nsset.push_back(DNSRecord(rr));
      }
      insertIntoRootNSZones(rr.qname.getLastLabel());
    }
  }
  t_RC->doWipeCache(g_rootdnsname, false, QType::NS);
  t_RC->replace(time(0), g_rootdnsname, QType(QType::NS), nsset, vector<std::shared_ptr<RRSIGRecordContent>>(), vector<std::shared_ptr<DNSRecord>>(), false, boost::none, validationState); // and stuff in the cache
}


// Do not only put the root hints into the cache, but also make sure
// the NS records of the top level domains of the names of the root
// servers are in the cache. We need these to correctly determine the
// security status of that specific domain (normally
// root-servers.net). This is caused by the accident that the root
// servers are authoritative for root-servers.net, and some
// implementations reply not with a delegation on a root-servers.net
// DS query, but with a NODATA response (the domain is unsigned).
void primeRootNSZones(bool dnssecmode)
{
  struct timeval now;
  gettimeofday(&now, 0);
  SyncRes sr(now);

  if (dnssecmode) {
    sr.setDoDNSSEC(true);
    sr.setDNSSECValidationRequested(true);
  }
  for (const auto & qname: t_rootNSZones) {
    t_RC->doWipeCache(qname, false, QType::NS);
    vector<DNSRecord> ret;
    sr.beginResolve(qname, QType(QType::NS), QClass::IN, ret);
  }
}

static void makeNameToIPZone(std::shared_ptr<SyncRes::domainmap_t> newMap, const DNSName& hostname, const string& ip)
{
  SyncRes::AuthDomain ad;
  ad.d_rdForward=false;

  DNSRecord dr;
  dr.d_name=hostname;
  dr.d_place=DNSResourceRecord::ANSWER;
  dr.d_ttl=86400;
  dr.d_type=QType::SOA;
  dr.d_class = 1;
  dr.d_content = DNSRecordContent::mastermake(QType::SOA, 1, "localhost. root 1 604800 86400 2419200 604800");
  
  ad.d_records.insert(dr);

  dr.d_type=QType::NS;
  dr.d_content=std::make_shared<NSRecordContent>("localhost.");

  ad.d_records.insert(dr);
  
  dr.d_type=QType::A;
  dr.d_content = DNSRecordContent::mastermake(QType::A, 1, ip);
  ad.d_records.insert(dr);
  
  if(newMap->count(dr.d_name)) {  
    g_log<<Logger::Warning<<"Hosts file will not overwrite zone '"<<dr.d_name<<"' already loaded"<<endl;
  }
  else {
    g_log<<Logger::Warning<<"Inserting forward zone '"<<dr.d_name<<"' based on hosts file"<<endl;
    ad.d_name=dr.d_name;
    (*newMap)[ad.d_name]=ad;
  }
}

//! parts[0] must be an IP address, the rest must be host names
static void makeIPToNamesZone(std::shared_ptr<SyncRes::domainmap_t> newMap, const vector<string>& parts)
{
  string address=parts[0];
  vector<string> ipparts;
  stringtok(ipparts, address,".");
  
  SyncRes::AuthDomain ad;
  ad.d_rdForward=false;

  DNSRecord dr;
  for(int n=ipparts.size()-1; n>=0 ; --n) {
    dr.d_name.appendRawLabel(ipparts[n]);
  }
  dr.d_name.appendRawLabel("in-addr");
  dr.d_name.appendRawLabel("arpa");
  dr.d_class = 1;
  dr.d_place=DNSResourceRecord::ANSWER;
  dr.d_ttl=86400;
  dr.d_type=QType::SOA;
  dr.d_content=DNSRecordContent::mastermake(QType::SOA, 1, "localhost. root 1 604800 86400 2419200 604800");
  
  ad.d_records.insert(dr);

  dr.d_type=QType::NS;
  dr.d_content=std::make_shared<NSRecordContent>(DNSName("localhost."));

  ad.d_records.insert(dr);
  dr.d_type=QType::PTR;

  if(ipparts.size()==4)  // otherwise this is a partial zone
    for(unsigned int n=1; n < parts.size(); ++n) {
      dr.d_content=DNSRecordContent::mastermake(QType::PTR, 1, DNSName(parts[n]).toString()); // XXX FIXME DNSNAME PAIN CAN THIS BE RIGHT?
      ad.d_records.insert(dr);
    }

  if(newMap->count(dr.d_name)) {  
    g_log<<Logger::Warning<<"Will not overwrite zone '"<<dr.d_name<<"' already loaded"<<endl;
  }
  else {
    if(ipparts.size()==4)
      g_log<<Logger::Warning<<"Inserting reverse zone '"<<dr.d_name<<"' based on hosts file"<<endl;
    ad.d_name = dr.d_name;
    (*newMap)[ad.d_name]=ad;
  }
}



/* mission in life: parse three cases
   1) 1.2.3.4
   2) 1.2.3.4:5300
   3) 2001::1
   4) [2002::1]:53
*/

ComboAddress parseIPAndPort(const std::string& input, uint16_t port)
{
  if(input.find(':') == string::npos || input.empty()) // common case
    return ComboAddress(input, port);

  pair<string,string> both;

  try { // case 2
    both=splitField(input,':');
    uint16_t newport=static_cast<uint16_t>(pdns_stou(both.second));
    return ComboAddress(both.first, newport);
  } 
  catch(...){}

  if(input[0]=='[') { // case 4
    both=splitField(input.substr(1),']');
    return ComboAddress(both.first, both.second.empty() ? port : static_cast<uint16_t>(pdns_stou(both.second.substr(1))));
  }

  return ComboAddress(input, port); // case 3
}


void convertServersForAD(const std::string& input, SyncRes::AuthDomain& ad, const char* sepa, bool verbose=true)
{
  vector<string> servers;
  stringtok(servers, input, sepa);
  ad.d_servers.clear();

  for(vector<string>::const_iterator iter = servers.begin(); iter != servers.end(); ++iter) {
    if(verbose && iter != servers.begin()) 
      g_log<<", ";

    ComboAddress addr=parseIPAndPort(*iter, 53);
    if(verbose)
      g_log<<addr.toStringWithPort();
    ad.d_servers.push_back(addr);
  }
  if(verbose)
    g_log<<endl;
}

void* pleaseWipeNegCache()
{
  SyncRes::clearNegCache();
  return 0;
}

void* pleaseUseNewSDomainsMap(std::shared_ptr<SyncRes::domainmap_t> newmap)
{
  SyncRes::setDomainMap(newmap);
  return 0;
}

string reloadAuthAndForwards()
{
  std::shared_ptr<SyncRes::domainmap_t> original=SyncRes::getDomainMap();
  
  try {
    g_log<<Logger::Warning<<"Reloading zones, purging data from cache"<<endl;

    string configname=::arg()["config-dir"]+"/recursor.conf";
    if(::arg()["config-name"]!="") {
      configname=::arg()["config-dir"]+"/recursor-"+::arg()["config-name"]+".conf";
    }
    cleanSlashes(configname);
    
    if(!::arg().preParseFile(configname.c_str(), "forward-zones"))
      throw runtime_error("Unable to re-parse configuration file '"+configname+"'");
    ::arg().preParseFile(configname.c_str(), "forward-zones-file");
    ::arg().preParseFile(configname.c_str(), "forward-zones-recurse");
    ::arg().preParseFile(configname.c_str(), "auth-zones");
    ::arg().preParseFile(configname.c_str(), "export-etc-hosts", "off");
    ::arg().preParseFile(configname.c_str(), "serve-rfc1918");
    ::arg().preParseFile(configname.c_str(), "include-dir");
    ::arg().preParse(g_argc, g_argv, "include-dir");

    // then process includes
    std::vector<std::string> extraConfigs;
    ::arg().gatherIncludes(extraConfigs);

    for(const std::string& fn :  extraConfigs) {
      if(!::arg().preParseFile(fn.c_str(), "forward-zones", ::arg()["forward-zones"]))
        throw runtime_error("Unable to re-parse configuration file include '"+fn+"'");
      ::arg().preParseFile(fn.c_str(), "forward-zones-file", ::arg()["forward-zones-file"]);
      ::arg().preParseFile(fn.c_str(), "forward-zones-recurse", ::arg()["forward-zones-recurse"]);
      ::arg().preParseFile(fn.c_str(), "auth-zones",::arg()["auth-zones"]);
      ::arg().preParseFile(fn.c_str(), "export-etc-hosts",::arg()["export-etc-hosts"]);
      ::arg().preParseFile(fn.c_str(), "serve-rfc1918",::arg()["serve-rfc1918"]);
    }

    ::arg().preParse(g_argc, g_argv, "forward-zones");
    ::arg().preParse(g_argc, g_argv, "forward-zones-file");
    ::arg().preParse(g_argc, g_argv, "forward-zones-recurse");
    ::arg().preParse(g_argc, g_argv, "auth-zones");
    ::arg().preParse(g_argc, g_argv, "export-etc-hosts");
    ::arg().preParse(g_argc, g_argv, "serve-rfc1918");

    std::shared_ptr<SyncRes::domainmap_t> newDomainMap = parseAuthAndForwards();

    // purge both original and new names
    std::set<DNSName> oldAndNewDomains;
    for(const auto& i : *newDomainMap) {
      oldAndNewDomains.insert(i.first);
    }

    if(original) {
      for(const auto& i : *original) {
        oldAndNewDomains.insert(i.first);
      }
    }

    for(const auto i : oldAndNewDomains) {
        broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, i, true));
        broadcastAccFunction<uint64_t>(boost::bind(pleaseWipePacketCache, i, true));
        broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, i, true));
    }

    broadcastFunction(boost::bind(pleaseUseNewSDomainsMap, newDomainMap));
    return "ok\n";
  }
  catch(std::exception& e) {
    g_log<<Logger::Error<<"Encountered error reloading zones, keeping original data: "<<e.what()<<endl;
  }
  catch(PDNSException& ae) {
    g_log<<Logger::Error<<"Encountered error reloading zones, keeping original data: "<<ae.reason<<endl;
  }
  catch(...) {
    g_log<<Logger::Error<<"Encountered unknown error reloading zones, keeping original data"<<endl;
  }
  return "reloading failed, see log\n";
}

std::shared_ptr<SyncRes::domainmap_t> parseAuthAndForwards()
{
  TXTRecordContent::report();
  OPTRecordContent::report();

  auto newMap = std::make_shared<SyncRes::domainmap_t>();

  typedef vector<string> parts_t;
  parts_t parts;  
  const char *option_names[3]={"auth-zones", "forward-zones", "forward-zones-recurse"};
  for(int n=0; n < 3 ; ++n ) {
    parts.clear();
    stringtok(parts, ::arg()[option_names[n]], " ,\t\n\r");
    for(parts_t::const_iterator iter = parts.begin(); iter != parts.end(); ++iter) {
      SyncRes::AuthDomain ad;
      if ((*iter).find('=') == string::npos)
        throw PDNSException("Error parsing '" + *iter + "', missing =");
      pair<string,string> headers=splitField(*iter, '=');
      trim(headers.first);
      trim(headers.second);
      // headers.first=toCanonic("", headers.first);
      if(n==0) {
        ad.d_rdForward = false;
        g_log<<Logger::Error<<"Parsing authoritative data for zone '"<<headers.first<<"' from file '"<<headers.second<<"'"<<endl;
        ZoneParserTNG zpt(headers.second, DNSName(headers.first));
        DNSResourceRecord rr;
	DNSRecord dr;
        while(zpt.get(rr)) {
          try {
	    dr=DNSRecord(rr);
	    dr.d_place=DNSResourceRecord::ANSWER;
          }
          catch(std::exception &e) {
            throw PDNSException("Error parsing record '"+rr.qname.toLogString()+"' of type "+rr.qtype.getName()+" in zone '"+headers.first+"' from file '"+headers.second+"': "+e.what());
          }
          catch(...) {
            throw PDNSException("Error parsing record '"+rr.qname.toLogString()+"' of type "+rr.qtype.getName()+" in zone '"+headers.first+"' from file '"+headers.second+"'");
          }

          ad.d_records.insert(dr);
        }
      }
      else {
        g_log<<Logger::Error<<"Redirecting queries for zone '"<<headers.first<<"' ";
        if(n == 2) {
          g_log<<"with recursion ";
          ad.d_rdForward = true;
        }
        else ad.d_rdForward = false;
        g_log<<"to: ";
        
        convertServersForAD(headers.second, ad, ";");
        if(n == 2) {
          ad.d_rdForward = true;
        }
      }

      ad.d_name = DNSName(headers.first);
      (*newMap)[ad.d_name]=ad;
    }
  }
  
  if(!::arg()["forward-zones-file"].empty()) {
    g_log<<Logger::Warning<<"Reading zone forwarding information from '"<<::arg()["forward-zones-file"]<<"'"<<endl;
    SyncRes::AuthDomain ad;
    auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(::arg()["forward-zones-file"].c_str(), "r"), fclose);
    if(!fp) {
      throw PDNSException("Error opening forward-zones-file '"+::arg()["forward-zones-file"]+"': "+stringerror());
    }

    string line;
    int linenum=0;
    uint64_t before = newMap->size();
    while(linenum++, stringfgets(fp.get(), line)) {
      trim(line);
      if (line[0] == '#') // Comment line, skip to the next line
        continue;
      string domain, instructions;
      tie(domain, instructions)=splitField(line, '=');
      instructions = splitField(instructions, '#').first; // Remove EOL comments
      trim(domain);
      trim(instructions);
      if(domain.empty() && instructions.empty()) { // empty line
        continue;
      }
      if(boost::starts_with(domain,"+")) {
        domain=domain.c_str()+1;
        ad.d_rdForward = true;
      }
      else
        ad.d_rdForward = false;
      if(domain.empty()) {
        throw PDNSException("Error parsing line "+std::to_string(linenum)+" of " +::arg()["forward-zones-file"]);
      }

      try {
        convertServersForAD(instructions, ad, ",; ", false);
      }
      catch(...) {
        throw PDNSException("Conversion error parsing line "+std::to_string(linenum)+" of " +::arg()["forward-zones-file"]);
      }

      ad.d_name = DNSName(domain);
      (*newMap)[ad.d_name]=ad;
    }
    g_log<<Logger::Warning<<"Done parsing " << newMap->size() - before<<" forwarding instructions from file '"<<::arg()["forward-zones-file"]<<"'"<<endl;
  }

  if(::arg().mustDo("export-etc-hosts")) {
    string line;
    string fname=::arg()["etc-hosts-file"];
    
    ifstream ifs(fname.c_str());
    if(!ifs) {
      g_log<<Logger::Warning<<"Could not open "<<fname<<" for reading"<<endl;
    }
    else {
      string searchSuffix = ::arg()["export-etc-hosts-search-suffix"];
      string::size_type pos;
      while(getline(ifs,line)) {
        pos=line.find('#');
        if(pos!=string::npos)
          line.resize(pos);
        trim(line);
        if(line.empty())
          continue;
        parts.clear();
        stringtok(parts, line, "\t\r\n ");
        if(parts[0].find(':')!=string::npos)
          continue;
        
        for(unsigned int n=1; n < parts.size(); ++n) {
          if(searchSuffix.empty() || parts[n].find('.') != string::npos)
	    makeNameToIPZone(newMap, DNSName(parts[n]), parts[0]);
          else {
	    DNSName canonic=toCanonic(DNSName(searchSuffix), parts[n]); /// XXXX DNSName pain
	    if(canonic != DNSName(parts[n])) {   // XXX further DNSName pain
              makeNameToIPZone(newMap, canonic, parts[0]);
            }
          }
        }
        makeIPToNamesZone(newMap, parts);
      }
    }
  }
  if(::arg().mustDo("serve-rfc1918")) {
    g_log<<Logger::Warning<<"Inserting rfc 1918 private space zones"<<endl;
    parts.clear();
    parts.push_back("127");
    makeIPToNamesZone(newMap, parts);
    parts[0]="10";
    makeIPToNamesZone(newMap, parts);

    parts[0]="192.168";
    makeIPToNamesZone(newMap, parts);
    for(int n=16; n < 32; n++) {
      parts[0]="172."+std::to_string(n);
      makeIPToNamesZone(newMap,parts);
    }
  }
  return newMap;
}
