/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2010  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "syncres.hh"
#include "arguments.hh"
#include "zoneparser-tng.hh"
#include "logger.hh"
#include "dnsrecords.hh"
#include <boost/foreach.hpp>
#include <thread>
#include "ixfr.hh"
#include "rpzloader.hh"

extern int g_argc;
extern char** g_argv;

void primeHints(void)
{
  // prime root cache
  vector<DNSRecord> nsset;
  if(!t_RC)
    t_RC = new MemRecursorCache();

  if(::arg()["hint-file"].empty()) {
    static const char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", 
                             "192.112.36.4", "128.63.2.53",
                             "192.36.148.17","192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"};
    static const char *ip6s[]={
      "2001:503:ba3e::2:30", "2001:500:84::b", "2001:500:2::c", "2001:500:2d::d", NULL,
      "2001:500:2f::f", NULL, "2001:500:1::803f:235", "2001:7fe::53",
      "2001:503:c27::2:30", "2001:7fd::1", "2001:500:3::42", "2001:dc3::35"
    };
    
    DNSRecord arr, aaaarr, nsrr;
    nsrr.d_name=DNSName(".");
    arr.d_type=QType::A;
    aaaarr.d_type=QType::AAAA;
    nsrr.d_type=QType::NS;
    arr.d_ttl=aaaarr.d_ttl=nsrr.d_ttl=time(0)+3600000;
    
    for(char c='a';c<='m';++c) {
      static char templ[40];
      strncpy(templ,"a.root-servers.net.", sizeof(templ) - 1);
      *templ=c;
      aaaarr.d_name=arr.d_name=DNSName(templ);
      nsrr.d_content=std::make_shared<NSRecordContent>(DNSName(templ));
      arr.d_content=std::make_shared<ARecordContent>(ComboAddress(ips[c-'a']));
      vector<DNSRecord> aset;
      aset.push_back(arr);
      t_RC->replace(time(0), DNSName(templ), QType(QType::A), aset, vector<std::shared_ptr<RRSIGRecordContent>>(), true); // auth, nuke it all
      if (ip6s[c-'a'] != NULL) {
        aaaarr.d_content=std::make_shared<AAAARecordContent>(ComboAddress(ip6s[c-'a']));

        vector<DNSRecord> aaaaset;
        aaaaset.push_back(aaaarr);
        t_RC->replace(time(0), DNSName(templ), QType(QType::AAAA), aaaaset, vector<std::shared_ptr<RRSIGRecordContent>>(), true);
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
        t_RC->replace(time(0), rr.qname, QType(QType::A), aset, vector<std::shared_ptr<RRSIGRecordContent>>(), true); // auth, etc see above
      } else if(rr.qtype.getCode()==QType::AAAA) {
        vector<DNSRecord> aaaaset;
        aaaaset.push_back(DNSRecord(rr));
        t_RC->replace(time(0), rr.qname, QType(QType::AAAA), aaaaset, vector<std::shared_ptr<RRSIGRecordContent>>(), true);
      } else if(rr.qtype.getCode()==QType::NS) {
        rr.content=toLower(rr.content);
        nsset.push_back(DNSRecord(rr));
      }
    }
  }
  t_RC->replace(time(0), DNSName("."), QType(QType::NS), nsset, vector<std::shared_ptr<RRSIGRecordContent>>(), true); // and stuff in the cache (auth)
}

static void makeNameToIPZone(SyncRes::domainmap_t* newMap, const DNSName& hostname, const string& ip)
{
  SyncRes::AuthDomain ad;
  ad.d_rdForward=false;

  DNSRecord dr;
  dr.d_name=hostname;
  dr.d_place=DNSResourceRecord::ANSWER;
  dr.d_ttl=86400;
  dr.d_type=QType::SOA;
  dr.d_class = 1;
  dr.d_content = std::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::SOA, 1, "localhost. root 1 604800 86400 2419200 604800"));
  
  ad.d_records.insert(dr);

  dr.d_type=QType::NS;
  dr.d_content=std::make_shared<NSRecordContent>("localhost.");

  ad.d_records.insert(dr);
  
  dr.d_type=QType::A;
  dr.d_content= std::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::A, 1, ip));
  ad.d_records.insert(dr);
  
  if(newMap->count(dr.d_name)) {  
    L<<Logger::Warning<<"Hosts file will not overwrite zone '"<<dr.d_name<<"' already loaded"<<endl;
  }
  else {
    L<<Logger::Warning<<"Inserting forward zone '"<<dr.d_name<<"' based on hosts file"<<endl;
    (*newMap)[dr.d_name]=ad;
  }
}

//! parts[0] must be an IP address, the rest must be host names
static void makeIPToNamesZone(SyncRes::domainmap_t* newMap, const vector<string>& parts) 
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
  dr.d_content=std::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::SOA, 1, "localhost. root 1 604800 86400 2419200 604800"));
  
  ad.d_records.insert(dr);

  dr.d_type=QType::NS;
  dr.d_content=std::make_shared<NSRecordContent>(DNSName("localhost."));

  ad.d_records.insert(dr);
  dr.d_type=QType::PTR;

  if(ipparts.size()==4)  // otherwise this is a partial zone
    for(unsigned int n=1; n < parts.size(); ++n) {
      dr.d_content=std::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::PTR, 1, DNSName(parts[n]).toString())); // XXX FIXME DNSNAME PAIN CAN THIS BE RIGHT?
      ad.d_records.insert(dr);
    }

  if(newMap->count(dr.d_name)) {  
    L<<Logger::Warning<<"Will not overwrite zone '"<<dr.d_name<<"' already loaded"<<endl;
  }
  else {
    if(ipparts.size()==4)
      L<<Logger::Warning<<"Inserting reverse zone '"<<dr.d_name<<"' based on hosts file"<<endl;
    (*newMap)[dr.d_name]=ad;
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
    uint16_t newport=boost::lexical_cast<uint16_t>(both.second);
    return ComboAddress(both.first, newport);
  } 
  catch(...){}

  if(input[0]=='[') { // case 4
    both=splitField(input.substr(1),']');
    return ComboAddress(both.first, both.second.empty() ? port : boost::lexical_cast<uint16_t>(both.second.substr(1)));
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
      L<<", ";

    ComboAddress addr=parseIPAndPort(*iter, 53);
    if(verbose)
      L<<addr.toStringWithPort();
    ad.d_servers.push_back(addr);
  }
  if(verbose)
    L<<endl;
}

void* pleaseWipeNegCache()
{
  t_sstorage->negcache.clear();   
  return 0;
}

void* pleaseUseNewSDomainsMap(SyncRes::domainmap_t* newmap)
{
  t_sstorage->domainmap = newmap;
  return 0;
}

string reloadAuthAndForwards()
{
  SyncRes::domainmap_t* original=t_sstorage->domainmap;  
  
  try {
    L<<Logger::Warning<<"Reloading zones, purging data from cache"<<endl;
  
    for(SyncRes::domainmap_t::const_iterator i = t_sstorage->domainmap->begin(); i != t_sstorage->domainmap->end(); ++i) {
      for(SyncRes::AuthDomain::records_t::const_iterator j = i->second.d_records.begin(); j != i->second.d_records.end(); ++j) 
        broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, j->d_name, false));
    }

    string configname=::arg()["config-dir"]+"/recursor.conf";
    cleanSlashes(configname);
    
    if(!::arg().preParseFile(configname.c_str(), "forward-zones")) 
      L<<Logger::Warning<<"Unable to re-parse configuration file '"<<configname<<"'"<<endl;
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

    BOOST_FOREACH(const std::string& fn, extraConfigs) {
      ::arg().preParseFile(fn.c_str(), "forward-zones", ::arg()["forward-zones"]);
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

    SyncRes::domainmap_t* newDomainMap = parseAuthAndForwards();
    
    // purge again - new zones need to blank out the cache
    for(SyncRes::domainmap_t::const_iterator i = newDomainMap->begin(); i != newDomainMap->end(); ++i) {
        broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, i->first, true));
        broadcastAccFunction<uint64_t>(boost::bind(pleaseWipePacketCache, i->first, true));
        broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, i->first, true));
    }

    broadcastFunction(boost::bind(pleaseUseNewSDomainsMap, newDomainMap)); 
    delete original;
    return "ok\n";
  }
  catch(std::exception& e) {
    L<<Logger::Error<<"Encountered error reloading zones, keeping original data: "<<e.what()<<endl;
  }
  catch(PDNSException& ae) {
    L<<Logger::Error<<"Encountered error reloading zones, keeping original data: "<<ae.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Encountered unknown error reloading zones, keeping original data"<<endl;
  }
  return "reloading failed, see log\n";
}

void ixfrTracker(const ComboAddress& master, const DNSName& zone, shared_ptr<SOARecordContent> oursr) 
{
  for(;;) {
    DNSRecord dr;
    dr.d_content=oursr;

    sleep(oursr->d_st.refresh);
    

    L<<Logger::Info<<"Getting IXFR deltas for "<<zone<<" from "<<master.toStringWithPort()<<", our serial: "<<std::dynamic_pointer_cast<SOARecordContent>(dr.d_content)->d_st.serial<<endl;

    auto deltas = getIXFRDeltas(master, zone, dr);
    if(deltas.empty())
      continue;
    L<<Logger::Info<<"Processing "<<deltas.size()<<" deltas for RPZ "<<zone<<endl;

    int totremove=0, totadd=0;
    for(const auto& delta : deltas) {
      const auto& remove = delta.first;
      const auto& add = delta.second;
      
      for(const auto& rr : remove) { // should always contain the SOA
	totremove++;
	if(rr.d_type == QType::SOA) {
	  auto oldsr = std::dynamic_pointer_cast<SOARecordContent>(rr.d_content);
	  if(oldsr->d_st.serial == oursr->d_st.serial) {
	    //	    cout<<"Got good removal of SOA serial "<<oldsr->d_st.serial<<endl;
	  }
	  else
	    cerr<<"GOT WRONG SOA SERIAL REMOVAL, SHOULD TRIGGER WHOLE RELOAD"<<endl;
	}
	else {
	  L<<Logger::Info<<"Had removal of "<<rr.d_name<<endl;
	  RPZRecordToPolicy(rr, g_dfe, false, 0);
	}
      }

      for(const auto& rr : add) { // should always contain the new SOA
	totadd++;
	if(rr.d_type == QType::SOA) {
	  auto newsr = std::dynamic_pointer_cast<SOARecordContent>(rr.d_content);
	  //	  L<<Logger::Info<<"New SOA serial for "<<zone<<": "<<newsr->d_st.serial<<endl;
	  oursr = newsr;
	}
	else {
	  L<<Logger::Info<<"Had addition of "<<rr.d_name<<endl;
	  RPZRecordToPolicy(rr, g_dfe, true, 0);
	}
      }
    }
    L<<Logger::Info<<"Had "<<totremove<<" RPZ removals, "<<totadd<<" additions for "<<zone<<" New serial: "<<oursr->d_st.serial<<endl;
  }
}


void loadRPZFiles()
{
  vector<string> fnames;
  stringtok(fnames, ::arg()["rpz-files"]," ,");
  int count=0;
  for(const auto& f : fnames) {
    loadRPZFromFile(f, g_dfe, count++);
  }

  fnames.clear();
  stringtok(fnames, ::arg()["rpz-masters"]," ,");

  for(const auto& f : fnames) {
    auto s = splitField(f, ':');
    ComboAddress master(s.first, 53);
    DNSName zone(s.second);
    auto sr=loadRPZFromServer(master,zone, g_dfe, count++);
    std::thread t(ixfrTracker, master, zone, sr);
    t.detach();
  }

}

SyncRes::domainmap_t* parseAuthAndForwards()
{
  TXTRecordContent::report();
  OPTRecordContent::report();

  SyncRes::domainmap_t* newMap = new SyncRes::domainmap_t();

  typedef vector<string> parts_t;
  parts_t parts;  
  const char *option_names[3]={"auth-zones", "forward-zones", "forward-zones-recurse"};
  for(int n=0; n < 3 ; ++n ) {
    parts.clear();
    stringtok(parts, ::arg()[option_names[n]], " ,\t\n\r");
    for(parts_t::const_iterator iter = parts.begin(); iter != parts.end(); ++iter) {
      SyncRes::AuthDomain ad;
      pair<string,string> headers=splitField(*iter, '=');
      trim(headers.first);
      trim(headers.second);
      // headers.first=toCanonic("", headers.first);
      if(n==0) {
        ad.d_rdForward = false;
        L<<Logger::Error<<"Parsing authoritative data for zone '"<<headers.first<<"' from file '"<<headers.second<<"'"<<endl;
        ZoneParserTNG zpt(headers.second, DNSName(headers.first));
        DNSResourceRecord rr;
	DNSRecord dr;
        while(zpt.get(rr)) {
          try {
	    dr=DNSRecord(rr);
	    dr.d_place=DNSResourceRecord::ANSWER;
          }
          catch(std::exception &e) {
            delete newMap;
            throw PDNSException("Error parsing record '"+rr.qname.toString()+"' of type "+rr.qtype.getName()+" in zone '"+headers.first+"' from file '"+headers.second+"': "+e.what());
          }
          catch(...) {
            delete newMap;
            throw PDNSException("Error parsing record '"+rr.qname.toString()+"' of type "+rr.qtype.getName()+" in zone '"+headers.first+"' from file '"+headers.second+"'");
          }

          ad.d_records.insert(dr);
        }
      }
      else {
        L<<Logger::Error<<"Redirecting queries for zone '"<<headers.first<<"' ";
        if(n == 2) {
          L<<"with recursion ";
          ad.d_rdForward = true;
        }
        else ad.d_rdForward = false;
        L<<"to: ";
        
        convertServersForAD(headers.second, ad, ";");
        if(n == 2) {
          ad.d_rdForward = true;
        }
      }
      
      (*newMap)[DNSName(headers.first)]=ad; 
    }
  }
  
  if(!::arg()["forward-zones-file"].empty()) {
    L<<Logger::Warning<<"Reading zone forwarding information from '"<<::arg()["forward-zones-file"]<<"'"<<endl;
    SyncRes::AuthDomain ad;
    FILE *rfp=fopen(::arg()["forward-zones-file"].c_str(), "r");

    if(!rfp) {
      delete newMap;
      throw PDNSException("Error opening forward-zones-file '"+::arg()["forward-zones-file"]+"': "+stringerror());
    }

    shared_ptr<FILE> fp=shared_ptr<FILE>(rfp, fclose);
    
    string line;
    int linenum=0;
    uint64_t before = newMap->size();
    while(linenum++, stringfgets(fp.get(), line)) {
      string domain, instructions;
      tie(domain, instructions)=splitField(line, '=');
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
        delete newMap;
        throw PDNSException("Error parsing line "+lexical_cast<string>(linenum)+" of " +::arg()["forward-zones-file"]);
      }

      try {
        convertServersForAD(instructions, ad, ",; ", false);
      }
      catch(...) {
        delete newMap;
        throw PDNSException("Conversion error parsing line "+lexical_cast<string>(linenum)+" of " +::arg()["forward-zones-file"]);
      }

      (*newMap)[DNSName(domain)]=ad;
    }
    L<<Logger::Warning<<"Done parsing " << newMap->size() - before<<" forwarding instructions from file '"<<::arg()["forward-zones-file"]<<"'"<<endl;
  }

  if(::arg().mustDo("export-etc-hosts")) {
    string line;
    string fname=::arg()["etc-hosts-file"];
    
    ifstream ifs(fname.c_str());
    if(!ifs) {
      L<<Logger::Warning<<"Could not open /etc/hosts for reading"<<endl;
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
    L<<Logger::Warning<<"Inserting rfc 1918 private space zones"<<endl;
    parts.clear();
    parts.push_back("127");
    makeIPToNamesZone(newMap, parts);
    parts[0]="10";
    makeIPToNamesZone(newMap, parts);

    parts[0]="192.168";
    makeIPToNamesZone(newMap, parts);
    for(int n=16; n < 32; n++) {
      parts[0]="172."+lexical_cast<string>(n);
      makeIPToNamesZone(newMap,parts);
    }
  }
  return newMap;
}

