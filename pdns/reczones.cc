/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2010  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 
    as published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "syncres.hh"
#include "arguments.hh"
#include "zoneparser-tng.hh"
#include "logger.hh"
#include "dnsrecords.hh"

void primeHints(void)
{
  // prime root cache
  set<DNSResourceRecord>nsset;
  if(!t_RC)
    t_RC = new MemRecursorCache();

  if(::arg()["hint-file"].empty()) {
    static const char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", 
        		     "192.112.36.4", "128.63.2.53",
        		     "192.36.148.17","192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"};
    static const char *ip6s[]={
      "2001:503:ba3e::2:30", NULL, NULL, NULL, NULL,
      "2001:500:2f::f", NULL, "2001:500:1::803f:235", NULL,
      "2001:503:c27::2:30", "2001:7fd::1", "2001:500:3::42", "2001:dc3::35"
    };
    
    DNSResourceRecord arr, aaaarr, nsrr;
    arr.qtype=QType::A;
    aaaarr.qtype=QType::AAAA;
    nsrr.qtype=QType::NS;
    arr.ttl=aaaarr.ttl=nsrr.ttl=time(0)+3600000;
    
    for(char c='a';c<='m';++c) {
      static char templ[40];
      strncpy(templ,"a.root-servers.net.", sizeof(templ) - 1);
      *templ=c;
      aaaarr.qname=arr.qname=nsrr.content=templ;
      arr.content=ips[c-'a'];
      set<DNSResourceRecord> aset;
      aset.insert(arr);
      t_RC->replace(time(0), string(templ), QType(QType::A), aset, true); // auth, nuke it all
      if (ip6s[c-'a'] != NULL) {
        aaaarr.content=ip6s[c-'a'];

        set<DNSResourceRecord> aaaaset;
        aaaaset.insert(aaaarr);
        t_RC->replace(time(0), string(templ), QType(QType::AAAA), aaaaset, true);
      }
      
      nsset.insert(nsrr);
    }
  }
  else {
    ZoneParserTNG zpt(::arg()["hint-file"]);
    DNSResourceRecord rr;

    while(zpt.get(rr)) {
      rr.ttl+=time(0);
      if(rr.qtype.getCode()==QType::A) {
        set<DNSResourceRecord> aset;
        aset.insert(rr);
        t_RC->replace(time(0), rr.qname, QType(QType::A), aset, true); // auth, etc see above
      } else if(rr.qtype.getCode()==QType::AAAA) {
        set<DNSResourceRecord> aaaaset;
        aaaaset.insert(rr);
        t_RC->replace(time(0), rr.qname, QType(QType::AAAA), aaaaset, true);
      } else if(rr.qtype.getCode()==QType::NS) {
        rr.content=toLower(rr.content);
        nsset.insert(rr);
      }
    }
  }
  t_RC->replace(time(0),".", QType(QType::NS), nsset, true); // and stuff in the cache (auth)
}

static void makeNameToIPZone(SyncRes::domainmap_t* newMap, const string& hostname, const string& ip)
{
  SyncRes::AuthDomain ad;
  DNSResourceRecord rr;
  rr.qname=toCanonic("", hostname);
  rr.d_place=DNSResourceRecord::ANSWER;
  rr.ttl=86400;
  rr.qtype=QType::SOA;
  rr.content="localhost. root 1 604800 86400 2419200 604800";
  
  ad.d_records.insert(rr);

  rr.qtype=QType::NS;
  rr.content="localhost.";

  ad.d_records.insert(rr);
  
  rr.qtype=QType::A;
  rr.content=ip;
  ad.d_records.insert(rr);
  
  if(newMap->count(rr.qname)) {  
    L<<Logger::Warning<<"Hosts file will not overwrite zone '"<<rr.qname<<"' already loaded"<<endl;
  }
  else {
    L<<Logger::Warning<<"Inserting forward zone '"<<rr.qname<<"' based on hosts file"<<endl;
    (*newMap)[rr.qname]=ad;
  }
}

//! parts[0] must be an IP address, the rest must be host names
static void makeIPToNamesZone(SyncRes::domainmap_t* newMap, const vector<string>& parts) 
{
  string address=parts[0];
  vector<string> ipparts;
  stringtok(ipparts, address,".");
  
  SyncRes::AuthDomain ad;
  DNSResourceRecord rr;
  for(int n=ipparts.size()-1; n>=0 ; --n) {
    rr.qname.append(ipparts[n]);
    rr.qname.append(1,'.');
  }
  rr.qname.append("in-addr.arpa.");

  rr.d_place=DNSResourceRecord::ANSWER;
  rr.ttl=86400;
  rr.qtype=QType::SOA;
  rr.content="localhost. root. 1 604800 86400 2419200 604800";
  
  ad.d_records.insert(rr);

  rr.qtype=QType::NS;
  rr.content="localhost.";

  ad.d_records.insert(rr);
  rr.qtype=QType::PTR;

  if(ipparts.size()==4)  // otherwise this is a partial zone
    for(unsigned int n=1; n < parts.size(); ++n) {
      rr.content=toCanonic("", parts[n]);
      ad.d_records.insert(rr);
    }

  if(newMap->count(rr.qname)) {  
    L<<Logger::Warning<<"Will not overwrite zone '"<<rr.qname<<"' already loaded"<<endl;
  }
  else {
    if(ipparts.size()==4)
      L<<Logger::Warning<<"Inserting reverse zone '"<<rr.qname<<"' based on hosts file"<<endl;
    (*newMap)[rr.qname]=ad;
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

void* pleaseWipeCache(const std::string& qname)
{
  t_RC->doWipeCache(qname); 
  return 0;
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
	broadcastFunction(boost::bind(pleaseWipeCache, j->qname));
    }

    string configname=::arg()["config-dir"]+"/recursor.conf";
    cleanSlashes(configname);
    
    if(!::arg().preParseFile(configname.c_str(), "forward-zones")) 
      L<<Logger::Warning<<"Unable to re-parse configuration file '"<<configname<<"'"<<endl;
    
    ::arg().preParseFile(configname.c_str(), "forward-zones-file");
    ::arg().preParseFile(configname.c_str(), "auth-zones");
    ::arg().preParseFile(configname.c_str(), "export-etc-hosts", "off");
    ::arg().preParseFile(configname.c_str(), "serve-rfc1918");

    SyncRes::domainmap_t* newDomainMap = parseAuthAndForwards();
    
    // purge again - new zones need to blank out the cache
    for(SyncRes::domainmap_t::const_iterator i = newDomainMap->begin(); i != newDomainMap->end(); ++i) {
      for(SyncRes::AuthDomain::records_t::const_iterator j = i->second.d_records.begin(); j != i->second.d_records.end(); ++j) 
	broadcastFunction(boost::bind(pleaseWipeCache, j->qname));
    }

    // this is pretty blunt
    broadcastFunction(pleaseWipeNegCache);
    broadcastFunction(boost::bind(pleaseUseNewSDomainsMap, newDomainMap)); 
    delete original;
    return "ok\n";
  }
  catch(std::exception& e) {
    L<<Logger::Error<<"Had error reloading zones, keeping original data: "<<e.what()<<endl;
  }
  catch(AhuException& ae) {
    L<<Logger::Error<<"Encountered error reloading zones, keeping original data: "<<ae.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Encountered unknown error reloading zones, keeping original data"<<endl;
  }
  return "reloading failed, see log\n";
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
    stringtok(parts, ::arg()[option_names[n]], ",\t\n\r");
    for(parts_t::const_iterator iter = parts.begin(); iter != parts.end(); ++iter) {
      SyncRes::AuthDomain ad;
      pair<string,string> headers=splitField(*iter, '=');
      trim(headers.first);
      trim(headers.second);
      headers.first=toCanonic("", headers.first);
      if(n==0) {
        L<<Logger::Error<<"Parsing authoritative data for zone '"<<headers.first<<"' from file '"<<headers.second<<"'"<<endl;
        ZoneParserTNG zpt(headers.second, headers.first);
        DNSResourceRecord rr;
        while(zpt.get(rr)) {
          try {
            string tmp=DNSRR2String(rr);
            rr=String2DNSRR(rr.qname, rr.qtype, tmp, rr.ttl);
          }
          catch(std::exception &e) {
	    delete newMap;
            throw AhuException("Error parsing record '"+rr.qname+"' of type "+rr.qtype.getName()+" in zone '"+headers.first+"' from file '"+headers.second+"': "+e.what());
          }
          catch(...) {
	    delete newMap;
            throw AhuException("Error parsing record '"+rr.qname+"' of type "+rr.qtype.getName()+" in zone '"+headers.first+"' from file '"+headers.second+"'");
          }

          ad.d_records.insert(rr);
        }
      }
      else {
        L<<Logger::Error<<"Redirecting queries for zone '"<<headers.first<<"' ";
        if(n == 2) {
          L<<"with recursion ";
          ad.d_rdForward = 1;
        }
        else ad.d_rdForward = 0;
        L<<"to: ";
        
        convertServersForAD(headers.second, ad, ";");
        if(n == 2) {
          ad.d_rdForward = 1;
        }
      }
      
      (*newMap)[headers.first]=ad; 
    }
  }
  
  if(!::arg()["forward-zones-file"].empty()) {
    L<<Logger::Warning<<"Reading zone forwarding information from '"<<::arg()["forward-zones-file"]<<"'"<<endl;
    SyncRes::AuthDomain ad;
    FILE *rfp=fopen(::arg()["forward-zones-file"].c_str(), "r");

    if(!rfp) {
      delete newMap;
      throw AhuException("Error opening forward-zones-file '"+::arg()["forward-zones-file"]+"': "+stringerror());
    }

    shared_ptr<FILE> fp=shared_ptr<FILE>(rfp, fclose);
    
    char line[1024];
    int linenum=0;
    uint64_t before = newMap->size();
    while(linenum++, fgets(line, sizeof(line)-1, fp.get())) {
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
        throw AhuException("Error parsing line "+lexical_cast<string>(linenum)+" of " +::arg()["forward-zones-file"]);
      }

      try {
        convertServersForAD(instructions, ad, ",; ", false);
      }
      catch(...) {
        delete newMap;
        throw AhuException("Conversion error parsing line "+lexical_cast<string>(linenum)+" of " +::arg()["forward-zones-file"]);
      }

      (*newMap)[toCanonic("", domain)]=ad;
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
	
	for(unsigned int n=1; n < parts.size(); ++n)
	  makeNameToIPZone(newMap, parts[n], parts[0]);
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

