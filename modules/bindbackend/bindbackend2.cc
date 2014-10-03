/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation; 

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

#include <errno.h>
#include <string>
#include <set>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <fcntl.h>
#include <sstream>
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include "pdns/dnsseckeeper.hh"
#include "pdns/dnssecinfra.hh"
#include "pdns/base32.hh"
#include "pdns/namespaces.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "bindbackend2.hh"
#include "pdns/dnspacket.hh"
#include "pdns/zoneparser-tng.hh"
#include "pdns/bindparserclasses.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/qtype.hh"
#include "pdns/misc.hh"
#include "pdns/dynlistener.hh"
#include "pdns/lock.hh"
#include "pdns/namespaces.hh"

/* 
   All instances of this backend share one s_state, which is indexed by zone name and zone id.
   The s_state is protected by a read/write lock, and the goal it to only interact with it briefly.
   When a query comes in, we take a read lock and COPY the best zone to answer from s_state (BB2DomainInfo object)
   All answers are served from this copy.

   To interact with s_state, use safeGetBBDomainInfo (search on name or id), safePutBBDomainInfo (to update)
   or safeRemoveBBDomainInfo. These all lock as they should.

   Several functions need to traverse s_state to get data for the rest of PowerDNS. When doing so,
   you need to manually take the s_state_lock (read).

   Parsing zones happens with parseZone(), which fills a BB2DomainInfo object. This can then be stored with safePutBBDomainInfo.

   Finally, the BB2DomainInfo contains all records as a LookButDontTouch object. This makes sure you only look, but don't touch, since
   the records might be in use in other places.
*/

Bind2Backend::state_t Bind2Backend::s_state;
int Bind2Backend::s_first=1;
bool Bind2Backend::s_ignore_broken_records=false;

pthread_rwlock_t Bind2Backend::s_state_lock=PTHREAD_RWLOCK_INITIALIZER;
pthread_mutex_t Bind2Backend::s_supermaster_config_lock=PTHREAD_MUTEX_INITIALIZER; // protects writes to config file
pthread_mutex_t Bind2Backend::s_startup_lock=PTHREAD_MUTEX_INITIALIZER;
string Bind2Backend::s_binddirectory;  

BB2DomainInfo::BB2DomainInfo()
{
  d_loaded=false;
  d_lastcheck=0;
  d_checknow=false;
  d_status="Unknown";
}

void BB2DomainInfo::setCheckInterval(time_t seconds)
{
  d_checkinterval=seconds;
}

bool BB2DomainInfo::current()
{
  if(d_checknow) {
    return false;
  }

  if(!d_checkinterval) 
    return true;

  if(time(0) - d_lastcheck < d_checkinterval) 
    return true;
  
  if(d_filename.empty())
    return true;

  return (getCtime()==d_ctime);
}

time_t BB2DomainInfo::getCtime()
{
  struct stat buf;
  
  if(d_filename.empty() || stat(d_filename.c_str(),&buf)<0)
    return 0; 
  d_lastcheck=time(0);
  return buf.st_ctime;
}

void BB2DomainInfo::setCtime()
{
  struct stat buf;
  if(stat(d_filename.c_str(),&buf)<0)
    return; 
  d_ctime=buf.st_ctime;
}

bool Bind2Backend::safeGetBBDomainInfo(int id, BB2DomainInfo* bbd)
{
  ReadLock rl(&s_state_lock);
  state_t::const_iterator iter = s_state.find(id);
  if(iter == s_state.end())
    return false;
  *bbd=*iter;
  return true;
}

bool Bind2Backend::safeGetBBDomainInfo(const std::string& name, BB2DomainInfo* bbd)
{
  ReadLock rl(&s_state_lock);
  typedef state_t::index<NameTag>::type nameindex_t;
  nameindex_t& nameindex = boost::multi_index::get<NameTag>(s_state);

  nameindex_t::const_iterator iter = nameindex.find(name);
  if(iter == nameindex.end())
    return false;
  *bbd=*iter;
  return true;
}

bool Bind2Backend::safeRemoveBBDomainInfo(const std::string& name)
{
  WriteLock rl(&s_state_lock);
  typedef state_t::index<NameTag>::type nameindex_t;
  nameindex_t& nameindex = boost::multi_index::get<NameTag>(s_state);

  nameindex_t::iterator iter = nameindex.find(name);
  if(iter == nameindex.end())
    return false;
  nameindex.erase(iter);
  return true;
}

void Bind2Backend::safePutBBDomainInfo(const BB2DomainInfo& bbd)
{
  WriteLock rl(&s_state_lock);
  replacing_insert(s_state, bbd);
}

void Bind2Backend::setNotified(uint32_t id, uint32_t serial)
{
  BB2DomainInfo bbd;
  safeGetBBDomainInfo(id, &bbd);
  bbd.d_lastnotified = serial;
  safePutBBDomainInfo(bbd);
}

void Bind2Backend::setFresh(uint32_t domain_id)
{
  BB2DomainInfo bbd;
  if(safeGetBBDomainInfo(domain_id, &bbd)) {
    bbd.d_lastcheck=time(0);
    safePutBBDomainInfo(bbd);
  }
}

bool Bind2Backend::startTransaction(const string &qname, int id)
{
  if(id < 0) {
    d_transaction_tmpname.clear();
    d_transaction_id=id;
    return true;
  }
  if(id == 0) {
    throw DBException("domain_id 0 is invalid for this backend.");
  }

  d_transaction_id=id;
  BB2DomainInfo bbd;
  if(safeGetBBDomainInfo(id, &bbd)) {
    d_transaction_tmpname=bbd.d_filename+"."+itoa(random());
    d_of=new ofstream(d_transaction_tmpname.c_str());
    if(!*d_of) {
      throw DBException("Unable to open temporary zonefile '"+d_transaction_tmpname+"': "+stringerror());
      unlink(d_transaction_tmpname.c_str());
      delete d_of;
      d_of=0;
    }
    
    *d_of<<"; Written by PowerDNS, don't edit!"<<endl;
    *d_of<<"; Zone '"+bbd.d_name+"' retrieved from master "<<endl<<"; at "<<nowTime()<<endl; // insert master info here again
    
    return true;
  }
  return false;
}

bool Bind2Backend::commitTransaction()
{
  if(d_transaction_id < 0)
    return true;
  delete d_of;
  d_of=0;

  BB2DomainInfo bbd;
  if(safeGetBBDomainInfo(d_transaction_id, &bbd)) {
    if(rename(d_transaction_tmpname.c_str(), bbd.d_filename.c_str())<0)
    throw DBException("Unable to commit (rename to: '" + bbd.d_filename+"') AXFRed zone: "+stringerror());
    queueReloadAndStore(bbd.d_id);
  }

  d_transaction_id=0;

  return true;
}

bool Bind2Backend::abortTransaction()
{
  // -1 = dnssec speciality
  // 0  = invalid transact
  // >0 = actual transaction
  if(d_transaction_id > 0) {
    delete d_of;
    d_of=0;
    unlink(d_transaction_tmpname.c_str());
    d_transaction_id=0;
  }

  return true;
}

bool Bind2Backend::feedRecord(const DNSResourceRecord &r, string *ordername)
{
  string qname=r.qname;

  BB2DomainInfo bbd;
  safeGetBBDomainInfo(d_transaction_id, &bbd);

  string domain = bbd.d_name;

  if(!stripDomainSuffix(&qname,domain)) 
    throw DBException("out-of-zone data '"+qname+"' during AXFR of zone '"+domain+"'");

  string content=r.content;

  // SOA needs stripping too! XXX FIXME - also, this should not be here I think
  switch(r.qtype.getCode()) {
  case QType::MX:
    if(!stripDomainSuffix(&content, domain))
      content+=".";
    *d_of<<qname<<"\t"<<r.ttl<<"\t"<<r.qtype.getName()<<"\t"<<r.priority<<"\t"<<content<<endl;
    break;
  case QType::SRV:
    if(!stripDomainSuffix(&content, domain))
      content+=".";
    *d_of<<qname<<"\t"<<r.ttl<<"\t"<<r.qtype.getName()<<"\t"<<r.priority<<"\t"<<content<<endl;
    break;
  case QType::CNAME:
  case QType::NS:
    if(!stripDomainSuffix(&content, domain))
      content+=".";
    *d_of<<qname<<"\t"<<r.ttl<<"\t"<<r.qtype.getName()<<"\t"<<content<<endl;
    break;
  default:
    *d_of<<qname<<"\t"<<r.ttl<<"\t"<<r.qtype.getName()<<"\t"<<r.content<<endl;
    break;
  }
  return true;
}

void Bind2Backend::getUpdatedMasters(vector<DomainInfo> *changedDomains)
{
  vector<DomainInfo> consider;
  {
    ReadLock rl(&s_state_lock);

    for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
      if(!i->d_masters.empty() && this->alsoNotify.empty() && i->d_also_notify.empty())
        continue;

      DomainInfo di;
      di.id=i->d_id;
      di.zone=i->d_name;
      di.last_check=i->d_lastcheck;
      di.notified_serial=i->d_lastnotified;
      di.backend=this;
      di.kind=DomainInfo::Master;
      consider.push_back(di);
    }
  }

  SOAData soadata;
  BOOST_FOREACH(DomainInfo& di, consider) {
    soadata.serial=0;
    try {
      this->getSOA(di.zone, soadata); // we might not *have* a SOA yet, but this might trigger a load of it
    }
    catch(...) {
      continue;
    }
    if(di.notified_serial != soadata.serial) {
      BB2DomainInfo bbd;
      if(safeGetBBDomainInfo(di.id, &bbd)) {
        bbd.d_lastnotified=soadata.serial;
        safePutBBDomainInfo(bbd);
      }
      if(di.notified_serial)  { // don't do notification storm on startup
        di.serial=soadata.serial;
        changedDomains->push_back(di);
      }
    }
  }
}

void Bind2Backend::getAllDomains(vector<DomainInfo> *domains, bool include_disabled) 
{
  SOAData soadata;

  // prevent deadlock by using getSOA() later on
  {
    ReadLock rl(&s_state_lock);

    for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
      DomainInfo di;
      di.id=i->d_id;
      di.zone=i->d_name;
      di.last_check=i->d_lastcheck;
      di.kind=i->d_masters.empty() ? DomainInfo::Master : DomainInfo::Slave; //TODO: what about Native?
      di.backend=this;
      domains->push_back(di);
    };
  }
 
  BOOST_FOREACH(DomainInfo &di, *domains) {
    soadata.db=(DNSBackend *)-1; // makes getSOA() skip the cache. 
    this->getSOA(di.zone, soadata);
    di.serial=soadata.serial;
  }
}

void Bind2Backend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  vector<DomainInfo> domains;
  {
    ReadLock rl(&s_state_lock);
    for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
      if(i->d_masters.empty())
        continue;
      DomainInfo sd;
      sd.id=i->d_id;
      sd.zone=i->d_name;
      sd.masters=i->d_masters;
      sd.last_check=i->d_lastcheck;
      sd.backend=this;
      sd.kind=DomainInfo::Slave;
      domains.push_back(sd);
    }
  }

  BOOST_FOREACH(DomainInfo &sd, domains) {
    SOAData soadata;
    soadata.refresh=0;
    soadata.serial=0;
    soadata.db=(DNSBackend *)-1; // not sure if this is useful, inhibits any caches that might be around
    try {
      getSOA(sd.zone,soadata); // we might not *have* a SOA yet
    }
    catch(...){}
    sd.serial=soadata.serial;
    if(sd.last_check+soadata.refresh < (unsigned int)time(0))
      unfreshDomains->push_back(sd);    
  }
}

bool Bind2Backend::getDomainInfo(const string &domain, DomainInfo &di)
{
  BB2DomainInfo bbd;
  if(!safeGetBBDomainInfo(domain, &bbd))
    return false;

  di.id=bbd.d_id;
  di.zone=domain;
  di.masters=bbd.d_masters;
  di.last_check=bbd.d_lastcheck;
  di.backend=this;
  di.kind=bbd.d_masters.empty() ? DomainInfo::Master : DomainInfo::Slave;
  di.serial=0;
  try {
    SOAData sd;
    sd.serial=0;
    
    getSOA(bbd.d_name,sd); // we might not *have* a SOA yet
    di.serial=sd.serial;
  }
  catch(...){}
  
  return true;
}

void Bind2Backend::alsoNotifies(const string &domain, set<string> *ips)
{
  // combine global list with local list
  for(set<string>::iterator i = this->alsoNotify.begin(); i != this->alsoNotify.end(); i++) {
    (*ips).insert(*i);
  }
  ReadLock rl(&s_state_lock);  
  for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
    if(pdns_iequals(i->d_name,domain)) {
      for(set<string>::iterator it = i->d_also_notify.begin(); it != i->d_also_notify.end(); it++) {
        (*ips).insert(*it);
      }
      return;
    }
  }   
}

// only parses, does NOT add to s_state!
void Bind2Backend::parseZoneFile(BB2DomainInfo *bbd) 
{
  NSEC3PARAMRecordContent ns3pr;
  bool nsec3zone;
  if (d_hybrid) {
    DNSSECKeeper dk;
    nsec3zone=dk.getNSEC3PARAM(bbd->d_name, &ns3pr);
  } else
    nsec3zone=getNSEC3PARAM(bbd->d_name, &ns3pr);

  bbd->d_records = shared_ptr<recordstorage_t>(new recordstorage_t());
        
  ZoneParserTNG zpt(bbd->d_filename, bbd->d_name, s_binddirectory);
  DNSResourceRecord rr;
  string hashed;
  while(zpt.get(rr)) { 
    if(rr.qtype.getCode() == QType::NSEC || rr.qtype.getCode() == QType::NSEC3)
      continue; // we synthesise NSECs on demand

    if(nsec3zone) {
      if(rr.qtype.getCode() != QType::NSEC3 && rr.qtype.getCode() != QType::RRSIG)
        hashed=toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, rr.qname));
      else
        hashed="";
    }
    insertRecord(*bbd, rr.qname, rr.qtype, rr.content, rr.ttl, rr.priority, hashed);
  }
  fixupAuth(bbd->d_records.getWRITABLE());
  doEmptyNonTerminals(*bbd, nsec3zone, ns3pr);
  bbd->setCtime();
  bbd->d_loaded=true; 
  bbd->d_checknow=false;
  bbd->d_status="parsed into memory at "+nowTime();
}

/** THIS IS AN INTERNAL FUNCTION! It does moadnsparser prio impedance matching
    Much of the complication is due to the efforts to benefit from std::string reference counting copy on write semantics */
void Bind2Backend::insertRecord(BB2DomainInfo& bb2, const string &qnameu, const QType &qtype, const string &content, int ttl, int prio, const std::string& hashed, bool *auth)
{
  Bind2DNSRecord bdr;
  shared_ptr<recordstorage_t> records = bb2.d_records.getWRITABLE();
  bdr.qname=toLowerCanonic(qnameu);

  if(bb2.d_name.empty())
    ;
  else if(dottedEndsOn(bdr.qname, bb2.d_name))
    bdr.qname.resize(max(0, static_cast<int>(bdr.qname.length() - (bb2.d_name.length() + 1))));
  else {
    string msg = "Trying to insert non-zone data, name='"+bdr.qname+"', qtype="+qtype.getName()+", zone='"+bb2.d_name+"'";
    if(s_ignore_broken_records) {
        L<<Logger::Warning<<msg<< " ignored" << endl;
        return;
    }
    else
      throw PDNSException(msg);
  }

  bdr.qname.swap(bdr.qname);

  if(!records->empty() && bdr.qname==boost::prior(records->end())->qname)
    bdr.qname=boost::prior(records->end())->qname;

  bdr.qname=labelReverse(bdr.qname);
  bdr.qtype=qtype.getCode();
  bdr.content=content; 
  bdr.nsec3hash = hashed;
  
  if (auth) // Set auth on empty non-terminals
    bdr.auth=*auth;
  else
    bdr.auth=true;

  if(bdr.qtype == QType::MX || bdr.qtype == QType::SRV) { 
    prio=atoi(bdr.content.c_str());
    
    string::size_type pos = bdr.content.find_first_not_of("0123456789");
    if(pos != string::npos)
      boost::erase_head(bdr.content, pos);
    trim_left(bdr.content);
  }
  
  if(bdr.qtype==QType::CNAME || bdr.qtype==QType::MX || bdr.qtype==QType::NS || bdr.qtype==QType::AFSDB)
    bdr.content=toLowerCanonic(bdr.content); // I think this is wrong, the zoneparser should not come up with . terminated stuff XXX FIXME

  bdr.ttl=ttl;
  bdr.priority=prio;  
  records->insert(bdr);
}

string Bind2Backend::DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  ostringstream ret;

  for(vector<string>::const_iterator i=parts.begin()+1;i<parts.end();++i) {
    BB2DomainInfo bbd;
    if(safeGetBBDomainInfo(*i, &bbd)) {
      Bind2Backend bb2;
      bb2.queueReloadAndStore(bbd.d_id);
      ret<< *i << ": "<< (bbd.d_loaded ? "": "[rejected]") <<"\t"<<bbd.d_status<<"\n";      
    }
    else
      ret<< *i << " no such domain\n";
  }    
  if(ret.str().empty())
    ret<<"no domains reloaded";
  return ret.str();
}


string Bind2Backend::DLDomStatusHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  ostringstream ret;
      
  if(parts.size() > 1) {
    for(vector<string>::const_iterator i=parts.begin()+1;i<parts.end();++i) {
      BB2DomainInfo bbd;
      if(safeGetBBDomainInfo(*i, &bbd)) {	
        ret<< *i << ": "<< (bbd.d_loaded ? "": "[rejected]") <<"\t"<<bbd.d_status<<"\n";      
    }
      else
        ret<< *i << " no such domain\n";
    }    
  }
  else {
    ReadLock rl(&s_state_lock);
    for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
      ret<< i->d_name << ": "<< (i->d_loaded ? "": "[rejected]") <<"\t"<<i->d_status<<"\n";      
    }
  }

  if(ret.str().empty())
    ret<<"no domains passed";

  return ret.str();
}

string Bind2Backend::DLListRejectsHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  ostringstream ret;
  ReadLock rl(&s_state_lock);
  for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
    if(!i->d_loaded)
      ret<<i->d_name<<"\t"<<i->d_status<<endl;
  }
  return ret.str();
}

string Bind2Backend::DLAddDomainHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  if(parts.size() < 3)
    return "ERROR: Domain name and zone filename are required";

  string domainname = toLowerCanonic(parts[1]);
  const string &filename = parts[2];
  BB2DomainInfo bbd;
  if(safeGetBBDomainInfo(domainname, &bbd))
    return "Already loaded";
  Bind2Backend bb2; // createdomainentry needs access to our configuration
  bbd=bb2.createDomainEntry(domainname, filename);
  bbd.d_filename=filename;
  bbd.d_checknow=true;
  bbd.d_loaded=true;
  bbd.d_lastcheck=0;
  bbd.d_status="parsing into memory";

  safePutBBDomainInfo(bbd);

  L<<Logger::Warning<<"Zone "<<domainname<< " loaded"<<endl;
  return "Loaded zone " + domainname + " from " + filename;
}

Bind2Backend::Bind2Backend(const string &suffix, bool loadZones)
{
  setArgPrefix("bind"+suffix);
  d_logprefix="[bind"+suffix+"backend]";
  d_hybrid=mustDo("hybrid");
  s_ignore_broken_records=mustDo("ignore-broken-records");

  if (!loadZones && d_hybrid)
    return;

  Lock l(&s_startup_lock);
  
  d_transaction_id=0;
  setupDNSSEC();
  if(!s_first) {
    return;
  }
  
  if(loadZones) {
    loadConfig();
    s_first=0;
  }
  
  extern DynListener *dl;
  dl->registerFunc("BIND-RELOAD-NOW", &DLReloadNowHandler, "bindbackend: reload domains", "<domains>");
  dl->registerFunc("BIND-DOMAIN-STATUS", &DLDomStatusHandler, "bindbackend: list status of all domains", "[domains]");
  dl->registerFunc("BIND-LIST-REJECTS", &DLListRejectsHandler, "bindbackend: list rejected domains");
  dl->registerFunc("BIND-ADD-ZONE", &DLAddDomainHandler, "bindbackend: add zone", "<domain> <filename>");
}

Bind2Backend::~Bind2Backend()
{}

void Bind2Backend::rediscover(string *status)
{
  loadConfig(status);
}

void Bind2Backend::reload()
{
  WriteLock rwl(&s_state_lock);
  for(state_t::iterator i = s_state.begin(); i != s_state.end() ; ++i) {
    i->d_checknow=true; // being a bit cheeky here, don't index state_t on this (mutable)
  }
}

void Bind2Backend::fixupAuth(shared_ptr<recordstorage_t> records)
{
  pair<recordstorage_t::const_iterator, recordstorage_t::const_iterator> range;
  string sqname;
  
  recordstorage_t nssets;
  BOOST_FOREACH(const Bind2DNSRecord& bdr, *records) {
    if(bdr.qtype==QType::NS) 
      nssets.insert(bdr);
  }
  
  BOOST_FOREACH(const Bind2DNSRecord& bdr, *records) {
    bdr.auth=true;
    
    if(bdr.qtype == QType::DS) // as are delegation signer records
      continue;

    sqname = labelReverse(bdr.qname);
    
    do {
      if(sqname.empty()) // this is auth of course!
        continue; 
      if(bdr.qtype == QType::NS || nssets.count(sqname)) { // NS records which are not apex are unauth by definition
        bdr.auth=false;
      }
    } while(chopOff(sqname));
  }
}

void Bind2Backend::doEmptyNonTerminals(BB2DomainInfo& bbd, bool nsec3zone, NSEC3PARAMRecordContent ns3pr)
{
  shared_ptr<const recordstorage_t> records = bbd.d_records.get();
  bool auth, doent=true;
  set<string> qnames;
  map<string, bool> nonterm;
  string shorter, hashed;

  uint32_t maxent = ::arg().asNum("max-ent-entries");

  BOOST_FOREACH(const Bind2DNSRecord& bdr, *records)
    qnames.insert(labelReverse(bdr.qname));

  BOOST_FOREACH(const Bind2DNSRecord& bdr, *records) {
    shorter=labelReverse(bdr.qname);

    if (!bdr.auth && bdr.qtype == QType::NS)
      auth=(!nsec3zone || !ns3pr.d_flags);
    else
      auth=bdr.auth;

    while(chopOff(shorter))
    {
      if(!qnames.count(shorter))
      {
        if(!(maxent))
        {
          L<<Logger::Error<<"Zone '"<<bbd.d_name<<"' has too many empty non terminals."<<endl;
          doent=false;
          break;
        }

        if (!nonterm.count(shorter)) {
          nonterm.insert(pair<string, bool>(shorter, auth));
          --maxent;
        } else if (auth)
          nonterm[shorter]=true;
      }
    }
    if(!doent)
      return;
  }

  DNSResourceRecord rr;
  rr.qtype="#0";
  rr.content="";
  rr.ttl=0;
  rr.priority=0;
  pair<string, bool> nt;
  BOOST_FOREACH(nt, nonterm)
  {
    rr.qname=nt.first+"."+bbd.d_name+".";
    if(nsec3zone)
      hashed=toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, rr.qname));
    insertRecord(bbd, rr.qname, rr.qtype, rr.content, rr.ttl, rr.priority, hashed, &nt.second);
  }
}

void Bind2Backend::loadConfig(string* status)
{
  static int domain_id=1;

  if(!getArg("config").empty()) {
    BindParser BP;
    try {
      BP.parse(getArg("config"));
    }
    catch(PDNSException &ae) {
      L<<Logger::Error<<"Error parsing bind configuration: "<<ae.reason<<endl;
      throw;
    }
      
    vector<BindDomainInfo> domains=BP.getDomains();
    this->alsoNotify = BP.getAlsoNotify();

    s_binddirectory=BP.getDirectory();
    //    ZP.setDirectory(d_binddirectory);

    L<<Logger::Warning<<d_logprefix<<" Parsing "<<domains.size()<<" domain(s), will report when done"<<endl;
    
    set<string> oldnames, newnames;
    {
      ReadLock rl(&s_state_lock);
      BOOST_FOREACH(const BB2DomainInfo& bbd, s_state) {
        oldnames.insert(bbd.d_name);
      }
    }
    int rejected=0;
    int newdomains=0;

    struct stat st;
      
    for(vector<BindDomainInfo>::iterator i=domains.begin(); i!=domains.end(); ++i) 
    {
      if(stat(i->filename.c_str(), &st) == 0) {
        i->d_dev = st.st_dev;
        i->d_ino = st.st_ino;
      }
    }

    sort(domains.begin(), domains.end()); // put stuff in inode order
    for(vector<BindDomainInfo>::const_iterator i=domains.begin();
        i!=domains.end();
        ++i) 
      {
        if(i->type!="master" && i->type!="slave") {
          L<<Logger::Warning<<d_logprefix<<" Warning! Skipping '"<<i->type<<"' zone '"<<i->name<<"'"<<endl;
          continue;
        }

        BB2DomainInfo bbd;

        if(!safeGetBBDomainInfo(i->name, &bbd)) { 
          bbd.d_id=domain_id++;
          bbd.setCheckInterval(getArgAsNum("check-interval"));
          bbd.d_lastnotified=0;
          bbd.d_loaded=false;
        }
        
        // overwrite what we knew about the domain
        bbd.d_name=toLowerCanonic(i->name);
        bool filenameChanged = (bbd.d_filename!=i->filename);
        bbd.d_filename=i->filename;
        bbd.d_masters=i->masters;
        bbd.d_also_notify=i->alsoNotify;

        newnames.insert(bbd.d_name);
        if(filenameChanged || !bbd.d_loaded || !bbd.current()) {
          L<<Logger::Info<<d_logprefix<<" parsing '"<<i->name<<"' from file '"<<i->filename<<"'"<<endl;

          try {
            parseZoneFile(&bbd);
          }
          catch(PDNSException &ae) {
            ostringstream msg;
            msg<<" error at "+nowTime()+" parsing '"<<i->name<<"' from file '"<<i->filename<<"': "<<ae.reason;

            if(status)
              *status+=msg.str();
	    bbd.d_status=msg.str();

            L<<Logger::Warning<<d_logprefix<<msg.str()<<endl;
            rejected++;
          }
          catch(std::exception &ae) {
            ostringstream msg;
            msg<<" error at "+nowTime()+" parsing '"<<i->name<<"' from file '"<<i->filename<<"': "<<ae.what();

            if(status)
              *status+=msg.str();
            bbd.d_status=msg.str();
            L<<Logger::Warning<<d_logprefix<<msg.str()<<endl;
            rejected++;
          }
	  safePutBBDomainInfo(bbd);
	  
        }
      }
    vector<string> diff;

    set_difference(oldnames.begin(), oldnames.end(), newnames.begin(), newnames.end(), back_inserter(diff));
    unsigned int remdomains=diff.size();
    
    BOOST_FOREACH(const std::string& name, diff) {
      safeRemoveBBDomainInfo(name);
    }

    // count number of entirely new domains
    diff.clear();
    set_difference(newnames.begin(), newnames.end(), oldnames.begin(), oldnames.end(), back_inserter(diff));
    newdomains=diff.size();

    ostringstream msg;
    msg<<" Done parsing domains, "<<rejected<<" rejected, "<<newdomains<<" new, "<<remdomains<<" removed"; 
    if(status)
      *status=msg.str();

    L<<Logger::Error<<d_logprefix<<msg.str()<<endl;
  }
}

void Bind2Backend::queueReloadAndStore(unsigned int id)
{
  BB2DomainInfo bbold;
  try {
    if(!safeGetBBDomainInfo(id, &bbold))
      return;
    parseZoneFile(&bbold);
    bbold.d_checknow=false;
    safePutBBDomainInfo(bbold);
    L<<Logger::Warning<<"Zone '"<<bbold.d_name<<"' ("<<bbold.d_filename<<") reloaded"<<endl;
  }
  catch(PDNSException &ae) {
    ostringstream msg;
    msg<<" error at "+nowTime()+" parsing '"<<bbold.d_name<<"' from file '"<<bbold.d_filename<<"': "<<ae.reason;
    bbold.d_status=msg.str();
    safePutBBDomainInfo(bbold);
  }
  catch(std::exception &ae) {
    ostringstream msg;
    msg<<" error at "+nowTime()+" parsing '"<<bbold.d_name<<"' from file '"<<bbold.d_filename<<"': "<<ae.what();
    bbold.d_status=msg.str();
    safePutBBDomainInfo(bbold);
  }
}

bool Bind2Backend::findBeforeAndAfterUnhashed(BB2DomainInfo& bbd, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)
{
  string domain=toLower(qname);
  shared_ptr<const recordstorage_t> records = bbd.d_records.get();
  recordstorage_t::const_iterator iter = records->upper_bound(domain);

  if (before.empty()){
    //cout<<"starting before for: '"<<domain<<"'"<<endl;
    iter = records->upper_bound(domain);

    while(iter == records->end() || (iter->qname) > domain || (!(iter->auth) && (!(iter->qtype == QType::NS))) || (!(iter->qtype)))
      iter--;

    before=iter->qname;
  }
  else {
    before=domain;
  }

  //cerr<<"Now after"<<endl;
  iter = records->upper_bound(domain);

  if(iter == records->end()) {
    //cerr<<"\tFound the end, begin storage: '"<<bbd.d_records->begin()->qname<<"', '"<<bbd.d_name<<"'"<<endl;
    after.clear(); // this does the right thing (i.e. point to apex, which is sure to have auth records)
  } else {
    //cerr<<"\tFound: '"<<(iter->qname)<<"' (nsec3hash='"<<(iter->nsec3hash)<<"')"<<endl;
    // this iteration is theoretically unnecessary - glue always sorts right behind a delegation
    // so we will never get here. But let's do it anyway.
    while((!(iter->auth) && (!(iter->qtype == QType::NS))) || (!(iter->qtype)))
    {
      iter++;
      if(iter == records->end())
      {
        after.clear();
        break;
      }
    }
    after = (iter)->qname;
  }

  //cerr<<"Before: '"<<before<<"', after: '"<<after<<"'\n";
  return true;
}

bool Bind2Backend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)
{
  BB2DomainInfo bbd;
  safeGetBBDomainInfo(id, &bbd);

  NSEC3PARAMRecordContent ns3pr;
  string auth=bbd.d_name;
    
  bool nsec3zone;
  if (d_hybrid) {
    DNSSECKeeper dk;
    nsec3zone=dk.getNSEC3PARAM(auth, &ns3pr);
  } else
    nsec3zone=getNSEC3PARAM(auth, &ns3pr);

  if(!nsec3zone) {
    //cerr<<"in bind2backend::getBeforeAndAfterAbsolute: no nsec3 for "<<auth<<endl;
    return findBeforeAndAfterUnhashed(bbd, qname, unhashed, before, after);
  
  }
  else {
    string lqname = toLower(qname);
    // cerr<<"\nin bind2backend::getBeforeAndAfterAbsolute: nsec3 HASH for "<<auth<<", asked for: "<<lqname<< " (auth: "<<auth<<".)"<<endl;
    typedef recordstorage_t::index<HashedTag>::type records_by_hashindex_t;
    records_by_hashindex_t& hashindex=boost::multi_index::get<HashedTag>(*bbd.d_records.getWRITABLE()); // needlessly dangerous
    
//    BOOST_FOREACH(const Bind2DNSRecord& bdr, hashindex) {
//      cerr<<"Hash: "<<bdr.nsec3hash<<"\t"<< (lqname < bdr.nsec3hash) <<endl;
//    }

    records_by_hashindex_t::const_iterator iter;
    bool wraponce;

    if (before.empty()) {
      iter = hashindex.upper_bound(lqname);

      if(iter != hashindex.begin() && (iter == hashindex.end() || iter->nsec3hash > lqname))
      {
        iter--;
      }

      if(iter == hashindex.begin() && (iter->nsec3hash > lqname))
      {
        iter = hashindex.end();
      }

      wraponce = false;
      while(iter == hashindex.end() || (!iter->auth && !(iter->qtype == QType::NS && !pdns_iequals(iter->qname, auth) && !ns3pr.d_flags)) || iter->nsec3hash.empty())
      {
        iter--;
        if(iter == hashindex.begin()) {
          if (!wraponce) {
            iter = hashindex.end();
            wraponce = true;
          }
          else {
            before.clear();
            after.clear();
            return false;
          }
        }
      }

      before = iter->nsec3hash;
      unhashed = dotConcat(labelReverse(iter->qname), auth);
      // cerr<<"before: "<<(iter->nsec3hash)<<"/"<<(iter->qname)<<endl;
    }
    else {
      before = lqname;
    }

    iter = hashindex.upper_bound(lqname);
    if(iter == hashindex.end())
    {
      iter = hashindex.begin();
    }

    wraponce = false;
    while((!iter->auth && !(iter->qtype == QType::NS && !pdns_iequals(iter->qname, auth) && !ns3pr.d_flags)) || iter->nsec3hash.empty())
    {
      iter++;
      if(iter == hashindex.end()) {
        if (!wraponce) {
          iter = hashindex.begin();
          wraponce = true;
        }
        else {
          before.clear();
          after.clear();
          return false;
        }
      }
    }

    after = iter->nsec3hash;
    // cerr<<"after: "<<(iter->nsec3hash)<<"/"<<(iter->qname)<<endl;
    //cerr<<"Before: '"<<before<<"', after: '"<<after<<"'\n";
    return true;
  }
}

void Bind2Backend::lookup(const QType &qtype, const string &qname, DNSPacket *pkt_p, int zoneId )
{
  d_handle.reset();
  string domain=toLower(qname);

  static bool mustlog=::arg().mustDo("query-logging");
  if(mustlog) 
    L<<Logger::Warning<<"Lookup for '"<<qtype.getName()<<"' of '"<<domain<<"'"<<endl;
  bool found=false;
  BB2DomainInfo bbd;
  do {
    found = safeGetBBDomainInfo(domain, &bbd);
  } while ((!found || (zoneId != (int)bbd.d_id && zoneId != -1)) && chopOff(domain));

  if(!found) {
    if(mustlog)
      L<<Logger::Warning<<"Found no authoritative zone for "<<qname<<endl;
    d_handle.d_list=false;
    return;
  }

  if(mustlog)
    L<<Logger::Warning<<"Found a zone '"<<domain<<"' (with id " << bbd.d_id<<") that might contain data "<<endl;
    
  d_handle.id=bbd.d_id;
  
  DLOG(L<<"Bind2Backend constructing handle for search for "<<qtype.getName()<<" for "<<
       qname<<endl);
  
  if(domain.empty())
    d_handle.qname=qname;
  else if(strcasecmp(qname.c_str(),domain.c_str()))
    d_handle.qname=qname.substr(0,qname.size()-domain.length()-1); // strip domain name

  d_handle.qtype=qtype;
  d_handle.domain=qname.substr(qname.size()-domain.length());

  if(!bbd.d_loaded) {
    d_handle.reset();
    throw DBException("Zone for '"+bbd.d_name+"' in '"+bbd.d_filename+"' temporarily not available (file missing, or master dead)"); // fsck
  }
    
  if(!bbd.current()) {
    L<<Logger::Warning<<"Zone '"<<bbd.d_name<<"' ("<<bbd.d_filename<<") needs reloading"<<endl;
    queueReloadAndStore(bbd.d_id);
    if (!safeGetBBDomainInfo(domain, &bbd))
      throw DBException("Zone '"+bbd.d_name+"' ("+bbd.d_filename+") gone after reload"); // if we don't throw here, we crash for some reason
  }

  d_handle.d_records = bbd.d_records.get();
  
  if(d_handle.d_records->empty())
    DLOG(L<<"Query with no results"<<endl);

  pair<recordstorage_t::const_iterator, recordstorage_t::const_iterator> range;

  string lname=labelReverse(toLower(d_handle.qname));
  //cout<<"starting equal range for: '"<<d_handle.qname<<"', search is for: '"<<lname<<"'"<<endl;
 
  range = d_handle.d_records->equal_range(lname);
  //cout<<"End equal range"<<endl;
  d_handle.mustlog = mustlog;
  
  if(range.first==range.second) {
    // cerr<<"Found nothing!"<<endl;
    d_handle.d_list=false;
    d_handle.d_iter = d_handle.d_end_iter  = range.first;
    return;
  }
  else {
    // cerr<<"Found something!"<<endl;
    d_handle.d_iter=range.first;
    d_handle.d_end_iter=range.second;
  }

  d_handle.d_list=false;
}

Bind2Backend::handle::handle()
{
  mustlog=false;
}

bool Bind2Backend::get(DNSResourceRecord &r)
{
  if(!d_handle.d_records) {
    if(d_handle.mustlog)
      L<<Logger::Warning<<"There were no answers"<<endl;
    return false;
  }

  if(!d_handle.get(r)) {
    if(d_handle.mustlog)
      L<<Logger::Warning<<"End of answers"<<endl;

    d_handle.reset();

    return false;
  }
  if(d_handle.mustlog)
    L<<Logger::Warning<<"Returning: '"<<r.qtype.getName()<<"' of '"<<r.qname<<"', content: '"<<r.content<<"', prio: "<<r.priority<<endl;
  return true;
}

bool Bind2Backend::handle::get(DNSResourceRecord &r)
{
  if(d_list)
    return get_list(r);
  else
    return get_normal(r);
}

void Bind2Backend::handle::reset()
{
  d_records.reset();
  qname.clear();
  mustlog=false;
}

//#define DLOG(x) x
bool Bind2Backend::handle::get_normal(DNSResourceRecord &r)
{
  DLOG(L << "Bind2Backend get() was called for "<<qtype.getName() << " record for '"<<
       qname<<"' - "<<d_records->size()<<" available in total!"<<endl);
  
  if(d_iter==d_end_iter) {
    return false;
  }

  while(d_iter!=d_end_iter && !(qtype.getCode()==QType::ANY || (d_iter)->qtype==qtype.getCode())) {
    DLOG(L<<Logger::Warning<<"Skipped "<<qname<<"/"<<QType(d_iter->qtype).getName()<<": '"<<d_iter->content<<"'"<<endl);
    d_iter++;
  }
  if(d_iter==d_end_iter) {
    return false;
  }
  DLOG(L << "Bind2Backend get() returning a rr with a "<<QType(d_iter->qtype).getCode()<<endl);

  r.qname=qname.empty() ? domain : (qname+"."+domain);
  r.domain_id=id;
  r.content=(d_iter)->content;
  //  r.domain_id=(d_iter)->domain_id;
  r.qtype=(d_iter)->qtype;
  r.ttl=(d_iter)->ttl;
  r.priority=(d_iter)->priority;

  //if(!d_iter->auth && r.qtype.getCode() != QType::A && r.qtype.getCode()!=QType::AAAA && r.qtype.getCode() != QType::NS)
  //  cerr<<"Warning! Unauth response for qtype "<< r.qtype.getName() << " for '"<<r.qname<<"'"<<endl;
  r.auth = d_iter->auth;

  d_iter++;

  return true;
}

bool Bind2Backend::list(const string &target, int id, bool include_disabled)
{
  BB2DomainInfo bbd;
  
  if(!safeGetBBDomainInfo(id, &bbd))
    return false;

  d_handle.reset(); 
  DLOG(L<<"Bind2Backend constructing handle for list of "<<id<<endl);

  d_handle.d_records=bbd.d_records.get(); // give it a copy, which will stay around
  d_handle.d_qname_iter= d_handle.d_records->begin();
  d_handle.d_qname_end=d_handle.d_records->end();   // iter now points to a vector of pointers to vector<BBResourceRecords>

  d_handle.id=id;
  d_handle.d_list=true;
  return true;
}

bool Bind2Backend::handle::get_list(DNSResourceRecord &r)
{
  if(d_qname_iter!=d_qname_end) {
    r.qname=d_qname_iter->qname.empty() ? domain : (labelReverse(d_qname_iter->qname)+"."+domain);
    r.domain_id=id;
    r.content=(d_qname_iter)->content;
    r.qtype=(d_qname_iter)->qtype;
    r.ttl=(d_qname_iter)->ttl;
    r.priority=(d_qname_iter)->priority;
    r.auth = d_qname_iter->auth;
    d_qname_iter++;
    return true;
  }
  return false;
}

bool Bind2Backend::isMaster(const string &name, const string &ip)
{
  BB2DomainInfo bbd;
  if(!safeGetBBDomainInfo(name, &bbd))
    return false;

  for(vector<string>::const_iterator iter = bbd.d_masters.begin(); iter != bbd.d_masters.end(); ++iter)
    if(*iter==ip)
      return true;
  
  return false;
}

bool Bind2Backend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db)
{
  // Check whether we have a configfile available.
  if (getArg("supermaster-config").empty())
    return false;

  ifstream c_if(getArg("supermasters").c_str(), std::ios::in); // this was nocreate?
  if (!c_if) {
    L << Logger::Error << "Unable to open supermasters file for read: " << stringerror() << endl;
    return false;
  }

  // Format:
  // <ip> <accountname>
  string line, sip, saccount;
  while (getline(c_if, line)) {
    std::istringstream ii(line);
    ii >> sip;
    if (sip == ip) {
      ii >> saccount;
      break;
    }
  } 
  c_if.close();

  if (sip != ip)  // ip not found in authorization list - reject
    return false;
  
  // ip authorized as supermaster - accept
  *db = this;
  if (saccount.length() > 0)
      *account = saccount.c_str();

  return true;
}

BB2DomainInfo Bind2Backend::createDomainEntry(const string &domain, const string &filename)
{
  int newid=1;
  {   // Find a free zone id nr.  
    ReadLock rl(&s_state_lock);
    if (!s_state.empty()) {
      newid = s_state.rbegin()->d_id+1;
    }
  }
  
  BB2DomainInfo bbd;
  bbd.d_id = newid;
  bbd.d_records = shared_ptr<recordstorage_t >(new recordstorage_t);
  bbd.d_name = domain;
  bbd.setCheckInterval(getArgAsNum("check-interval"));
  bbd.d_filename = filename;
  return bbd;
}

bool Bind2Backend::createSlaveDomain(const string &ip, const string &domain, const string &nameserver, const string &account)
{
  string filename = getArg("supermaster-destdir")+'/'+domain;
  
  L << Logger::Warning << d_logprefix
    << " Writing bind config zone statement for superslave zone '" << domain
    << "' from supermaster " << ip << endl;

  {
    Lock l2(&s_supermaster_config_lock);
        
    ofstream c_of(getArg("supermaster-config").c_str(),  std::ios::app);
    if (!c_of) {
      L << Logger::Error << "Unable to open supermaster configfile for append: " << stringerror() << endl;
      throw DBException("Unable to open supermaster configfile for append: "+stringerror());
    }
    
    c_of << endl;
    c_of << "# Superslave zone " << domain << " (added: " << nowTime() << ") (account: " << account << ')' << endl;
    c_of << "zone \"" << domain << "\" {" << endl;
    c_of << "\ttype slave;" << endl;
    c_of << "\tfile \"" << filename << "\";" << endl;
    c_of << "\tmasters { " << ip << "; };" << endl;
    c_of << "};" << endl;
    c_of.close();
  }

  BB2DomainInfo bbd = createDomainEntry(toLowerCanonic(domain), filename);
  bbd.d_masters.push_back(ip);
  safePutBBDomainInfo(bbd);
  return true;
}

class Bind2Factory : public BackendFactory
{
   public:
      Bind2Factory() : BackendFactory("bind") {}

      void declareArguments(const string &suffix="")
      {
         declare(suffix,"ignore-broken-records","Ignore records that are out-of-bound for the zone.","no");
         declare(suffix,"config","Location of named.conf","");
         declare(suffix,"check-interval","Interval for zonefile changes","0");
         declare(suffix,"supermaster-config","Location of (part of) named.conf where pdns can write zone-statements to","");
         declare(suffix,"supermasters","List of IP-addresses of supermasters","");
         declare(suffix,"supermaster-destdir","Destination directory for newly added slave zones",::arg()["config-dir"]);
         declare(suffix,"dnssec-db","Filename to store & access our DNSSEC metadatabase, empty for none", "");         
         declare(suffix,"hybrid","Store DNSSEC metadata in other backend","no");
      }

      DNSBackend *make(const string &suffix="")
      {
         return new Bind2Backend(suffix);
      }
      
      DNSBackend *makeMetadataOnly(const string &suffix="")
      {
        return new Bind2Backend(suffix, false);
      }
};

//! Magic class that is activated when the dynamic library is loaded
class Bind2Loader
{
public:
  Bind2Loader()
  {
    BackendMakers().report(new Bind2Factory);
    L << Logger::Info << "[bind2backend] This is the bind backend version " VERSION " reporting" << endl;
  }
};
static Bind2Loader bind2loader;
