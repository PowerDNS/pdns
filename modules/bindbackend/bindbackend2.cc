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
#include <system_error>

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

template <typename T>
std::mutex LookButDontTouch<T>::s_lock;

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

bool Bind2Backend::safeGetBBDomainInfo(const DNSName& name, BB2DomainInfo* bbd)
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

bool Bind2Backend::safeRemoveBBDomainInfo(const DNSName& name)
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
  if (!safeGetBBDomainInfo(id, &bbd))
    return;
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

bool Bind2Backend::startTransaction(const DNSName &qname, int id)
{
  if(id < 0) {
    d_transaction_tmpname.clear();
    d_transaction_id=id;
    return false;
  }
  if(id == 0) {
    throw DBException("domain_id 0 is invalid for this backend.");
  }

  d_transaction_id=id;
  BB2DomainInfo bbd;
  if(safeGetBBDomainInfo(id, &bbd)) {
    d_transaction_tmpname = bbd.d_filename + "XXXXXX";
    int fd = mkstemp(&d_transaction_tmpname.at(0));
    if (fd == -1) {
      throw DBException("Unable to create a unique temporary zonefile '"+d_transaction_tmpname+"': "+stringerror());
      return false;
    }

    d_of = std::unique_ptr<ofstream>(new ofstream(d_transaction_tmpname.c_str()));
    if(!*d_of) {
      unlink(d_transaction_tmpname.c_str());
      close(fd);
      fd = -1;
      d_of.reset();
      throw DBException("Unable to open temporary zonefile '"+d_transaction_tmpname+"': "+stringerror());
    }
    close(fd);
    fd = -1;

    *d_of<<"; Written by PowerDNS, don't edit!"<<endl;
    *d_of<<"; Zone '"<<bbd.d_name<<"' retrieved from master "<<endl<<"; at "<<nowTime()<<endl; // insert master info here again

    return true;
  }
  return false;
}

bool Bind2Backend::commitTransaction()
{
  if(d_transaction_id < 0)
    return false;
  d_of.reset();

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
    unlink(d_transaction_tmpname.c_str());
    d_of.reset();
    d_transaction_id=0;
  }

  return true;
}

bool Bind2Backend::feedRecord(const DNSResourceRecord &rr, const DNSName &ordername, bool ordernameIsNSEC3)
{
  BB2DomainInfo bbd;
  if (!safeGetBBDomainInfo(d_transaction_id, &bbd))
    return false;

  string qname;
  string name = bbd.d_name.toString();
  if (bbd.d_name.empty()) {
    qname = rr.qname.toString();
  }
  else if (rr.qname.isPartOf(bbd.d_name)) {
    if (rr.qname == bbd.d_name) {
      qname = "@";
    }
    else {
      DNSName relName = rr.qname.makeRelative(bbd.d_name);
      qname = relName.toStringNoDot();
    }
  }
  else {
    throw DBException("out-of-zone data '"+rr.qname.toLogString()+"' during AXFR of zone '"+bbd.d_name.toLogString()+"'");
  }

  shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content));
  string content = drc->getZoneRepresentation();

  // SOA needs stripping too! XXX FIXME - also, this should not be here I think
  switch(rr.qtype.getCode()) {
  case QType::MX:
  case QType::SRV:
  case QType::CNAME:
  case QType::DNAME:
  case QType::NS:
    stripDomainSuffix(&content, name);
    // fallthrough
  default:
    if (d_of && *d_of) {
      *d_of<<qname<<"\t"<<rr.ttl<<"\t"<<rr.qtype.getName()<<"\t"<<content<<endl;
    }
  }
  return true;
}

void Bind2Backend::getUpdatedMasters(vector<DomainInfo> *changedDomains)
{
  vector<DomainInfo> consider;
  {
    ReadLock rl(&s_state_lock);

    for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
      if(i->d_kind != DomainInfo::Master && this->alsoNotify.empty() && i->d_also_notify.empty())
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
  for(DomainInfo& di :  consider) {
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
      di.kind=i->d_kind;
      di.masters=i->d_masters;
      di.backend=this;
      domains->push_back(di);
    };
  }

  for(DomainInfo &di :  *domains) {
    // do not corrupt di if domain supplied by another backend.
    if (di.backend != this)
      continue;
    try {
      this->getSOA(di.zone, soadata);
    } catch(...) {
      continue;
    }
    di.serial=soadata.serial;
  }
}

void Bind2Backend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  vector<DomainInfo> domains;
  {
    ReadLock rl(&s_state_lock);
    for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
      if(i->d_kind != DomainInfo::Slave)
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

  for(DomainInfo &sd :  domains) {
    SOAData soadata;
    soadata.refresh=0;
    soadata.serial=0;
    try {
      getSOA(sd.zone,soadata); // we might not *have* a SOA yet
    }
    catch(...){}
    sd.serial=soadata.serial;
    if(sd.last_check+soadata.refresh < (unsigned int)time(0))
      unfreshDomains->push_back(sd);    
  }
}

bool Bind2Backend::getDomainInfo(const DNSName& domain, DomainInfo &di, bool getSerial)
{
  BB2DomainInfo bbd;
  if(!safeGetBBDomainInfo(domain, &bbd))
    return false;

  di.id=bbd.d_id;
  di.zone=domain;
  di.masters=bbd.d_masters;
  di.last_check=bbd.d_lastcheck;
  di.backend=this;
  di.kind=bbd.d_kind;
  di.serial=0;
  if(getSerial) {
    try {
      SOAData sd;
      sd.serial=0;

      getSOA(bbd.d_name,sd); // we might not *have* a SOA yet
      di.serial=sd.serial;
    }
    catch(...){}
  }
  
  return true;
}

void Bind2Backend::alsoNotifies(const DNSName& domain, set<string> *ips)
{
  // combine global list with local list
  for(set<string>::iterator i = this->alsoNotify.begin(); i != this->alsoNotify.end(); i++) {
    (*ips).insert(*i);
  }
  // check metadata too if available
  vector<string> meta;
  if (getDomainMetadata(domain, "ALSO-NOTIFY", meta)) {
    for(const auto& str: meta) {
      (*ips).insert(str);
    }
  }
  ReadLock rl(&s_state_lock);  
  for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
    if(i->d_name == domain) {
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
    if(rr.qtype.getCode() == QType::NSEC || rr.qtype.getCode() == QType::NSEC3 || rr.qtype.getCode() == QType::NSEC3PARAM)
      continue; // we synthesise NSECs on demand

    insertRecord(*bbd, rr.qname, rr.qtype, rr.content, rr.ttl, "");
  }
  fixupOrderAndAuth(*bbd, nsec3zone, ns3pr);
  doEmptyNonTerminals(*bbd, nsec3zone, ns3pr);
  bbd->setCtime();
  bbd->d_loaded=true; 
  bbd->d_checknow=false;
  bbd->d_status="parsed into memory at "+nowTime();
}

/** THIS IS AN INTERNAL FUNCTION! It does moadnsparser prio impedance matching
    Much of the complication is due to the efforts to benefit from std::string reference counting copy on write semantics */
void Bind2Backend::insertRecord(BB2DomainInfo& bb2, const DNSName &qname, const QType &qtype, const string &content, int ttl, const std::string& hashed, bool *auth)
{
  Bind2DNSRecord bdr;
  shared_ptr<recordstorage_t> records = bb2.d_records.getWRITABLE();
  bdr.qname=qname;

  if(bb2.d_name.empty())
    ;
  else if(bdr.qname.isPartOf(bb2.d_name))
    bdr.qname = bdr.qname.makeRelative(bb2.d_name);
  else {
    string msg = "Trying to insert non-zone data, name='"+bdr.qname.toLogString()+"', qtype="+qtype.getName()+", zone='"+bb2.d_name.toLogString()+"'";
    if(s_ignore_broken_records) {
        g_log<<Logger::Warning<<msg<< " ignored" << endl;
        return;
    }
    else
      throw PDNSException(msg);
  }

//  bdr.qname.swap(bdr.qname);

  if(!records->empty() && bdr.qname==boost::prior(records->end())->qname)
    bdr.qname=boost::prior(records->end())->qname;

  bdr.qname=bdr.qname;
  bdr.qtype=qtype.getCode();
  bdr.content=content; 
  bdr.nsec3hash = hashed;
  
  if (auth) // Set auth on empty non-terminals
    bdr.auth=*auth;
  else
    bdr.auth=true;

  bdr.ttl=ttl;
  records->insert(bdr);
}

string Bind2Backend::DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  ostringstream ret;

  for(vector<string>::const_iterator i=parts.begin()+1;i<parts.end();++i) {
    BB2DomainInfo bbd;
    DNSName zone(*i);
    if(safeGetBBDomainInfo(zone, &bbd)) {
      Bind2Backend bb2;
      bb2.queueReloadAndStore(bbd.d_id);
      if (!safeGetBBDomainInfo(zone, &bbd)) // Read the *new* domain status
          ret << *i << ": [missing]\n";
      else
          ret<< *i << ": "<< (bbd.d_wasRejectedLastReload ? "[rejected]": "") <<"\t"<<bbd.d_status<<"\n";
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
      if(safeGetBBDomainInfo(DNSName(*i), &bbd)) {	
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

  DNSName domainname(parts[1]);
  const string &filename = parts[2];
  BB2DomainInfo bbd;
  if(safeGetBBDomainInfo(domainname, &bbd))
    return "Already loaded";

  if (!boost::starts_with(filename, "/") && ::arg()["chroot"].empty())
    return "Unable to load zone " + domainname.toLogString() + " from " + filename + " as the filename is not absolute.";

  struct stat buf;
  if (stat(filename.c_str(), &buf) != 0)
    return "Unable to load zone " + domainname.toLogString() + " from " + filename + ": " + strerror(errno);

  Bind2Backend bb2; // createdomainentry needs access to our configuration
  bbd=bb2.createDomainEntry(domainname, filename);
  bbd.d_filename=filename;
  bbd.d_checknow=true;
  bbd.d_loaded=true;
  bbd.d_lastcheck=0;
  bbd.d_status="parsing into memory";
  bbd.setCtime();

  safePutBBDomainInfo(bbd);

  g_log<<Logger::Warning<<"Zone "<<domainname<< " loaded"<<endl;
  return "Loaded zone " + domainname.toLogString() + " from " + filename;
}

Bind2Backend::Bind2Backend(const string &suffix, bool loadZones)
{
  d_getAllDomainMetadataQuery_stmt = NULL;
  d_getDomainMetadataQuery_stmt = NULL;
  d_deleteDomainMetadataQuery_stmt = NULL;
  d_insertDomainMetadataQuery_stmt = NULL;
  d_getDomainKeysQuery_stmt = NULL;
  d_deleteDomainKeyQuery_stmt = NULL;
  d_insertDomainKeyQuery_stmt = NULL;
  d_GetLastInsertedKeyIdQuery_stmt = NULL;
  d_activateDomainKeyQuery_stmt = NULL;
  d_deactivateDomainKeyQuery_stmt = NULL;
  d_getTSIGKeyQuery_stmt = NULL;
  d_setTSIGKeyQuery_stmt = NULL;
  d_deleteTSIGKeyQuery_stmt = NULL;
  d_getTSIGKeysQuery_stmt = NULL;

  setArgPrefix("bind"+suffix);
  d_logprefix="[bind"+suffix+"backend]";
  d_hybrid=mustDo("hybrid");
  d_transaction_id=0;
  s_ignore_broken_records=mustDo("ignore-broken-records");

  if (!loadZones && d_hybrid)
    return;

  Lock l(&s_startup_lock);
  
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
{ freeStatements(); } // deallocate statements 

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

void Bind2Backend::fixupOrderAndAuth(BB2DomainInfo& bbd, bool nsec3zone, NSEC3PARAMRecordContent ns3pr)
{
  shared_ptr<recordstorage_t> records = bbd.d_records.getWRITABLE();

  bool skip;
  DNSName shorter;
  set<DNSName> nssets, dssets;

  for(const auto& bdr: *records) {
    if(!bdr.qname.isRoot() && bdr.qtype == QType::NS)
      nssets.insert(bdr.qname);
    else if(bdr.qtype == QType::DS)
      dssets.insert(bdr.qname);
  }

  for(auto iter = records->begin(); iter != records->end(); iter++) {
    skip = false;
    shorter = iter->qname;

    if (!iter->qname.isRoot() && shorter.chopOff() && !iter->qname.isRoot()) {
      do {
        if(nssets.count(shorter)) {
          skip = true;
          break;
        }
      } while(shorter.chopOff() && !iter->qname.isRoot());
    }

    iter->auth = (!skip && (iter->qtype == QType::DS || iter->qtype == QType::RRSIG || !nssets.count(iter->qname)));

    if(!skip && nsec3zone && iter->qtype != QType::RRSIG && (iter->auth || (iter->qtype == QType::NS && !ns3pr.d_flags) || dssets.count(iter->qname))) {
      Bind2DNSRecord bdr = *iter;
      bdr.nsec3hash = toBase32Hex(hashQNameWithSalt(ns3pr, bdr.qname+bbd.d_name));
      records->replace(iter, bdr);
    }

    // cerr<<iter->qname<<"\t"<<QType(iter->qtype).getName()<<"\t"<<iter->nsec3hash<<"\t"<<iter->auth<<endl;
  }
}

void Bind2Backend::doEmptyNonTerminals(BB2DomainInfo& bbd, bool nsec3zone, NSEC3PARAMRecordContent ns3pr)
{
  shared_ptr<const recordstorage_t> records = bbd.d_records.get();

  bool auth;
  DNSName shorter;
  set<DNSName> qnames;
  map<DNSName, bool> nonterm;

  uint32_t maxent = ::arg().asNum("max-ent-entries");

  for(const auto& bdr : *records)
    qnames.insert(bdr.qname);

  for(const auto& bdr : *records) {

    if (!bdr.auth && bdr.qtype == QType::NS)
      auth = (!nsec3zone || !ns3pr.d_flags);
    else
      auth = bdr.auth;

    shorter = bdr.qname;
    while(shorter.chopOff())
    {
      if(!qnames.count(shorter))
      {
        if(!(maxent))
        {
          g_log<<Logger::Error<<"Zone '"<<bbd.d_name<<"' has too many empty non terminals."<<endl;
          return;
        }

        if (!nonterm.count(shorter)) {
          nonterm.insert(pair<DNSName, bool>(shorter, auth));
          --maxent;
        } else if (auth)
          nonterm[shorter] = true;
      }
    }
  }

  DNSResourceRecord rr;
  rr.qtype = "#0";
  rr.content = "";
  rr.ttl = 0;
  for(auto& nt : nonterm)
  {
    string hashed;
    rr.qname = nt.first + bbd.d_name;
    if(nsec3zone && nt.second)
      hashed = toBase32Hex(hashQNameWithSalt(ns3pr, rr.qname));
    insertRecord(bbd, rr.qname, rr.qtype, rr.content, rr.ttl, hashed, &nt.second);

    // cerr<<rr.qname<<"\t"<<rr.qtype.getName()<<"\t"<<hashed<<"\t"<<nt.second<<endl;
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
      g_log<<Logger::Error<<"Error parsing bind configuration: "<<ae.reason<<endl;
      throw;
    }
      
    vector<BindDomainInfo> domains=BP.getDomains();
    this->alsoNotify = BP.getAlsoNotify();

    s_binddirectory=BP.getDirectory();
    //    ZP.setDirectory(d_binddirectory);

    g_log<<Logger::Warning<<d_logprefix<<" Parsing "<<domains.size()<<" domain(s), will report when done"<<endl;
    
    set<DNSName> oldnames, newnames;
    {
      ReadLock rl(&s_state_lock);
      for(const BB2DomainInfo& bbd :  s_state) {
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
        if (!(i->hadFileDirective)) {
          g_log<<Logger::Warning<<d_logprefix<<" Zone '"<<i->name<<"' has no 'file' directive set in "<<getArg("config")<<endl;
          rejected++;
          continue;
        }

        if(i->type == "")
          g_log<<Logger::Notice<<d_logprefix<<" Zone '"<<i->name<<"' has no type specified, assuming 'native'"<<endl;
        if(i->type!="master" && i->type!="slave" && i->type != "native" && i->type != "") {
          g_log<<Logger::Warning<<d_logprefix<<" Warning! Skipping zone '"<<i->name<<"' because type '"<<i->type<<"' is invalid"<<endl;
          rejected++;
          continue;
        }

        BB2DomainInfo bbd;
        bool isNew = false;

        if(!safeGetBBDomainInfo(i->name, &bbd)) { 
          isNew = true;
          bbd.d_id=domain_id++;
          bbd.setCheckInterval(getArgAsNum("check-interval"));
          bbd.d_lastnotified=0;
          bbd.d_loaded=false;
        }
        
        // overwrite what we knew about the domain
        bbd.d_name=i->name;
        bool filenameChanged = (bbd.d_filename!=i->filename);
        bbd.d_filename=i->filename;
        bbd.d_masters=i->masters;
        bbd.d_also_notify=i->alsoNotify;

        bbd.d_kind = DomainInfo::Native;
        if (i->type == "master")
          bbd.d_kind = DomainInfo::Master;
        if (i->type == "slave")
          bbd.d_kind = DomainInfo::Slave;

        newnames.insert(bbd.d_name);
        if(filenameChanged || !bbd.d_loaded || !bbd.current()) {
          g_log<<Logger::Info<<d_logprefix<<" parsing '"<<i->name<<"' from file '"<<i->filename<<"'"<<endl;

          try {
            parseZoneFile(&bbd);
          }
          catch(PDNSException &ae) {
            ostringstream msg;
            msg<<" error at "+nowTime()+" parsing '"<<i->name<<"' from file '"<<i->filename<<"': "<<ae.reason;

            if(status)
              *status+=msg.str();
	    bbd.d_status=msg.str();

            g_log<<Logger::Warning<<d_logprefix<<msg.str()<<endl;
            rejected++;
          }
          catch(std::system_error &ae) {
            ostringstream msg;
            if (ae.code().value() == ENOENT && isNew && i->type == "slave")
              msg<<" error at "+nowTime()<<" no file found for new slave domain '"<<i->name<<"'. Has not been AXFR'd yet";
            else
              msg<<" error at "+nowTime()+" parsing '"<<i->name<<"' from file '"<<i->filename<<"': "<<ae.what();

            if(status)
              *status+=msg.str();
            bbd.d_status=msg.str();
            g_log<<Logger::Warning<<d_logprefix<<msg.str()<<endl;
            rejected++;
          }
          catch(std::exception &ae) {
            ostringstream msg;
            msg<<" error at "+nowTime()+" parsing '"<<i->name<<"' from file '"<<i->filename<<"': "<<ae.what();

            if(status)
              *status+=msg.str();
            bbd.d_status=msg.str();

            g_log<<Logger::Warning<<d_logprefix<<msg.str()<<endl;
            rejected++;
          }
	  safePutBBDomainInfo(bbd);
	  
        }
      }
    vector<DNSName> diff;

    set_difference(oldnames.begin(), oldnames.end(), newnames.begin(), newnames.end(), back_inserter(diff));
    unsigned int remdomains=diff.size();
    
    for(const DNSName& name: diff) {
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

    g_log<<Logger::Error<<d_logprefix<<msg.str()<<endl;
  }
}

void Bind2Backend::queueReloadAndStore(unsigned int id)
{
  BB2DomainInfo bbold;
  try {
    if(!safeGetBBDomainInfo(id, &bbold))
      return;
    BB2DomainInfo bbnew(bbold);
    parseZoneFile(&bbnew);
    bbnew.d_checknow=false;
    bbnew.d_wasRejectedLastReload=false;
    safePutBBDomainInfo(bbnew);
    g_log<<Logger::Warning<<"Zone '"<<bbnew.d_name<<"' ("<<bbnew.d_filename<<") reloaded"<<endl;
  }
  catch(PDNSException &ae) {
    ostringstream msg;
    msg<<" error at "+nowTime()+" parsing '"<<bbold.d_name<<"' from file '"<<bbold.d_filename<<"': "<<ae.reason;
    g_log<<Logger::Warning<<" error parsing '"<<bbold.d_name<<"' from file '"<<bbold.d_filename<<"': "<<ae.reason<<endl;
    bbold.d_status=msg.str();
    bbold.d_wasRejectedLastReload=true;
    safePutBBDomainInfo(bbold);
  }
  catch(std::exception &ae) {
    ostringstream msg;
    msg<<" error at "+nowTime()+" parsing '"<<bbold.d_name<<"' from file '"<<bbold.d_filename<<"': "<<ae.what();
    g_log<<Logger::Warning<<" error parsing '"<<bbold.d_name<<"' from file '"<<bbold.d_filename<<"': "<<ae.what()<<endl;
    bbold.d_status=msg.str();
    bbold.d_wasRejectedLastReload=true;
    safePutBBDomainInfo(bbold);
  }
}

bool Bind2Backend::findBeforeAndAfterUnhashed(BB2DomainInfo& bbd, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
  shared_ptr<const recordstorage_t> records = bbd.d_records.get();

  // for(const auto& record: *records)
  //   cerr<<record.qname<<"\t"<<makeHexDump(record.qname.toDNSString())<<endl;

  recordstorage_t::const_iterator iterBefore, iterAfter;

  iterBefore = iterAfter = records->upper_bound(qname.makeLowerCase());

  if(iterBefore != records->begin())
    --iterBefore;
  while((!iterBefore->auth && iterBefore->qtype != QType::NS) || !iterBefore->qtype)
    --iterBefore;
  before=iterBefore->qname;

  if(iterAfter == records->end()) {
    iterAfter = records->begin();
  } else {
    while((!iterAfter->auth && iterAfter->qtype != QType::NS) || !iterAfter->qtype) {
      ++iterAfter;
      if(iterAfter == records->end()) {
        iterAfter = records->begin();
        break;
      }
    }
  }
  after = iterAfter->qname;

  return true;
}

bool Bind2Backend::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
  BB2DomainInfo bbd;
  if (!safeGetBBDomainInfo(id, &bbd))
    return false;

  NSEC3PARAMRecordContent ns3pr;

  bool nsec3zone;
  if (d_hybrid) {
    DNSSECKeeper dk;
    nsec3zone=dk.getNSEC3PARAM(bbd.d_name, &ns3pr);
  } else
    nsec3zone=getNSEC3PARAM(bbd.d_name, &ns3pr);

  if(!nsec3zone) {
    return findBeforeAndAfterUnhashed(bbd, qname, unhashed, before, after);
  }
  else {
    auto& hashindex=boost::multi_index::get<NSEC3Tag>(*bbd.d_records.getWRITABLE());

    // for(auto iter = first; iter != hashindex.end(); iter++)
    //  cerr<<iter->nsec3hash<<endl;

    auto first = hashindex.upper_bound("");
    auto iter = hashindex.upper_bound(qname.toStringNoDot());

    if (iter == hashindex.end()) {
      --iter;
      before = DNSName(iter->nsec3hash);
      after = DNSName(first->nsec3hash);
    } else {
      after = DNSName(iter->nsec3hash);
      if (iter != first)
        --iter;
      else
        iter = --hashindex.end();
      before = DNSName(iter->nsec3hash);
    }
    unhashed = iter->qname+bbd.d_name;

    return true;
  }
}

void Bind2Backend::lookup(const QType &qtype, const DNSName &qname, int zoneId, DNSPacket *pkt_p )
{
  d_handle.reset();

  static bool mustlog=::arg().mustDo("query-logging");

  bool found;
  DNSName domain;
  BB2DomainInfo bbd;

  if(mustlog)
    g_log<<Logger::Warning<<"Lookup for '"<<qtype.getName()<<"' of '"<<qname<<"' within zoneID "<<zoneId<<endl;

  if (zoneId >= 0) {
    if ((found = (safeGetBBDomainInfo(zoneId, &bbd) && qname.isPartOf(bbd.d_name)))) {
      domain = bbd.d_name;
    }
  } else {
    domain = qname;
    do {
      found = safeGetBBDomainInfo(domain, &bbd);
    } while (!found && qtype != QType::SOA && domain.chopOff());
  }

  if(!found) {
    if(mustlog)
      g_log<<Logger::Warning<<"Found no authoritative zone for '"<<qname<<"' and/or id "<<bbd.d_id<<endl;
    d_handle.d_list=false;
    return;
  }

  if(mustlog)
    g_log<<Logger::Warning<<"Found a zone '"<<domain<<"' (with id " << bbd.d_id<<") that might contain data "<<endl;

  d_handle.id=bbd.d_id;
  d_handle.qname=qname.makeRelative(domain); // strip domain name
  d_handle.qtype=qtype;
  d_handle.domain=domain;

  if(!bbd.d_loaded) {
    d_handle.reset();
    throw DBException("Zone for '"+bbd.d_name.toLogString()+"' in '"+bbd.d_filename+"' temporarily not available (file missing, or master dead)"); // fsck
  }
    
  if(!bbd.current()) {
    g_log<<Logger::Warning<<"Zone '"<<bbd.d_name<<"' ("<<bbd.d_filename<<") needs reloading"<<endl;
    queueReloadAndStore(bbd.d_id);
    if (!safeGetBBDomainInfo(domain, &bbd))
      throw DBException("Zone '"+bbd.d_name.toLogString()+"' ("+bbd.d_filename+") gone after reload"); // if we don't throw here, we crash for some reason
  }

  d_handle.d_records = bbd.d_records.get();
  
  if(d_handle.d_records->empty())
    DLOG(g_log<<"Query with no results"<<endl);

  d_handle.mustlog = mustlog;

  auto& hashedidx = boost::multi_index::get<UnorderedNameTag>(*d_handle.d_records);
  auto range = hashedidx.equal_range(d_handle.qname);
  
  if(range.first==range.second) {
    d_handle.d_list=false;
    d_handle.d_iter = d_handle.d_end_iter  = range.first;
    return;
  }
  else {
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
      g_log<<Logger::Warning<<"There were no answers"<<endl;
    return false;
  }

  if(!d_handle.get(r)) {
    if(d_handle.mustlog)
      g_log<<Logger::Warning<<"End of answers"<<endl;

    d_handle.reset();

    return false;
  }
  if(d_handle.mustlog)
    g_log<<Logger::Warning<<"Returning: '"<<r.qtype.getName()<<"' of '"<<r.qname<<"', content: '"<<r.content<<"'"<<endl;
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
  DLOG(g_log << "Bind2Backend get() was called for "<<qtype.getName() << " record for '"<<
       qname<<"' - "<<d_records->size()<<" available in total!"<<endl);
  
  if(d_iter==d_end_iter) {
    return false;
  }

  while(d_iter!=d_end_iter && !(qtype.getCode()==QType::ANY || (d_iter)->qtype==qtype.getCode())) {
    DLOG(g_log<<Logger::Warning<<"Skipped "<<qname<<"/"<<QType(d_iter->qtype).getName()<<": '"<<d_iter->content<<"'"<<endl);
    d_iter++;
  }
  if(d_iter==d_end_iter) {
    return false;
  }
  DLOG(g_log << "Bind2Backend get() returning a rr with a "<<QType(d_iter->qtype).getCode()<<endl);

  r.qname=qname.empty() ? domain : (qname+domain);
  r.domain_id=id;
  r.content=(d_iter)->content;
  //  r.domain_id=(d_iter)->domain_id;
  r.qtype=(d_iter)->qtype;
  r.ttl=(d_iter)->ttl;

  //if(!d_iter->auth && r.qtype.getCode() != QType::A && r.qtype.getCode()!=QType::AAAA && r.qtype.getCode() != QType::NS)
  //  cerr<<"Warning! Unauth response for qtype "<< r.qtype.getName() << " for '"<<r.qname<<"'"<<endl;
  r.auth = d_iter->auth;

  d_iter++;

  return true;
}

bool Bind2Backend::list(const DNSName& target, int id, bool include_disabled)
{
  BB2DomainInfo bbd;
  
  if(!safeGetBBDomainInfo(id, &bbd))
    return false;

  d_handle.reset(); 
  DLOG(g_log<<"Bind2Backend constructing handle for list of "<<id<<endl);

  d_handle.d_records=bbd.d_records.get(); // give it a copy, which will stay around
  d_handle.d_qname_iter= d_handle.d_records->begin();
  d_handle.d_qname_end=d_handle.d_records->end();   // iter now points to a vector of pointers to vector<BBResourceRecords>

  d_handle.id=id;
  d_handle.domain=bbd.d_name;
  d_handle.d_list=true;
  return true;
}

bool Bind2Backend::handle::get_list(DNSResourceRecord &r)
{
  if(d_qname_iter!=d_qname_end) {
    r.qname=d_qname_iter->qname.empty() ? domain : (d_qname_iter->qname+domain);
    r.domain_id=id;
    r.content=(d_qname_iter)->content;
    r.qtype=(d_qname_iter)->qtype;
    r.ttl=(d_qname_iter)->ttl;
    r.auth = d_qname_iter->auth;
    d_qname_iter++;
    return true;
  }
  return false;
}

bool Bind2Backend::superMasterBackend(const string &ip, const DNSName& domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db)
{
  // Check whether we have a configfile available.
  if (getArg("supermaster-config").empty())
    return false;

  ifstream c_if(getArg("supermasters").c_str(), std::ios::in); // this was nocreate?
  if (!c_if) {
    g_log << Logger::Error << "Unable to open supermasters file for read: " << stringerror() << endl;
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

BB2DomainInfo Bind2Backend::createDomainEntry(const DNSName& domain, const string &filename)
{
  int newid=1;
  {   // Find a free zone id nr.  
    ReadLock rl(&s_state_lock);
    if (!s_state.empty()) {
      newid = s_state.rbegin()->d_id+1;
    }
  }
  
  BB2DomainInfo bbd;
  bbd.d_kind = DomainInfo::Native;
  bbd.d_id = newid;
  bbd.d_records = shared_ptr<recordstorage_t >(new recordstorage_t);
  bbd.d_name = domain;
  bbd.setCheckInterval(getArgAsNum("check-interval"));
  bbd.d_filename = filename;
  
  return bbd;
}

bool Bind2Backend::createSlaveDomain(const string &ip, const DNSName& domain, const string &nameserver, const string &account)
{
  string filename = getArg("supermaster-destdir")+'/'+domain.toStringNoDot();
  
  g_log << Logger::Warning << d_logprefix
    << " Writing bind config zone statement for superslave zone '" << domain
    << "' from supermaster " << ip << endl;

  {
    Lock l2(&s_supermaster_config_lock);
        
    ofstream c_of(getArg("supermaster-config").c_str(),  std::ios::app);
    if (!c_of) {
      g_log << Logger::Error << "Unable to open supermaster configfile for append: " << stringerror() << endl;
      throw DBException("Unable to open supermaster configfile for append: "+stringerror());
    }
    
    c_of << endl;
    c_of << "# Superslave zone '" << domain.toString() << "' (added: " << nowTime() << ") (account: " << account << ')' << endl;
    c_of << "zone \"" << domain.toStringNoDot() << "\" {" << endl;
    c_of << "\ttype slave;" << endl;
    c_of << "\tfile \"" << filename << "\";" << endl;
    c_of << "\tmasters { " << ip << "; };" << endl;
    c_of << "};" << endl;
    c_of.close();
  }

  BB2DomainInfo bbd = createDomainEntry(domain, filename);
  bbd.d_kind = DomainInfo::Slave;
  bbd.d_masters.push_back(ComboAddress(ip, 53));
  bbd.setCtime();
  safePutBBDomainInfo(bbd);
  return true;
}

bool Bind2Backend::searchRecords(const string &pattern, int maxResults, vector<DNSResourceRecord>& result)
{
  SimpleMatch sm(pattern,true);
  static bool mustlog=::arg().mustDo("query-logging");
  if(mustlog)
    g_log<<Logger::Warning<<"Search for pattern '"<<pattern<<"'"<<endl;

  {
    ReadLock rl(&s_state_lock);

    for(state_t::const_iterator i = s_state.begin(); i != s_state.end() ; ++i) {
      BB2DomainInfo h;
      if (!safeGetBBDomainInfo(i->d_id, &h)) {
        continue;
      }

      shared_ptr<const recordstorage_t> rhandle = h.d_records.get();

      for(recordstorage_t::const_iterator ri = rhandle->begin(); result.size() < static_cast<vector<DNSResourceRecord>::size_type>(maxResults) && ri != rhandle->end(); ri++) {
        DNSName name = ri->qname.empty() ? i->d_name : (ri->qname+i->d_name);
        if (sm.match(name) || sm.match(ri->content)) {
          DNSResourceRecord r;
          r.qname=name;
          r.domain_id=i->d_id;
          r.content=ri->content;
          r.qtype=ri->qtype;
          r.ttl=ri->ttl;
          r.auth = ri->auth;
          result.push_back(r);
        }
      }
    }
  }

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
         declare(suffix,"dnssec-db-journal-mode","SQLite3 journal mode", "WAL");
         declare(suffix,"hybrid","Store DNSSEC metadata in other backend","no");
      }

      DNSBackend *make(const string &suffix="")
      {
         assertEmptySuffix(suffix);
         return new Bind2Backend(suffix);
      }
      
      DNSBackend *makeMetadataOnly(const string &suffix="")
      {
        assertEmptySuffix(suffix);
        return new Bind2Backend(suffix, false);
      }
   private:
      void assertEmptySuffix(const string &suffix)
      {
        if(suffix.length())
          throw PDNSException("launch= suffixes are not supported on the bindbackend");
      }
};

//! Magic class that is activated when the dynamic library is loaded
class Bind2Loader
{
public:
  Bind2Loader()
  {
    BackendMakers().report(new Bind2Factory);
    g_log << Logger::Info << "[bind2backend] This is the bind backend version " << VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
#ifdef HAVE_SQLITE3
      << " (with bind-dnssec-db support)"
#endif
      << " reporting" << endl;
  }
};
static Bind2Loader bind2loader;
