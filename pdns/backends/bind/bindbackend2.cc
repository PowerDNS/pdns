/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation; 

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
#include <map>
#include <set>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <fcntl.h>
#include <sstream>
#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "base32.hh"
#include "namespaces.hh"

#include "dns.hh"
#include "dnsbackend.hh"
#include "bindbackend2.hh"
#include "dnspacket.hh"
#include "zoneparser-tng.hh"
#include "bindparser.hh"
#include "logger.hh"
#include "arguments.hh"
#include "qtype.hh"
#include "misc.hh"
#include "dynlistener.hh"
#include "lock.hh"
#include "namespaces.hh"

/** new scheme of things:
    we have zone-id map
    a zone-id has a vector of DNSResourceRecords 
    on start of query, we find the best zone to answer from
*/

// this map contains BB2DomainInfo structs, each of which contains a *pointer* to domain data
shared_ptr<Bind2Backend::State> Bind2Backend::s_state;

/* the model is that all our state hides in s_state. This State instance consists of the id_zone_map, which contains all our zone information, indexed by id.
   Then there is the name_id_map, which allows us to map a query to a zone id.

   The s_state is never written to, and it is a reference counted shared_ptr. Any function which needs to access the state
   should do so by making a shared_ptr copy of it, and do all its work on that copy.

   When I said s_state is never written to, I lied. No elements are ever added to it, or removed from it.
   Its values however may be changed, but not the keys. 

   When it is necessary to change the State, a deep copy is made, which is changed. Afterwards, 
   the s_state pointer is made to point to the new State.

   Anybody who is currently accessing the original holds a reference counted handle (shared_ptr) to it, which means it will stay around
   To save memory, we hold the records as a shared_ptr as well.

   Changes made to s_state directly should take the s_state_lock, so as to prevent writing to a stale copy.
*/

int Bind2Backend::s_first=1;

pthread_mutex_t Bind2Backend::s_startup_lock=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Bind2Backend::s_state_lock=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Bind2Backend::s_state_swap_lock=PTHREAD_MUTEX_INITIALIZER;
string Bind2Backend::s_binddirectory;  
/* when a query comes in, we find the most appropriate zone and answer from that */

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
  if(d_checknow)
    return false;

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

void Bind2Backend::setNotified(uint32_t id, uint32_t serial)
{
  Lock l(&s_state_lock);
  s_state->id_zone_map[id].d_lastnotified=serial;
}

void Bind2Backend::setFresh(uint32_t domain_id)
{
  Lock l(&s_state_lock);
  s_state->id_zone_map[domain_id].d_lastcheck=time(0);
}

shared_ptr<Bind2Backend::State> Bind2Backend::getState()
{
  shared_ptr<State> ret;
  {
    Lock l(&s_state_swap_lock);
    ret = s_state; // is only read from
  }
  return ret;
}

bool Bind2Backend::startTransaction(const string &qname, int id)
{
  if(id < 0) {
    d_transaction_tmpname.clear();
    d_transaction_id=id;
    return true;
  }
  shared_ptr<State> state = getState(); 

  const BB2DomainInfo &bbd=state->id_zone_map[d_transaction_id=id];

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

bool Bind2Backend::commitTransaction()
{
  if(d_transaction_id < 0)
    return true;
  delete d_of;
  d_of=0;
  shared_ptr<State> state = getState(); 

  // this might fail if s_state was cycled during the AXFR
  if(rename(d_transaction_tmpname.c_str(), state->id_zone_map[d_transaction_id].d_filename.c_str())<0)
    throw DBException("Unable to commit (rename to: '" + state->id_zone_map[d_transaction_id].d_filename+"') AXFRed zone: "+stringerror());

  queueReload(&state->id_zone_map[d_transaction_id]);

  d_transaction_id=0;

  return true;
}

bool Bind2Backend::abortTransaction()
{
  if(d_transaction_id >= 0) {
    delete d_of;
    d_of=0;
    unlink(d_transaction_tmpname.c_str());
    d_transaction_id=0;
  }

  return true;
}

bool Bind2Backend::updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth)
{
  #if 0
  const shared_ptr<State> state = getState();
  BB2DomainInfo& bbd = state->id_zone_map[domain_id];

  string sqname;

  if(bbd.d_name.empty())
    sqname=qname;
  else if(strcasecmp(qname.c_str(), bbd.d_name.c_str()))
    sqname=qname.substr(0,qname.size() - bbd.d_name.length()-1); // strip domain name

  sqname = labelReverse(sqname);
  
  if(!auth)
    d_authDelayed[sqname] = auth;
  
  #endif
  return false;
}

bool Bind2Backend::feedRecord(const DNSResourceRecord &r)
{
  string qname=r.qname;

  const shared_ptr<State> state = getState();
  string domain = state->id_zone_map[d_transaction_id].d_name;

  if(!stripDomainSuffix(&qname,domain)) 
    throw DBException("out-of-zone data '"+qname+"' during AXFR of zone '"+domain+"'");

  string content=r.content;

  // SOA needs stripping too! XXX FIXME - also, this should not be here I think
  switch(r.qtype.getCode()) {
  case QType::MX:
    if(!stripDomainSuffix(&content, domain))
      content+=".";
  case QType::SRV:
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
  SOAData soadata;
  shared_ptr<State> state = getState(); 

  for(id_zone_map_t::const_iterator i = state->id_zone_map.begin(); i != state->id_zone_map.end() ; ++i) {
    if(!i->second.d_masters.empty() && this->alsoNotify.empty() && i->second.d_also_notify.empty())
      continue;
    soadata.serial=0;
    try {
      this->getSOA(i->second.d_name, soadata); // we might not *have* a SOA yet, but this might trigger a load of it
    }
    catch(...){}
    DomainInfo di;
    di.id=i->first;
    di.serial=soadata.serial;
    di.zone=i->second.d_name;
    di.last_check=i->second.d_lastcheck;
    di.backend=this;
    di.kind=DomainInfo::Master;
    if(!i->second.d_lastnotified)  {          // don't do notification storm on startup 
      Lock l(&s_state_lock);
      s_state->id_zone_map[i->first].d_lastnotified=soadata.serial;
    }
    else
      if(soadata.serial!=i->second.d_lastnotified)
        changedDomains->push_back(di);
  }
}

void Bind2Backend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  shared_ptr<State> state = getState();
  for(id_zone_map_t::const_iterator i = state->id_zone_map.begin(); i != state->id_zone_map.end() ; ++i) {
    if(i->second.d_masters.empty())
      continue;
    DomainInfo sd;
    sd.id=i->first;
    sd.zone=i->second.d_name;
    sd.masters=i->second.d_masters;
    sd.last_check=i->second.d_lastcheck;
    sd.backend=this;
    sd.kind=DomainInfo::Slave;
    SOAData soadata;
    soadata.refresh=0;
    soadata.serial=0;
    soadata.db=(DNSBackend *)-1; // not sure if this is useful, inhibits any caches that might be around
    try {
      getSOA(i->second.d_name,soadata); // we might not *have* a SOA yet
    }
    catch(...){}
    sd.serial=soadata.serial;
    if(sd.last_check+soadata.refresh<(unsigned int)time(0))
      unfreshDomains->push_back(sd);    
  }
}

bool Bind2Backend::getDomainInfo(const string &domain, DomainInfo &di)
{
  shared_ptr<State> state = getState();
  for(id_zone_map_t::const_iterator i = state->id_zone_map.begin(); i != state->id_zone_map.end() ; ++i) { // why is this a linear scan??
    if(pdns_iequals(i->second.d_name,domain)) {
      di.id=i->first;
      di.zone=domain;
      di.masters=i->second.d_masters;
      di.last_check=i->second.d_lastcheck;
      di.backend=this;
      di.kind=i->second.d_masters.empty() ? DomainInfo::Master : DomainInfo::Slave;
      di.serial=0;
      try {
        SOAData sd;
        sd.serial=0;
        
        getSOA(i->second.d_name,sd); // we might not *have* a SOA yet
        di.serial=sd.serial;
      }
      catch(...){}

      return true;
    }
  }
  return false;
}

void Bind2Backend::alsoNotifies(const string &domain, set<string> *ips)
{
  shared_ptr<State> state = getState();
  // combine global list with local list
  for(set<string>::iterator i = this->alsoNotify.begin(); i != this->alsoNotify.end(); i++) {
    (*ips).insert(*i);
  }
  for(id_zone_map_t::const_iterator i = state->id_zone_map.begin(); i != state->id_zone_map.end() ; ++i) {
    if(i->second.d_name==domain) {
      for(set<string>::iterator it = i->second.d_also_notify.begin(); it != i->second.d_also_notify.end(); it++) {
        (*ips).insert(*it);
      }
      return;
    }
  }   
}

//! lowercase, strip trailing .
static string canonic(string ret)
{
  string::iterator i;

  for(i=ret.begin();
      i!=ret.end();
      ++i)
    *i=tolower(*i);


  if(*(i-1)=='.')
    ret.resize(i-ret.begin()-1);
  return ret;
}

/** THIS IS AN INTERNAL FUNCTION! It does moadnsparser prio impedence matching
    This function adds a record to a domain with a certain id. 
    Much of the complication is due to the efforts to benefit from std::string reference counting copy on write semantics */
void Bind2Backend::insert(shared_ptr<State> stage, int id, const string &qnameu, const QType &qtype, const string &content, int ttl, int prio, const std::string& hashed)
{
  BB2DomainInfo bb2 = stage->id_zone_map[id];
  Bind2DNSRecord bdr;

  recordstorage_t& records=*bb2.d_records; 

  bdr.qname=toLower(canonic(qnameu));
  if(bb2.d_name.empty())
    ;
  else if(bdr.qname==toLower(bb2.d_name))
    bdr.qname.clear();
  else if(bdr.qname.length() > bb2.d_name.length())
    bdr.qname.resize(bdr.qname.length() - (bb2.d_name.length() + 1));
  else
    throw AhuException("Trying to insert non-zone data, name='"+bdr.qname+"', qtype="+qtype.getName()+", zone='"+bb2.d_name+"'");

  bdr.qname.swap(bdr.qname);


  if(!records.empty() && bdr.qname==boost::prior(records.end())->qname)
    bdr.qname=boost::prior(records.end())->qname;

  //  cerr<<"Before reverse: '"<<bdr.qname<<"', ";
  bdr.qname=labelReverse(bdr.qname);
  //  cerr<<"After: '"<<bdr.qname<<"'"<<endl;

  bdr.qtype=qtype.getCode();
  bdr.content=content; 
  bdr.nsec3hash = hashed;

  if(bdr.qtype == QType::MX || bdr.qtype == QType::SRV) { 
    prio=atoi(bdr.content.c_str());
    
    string::size_type pos = bdr.content.find_first_not_of("0123456789");
    if(pos != string::npos)
      boost::erase_head(bdr.content, pos);
    trim_left(bdr.content);
  }
  
  if(bdr.qtype==QType::CNAME || bdr.qtype==QType::MX || bdr.qtype==QType::NS || bdr.qtype==QType::AFSDB)
    bdr.content=canonic(bdr.content); // I think this is wrong, the zoneparser should not come up with . terminated stuff XXX FIXME

  bdr.ttl=ttl;
  bdr.priority=prio;
  
  records.insert(bdr);
}

void Bind2Backend::reload()
{
  Lock l(&s_state_lock);
  for(id_zone_map_t::iterator i = s_state->id_zone_map.begin(); i != s_state->id_zone_map.end(); ++i) 
    i->second.d_checknow=true;
}

string Bind2Backend::DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  shared_ptr<State> state = getState();
  ostringstream ret;

  for(vector<string>::const_iterator i=parts.begin()+1;i<parts.end();++i) {
    if(state->name_id_map.count(*i)) {
      BB2DomainInfo& bbd=state->id_zone_map[state->name_id_map[*i]];
      
      queueReload(&bbd);
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
  shared_ptr<State> state = getState();
      
  if(parts.size() > 1) {
    for(vector<string>::const_iterator i=parts.begin()+1;i<parts.end();++i) {
      if(state->name_id_map.count(*i)) {
        BB2DomainInfo& bbd=state->id_zone_map[state->name_id_map[*i]];  // XXX s_name_id_map needs trick as well
        ret<< *i << ": "<< (bbd.d_loaded ? "": "[rejected]") <<"\t"<<bbd.d_status<<"\n";      
    }
      else
        ret<< *i << " no such domain\n";
    }    
  }
  else
    for(id_zone_map_t::iterator i=state->id_zone_map.begin(); i!=state->id_zone_map.end(); ++i) 
      ret<< i->second.d_name << ": "<< (i->second.d_loaded ? "": "[rejected]") <<"\t"<<i->second.d_status<<"\n";      

  if(ret.str().empty())
    ret<<"no domains passed";

  return ret.str();
}


string Bind2Backend::DLListRejectsHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  shared_ptr<State> state = getState();

  ostringstream ret;
  for(id_zone_map_t::iterator j = state->id_zone_map.begin(); j != state->id_zone_map.end(); ++j) 
    if(!j->second.d_loaded)
      ret<<j->second.d_name<<"\t"<<j->second.d_status<<endl;
        
  return ret.str();
}

Bind2Backend::Bind2Backend(const string &suffix)
{
#if __GNUC__ >= 3
    std::ios_base::sync_with_stdio(false);
#endif
  d_logprefix="[bind"+suffix+"backend]";
  setArgPrefix("bind"+suffix);
  Lock l(&s_startup_lock);

  d_transaction_id=0;
  if(!s_first) {
    return;
  }
  s_first=0;
  s_state = shared_ptr<State>(new State);
  loadConfig();

  extern DynListener *dl;
  dl->registerFunc("BIND-RELOAD-NOW", &DLReloadNowHandler);
  dl->registerFunc("BIND-DOMAIN-STATUS", &DLDomStatusHandler);
  dl->registerFunc("BIND-LIST-REJECTS", &DLListRejectsHandler);
}

Bind2Backend::~Bind2Backend()
{

}

void Bind2Backend::rediscover(string *status)
{
  loadConfig(status);
}
#if 0
static void prefetchFile(const std::string& fname)
{

  static int fd;
  if(fd > 0)
    close(fd);
  fd=open(fname.c_str(), O_RDONLY);
  if(fd < 0)
    return;

  posix_fadvise(fd, 0, 0, POSIX_FADV_WILLNEED);
}
#endif 

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

void Bind2Backend::loadConfig(string* status)
{
  // Interference with createSlaveDomain()
  Lock l(&s_state_lock);
  
  static int domain_id=1;

  shared_ptr<State> staging = shared_ptr<State>(new State);

  if(!getArg("config").empty()) {
    BindParser BP;
    try {
      BP.parse(getArg("config"));
    }
    catch(AhuException &ae) {
      L<<Logger::Error<<"Error parsing bind configuration: "<<ae.reason<<endl;
      throw;
    }
      
    vector<BindDomainInfo> domains=BP.getDomains();
    this->alsoNotify = BP.getAlsoNotify();

    s_binddirectory=BP.getDirectory();
    //    ZP.setDirectory(d_binddirectory);

    L<<Logger::Warning<<d_logprefix<<" Parsing "<<domains.size()<<" domain(s), will report when done"<<endl;
    
    int rejected=0;
    int newdomains=0;

    //    random_shuffle(domains.begin(), domains.end());
    struct stat st;
      
    for(vector<BindDomainInfo>::iterator i=domains.begin(); i!=domains.end(); ++i) 
    {
      if(stat(i->filename.c_str(), &st) == 0) {
        i->d_dev = st.st_dev;
        i->d_ino = st.st_ino;
      }
    }

    sort(domains.begin(), domains.end()); // put stuff in inode order
    DNSSECKeeper dk;
    for(vector<BindDomainInfo>::const_iterator i=domains.begin();
        i!=domains.end();
        ++i) 
      {
        if(i->type!="master" && i->type!="slave") {
          L<<Logger::Warning<<d_logprefix<<" Warning! Skipping '"<<i->type<<"' zone '"<<i->name<<"'"<<endl;
          continue;
        }

        BB2DomainInfo* bbd=0;

        if(!s_state->name_id_map.count(i->name)) { // is it fully new?
          bbd=&staging->id_zone_map[domain_id];
          bbd->d_id=domain_id++;
        
          // this isn't necessary, we do this on the actual load
          //	  bbd->d_records=shared_ptr<recordstorage_t > (new recordstorage_t);

          bbd->setCheckInterval(getArgAsNum("check-interval"));
          bbd->d_lastnotified=0;
          bbd->d_loaded=false;
        }
        else {  // no, we knew about it already
          staging->id_zone_map[s_state->name_id_map[i->name]] = s_state->id_zone_map[s_state->name_id_map[i->name]]; // these should all be read-only on s_state
          bbd = &staging->id_zone_map[s_state->name_id_map[i->name]];
        }
        
        staging->name_id_map[i->name]=bbd->d_id; // fill out name -> id map

        // overwrite what we knew about the domain
        bbd->d_name=i->name;

        bool filenameChanged = (bbd->d_filename!=i->filename);
        bbd->d_filename=i->filename;
        bbd->d_masters=i->masters;
        bbd->d_also_notify=i->alsoNotify;
        
        if(filenameChanged || !bbd->d_loaded || !bbd->current()) {
          L<<Logger::Info<<d_logprefix<<" parsing '"<<i->name<<"' from file '"<<i->filename<<"'"<<endl;

          NSEC3PARAMRecordContent ns3pr;
          bool nsec3zone=dk.getNSEC3PARAM(i->name, &ns3pr);
        
          try {
            // we need to allocate a new vector so we don't kill the original, which is still in use!
            bbd->d_records=shared_ptr<recordstorage_t> (new recordstorage_t()); 

            ZoneParserTNG zpt(i->filename, i->name, BP.getDirectory());
            DNSResourceRecord rr;
            string hashed;
            while(zpt.get(rr)) {
              if(nsec3zone)
                hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, rr.qname)));
              insert(staging, bbd->d_id, rr.qname, rr.qtype, rr.content, rr.ttl, rr.priority, hashed);
            }
        
            // sort(staging->id_zone_map[bbd->d_id].d_records->begin(), staging->id_zone_map[bbd->d_id].d_records->end());
            
            shared_ptr<recordstorage_t > records=staging->id_zone_map[bbd->d_id].d_records;
            fixupAuth(records);
            
            staging->id_zone_map[bbd->d_id].setCtime();
            staging->id_zone_map[bbd->d_id].d_loaded=true; 
            staging->id_zone_map[bbd->d_id].d_status="parsed into memory at "+nowTime();
            
            //  s_stage->id_zone_map[bbd->d_id].d_records->swap(*s_staging_zone_map[bbd->d_id].d_records);
          }
          catch(AhuException &ae) {
            ostringstream msg;
            msg<<" error at "+nowTime()+" parsing '"<<i->name<<"' from file '"<<i->filename<<"': "<<ae.reason;

            if(status)
              *status+=msg.str();
            staging->id_zone_map[bbd->d_id].d_status=msg.str();
            L<<Logger::Warning<<d_logprefix<<msg.str()<<endl;
            rejected++;
          }
          catch(std::exception &ae) {
            ostringstream msg;
            msg<<" error at "+nowTime()+" parsing '"<<i->name<<"' from file '"<<i->filename<<"': "<<ae.what();

            if(status)
              *status+=msg.str();
            staging->id_zone_map[bbd->d_id].d_status=msg.str();
            L<<Logger::Warning<<d_logprefix<<msg.str()<<endl;
            rejected++;
          }
        }
        /*
        vector<vector<BBResourceRecord> *>&tmp=d_zone_id_map[bbd.d_id];  // shrink trick
        vector<vector<BBResourceRecord> *>(tmp).swap(tmp);
        */
      }

    // figure out which domains were new and which vanished
    int remdomains=0;
    set<string> oldnames, newnames;
    for(id_zone_map_t::const_iterator j=s_state->id_zone_map.begin();j != s_state->id_zone_map.end();++j) {
      oldnames.insert(j->second.d_name);
    }
    for(id_zone_map_t::const_iterator j=staging->id_zone_map.begin(); j!= staging->id_zone_map.end(); ++j) {
      newnames.insert(j->second.d_name);
    }

    vector<string> diff;
    set_difference(oldnames.begin(), oldnames.end(), newnames.begin(), newnames.end(), back_inserter(diff));
    remdomains=diff.size();

#if 0        
    // remove domains from the *name* map, delete their pointer
    for(vector<string>::const_iterator k=diff.begin();k!=diff.end(); ++k) {
      L<<Logger::Error<<"Removing domain: "<<*k<<endl;
      s_state->name_id_map.erase(*k);
    }

    // now remove from the s_state->id_zone_map
    for(id_zone_map_t::iterator j=s_state->id_zone_map.begin();j!=s_state->id_zone_map.end();++j) { // O(N*M)
      for(vector<string>::const_iterator k=diff.begin();k!=diff.end();++k)
        if(j->second.d_name==*k) {
          L<<Logger::Error<<"Removing records from zone '"<<j->second.d_name<<"' from memory"<<endl;

          j->second.d_loaded=false;
          nukeZoneRecords(&j->second);

          break;
        }
    }
#endif

    // count number of entirely new domains
    vector<string> diff2;
    set_difference(newnames.begin(), newnames.end(), oldnames.begin(), oldnames.end(), back_inserter(diff2));
    newdomains=diff2.size();
    
    Lock l(&s_state_swap_lock);
    s_state.swap(staging); 

    // report
    ostringstream msg;
    msg<<" Done parsing domains, "<<rejected<<" rejected, "<<newdomains<<" new, "<<remdomains<<" removed"; 
    if(status)
      *status=msg.str();

    L<<Logger::Error<<d_logprefix<<msg.str()<<endl;
  }
}

/** nuke all records from memory, keep bbd intact though. */
void Bind2Backend::nukeZoneRecords(BB2DomainInfo *bbd)
{
  bbd->d_loaded=0; // block further access
  bbd->d_records = shared_ptr<recordstorage_t > (new recordstorage_t);
}


void Bind2Backend::queueReload(BB2DomainInfo *bbd)
{
  Lock l(&s_state_lock);

  shared_ptr<State> staging(new State);

  // we reload *now* for the time being

  try {
    nukeZoneRecords(bbd); // ? do we need this?
    staging->id_zone_map[bbd->d_id]=s_state->id_zone_map[bbd->d_id];
    staging->id_zone_map[bbd->d_id].d_records=shared_ptr<recordstorage_t > (new recordstorage_t);  // nuke it

    ZoneParserTNG zpt(bbd->d_filename, bbd->d_name, s_binddirectory);
    DNSResourceRecord rr;
    string hashed;
    DNSSECKeeper dk;
    NSEC3PARAMRecordContent ns3pr;
    bool nsec3zone=dk.getNSEC3PARAM(bbd->d_name, &ns3pr);
    while(zpt.get(rr)) {
      if(nsec3zone)
        hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, rr.qname)));
      insert(staging, bbd->d_id, rr.qname, rr.qtype, rr.content, rr.ttl, rr.priority, hashed);
    }
    // cerr<<"Start sort of "<<staging->id_zone_map[bbd->d_id].d_records->size()<<" records"<<endl;        
    // sort(staging->id_zone_map[bbd->d_id].d_records->begin(), staging->id_zone_map[bbd->d_id].d_records->end());
    // cerr<<"Sorting done"<<endl;
    
    fixupAuth(staging->id_zone_map[bbd->d_id].d_records);
    staging->id_zone_map[bbd->d_id].setCtime();

    s_state->id_zone_map[bbd->d_id]=staging->id_zone_map[bbd->d_id]; // move over

    bbd->setCtime();
    // and raise d_loaded again!
    bbd->d_loaded=1;
    bbd->d_checknow=0;
    bbd->d_status="parsed into memory at "+nowTime();
    L<<Logger::Warning<<"Zone '"<<bbd->d_name<<"' ("<<bbd->d_filename<<") reloaded"<<endl;
  }
  catch(AhuException &ae) {
    ostringstream msg;
    msg<<" error at "+nowTime()+" parsing '"<<bbd->d_name<<"' from file '"<<bbd->d_filename<<"': "<<ae.reason;
    bbd->d_status=msg.str();
  }
  catch(std::exception &ae) {
    ostringstream msg;
    msg<<" error at "+nowTime()+" parsing '"<<bbd->d_name<<"' from file '"<<bbd->d_filename<<"': "<<ae.what();
    bbd->d_status=msg.str();
  }
}

bool Bind2Backend::findBeforeAndAfterUnhashed(BB2DomainInfo& bbd, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)
{
  string domain=toLower(qname);

  //cout<<"starting lower bound for: '"<<domain<<"'"<<endl;

  recordstorage_t::const_iterator iter = bbd.d_records->lower_bound(domain);

  if (iter == bbd.d_records->end() || (iter->qname) > domain)
  {
    before = boost::prior(iter)->qname;
  }
  else
  {
    before = qname;
  }

  //cerr<<"Now upper bound"<<endl;
  iter = bbd.d_records->upper_bound(domain);

  if(iter == bbd.d_records->end()) {
    //cerr<<"\tFound the end, begin storage: '"<<bbd.d_records->begin()->qname<<"', '"<<bbd.d_name<<"'"<<endl;
    after.clear(); // this does the right thing
  } else {
    //cerr<<"\tFound: '"<<(iter->qname)<<"' (nsec3hash='"<<(iter->nsec3hash)<<"')"<<endl;
    after = (iter)->qname;
  }

  //cerr<<"Before: '"<<before<<"', after: '"<<after<<"'\n";
  return true;
}

bool Bind2Backend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)
{
  shared_ptr<State> state = s_state;
  BB2DomainInfo& bbd = state->id_zone_map[id];  
  DNSSECKeeper dk;
  NSEC3PARAMRecordContent ns3pr;
  string auth=state->id_zone_map[id].d_name;
    
  if(!dk.getNSEC3PARAM(auth, &ns3pr)) {
    //cerr<<"in bind2backend::getBeforeAndAfterAbsolute: no nsec3 for "<<auth<<endl;
    return findBeforeAndAfterUnhashed(bbd, qname, unhashed, before, after);
  
  }
  else {
    string lqname = toLower(qname);
    //cerr<<"\nin bind2backend::getBeforeAndAfterAbsolute: nsec3 HASH for "<<auth<<", asked for: "<<lqname<< " (auth: "<<auth<<".)"<<endl;
    typedef recordstorage_t::index<HashedTag>::type records_by_hashindex_t;
    records_by_hashindex_t& hashindex=boost::multi_index::get<HashedTag>(*bbd.d_records);
    
//    BOOST_FOREACH(const Bind2DNSRecord& bdr, hashindex) {
//      cerr<<"Hash: "<<bdr.nsec3hash<<"\t"<< (lqname < bdr.nsec3hash) <<endl;
//    }
    
    records_by_hashindex_t::const_iterator lowIter = hashindex.lower_bound(lqname);
    records_by_hashindex_t::const_iterator highIter = hashindex.upper_bound(lqname);
//    cerr<<"iter == hashindex.begin(): "<< (iter == hashindex.begin()) << ", ";
  //  cerr<<"iter == hashindex.end(): "<< (iter == hashindex.end()) << endl;
    if(lowIter == hashindex.end()) {  
//      cerr<<"This hash is beyond the highest hash, wrapping around"<<endl;
      before = hashindex.rbegin()->nsec3hash; // highest hash
      after = hashindex.begin()->nsec3hash; // lowest hash
      unhashed = dotConcat(labelReverse(hashindex.rbegin()->qname), auth);
    }
    else if(lowIter->nsec3hash == lqname) { // exact match
      before = lowIter->nsec3hash;
      unhashed = dotConcat(labelReverse(lowIter->qname), auth);
  //    cerr<<"Had direct hit, setting unhashed: "<<unhashed<<endl;      
      if(highIter != hashindex.end())
       after = highIter->nsec3hash;
      else
       after = hashindex.begin()->nsec3hash;
    }
    else  {
     // iter will always be HIGHER than lqname, but that's not what we need
     //  rest .. before pos_iter/after pos
     //             lqname
      if(highIter != hashindex.end())
       after = highIter->nsec3hash; // that one is easy
      else
       after = hashindex.begin()->nsec3hash;
       
      if(lowIter != hashindex.begin()) {
       --lowIter;
       before = lowIter->nsec3hash;
       unhashed = dotConcat(labelReverse(lowIter->qname), auth);
      }
      else {
       before = hashindex.rbegin()->nsec3hash;
       unhashed = dotConcat(labelReverse(hashindex.rbegin()->qname), auth);       
      }
    }
    
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

  shared_ptr<State> state = s_state;

  name_id_map_t::const_iterator iditer;
  while((iditer=state->name_id_map.find(domain)) == state->name_id_map.end() && chopOff(domain))
    ;

  if(iditer==state->name_id_map.end()) {
    if(mustlog)
      L<<Logger::Warning<<"Found no authoritative zone for "<<qname<<endl;
    d_handle.d_list=false;
    return;
  }
  //  unsigned int id=*iditer;
  if(mustlog)
    L<<Logger::Warning<<"Found a zone '"<<domain<<"' (with id " << iditer->second<<") that might contain data "<<endl;
    
  d_handle.id=iditer->second;
  
  DLOG(L<<"Bind2Backend constructing handle for search for "<<qtype.getName()<<" for "<<
       qname<<endl);
  
  if(domain.empty())
    d_handle.qname=qname;
  else if(strcasecmp(qname.c_str(),domain.c_str()))
    d_handle.qname=qname.substr(0,qname.size()-domain.length()-1); // strip domain name

  d_handle.qtype=qtype;
  d_handle.domain=qname.substr(qname.size()-domain.length());

  BB2DomainInfo& bbd = state->id_zone_map[iditer->second];
  if(!bbd.d_loaded) {
    d_handle.reset();
    throw DBException("Zone for '"+bbd.d_name+"' in '"+bbd.d_filename+"' temporarily not available (file missing, or master dead)"); // fsck
  }
    
  if(!bbd.current()) {
    L<<Logger::Warning<<"Zone '"<<bbd.d_name<<"' ("<<bbd.d_filename<<") needs reloading"<<endl;
    queueReload(&bbd);  // how can this be safe - ok, everybody should have their own reference counted copy of 'records'
    state = s_state;
  }

  d_handle.d_records = bbd.d_records; // give it a reference counted copy
  
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

  if(!d_iter->auth && r.qtype.getCode() != QType::A && r.qtype.getCode()!=QType::AAAA && r.qtype.getCode() != QType::NS)
    cerr<<"Warning! Unauth response!"<<endl;
  r.auth = d_iter->auth;

  d_iter++;

  return true;
}

bool Bind2Backend::list(const string &target, int id)
{
  shared_ptr<State> state = s_state;
  if(!state->id_zone_map.count(id))
    return false;

  d_handle.reset(); 
  DLOG(L<<"Bind2Backend constructing handle for list of "<<id<<endl);

  d_handle.d_records=state->id_zone_map[id].d_records; // give it a copy, which will stay around
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

// this function really is too slow
bool Bind2Backend::isMaster(const string &name, const string &ip)
{
  shared_ptr<State> state = getState(); 
  for(id_zone_map_t::iterator j=state->id_zone_map.begin(); j!=state->id_zone_map.end();++j) {
    if(j->second.d_name==name) {
      for(vector<string>::const_iterator iter = j->second.d_masters.begin(); iter != j->second.d_masters.end(); ++iter)
        if(*iter==ip)
          return true;
    }
  }
  return false;
}

bool Bind2Backend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db)
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

bool Bind2Backend::createSlaveDomain(const string &ip, const string &domain, const string &account)
{
  // Interference with loadConfig(), use locking
  Lock l(&s_state_lock);

  string filename = getArg("supermaster-destdir")+'/'+domain;
  
  L << Logger::Warning << d_logprefix
    << " Writing bind config zone statement for superslave zone '" << domain
    << "' from supermaster " << ip << endl;
        
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

  int newid=0;
  // Find a free zone id nr.  
  
  if (!s_state->id_zone_map.empty()) {
    id_zone_map_t::reverse_iterator i = s_state->id_zone_map.rbegin();
    newid = i->second.d_id + 1;
  }
  
  BB2DomainInfo &bbd = s_state->id_zone_map[newid];

  bbd.d_records = shared_ptr<recordstorage_t >(new recordstorage_t);
  bbd.d_name = domain;
  bbd.setCheckInterval(getArgAsNum("check-interval"));
  bbd.d_masters.push_back(ip);
  bbd.d_filename = filename;

  s_state->name_id_map[domain] = bbd.d_id;
  
  return true;
}

class Bind2Factory : public BackendFactory
{
   public:
      Bind2Factory() : BackendFactory("bind") {}

      void declareArguments(const string &suffix="")
      {
         declare(suffix,"config","Location of named.conf","");
         //         declare(suffix,"example-zones","Install example zones","no");
         declare(suffix,"check-interval","Interval for zonefile changes","0");
         declare(suffix,"supermaster-config","Location of (part of) named.conf where pdns can write zone-statements to","");
         declare(suffix,"supermasters","List of IP-addresses of supermasters","");
         declare(suffix,"supermaster-destdir","Destination directory for newly added slave zones",::arg()["config-dir"]);
      }

      DNSBackend *make(const string &suffix="")
      {
         return new Bind2Backend(suffix);
      }
};

//! Magic class that is activated when the dynamic library is loaded
class Bind2Loader
{
public:
  Bind2Loader()
  {
    BackendMakers().report(new Bind2Factory);
    L<<Logger::Notice<<"[Bind2Backend] This is the bind backend version "VERSION" ("__DATE__", "__TIME__") reporting"<<endl;
  }
};
static Bind2Loader bind2loader;
