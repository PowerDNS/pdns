/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2007  PowerDNS.COM BV

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
#include <sstream>
#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
using namespace std;

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
using namespace std;

/** new scheme of things:
    we have zone-id map
    a zone-id has a vector of DNSResourceRecords 
    on start of query, we find the best zone to answer from
*/

static Bind2Backend *us;

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

/* when a query comes in, we find the most appropriate zone and answer from that */

BB2DomainInfo::BB2DomainInfo()
{
  d_loaded=false;
  d_last_check=0;
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

  if(!d_checkinterval || (time(0) - d_lastcheck < d_checkinterval ) || d_filename.empty())
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
  s_state->id_zone_map[domain_id].d_last_check=time(0);
}

bool Bind2Backend::startTransaction(const string &qname, int id)
{
  shared_ptr<State> state = s_state; // is only read from

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
  *d_of<<"; Zone '"+bbd.d_name+"' retrieved from master "<<bbd.d_master<<endl<<"; at "<<nowTime()<<endl;

  return true;
}

bool Bind2Backend::commitTransaction()
{
  delete d_of;
  d_of=0;
  shared_ptr<State> state = s_state;

  // this might fail if s_state was cycled during the AXFR
  if(rename(d_transaction_tmpname.c_str(), state->id_zone_map[d_transaction_id].d_filename.c_str())<0)
    throw DBException("Unable to commit (rename to: '" + state->id_zone_map[d_transaction_id].d_filename+"') AXFRed zone: "+stringerror());

  us->queueReload(&state->id_zone_map[d_transaction_id]);

  d_transaction_id=0;

  return true;
}

bool Bind2Backend::abortTransaction()
{
  if(d_transaction_id) {
    delete d_of;
    d_of=0;
    unlink(d_transaction_tmpname.c_str());
    d_transaction_id=0;
  }

  return true;
}

bool Bind2Backend::feedRecord(const DNSResourceRecord &r)
{
  string qname=r.qname;

  const shared_ptr<State> state = s_state;
  string domain = state->id_zone_map[d_transaction_id].d_name;

  if(!stripDomainSuffix(&qname,domain)) 
    throw DBException("out-of-zone data '"+qname+"' during AXFR of zone '"+domain+"'");

  string content=r.content;

  // SOA needs stripping too! XXX FIXME - also, this should not be here I think
  switch(r.qtype.getCode()) {
  case QType::TXT:
    *d_of<<qname<<"\t"<<r.ttl<<"\t"<<r.qtype.getName()<<"\t\""<<r.content<<"\""<<endl;
    break;
  case QType::MX:
    if(!stripDomainSuffix(&content,domain))
      content+=".";
    *d_of<<qname<<"\t"<<r.ttl<<"\t"<<r.qtype.getName()<<"\t"<<r.priority<<"\t"<<content<<endl;
    break;
  case QType::CNAME:
  case QType::NS:
    if(!stripDomainSuffix(&content,domain))
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

  Lock l(&s_state_lock); // needs to work on the actual state, as we change stuff

  for(id_zone_map_t::iterator i = s_state->id_zone_map.begin(); i != s_state->id_zone_map.end() ; ++i) {
    if(!i->second.d_master.empty())
      continue;
    soadata.serial=0;
    try {
      getSOA(i->second.d_name,soadata); // we might not *have* a SOA yet
    }
    catch(...){}
    DomainInfo di;
    di.id=i->first;
    di.serial=soadata.serial;
    di.zone=i->second.d_name;
    di.last_check=i->second.d_last_check;
    di.backend=this;
    di.kind=DomainInfo::Master;
    if(!i->second.d_lastnotified)            // don't do notification storm on startup 
      i->second.d_lastnotified=soadata.serial;
    else
      if(soadata.serial!=i->second.d_lastnotified)
	changedDomains->push_back(di);
  }
}

void Bind2Backend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  shared_ptr<State> state = s_state;
  for(id_zone_map_t::const_iterator i = state->id_zone_map.begin(); i != state->id_zone_map.end() ; ++i) {
    if(i->second.d_master.empty())
      continue;
    DomainInfo sd;
    sd.id=i->first;
    sd.zone=i->second.d_name;
    sd.master=i->second.d_master;
    sd.last_check=i->second.d_last_check;
    sd.backend=this;
    sd.kind=DomainInfo::Slave;
    SOAData soadata;
    soadata.serial=0;
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
  shared_ptr<State> state = s_state;
  for(id_zone_map_t::const_iterator i = state->id_zone_map.begin(); i != state->id_zone_map.end() ; ++i) {
    if(i->second.d_name==domain) {
      di.id=i->first;
      di.zone=domain;
      di.master=i->second.d_master;
      di.last_check=i->second.d_last_check;
      di.backend=this;
      di.kind=i->second.d_master.empty() ? DomainInfo::Master : DomainInfo::Slave;
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

set<string> contents;

/** This function adds a record to a domain with a certain id. 
    Much of the complication is due to the efforts to benefit from std::string reference counting copy on write semantics */
void Bind2Backend::insert(shared_ptr<State> stage, int id, const string &qnameu, const QType &qtype, const string &content, int ttl=300, int prio=25)
{
  // XXXX WRONG WRONG WRONG REWRITE

  BB2DomainInfo bb2 = stage->id_zone_map[id];
  Bind2DNSRecord bdr;

  vector<Bind2DNSRecord>& records=*bb2.d_records; 

  bdr.qname=toLower(canonic(qnameu));
  if(bdr.qname==toLower(bb2.d_name))
    bdr.qname.clear();
  else if(bdr.qname.length() > bb2.d_name.length())
    bdr.qname.resize(bdr.qname.length() - (bb2.d_name.length() + 1));
  else
    throw AhuException("Trying to insert non-zone data, name='"+bdr.qname+"', zone='" + s_state->id_zone_map[id].d_name+"'");

  bdr.qname.swap(bdr.qname);

  if(!records.empty() && bdr.qname==(records.end()-1)->qname)
    bdr.qname=(records.end()-1)->qname;

  bdr.qtype=qtype.getCode();
  bdr.content=content; 

  if(bdr.qtype == QType::MX || bdr.qtype == QType::SRV) { 
    prio=atoi(bdr.content.c_str());
    
    string::size_type pos = bdr.content.find_first_not_of("0123456789");
    if(pos != string::npos)
      erase_head(bdr.content, pos);
    trim_left(bdr.content);
  }
  
  if(bdr.qtype==QType::CNAME || bdr.qtype==QType::MX || bdr.qtype==QType::NS || bdr.qtype==QType::AFSDB)
    bdr.content=canonic(bdr.content); // I think this is wrong, the zoneparser should not come up with . terminated stuff XXX FIXME

  set<string>::const_iterator i=contents.find(bdr.content);
  if(i!=contents.end())
   bdr.content=*i;
  else {
    contents.insert(bdr.content);
  }

  bdr.ttl=ttl;
  bdr.priority=prio;
  
  records.push_back(bdr);
}

void Bind2Backend::reload()
{
  Lock l(&s_state_lock);
  for(id_zone_map_t::iterator i = us->s_state->id_zone_map.begin(); i != us->s_state->id_zone_map.end(); ++i) 
    i->second.d_checknow=true;
}

string Bind2Backend::DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  shared_ptr<State> state = s_state;
  ostringstream ret;

  for(vector<string>::const_iterator i=parts.begin()+1;i<parts.end();++i) {
    if(state->name_id_map.count(*i)) {
      BB2DomainInfo& bbd=state->id_zone_map[state->name_id_map[*i]];
      
      us->queueReload(&bbd);
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
  shared_ptr<State> state = s_state;;
      
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
  shared_ptr<State> state = s_state;

  ostringstream ret;
  for(id_zone_map_t::iterator j = state->id_zone_map.begin(); j != state->id_zone_map.end(); ++j) 
    if(!j->second.d_loaded)
      ret<<j->second.d_name<<"\t"<<j->second.d_status<<endl;
	
  return ret.str();
}


Bind2Backend::Bind2Backend(const string &suffix)
{
#if __GNUC__ >= 3
    ios_base::sync_with_stdio(false);
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
  us=this;
  dl->registerFunc("BIND-RELOAD-NOW", &DLReloadNowHandler);
  dl->registerFunc("BIND-DOMAIN-STATUS", &DLDomStatusHandler);
  dl->registerFunc("BIND-LIST-REJECTS", &DLListRejectsHandler);
}

Bind2Backend::~Bind2Backend()
{
  if(us==this) {
    L<<Logger::Error<<"Main bind2backend instance being destructed"<<endl;
    exit(1);
  }
}

void Bind2Backend::rediscover(string *status)
{
  us->loadConfig(status);
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
    
    us=this;

    d_binddirectory=BP.getDirectory();
    //    ZP.setDirectory(d_binddirectory);
    //    ZoneParser::callback_t func=boost::bind(&InsertionCallback, staging, _1, _2, _3, _4, _5, _6);


    L<<Logger::Warning<<d_logprefix<<" Parsing "<<domains.size()<<" domain(s), will report when done"<<endl;
    
    int rejected=0;
    int newdomains=0;

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
	  //	  bbd->d_records=shared_ptr<vector<Bind2DNSRecord> > (new vector<Bind2DNSRecord>);

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
	bbd->d_filename=i->filename;
	bbd->d_master=i->master;
	
	if(!bbd->d_loaded || !bbd->current()) {
	  L<<Logger::Info<<d_logprefix<<" parsing '"<<i->name<<"' from file '"<<i->filename<<"'"<<endl;
	  
	  try {
	    // we need to allocate a new vector so we don't kill the original, which is still in use!
	    bbd->d_records=shared_ptr<vector<Bind2DNSRecord> > (new vector<Bind2DNSRecord>); 

	    ZoneParserTNG zpt(i->filename, i->name, BP.getDirectory());
	    DNSResourceRecord rr;
	    while(zpt.get(rr)) {
	      insert(staging, bbd->d_id, rr.qname, rr.qtype, rr.content, rr.ttl, rr.priority);
	    }

	    //	    ZP.parse(i->filename, i->name, bbd->d_id); // calls callback for us
	    L<<Logger::Info<<d_logprefix<<" sorting '"<<i->name<<"'"<<endl;

	    sort(staging->id_zone_map[bbd->d_id].d_records->begin(), staging->id_zone_map[bbd->d_id].d_records->end());
	    
	    staging->id_zone_map[bbd->d_id].setCtime();
	    staging->id_zone_map[bbd->d_id].d_loaded=true; 
	    staging->id_zone_map[bbd->d_id].d_status="parsed into memory at "+nowTime();

	    contents.clear();
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
	  catch(exception &ae) {
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
    
    s_state.swap(staging); // and boy do we hope this is a threadsafe operation!

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
  bbd->d_records = shared_ptr<vector<Bind2DNSRecord> > (new vector<Bind2DNSRecord>);
}


void Bind2Backend::queueReload(BB2DomainInfo *bbd)
{
  Lock l(&s_state_lock);

  shared_ptr<State> staging(new State);

  // we reload *now* for the time being

  try {
    nukeZoneRecords(bbd); // ? do we need this?
    
    us=this;

    staging->id_zone_map[bbd->d_id]=s_state->id_zone_map[bbd->d_id];
    staging->id_zone_map[bbd->d_id].d_records=shared_ptr<vector<Bind2DNSRecord> > (new vector<Bind2DNSRecord>);  // nuke it

    ZoneParserTNG zpt(bbd->d_filename, bbd->d_name, d_binddirectory);
    DNSResourceRecord rr;
    while(zpt.get(rr)) {
      insert(staging, bbd->d_id, rr.qname, rr.qtype, rr.content, rr.ttl, rr.priority);
    }
        
    sort(staging->id_zone_map[bbd->d_id].d_records->begin(), staging->id_zone_map[bbd->d_id].d_records->end());
    staging->id_zone_map[bbd->d_id].setCtime();
    
    contents.clear();

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
  catch(exception &ae) {
    ostringstream msg;
    msg<<" error at "+nowTime()+" parsing '"<<bbd->d_name<<"' from file '"<<bbd->d_filename<<"': "<<ae.what();
    bbd->d_status=msg.str();
  }
}

bool operator<(const Bind2DNSRecord &a, const string &b)
{
  return a.qname < b;
}

bool operator<(const string &a, const Bind2DNSRecord &b)
{
  return a < b.qname;
}


void Bind2Backend::lookup(const QType &qtype, const string &qname, DNSPacket *pkt_p, int zoneId )
{
  d_handle.reset();

  string domain=toLower(qname);

  bool mustlog=::arg().mustDo("query-logging");
  if(mustlog) 
    L<<Logger::Warning<<"Lookup for '"<<qtype.getName()<<"' of '"<<domain<<"'"<<endl;

  shared_ptr<State> state = s_state;

  while(!state->name_id_map.count(domain) && chopOff(domain));

  name_id_map_t::const_iterator iditer=state->name_id_map.find(domain);

  if(iditer==state->name_id_map.end()) {
    if(mustlog)
      L<<Logger::Warning<<"Found no authoritative zone for "<<qname<<endl;
    d_handle.d_list=false;
    return;
  }
  //  unsigned int id=*iditer;
  if(mustlog)
    L<<Logger::Warning<<"Found data in zone '"<<domain<<"' with id "<<iditer->second<<endl;
    
  d_handle.id=iditer->second;
  
  DLOG(L<<"Bind2Backend constructing handle for search for "<<qtype.getName()<<" for "<<
       qname<<endl);
  
  if(strcasecmp(qname.c_str(),domain.c_str()))
    d_handle.qname=qname.substr(0,qname.size()-domain.length()-1); // strip domain name

  d_handle.parent=this;
  d_handle.qtype=qtype;
  d_handle.domain=qname.substr(qname.size()-domain.length());

  BB2DomainInfo& bbd = state->id_zone_map[iditer->second];
  if(!bbd.d_loaded) {
    d_handle.reset();
    throw DBException("Zone temporarily not available (file missing, or master dead)"); // fsck
  }
    
  if(!bbd.current()) {
    L<<Logger::Warning<<"Zone '"<<bbd.d_name<<"' ("<<bbd.d_filename<<") needs reloading"<<endl;
    us->queueReload(&bbd);  // how can this be safe - ok, everybody should have their own reference counted copy of 'records'
    d_handle.d_records = state->id_zone_map[iditer->second].d_records; // give it a *fresh* copy
  }

  d_handle.d_records = state->id_zone_map[iditer->second].d_records; // give it a copy
  
  if(d_handle.d_records->empty())
    DLOG(L<<"Query with no results"<<endl);
  
  pair<vector<Bind2DNSRecord>::const_iterator, vector<Bind2DNSRecord>::const_iterator> range;

  //  cout<<"starting equal range for: '"<<d_handle.qname<<"'"<<endl;
  
  string lname=toLower(d_handle.qname);
  range=equal_range(d_handle.d_records->begin(), d_handle.d_records->end(), lname);
  
  if(range.first==range.second) {
    d_handle.d_list=false;
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
  //  d_records=0;
  count=0;
}

bool Bind2Backend::get(DNSResourceRecord &r)
{
  if(!d_handle.d_records)
    return false;

  if(!d_handle.get(r)) {
    d_handle.reset();

    if(::arg().mustDo("query-logging"))
      L<<"End of answers"<<endl;

    return false;
  }
  if(::arg().mustDo("query-logging"))
    L<<"Returning: '"<<r.qtype.getName()<<"' of '"<<r.qname<<"', content: '"<<r.content<<"', prio: "<<r.priority<<endl;
  return true;
}

bool Bind2Backend::handle::get(DNSResourceRecord &r)
{
  if(d_list)
    return get_list(r);
  else
    return get_normal(r);
}

bool Bind2Backend::handle::get_normal(DNSResourceRecord &r)
{
  DLOG(L << "Bind2Backend get() was called for "<<qtype.getName() << " record  for "<<
       qname<<"- "<<d_records->size()<<" available!"<<endl);
  
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

  d_handle.parent=this;
  d_handle.id=id;
  d_handle.d_list=true;
  return true;

}

bool Bind2Backend::handle::get_list(DNSResourceRecord &r)
{
  if(d_qname_iter!=d_qname_end) {
    r.qname=d_qname_iter->qname.empty() ? domain : (d_qname_iter->qname+"."+domain);
    r.domain_id=id;
    r.content=(d_qname_iter)->content;
    r.qtype=(d_qname_iter)->qtype;
    r.ttl=(d_qname_iter)->ttl;
    r.priority=(d_qname_iter)->priority;
    d_qname_iter++;
    return true;
  }
  return false;

}

bool Bind2Backend::isMaster(const string &name, const string &ip)
{
  for(id_zone_map_t::iterator j=us->s_state->id_zone_map.begin();j!=us->s_state->id_zone_map.end();++j) 
    if(j->second.d_name==name)
      return j->second.d_master==ip;
  return false;
}

bool Bind2Backend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db)
{
  // Check whether we have a configfile available.
  if (getArg("supermaster-config").empty())
    return false;

  ifstream c_if(getArg("supermasters").c_str(), ios::in); // this was nocreate?
  if (!c_if) {
    L << Logger::Error << "Unable to open supermasters file for read: " << stringerror() << endl;
    return false;
  }

  // Format:
  // <ip> <accountname>
  string line, sip, saccount;
  while (getline(c_if, line)) {
    istringstream ii(line);
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
        
  ofstream c_of(getArg("supermaster-config").c_str(),  ios::app);
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

  bbd.d_records = shared_ptr<vector<Bind2DNSRecord> >(new vector<Bind2DNSRecord>);
  bbd.d_name = domain;
  bbd.setCheckInterval(getArgAsNum("check-interval"));
  bbd.d_master = ip;
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
