/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation; 

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

using namespace std;

#include "dns.hh"
#include "dnsbackend.hh"
#include "bindbackend2.hh"
#include "dnspacket.hh"

#include "zoneparser.hh"
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

map<string,int> Bind2Backend::s_name_id_map;
map<u_int32_t,BB2DomainInfo* > Bind2Backend::s_id_zone_map;
int Bind2Backend::s_first=1;
pthread_mutex_t Bind2Backend::s_startup_lock=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Bind2Backend::s_zonemap_lock=PTHREAD_MUTEX_INITIALIZER;

/* when a query comes in, we find the most appropriate zone and answer from that */

BB2DomainInfo::BB2DomainInfo()
{
  d_loaded=false;
  d_last_check=0;
  d_checknow=false;
  d_rwlock=new pthread_rwlock_t;
  d_status="Seen in bind configuration";
  d_confcount=0;
  //  cout<<"Generated a new bbdomaininfo: "<<(void*)d_rwlock<<"/"<<getpid()<<endl;
  pthread_rwlock_init(d_rwlock,0);
}

void BB2DomainInfo::setCheckInterval(time_t seconds)
{
  d_checkinterval=seconds;
}

bool BB2DomainInfo::current()
{
  if(d_checknow)
    return false;

  if(!d_checknow && !d_checkinterval || (time(0)-d_lastcheck<d_checkinterval) || d_filename.empty())
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

void Bind2Backend::setNotified(u_int32_t id, u_int32_t serial)
{
  s_id_zone_map[id]->d_lastnotified=serial;
}

void Bind2Backend::setFresh(u_int32_t domain_id)
{
  s_id_zone_map[domain_id]->d_last_check=time(0);
}

bool Bind2Backend::startTransaction(const string &qname, int id)
{
  BB2DomainInfo &bbd=*s_id_zone_map[d_transaction_id=id];
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
  bbd.lock();

  return true;
}

bool Bind2Backend::commitTransaction()
{
  delete d_of;
  d_of=0;
  if(rename(d_transaction_tmpname.c_str(),s_id_zone_map[d_transaction_id]->d_filename.c_str())<0)
    throw DBException("Unable to commit (rename to: '"+s_id_zone_map[d_transaction_id]->d_filename+"') AXFRed zone: "+stringerror());


  queueReload(s_id_zone_map[d_transaction_id]);
  s_id_zone_map[d_transaction_id]->unlock();
  d_transaction_id=0;

  return true;
}

bool Bind2Backend::abortTransaction()
{
  if(d_transaction_id) {
    s_id_zone_map[d_transaction_id]->unlock();
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
  string domain=s_id_zone_map[d_transaction_id]->d_name;

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
  for(map<u_int32_t,BB2DomainInfo*>::iterator i=s_id_zone_map.begin();i!=s_id_zone_map.end();++i) {
    if(!i->second->d_master.empty())
      continue;
    soadata.serial=0;
    try {
      getSOA(i->second->d_name,soadata); // we might not *have* a SOA yet
    }
    catch(...){}
    DomainInfo di;
    di.id=i->first;
    di.serial=soadata.serial;
    di.zone=i->second->d_name;
    di.last_check=i->second->d_last_check;
    di.backend=this;
    di.kind=DomainInfo::Master;
    if(!i->second->d_lastnotified)            // don't do notification storm on startup 
      i->second->d_lastnotified=soadata.serial;
    else
      if(soadata.serial!=i->second->d_lastnotified)
	changedDomains->push_back(di);
  }
}

void Bind2Backend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  for(map<u_int32_t,BB2DomainInfo*>::const_iterator i=s_id_zone_map.begin();i!=s_id_zone_map.end();++i) {
    if(i->second->d_master.empty())
      continue;
    DomainInfo sd;
    sd.id=i->first;
    sd.zone=i->second->d_name;
    sd.master=i->second->d_master;
    sd.last_check=i->second->d_last_check;
    sd.backend=this;
    sd.kind=DomainInfo::Slave;
    SOAData soadata;
    soadata.serial=0;
    soadata.refresh=0;
    soadata.serial=0;
    soadata.db=(DNSBackend *)-1; // not sure if this is useful, inhibits any caches that might be around
    try {
      getSOA(i->second->d_name,soadata); // we might not *have* a SOA yet
    }
    catch(...){}
    sd.serial=soadata.serial;
    if(sd.last_check+soadata.refresh<(unsigned int)time(0))
      unfreshDomains->push_back(sd);    
  }
}

bool Bind2Backend::getDomainInfo(const string &domain, DomainInfo &di)
{
  for(map<u_int32_t,BB2DomainInfo*>::const_iterator i=s_id_zone_map.begin();i!=s_id_zone_map.end();++i) {
    if(i->second->d_name==domain) {
      di.id=i->first;
      di.zone=domain;
      di.master=i->second->d_master;
      di.last_check=i->second->d_last_check;
      di.backend=this;
      di.kind=i->second->d_master.empty() ? DomainInfo::Master : DomainInfo::Slave;
      di.serial=0;
      try {
	SOAData sd;
	sd.serial=0;
	
	getSOA(i->second->d_name,sd); // we might not *have* a SOA yet
	di.serial=sd.serial;
      }
      catch(...){}

      return true;
    }
  }
  return false;
}


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

map<unsigned int, BB2DomainInfo*> nbbds;
/** This function adds a record to a domain with a certain id. */
void Bind2Backend::insert(int id, const string &qnameu, const string &qtype, const string &content, int ttl=300, int prio=25)
{
  Bind2DNSRecord bdr;

  //  rr.domain_id=id;
  BB2DomainInfo* bb2=nbbds[id];

  vector<Bind2DNSRecord> &records=*bb2->d_records;

  bdr.qname=toLower(canonic(qnameu));
  if(bdr.qname==bb2->d_name)
    bdr.qname.clear();
  else if(bdr.qname.length() > bb2->d_name.length())
    bdr.qname.resize(bdr.qname.length() - (bb2->d_name.length() + 1));
  else
    throw AhuException("Trying to insert non-zone data, name='"+bdr.qname+"', zone='"+nbbds[id]->d_name+"'");

  bdr.qname.swap(bdr.qname);

  if(!records.empty() && bdr.qname==(records.end()-1)->qname)
    bdr.qname=(records.end()-1)->qname;

  bdr.qtype=QType(qtype.c_str()).getCode();
  bdr.content=canonic(content); // I think this is wrong, the zoneparser should not come up with . terminated stuff XXX FIXME
  set<string>::const_iterator i=contents.find(bdr.content);
  if(i!=contents.end())
   bdr.content=*i;
  else {
    contents.insert(bdr.content);
  }

  bdr.ttl=ttl;

  if(qtype=="SOA")
    cout<<"Adding bdr.qname: '"<<bdr.qname<<"'"<<endl;
  records.push_back(bdr);
}


static Bind2Backend *us;

void Bind2Backend::reload()
{
  for(map<u_int32_t,BB2DomainInfo*>::iterator i=us->s_id_zone_map.begin();i!=us->s_id_zone_map.end();++i) 
    i->second->d_checknow=true;
}

string Bind2Backend::DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  ostringstream ret;
  bool doReload=false;
  for(map<u_int32_t,BB2DomainInfo*>::iterator j=us->s_id_zone_map.begin();j!=us->s_id_zone_map.end();++j) {
    doReload=false;
    if(parts.size()==1)
      doReload=true;
    else 
      for(vector<string>::const_iterator i=parts.begin()+1;i<parts.end();++i)                 // O(N) badness XXX FIXME
	if(*i==j->second->d_name) {
	  doReload=true;
	  break;
	}
    
    if(doReload) {
      j->second->lock();

      us->queueReload(j->second);
      j->second->unlock();
      ret<<j->second->d_name<< (j->second->d_loaded ? "": "[rejected]") <<"\t"<<j->second->d_status<<"\n";
    }
    doReload=false;
  }
	
  return ret.str();
}


string Bind2Backend::DLDomStatusHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  string ret;
  bool doPrint=false;
  for(map<u_int32_t,BB2DomainInfo*>::iterator j=us->s_id_zone_map.begin();j!=us->s_id_zone_map.end();++j) {
    ostringstream line;
    doPrint=false;
    if(parts.size()==1)
      doPrint=true;
    else 
      for(vector<string>::const_iterator i=parts.begin()+1;i<parts.end();++i)                 // O(N) badness XXX FIXME
	if(*i==j->second->d_name) {
	  doPrint=true;
	  break;
	}
    
    if(doPrint)
      line<<j->second->d_name<< (j->second->d_loaded ? "": "[rejected]") <<"\t"<<j->second->d_status<<"\n";
    doPrint=false;
    ret+=line.str();
  }
	
  return ret;
}


string Bind2Backend::DLListRejectsHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  ostringstream ret;
  for(map<u_int32_t,BB2DomainInfo*>::iterator j=us->s_id_zone_map.begin();j!=us->s_id_zone_map.end();++j) 
    if(!j->second->d_loaded)
      ret<<j->second->d_name<<"\t"<<j->second->d_status<<endl;
	
  return ret.str();
}

static void callback(unsigned int domain_id, const string &domain, const string &qtype, const string &content, int ttl, int prio)
{
  us->insert(domain_id,domain,qtype,content,ttl,prio);
}

Bind2Backend::Bind2Backend(const string &suffix)
{
#if __GNUC__ >= 3
    ios_base::sync_with_stdio(false);
#endif
  d_logprefix="[bind2"+suffix+"backend]";
  setArgPrefix("bind2"+suffix);
  Lock l(&s_startup_lock);

  d_transaction_id=0;
  if(!s_first) {
    return;
  }
   
  s_first=0;
  
  loadConfig();

  extern DynListener *dl;
  us=this;
  dl->registerFunc("BIND2-RELOAD-NOW", &DLReloadNowHandler);
  dl->registerFunc("BIND2-DOMAIN-STATUS", &DLDomStatusHandler);
  dl->registerFunc("BIND2-LIST-REJECTS", &DLListRejectsHandler);
}


void Bind2Backend::rediscover(string *status)
{
  loadConfig(status);
}

void Bind2Backend::loadConfig(string* status)
{
  // Interference with createSlaveDomain()
  Lock l(&s_zonemap_lock);
  
  static int domain_id=1;
  nbbds.clear();
  if(!getArg("config").empty()) {
    BindParser BP;
    try {
      BP.parse(getArg("config"));
    }
    catch(AhuException &ae) {
      L<<Logger::Error<<"Error parsing bind configuration: "<<ae.reason<<endl;
      throw;
    }
    /*
    cout<<"sizeof Bind2DNSRecord: "<<sizeof(Bind2DNSRecord)<<endl;
    cout<<"sizeof string: "<<sizeof(string)<<endl;
    cout<<"sizeof qtype: "<<sizeof(QType)<<endl;
    */

    ZoneParser ZP;
      
    vector<BindDomainInfo> domains=BP.getDomains();
    
    us=this;

    ZP.setDirectory(BP.getDirectory());
    ZP.setCallback(&callback);  
    L<<Logger::Warning<<d_logprefix<<" Parsing "<<domains.size()<<" domain(s), will report when done"<<endl;
    
    int rejected=0;
    int newdomains=0;

    for(vector<BindDomainInfo>::const_iterator i=domains.begin();
	i!=domains.end();
	++i)
      {
	BB2DomainInfo *bbd=0;
	if(i->type!="master" && i->type!="slave") {
	  L<<Logger::Warning<<d_logprefix<<" Warning! Skipping '"<<i->type<<"' zone '"<<i->name<<"'"<<endl;
	  continue;
	}
	map<unsigned int, BB2DomainInfo*>::const_iterator j=s_id_zone_map.begin();
	for(;j!=s_id_zone_map.end();++j)
	  if(j->second->d_name==i->name) {
	    bbd=j->second;
	    break;
	  }
	if(j==s_id_zone_map.end()) { // entirely new
	  bbd=new BB2DomainInfo;
	  bbd->d_records=new vector<Bind2DNSRecord>;
	  
	  bbd->d_id=domain_id++;
	  s_name_id_map[i->name]=bbd->d_id;
	  bbd->setCheckInterval(getArgAsNum("check-interval"));
	  bbd->d_lastnotified=0;
	  bbd->d_loaded=false;
	}

	bbd->d_name=i->name;
	bbd->d_filename=i->filename;
	bbd->d_master=i->master;
	
	nbbds[bbd->d_id]=bbd; 
	if(!bbd->d_loaded) {
	  L<<Logger::Info<<d_logprefix<<" parsing '"<<i->name<<"' from file '"<<i->filename<<"'"<<endl;
	  
	  try {
	    ZP.parse(i->filename,i->name,bbd->d_id); // calls callback for us
	    L<<Logger::Info<<d_logprefix<<" sorting '"<<i->name<<"'"<<endl;
	    sort(nbbds[bbd->d_id]->d_records->begin(), nbbds[bbd->d_id]->d_records->end());
	    nbbds[bbd->d_id]->setCtime();
	    nbbds[bbd->d_id]->d_loaded=true;          // does this perform locking for us?
	    nbbds[bbd->d_id]->d_status="parsed into memory at "+nowTime();
	    //	    cout<<"Had "<<contents.size()<<" different content fields, "<<nbbds[bbd->d_id]->d_records->size()<<" records, capacity: "<<
	    //	      nbbds[bbd->d_id]->d_records->capacity()<<endl;
	    contents.clear();
	    nbbds[bbd->d_id]->d_records->swap(*nbbds[bbd->d_id]->d_records);

	  }
	  catch(AhuException &ae) {
	    ostringstream msg;
	    msg<<" error at "+nowTime()+" parsing '"<<i->name<<"' from file '"<<i->filename<<"': "<<ae.reason;

	    if(status)
	      *status+=msg.str();
	    nbbds[bbd->d_id]->d_status=msg.str();
	    L<<Logger::Warning<<d_logprefix<<msg.str()<<endl;
	    rejected++;
	  }
	}
	/*
	vector<vector<BBResourceRecord> *>&tmp=d_zone_id_map[bbd.d_id];  // shrink trick
	vector<vector<BBResourceRecord> *>(tmp).swap(tmp);
	*/
      }


    int remdomains=0;
    set<string> oldnames, newnames;
    for(map<unsigned int, BB2DomainInfo*>::const_iterator j=s_id_zone_map.begin();j!=s_id_zone_map.end();++j) {
      oldnames.insert(j->second->d_name);
    }
    for(map<unsigned int, BB2DomainInfo*>::const_iterator j=nbbds.begin();j!=nbbds.end();++j) {
      newnames.insert(j->second->d_name);
    }

    vector<string> diff;
    set_difference(oldnames.begin(), oldnames.end(), newnames.begin(), newnames.end(), back_inserter(diff));
    remdomains=diff.size();
    for(vector<string>::const_iterator k=diff.begin();k!=diff.end();++k) {
      delete s_id_zone_map[s_name_id_map[*k]]->d_records;
      delete s_id_zone_map[s_name_id_map[*k]];
      s_name_id_map.erase(*k);
      L<<Logger::Error<<"Removed: "<<*k<<endl;
    }

    for(map<unsigned int, BB2DomainInfo*>::iterator j=s_id_zone_map.begin();j!=s_id_zone_map.end();++j) { // O(N*M)
      for(vector<string>::const_iterator k=diff.begin();k!=diff.end();++k)
	if(j->second->d_name==*k) {
	  L<<Logger::Error<<"Removing records from zone '"<<j->second->d_name<<"' from memory"<<endl;
	  j->second->lock();
	  j->second->d_loaded=false;
	  nukeZoneRecords(j->second);
	  j->second->unlock(); 
	  break;
	}
    }

    vector<string> diff2;
    set_difference(newnames.begin(), newnames.end(), oldnames.begin(), oldnames.end(), back_inserter(diff2));
    newdomains=diff2.size();

    s_id_zone_map.swap(nbbds); // commit
    ostringstream msg;
    msg<<" Done parsing domains, "<<rejected<<" rejected, "<<newdomains<<" new, "<<remdomains<<" removed"; 
    if(status)
      *status=msg.str();

    L<<Logger::Error<<d_logprefix<<msg.str()<<endl;
    //   L<<Logger::Info<<d_logprefix<<" Number of hash buckets: "<<d_qnames.bucket_count()<<", number of entries: "<<d_qnames.size()<< endl;
  }
}

/** nuke all records from memory, keep bbd intact though. Must be called with bbd lock held already! */
void Bind2Backend::nukeZoneRecords(BB2DomainInfo *bbd)
{
  bbd->d_loaded=0; // block further access
  bbd->d_records->clear();
}

/** Must be called with bbd locked already. Will not be unlocked on return, is your own problem.
    Does not throw errors or anything, may update d_status however */

void Bind2Backend::queueReload(BB2DomainInfo *bbd)
{
  nbbds.clear();

  // we reload *now* for the time being
  //cout<<"unlock domain"<<endl;
  bbd->unlock();
  //cout<<"lock it again"<<endl;

  bbd->lock();
  try {
    nukeZoneRecords(bbd);
    
    ZoneParser ZP;
    us=this;
    ZP.setCallback(&callback);  

    nbbds[bbd->d_id]=s_id_zone_map[bbd->d_id];
    ZP.parse(bbd->d_filename,bbd->d_name,bbd->d_id);
    s_id_zone_map[bbd->d_id]=nbbds[bbd->d_id];

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
}

bool operator<(const Bind2DNSRecord &a, const string &b)
{
  return a.qname < b;
}

bool operator<(const string &a, const Bind2DNSRecord &b)
{
  return a < b.qname;
}


void Bind2Backend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int zoneId )
{
  d_handle.reset(); // =new Bind2Backend::handle;

  string domain=toLower(qname);

  if(arg().mustDo("query-logging"))
    L<<"Lookup for '"<<qtype.getName()<<"' of '"<<domain<<"'"<<endl;

  while(!s_name_id_map.count(domain) && chopOff(domain));

  if(!s_name_id_map.count(domain)) {
    d_handle.d_list=false;
    d_handle.d_bbd=0;
    return;
  }
  unsigned int id=s_name_id_map[domain];

  d_handle.id=id;
  
  DLOG(L<<"Bind2Backend constructing handle for search for "<<qtype.getName()<<" for "<<
       qname<<endl);
  
  if(strcasecmp(qname.c_str(),domain.c_str()))
    d_handle.qname=toLower(qname.substr(0,qname.size()-domain.length()-1)); // strip domain name
  
  d_handle.parent=this;
  d_handle.qtype=qtype;
  d_handle.domain=domain;
  d_handle.d_records=s_id_zone_map[id]->d_records; // give it a copy
  d_handle.d_bbd=0;
  if(!d_handle.d_records->empty()) {
    BB2DomainInfo& bbd=*s_id_zone_map[id];
    if(!bbd.d_loaded) {
      d_handle.reset();
      throw DBException("Zone temporarily not available (file missing, or master dead)"); // fsck
    }

    if(!bbd.tryRLock()) {
      L<<Logger::Warning<<"Can't get read lock on zone '"<<bbd.d_name<<"'"<<endl;
      d_handle.reset();
      throw DBException("Temporarily unavailable due to a zone lock"); // fsck
    }
    
    if(!bbd.current()) {
      L<<Logger::Warning<<"Zone '"<<bbd.d_name<<"' ("<<bbd.d_filename<<") needs reloading"<<endl;
      queueReload(&bbd);
    }
    d_handle.d_bbd=&bbd;
  }
  else {
    DLOG(L<<"Query with no results"<<endl);
  }

  pair<vector<Bind2DNSRecord>::const_iterator, vector<Bind2DNSRecord>::const_iterator> range;

  //  cout<<"starting equal range for: '"<<d_handle.qname<<"'"<<endl;
  range=equal_range(d_handle.d_records->begin(), d_handle.d_records->end(), d_handle.qname);
  
  if(range.first==range.second) {
    d_handle.d_bbd=0;
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
  d_bbd=0;
  d_records=0;
  count=0;
}

bool Bind2Backend::get(DNSResourceRecord &r)
{
  if(!d_handle.d_records)
    return false;

  if(!d_handle.get(r)) {
    d_handle.reset();

    if(arg().mustDo("query-logging"))
      L<<"End of answers"<<endl;

    return false;
  }
  if(arg().mustDo("query-logging"))
    L<<"Returning: '"<<r.qtype.getName()<<"' of '"<<r.qname<<"', content: '"<<r.content<<"'"<<endl;
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
    if(d_bbd) {
      d_bbd->unlock();
      d_bbd=0;
    }
    return false;
  }

  while(d_iter!=d_end_iter && !(qtype.getCode()==QType::ANY || (d_iter)->qtype==qtype.getCode())) {
    DLOG(L<<Logger::Warning<<"Skipped "<<qname<<"/"<<QType(d_iter->qtype).getName()<<": '"<<d_iter->content<<"'"<<endl);
    d_iter++;
  }
  if(d_iter==d_end_iter) {
    if(d_bbd) {
      d_bbd->unlock();
      d_bbd=0;
    }
    return false;
  }
  DLOG(L << "Bind2Backend get() returning a rr with a "<<QType(d_iter->qtype).getCode()<<endl);

  r.qname=qname.empty() ? domain : (qname+"."+domain);
  r.domain_id=id;
  r.content=(d_iter)->content;
  //  r.domain_id=(d_iter)->domain_id;
  r.qtype=(d_iter)->qtype;
  r.ttl=(d_iter)->ttl;
  //  r.priority=(d_iter)->priority;
  d_iter++;

  return true;
}

bool Bind2Backend::list(const string &target, int id)
{
  if(!s_id_zone_map.count(id))
    return false;

  d_handle.reset(); // new Bind2Backend::handle;
  DLOG(L<<"Bind2Backend constructing handle for list of "<<id<<endl);

  d_handle.d_qname_iter=s_id_zone_map[id]->d_records->begin();
  d_handle.d_qname_end=s_id_zone_map[id]->d_records->end();   // iter now points to a vector of pointers to vector<BBResourceRecords>

  d_handle.d_records=s_id_zone_map[id]->d_records; // give it a copy --- WHY??? XXX FIXME

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
    d_qname_iter++;
    return true;
  }
  return false;

}

bool Bind2Backend::isMaster(const string &name, const string &ip)
{
  for(map<u_int32_t,BB2DomainInfo*>::iterator j=us->s_id_zone_map.begin();j!=us->s_id_zone_map.end();++j) 
    if(j->second->d_name==name)
      return j->second->d_master==ip;
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
  Lock l(&s_zonemap_lock);

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
  
  BB2DomainInfo *bbd = new BB2DomainInfo;

  bbd->d_records = new vector<Bind2DNSRecord>;
  bbd->d_name = domain;
  bbd->setCheckInterval(getArgAsNum("check-interval"));
  bbd->d_master = ip;
  bbd->d_filename = filename;

  // Find a free zone id nr.    
  if (!s_id_zone_map.empty()) {
    map<unsigned int, BB2DomainInfo*>::reverse_iterator i = s_id_zone_map.rbegin();
    bbd->d_id = i->second->d_id + 1;
  }
  else
    bbd->d_id = 0;

  s_id_zone_map[bbd->d_id] = bbd;
  s_name_id_map[domain] = bbd->d_id;
  
  return true;
}

class Bind2Factory : public BackendFactory
{
   public:
      Bind2Factory() : BackendFactory("bind2") {}

      void declareArguments(const string &suffix="")
      {
         declare(suffix,"config","Location of named.conf","");
         declare(suffix,"example-zones","Install example zones","no");
         declare(suffix,"check-interval","Interval for zonefile changes","0");
         declare(suffix,"supermaster-config","Location of (part of) named.conf where pdns can write zone-statements to","");
         declare(suffix,"supermasters","List of IP-addresses of supermasters","");
         declare(suffix,"supermaster-destdir","Destination directory for newly added slave zones",arg()["config-dir"]);
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
