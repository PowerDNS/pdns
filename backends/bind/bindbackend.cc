/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
// $Id: bindbackend.cc,v 1.2 2002/12/09 16:24:17 ahu Exp $ 
#include <errno.h>
#include <string>
#include <map>
#include <set>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

#include "dns.hh"
#include "dnsbackend.hh"
#include "bindbackend.hh"
#include "dnspacket.hh"

#include "zoneparser.hh"
#include "bindparser.hh"
#include "logger.hh"
#include "arguments.hh"
#include "huffman.hh"
#include "qtype.hh"
#include "misc.hh"

using namespace std;


cmap_t BindBackend::d_qnames;
map<int,vector<vector<BBResourceRecord>* > > BindBackend::d_zone_id_map;  
set<string> BindBackend::s_contents;
HuffmanCodec BindBackend::s_hc;

map<unsigned int,BBDomainInfo> BindBackend::d_bbds;

int BindBackend::s_first=1;

BBDomainInfo::BBDomainInfo()
{
  d_loaded=false;
  d_last_check=0;
  d_checknow=false;
  d_rwlock=new pthread_rwlock_t;
  //cout<<"Generated a new bbdomaininfo: "<<(void*)d_rwlock<<"/"<<getpid()<<endl;
  pthread_rwlock_init(d_rwlock,0);
}

void BBDomainInfo::setCheckInterval(time_t seconds)
{
  d_checkinterval=seconds;
}

bool BBDomainInfo::current()
{
  if(d_checknow)
    return false;

  if(!d_checkinterval || (time(0)-d_lastcheck<d_checkinterval) || d_filename.empty())
    return true;

  return (getCtime()==d_ctime);
}

time_t BBDomainInfo::getCtime()
{
  struct stat buf;
  
  if(d_filename.empty() || stat(d_filename.c_str(),&buf)<0)
    return 0; 
  d_lastcheck=time(0);
  return buf.st_ctime;
}

void BBDomainInfo::setCtime()
{
  struct stat buf;
  if(stat(d_filename.c_str(),&buf)<0)
    return; 
  d_ctime=buf.st_ctime;
}


void BindBackend::setFresh(u_int32_t domain_id)
{
  d_bbds[domain_id].d_last_check=time(0);
}

bool BindBackend::startTransaction(const string &qname, int id)
{
  d_of=new ofstream("/tmp/juh");
  d_bbds[d_transaction_id=id].lock();
  return true;
}

bool BindBackend::commitTransaction()
{
  delete d_of;
  rename("/tmp/juh",d_bbds[d_transaction_id].d_filename.c_str());
  queueReload(&d_bbds[d_transaction_id]);
  d_bbds[d_transaction_id].unlock();
  return true;
}


bool BindBackend::feedRecord(const DNSResourceRecord &r)
{
  if(r.qtype.getCode()!=QType::MX)
    *d_of<<r.qname<<".\t"<<r.ttl<<"\t"<<r.qtype.getName()<<"\t"<<r.content<<endl;
  else
    *d_of<<r.qname<<".\t"<<r.ttl<<"\t"<<r.qtype.getName()<<"\t"<<r.ttl<<"\t"<<r.priority<<"\t"<<r.content<<endl;
  return true;
}

void BindBackend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  for(map<u_int32_t,BBDomainInfo>::const_iterator i=d_bbds.begin();i!=d_bbds.end();++i) {
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
    getSOA(i->second.d_name,soadata);
    sd.serial=soadata.serial;
    if(sd.last_check+soadata.refresh<(unsigned int)time(0))
      unfreshDomains->push_back(sd);    
  }
}

bool BindBackend::getDomainInfo(const string &domain, DomainInfo &di)
{
  for(map<u_int32_t,BBDomainInfo>::const_iterator i=d_bbds.begin();i!=d_bbds.end();++i) {
    if(i->second.d_name==domain) {
      di.id=i->first;
      di.zone=domain;
      di.master=i->second.d_master;
      di.last_check=i->second.d_last_check;
      di.backend=this;
      di.kind=i->second.d_master.empty() ? DomainInfo::Master : DomainInfo::Slave;

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


void BindBackend::insert(int id, const string &qnameu, const string &qtype, const string &content, int ttl=300, int prio=25)
{
  static int s_count;
  static unsigned int len;
  static unsigned int ulen;
  DLOG(  
  if(!((s_count++)%10000))
    cerr<<"\r"<<s_count-1<<", "<<s_contents.size()<<" different contents, "<<d_qnames.size()<<" different qnames, "<<len/1000000<<"MB, saved: "<<
      (ulen-len)/1000;
  );
  string compressed;
  s_hc.encode(toLower(canonic(qnameu)),compressed);
  //  string(compressed).swap(compressed);
  //  cout<<"saved: "<<qnameu.size()-compressed.size()<<endl;

  vector<BBResourceRecord>::const_iterator i;

  if(d_qnames[compressed].empty()) {  // NEW! NEW! NEW! in de top 40!
    d_zone_id_map[id].push_back(&d_qnames[compressed]); 
    i=d_qnames[compressed].end();
  }
  else
    for(i=d_qnames[compressed].begin();i!=d_qnames[compressed].end();++i)
      if(((i)->qtype==QType::chartocode(qtype.c_str())))
	if((*(i)->content==canonic(content)))
	  break; 
  
  // never saw this specific name/type/content triple before
  if(i==d_qnames[compressed].end()) {
    BBResourceRecord v=resourceMaker(id,qtype,canonic(content),ttl,prio);
    v.qnameptr=&d_qnames.find(compressed)->first;
    len+=compressed.size();
    ulen+=qnameu.size();
    d_qnames[compressed].push_back(v);
    
    d_qnames[compressed].reserve(0);
    //    vector<BBResourceRecord>&tmp=d_qnames[compressed];
    // vector<BBResourceRecord>(tmp).swap(tmp);
  }
  else {
    s_count--;
  }

  
}



BBResourceRecord BindBackend::resourceMaker(int id, const string &qtype, const string &content, int ttl, int prio)
{
  BBResourceRecord make;
  
  make.domain_id=id;

  make.qtype=QType::chartocode(qtype.c_str());

  set<string>::const_iterator i=s_contents.find(content);
  if(i==s_contents.end()) {
    s_contents.insert(content);
    i=s_contents.find(content);
  }
  make.content=&*i;
  make.ttl=ttl;
  make.priority=prio;
  return make;
}

static BindBackend *us;
static int domain_id;

static void callback(const string &domain, const string &qtype, const string &content, int ttl, int prio)
{
  us->insert(domain_id,domain,qtype,content,ttl,prio);
}



BindBackend::BindBackend(const string &suffix)
{
  if(!s_first)
    return;
   
  setArgPrefix("bind"+suffix);

  s_first=0;
  if(!mustDo("enable-huffman"))
    s_hc.passthrough(true);
  
  if(mustDo("example-zones")) {
    insert(0,"www.example.com","A","1.2.3.4");
    insert(0,"example.com","SOA","ns1.example.com hostmaster.example.com");
    insert(0,"example.com","NS","ns1.example.com",86400);
    insert(0,"example.com","NS","ns2.example.com",86400);
    insert(0,"example.com","MX","mail.example.com",3600,25);
    insert(0,"example.com","MX","mail1.example.com",3600,25);
    insert(0,"mail.example.com","A","4.3.2.1");
    insert(0,"mail1.example.com","A","5.4.3.2");
    insert(0,"ns1.example.com","A","4.3.2.1");
    insert(0,"ns2.example.com","A","5.4.3.2");
      
    for(int i=0;i<1000;i++)
      insert(0,"host-"+itoa(i)+".example.com","A","2.3.4.5");

    BBDomainInfo bbd;
    bbd.d_name="example.com";
    bbd.d_filename="";
    bbd.d_id=0;
    d_bbds[0]=bbd; 
    
    d_bbds[0].d_loaded=true;
  }
  

  if(!getArg("config").empty()) {
    BindParser BP;
    BP.parse(getArg("config"));
    
    ZoneParser ZP;
      
    vector<BindDomainInfo> domains=BP.getDomains();
    
    us=this;
    domain_id=1;
    ZP.setDirectory(BP.getDirectory());
    ZP.setCallback(&callback);  
    L<<Logger::Warning<<"Parsing "<<domains.size()<<" domain(s)"<<endl;
    
    for(vector<BindDomainInfo>::const_iterator i=domains.begin();
	i!=domains.end();
	++i)
      {
	BBDomainInfo bbd;
	bbd.d_name=i->name;
	bbd.d_filename=i->filename;
	bbd.d_master=i->master;
	bbd.d_id=domain_id;
	bbd.setCtime();
	bbd.setCheckInterval(getArgAsNum("check-interval"));
	
	d_bbds[domain_id]=bbd; 
	
	ZP.parse(i->filename,i->name); // calls callback for us

	vector<vector<BBResourceRecord> *>&tmp=d_zone_id_map[domain_id];
	vector<vector<BBResourceRecord> *>(tmp).swap(tmp);
	d_bbds[domain_id].d_loaded=true;
	
	domain_id++;
      }
    L<<Logger::Warning<<"Done"<<endl;
    L<<Logger::Info<<"Number of buckets: "<<d_qnames.bucket_count()<<", number of entries: "<<d_qnames.size()<< endl;
  }
}

void BindBackend::rediscover()
{

}

void BindBackend::queueReload(BBDomainInfo *bbd)
{
  // we reload *now* for the time being
  //cout<<"unlock domain"<<endl;
  bbd->unlock();
  //cout<<"lock it again"<<endl;
  bbd->lock();
  //cout<<"locked, start nuking records"<<endl;
  bbd->d_loaded=0; // block further access
  
  // now nuke all records with our id
  for(vector<vector<BBResourceRecord> *>::const_iterator i=d_zone_id_map[bbd->d_id].begin();
      i!=d_zone_id_map[bbd->d_id].end();++i)
    {
      (*i)->clear();
    }
  //  cout<<"Now clearing the list of records"<<endl;
  // now zonk the list with all records for our id
  d_zone_id_map[bbd->d_id].clear();
  // now reload


  ZoneParser ZP;
  us=this;
  domain_id=bbd->d_id;
  ZP.setCallback(&callback);  
  ZP.parse(bbd->d_filename,bbd->d_name);
  bbd->setCtime();
  // and raise d_loaded again!
  bbd->d_loaded=1;
  bbd->d_checknow=0;
  L<<Logger::Warning<<"Zone '"<<bbd->d_name<<"' ("<<bbd->d_filename<<") reloaded"<<endl;
}

void BindBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int zoneId )
{
  d_handle=new BindBackend::handle;
  DLOG(L<<"BindBackend constructing handle for search for "<<qtype.getName()<<" for "<<
       qname<<endl);

  d_handle->qname=qname;
  d_handle->parent=this;
  d_handle->qtype=qtype;
  string compressed;
  s_hc.encode(toLower(qname),compressed);
  d_handle->d_records=d_qnames[compressed];
  d_handle->d_bbd=0;
  if(!d_handle->d_records.empty()) {
    BBDomainInfo& bbd=d_bbds[d_handle->d_records.begin()->domain_id];
    if(!bbd.tryRLock()) {
      L<<Logger::Warning<<"Can't get read lock on zone '"<<bbd.d_name<<"'"<<endl;
      delete d_handle;
      throw AhuException("Temporarily unavailable due to a zone lock"); // fuck
    }
      
    if(!bbd.d_loaded) {
      delete d_handle;
      throw AhuException("Temporarily unavailable due to a zone lock"); // fuck
    }

    if(!bbd.current()) {
      L<<Logger::Warning<<"Zone '"<<bbd.d_name<<"' ("<<bbd.d_filename<<") needs reloading"<<endl;
      queueReload(&bbd);
    }
    d_handle->d_bbd=&bbd;
  }
  else {
    DLOG(L<<"Query with no results"<<endl);
  }
  d_handle->d_iter=d_handle->d_records.begin();
  d_handle->d_list=false;
}

BindBackend::handle::handle()
{
  d_bbd=0;
  count=0;
}

bool  BindBackend::get(DNSResourceRecord &r)
{
  if(!d_handle->get(r)) {
    delete d_handle;
    d_handle=0;
    return false;
  }
  return true;
}

bool BindBackend::handle::get(DNSResourceRecord &r)
{
  if(d_list)
    return get_list(r);
  else
    return get_normal(r);
}

bool BindBackend::handle::get_normal(DNSResourceRecord &r)
{
  DLOG(L << "BindBackend get() was called for "<<qtype.getName() << " record  for "<<
       qname<<"- "<<d_records.size()<<" available!"<<endl);
  

  while(d_iter!=d_records.end() && !(qtype=="ANY" || (d_iter)->qtype==QType(qtype).getCode())) {
    DLOG(L<<"Skipped "<<qname<<"/"<<QType(d_iter->qtype).getName()<<": '"<<*d_iter->content<<"'"<<endl);
    d_iter++;
  }
  if(d_iter==d_records.end()) { // we've reached the end
    if(d_bbd) {
      d_bbd->unlock();
      d_bbd=0;
    }
    return false;
  }

  DLOG(L << "BindBackend get() returning a rr with a "<<QType(d_iter->qtype).getCode()<<endl);

  r.qname=qname; // fill this in
  
  r.content=*(d_iter)->content;
  r.domain_id=(d_iter)->domain_id;
  r.qtype=(d_iter)->qtype;
  r.ttl=(d_iter)->ttl;
  r.priority=(d_iter)->priority;
  d_iter++;

  return true;
}

bool BindBackend::list(int id)
{
  d_handle=new BindBackend::handle;
  DLOG(L<<"BindBackend constructing handle for list of "<<id<<endl);

  d_handle->d_qname_iter=d_zone_id_map[id].begin();
  d_handle->d_qname_end=d_zone_id_map[id].end();   // iter now points to a vector of pointers to vector<BBResourceRecords>
  d_handle->d_riter=(*(d_handle->d_qname_iter))->begin();
  d_handle->d_rend=(*(d_handle->d_qname_iter))->end();
  // rend?
  d_handle->parent=this;
  d_handle->id=id;
  d_handle->d_list=true;
  return true;
}

// naam -> naamnummer
// naamnummer -> vector<BBResourceRecords>, BBResourceRecord bevat ook een pointer naar 

bool BindBackend::handle::get_list(DNSResourceRecord &r)
{
  DLOG(L << "BindBackend get_list()"<<endl);

  while(d_riter==d_rend) {
    DLOG(L<<"Starting new record"<<endl);
    d_qname_iter++;
    if(d_qname_iter==d_qname_end) { // we've reached the end of recordsets for this id
      DLOG(L<<"Really stop!"<<endl);
      return false;
    }
    d_riter=(*(d_qname_iter))->begin();
    d_rend=(*(d_qname_iter))->end();
  }
  // d_riter points to a pointer to BBResourceRecord 

  //  r.qname=qname; // fill this in  HOW?!

  r.qname=parent->s_hc.decode(*d_riter->qnameptr);
  
  r.content=*(d_riter)->content;
  r.domain_id=(d_riter)->domain_id;
  r.qtype=(d_riter)->qtype;
  r.ttl=(d_riter)->ttl;
  r.priority=(d_riter)->priority;
  d_riter++;
  return true;
}

class BindFactory : public BackendFactory
{
   public:
      BindFactory() : BackendFactory("bind") {}

      void declareArguments(const string &suffix="")
      {
         declare(suffix,"config","Location of named.conf","");
         declare(suffix,"example-zones","Install example zones","no");
         declare(suffix,"enable-huffman","Enable huffman compression","no");
         declare(suffix,"check-interval","Interval for zonefile changes","0");
      }

      DNSBackend *make(const string &suffix="")
      {
         return new BindBackend(suffix);
      }
};


//! Magic class that is activated when the dynamic library is loaded
class BindLoader
{
public:
  BindLoader()
  {
    BackendMakers().report(new BindFactory);
    L<<Logger::Notice<<"[BindBackend] This is the bind backend version "VERSION" ("__DATE__", "__TIME__") reporting"<<endl;
  }
};
static BindLoader bindloader;
