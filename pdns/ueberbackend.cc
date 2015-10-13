/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

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
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#include "packetcache.hh"
#include "utility.hh"

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif // HAVE_CONFIG_H

#include <string>
#include <map>
#include <sys/types.h>
#include <sstream>
#include <errno.h>
#include <iostream>
#include <sstream>
#include <functional>
#include <boost/foreach.hpp>
#include "dns.hh"
#include "arguments.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "statbag.hh"
#include <boost/serialization/vector.hpp>


extern StatBag S;

vector<UeberBackend *>UeberBackend::instances;
pthread_mutex_t UeberBackend::instances_lock=PTHREAD_MUTEX_INITIALIZER;

sem_t UeberBackend::d_dynserialize;
string UeberBackend::s_status;

// initially we are blocked
bool UeberBackend::d_go=false;
pthread_mutex_t  UeberBackend::d_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t UeberBackend::d_cond = PTHREAD_COND_INITIALIZER;

int UeberBackend::s_s=-1; // ?

#ifdef NEED_RTLD_NOW
#define RTLD_NOW RTLD_LAZY
#endif

//! Loads a module and reports it to all UeberBackend threads
bool UeberBackend::loadmodule(const string &name)
{
  L<<Logger::Warning <<"Loading '"<<name<<"'" << endl;

  void *dlib=dlopen(name.c_str(), RTLD_NOW);

  if(dlib == NULL) {
    L<<Logger::Error <<"Unable to load module '"<<name<<"': "<<dlerror() << endl;
    return false;
  }

  return true;
}

void UeberBackend::go(void)
{
  pthread_mutex_lock(&d_mut);
  d_go=true;
  pthread_cond_broadcast(&d_cond);
  pthread_mutex_unlock(&d_mut);
}

bool UeberBackend::getDomainInfo(const string &domain, DomainInfo &di)
{
  for(vector<DNSBackend *>::const_iterator i=backends.begin();i!=backends.end();++i)
    if((*i)->getDomainInfo(domain, di))
      return true;
  return false;
}

bool UeberBackend::createDomain(const string &domain)
{
  BOOST_FOREACH(DNSBackend* mydb, backends) {
    if(mydb->createDomain(domain)) {
      return true;
    }
  }
  return false;
}

int UeberBackend::addDomainKey(const string& name, const KeyData& key)
{
  int ret;
  BOOST_FOREACH(DNSBackend* db, backends) {
    if((ret = db->addDomainKey(name, key)) >= 0)
      return ret;
  }
  return -1;
}
bool UeberBackend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->getDomainKeys(name, kind, keys))
      return true;
  }
  return false;
}

bool UeberBackend::getAllDomainMetadata(const string& name, std::map<std::string, std::vector<std::string> >& meta)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->getAllDomainMetadata(name, meta))
      return true;
  }
  return false;
}

bool UeberBackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->getDomainMetadata(name, kind, meta))
      return true;
  }
  return false;
}

bool UeberBackend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->setDomainMetadata(name, kind, meta))
      return true;
  }
  return false;
}

bool UeberBackend::activateDomainKey(const string& name, unsigned int id)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->activateDomainKey(name, id))
      return true;
  }
  return false;
}

bool UeberBackend::deactivateDomainKey(const string& name, unsigned int id)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->deactivateDomainKey(name, id))
      return true;
  }
  return false;
}

bool UeberBackend::removeDomainKey(const string& name, unsigned int id)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->removeDomainKey(name, id))
      return true;
  }
  return false;
}


bool UeberBackend::getTSIGKey(const string& name, string* algorithm, string* content)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->getTSIGKey(name, algorithm, content))
      return true;
  }
  return false;
}


bool UeberBackend::setTSIGKey(const string& name, const string& algorithm, const string& content)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->setTSIGKey(name, algorithm, content))
      return true;
  }
  return false;
}

bool UeberBackend::deleteTSIGKey(const string& name)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->deleteTSIGKey(name))
      return true;
  }
  return false;
}

bool UeberBackend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    db->getTSIGKeys(keys);
  }
  return true;
}

bool UeberBackend::getDirectNSECx(uint32_t id, const string &hashed, const QType &qtype, string &before, DNSResourceRecord &rr)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->getDirectNSECx(id, hashed, qtype, before, rr))
      return true;
  }
  return false;
}

bool UeberBackend::getDirectRRSIGs(const string &signer, const string &qname, const QType &qtype, vector<DNSResourceRecord> &rrsigs)
{
  BOOST_FOREACH(DNSBackend* db, backends) {
    if(db->getDirectRRSIGs(signer, qname, qtype, rrsigs))
      return true;
  }
  return false;
}

void UeberBackend::reload()
{
  for ( vector< DNSBackend * >::iterator i = backends.begin(); i != backends.end(); ++i )
  {
    ( *i )->reload();
  }
}

void UeberBackend::rediscover(string *status)
{
  
  for ( vector< DNSBackend * >::iterator i = backends.begin(); i != backends.end(); ++i )
  {
    string tmpstr;
    ( *i )->rediscover(&tmpstr);
    if(status) 
      *status+=tmpstr + (i!=backends.begin() ? "\n" : "");
  }
}


void UeberBackend::getUnfreshSlaveInfos(vector<DomainInfo>* domains)
{
  for ( vector< DNSBackend * >::iterator i = backends.begin(); i != backends.end(); ++i )
  {
    ( *i )->getUnfreshSlaveInfos( domains );
  }  
}



void UeberBackend::getUpdatedMasters(vector<DomainInfo>* domains)
{
  for ( vector< DNSBackend * >::iterator i = backends.begin(); i != backends.end(); ++i )
  {
    ( *i )->getUpdatedMasters( domains );
  }
}

bool UeberBackend::getAuth(DNSPacket *p, SOAData *sd, const string &target, int *zoneId)
{
  int best_match_len = -1;
  bool from_cache = false;  // Was this result fetched from the cache?
  map<string,int> negCacheMap;

  // If not special case of caching explicitly disabled (sd->db = -1), first
  // find the best match from the cache. If DS then we need to find parent so
  // dont bother with caching as it confuses matters.
  if( sd->db != (DNSBackend *)-1 && (d_cache_ttl || d_negcache_ttl)) {
      string subdomain(target);
      int cstat, loops = 0;
      do {
        d_question.qtype = QType::SOA;
        d_question.qname = subdomain;
        d_question.zoneId = -1;

        cstat = cacheHas(d_question,d_answers);

        if(cstat==1 && !d_answers.empty() && d_cache_ttl) {
          fillSOAData(d_answers[0].content,*sd);
          sd->domain_id = d_answers[0].domain_id;
          sd->ttl = d_answers[0].ttl;
          sd->db = 0;
          sd->qname = subdomain;
          //L<<Logger::Error<<"Best cache match: " << sd->qname << " itteration " << loops <<endl;

          // Found first time round this must be the best match
          if( loops == 0  && p->qtype != QType::DS)
            return true;

          from_cache = true;
          best_match_len = sd->qname.length();

          if ( p->qtype != QType::DS || best_match_len < (int)target.length())
            break;
        } else if (cstat==0 && d_negcache_ttl) {
          negCacheMap[subdomain]=1;
        } else
          negCacheMap[subdomain]=0;
        loops++;
      }
      while( chopOff( subdomain ) );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  }

  for(vector<DNSBackend *>::const_iterator i=backends.begin(); i!=backends.end();++i) {

    // Shortcut for the case that we got a direct hit - no need to go
    // through the other backends then.
    if( best_match_len == (int)target.length() && p->qtype != QType::DS )
      goto auth_found;

    if((*i)->getAuth(p, sd, target, zoneId, best_match_len, negCacheMap)) {
        best_match_len = sd->qname.length();
        from_cache = false;
    }
  }

  if( sd->db != (DNSBackend *)-1 && d_negcache_ttl) {
    string shorter(target);

    d_question.qtype=QType::SOA;
    d_question.zoneId=-1;
    while((int)shorter.length() > best_match_len ) {
      map<string,int>::iterator it = negCacheMap.find(shorter);
      if (it == negCacheMap.end() || it->second == 0) {
        d_question.qname=shorter;
        addNegCache(d_question);
      }
      if (!chopOff(shorter))
        break;
    }
  }

  if( best_match_len == -1 )
      return false;

auth_found:
    // Insert into cache. Don't cache if the query was a DS
    if( d_cache_ttl && ! from_cache && p->qtype != QType::DS ) {
        //L<<Logger::Error<<"Saving auth cache for " << sd->qname <<endl;
        d_question.qtype = QType::SOA;
        d_question.qname = sd->qname;
        d_question.zoneId = -1;

        DNSResourceRecord rr;
        rr.qname = sd->qname;
        rr.qtype = QType::SOA;
        rr.content = serializeSOAData(*sd);
        rr.ttl = sd->ttl;
        rr.domain_id = sd->domain_id;
        vector<DNSResourceRecord> rrs;
        rrs.push_back(rr);
        addCache(d_question, rrs);
    }

    return true;
}

/** special trick - if sd.db is set to -1, the cache is ignored */
bool UeberBackend::getSOA(const string &domain, SOAData &sd, DNSPacket *p)
{
  d_question.qtype=QType::SOA;
  d_question.qname=domain;
  d_question.zoneId=-1;
    
  if(sd.db!=(DNSBackend *)-1) {
    int cstat=cacheHas(d_question,d_answers);
    if(cstat==0) { // negative
      return false;
    }
    else if(cstat==1 && !d_answers.empty()) {
      fillSOAData(d_answers[0].content,sd);
      sd.domain_id=d_answers[0].domain_id;
      sd.ttl=d_answers[0].ttl;
      sd.db=0;
      return true;
    }
  }
    
  for(vector<DNSBackend *>::const_iterator i=backends.begin();i!=backends.end();++i)
    if((*i)->getSOA(domain, sd, p)) {
      if( d_cache_ttl ) {
        DNSResourceRecord rr;
        rr.qname=domain;
        rr.qtype=QType::SOA;
        rr.content=serializeSOAData(sd);
        rr.ttl=sd.ttl;
        rr.domain_id=sd.domain_id;
        vector<DNSResourceRecord> rrs;
        rrs.push_back(rr);
        addCache(d_question, rrs);
      }
      return true;
    }

  addNegCache(d_question); 
  return false;
}

bool UeberBackend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db)
{
  for(vector<DNSBackend *>::const_iterator i=backends.begin();i!=backends.end();++i)
    if((*i)->superMasterBackend(ip, domain, nsset, nameserver, account, db))
      return true;
  return false;
}

void UeberBackend::setStatus(const string &st)
{
  s_status=st;
}

UeberBackend::UeberBackend(const string &pname)
{
  pthread_mutex_lock(&instances_lock);
  instances.push_back(this); // report to the static list of ourself
  pthread_mutex_unlock(&instances_lock);

  d_cache_ttl = ::arg().asNum("query-cache-ttl");
  d_negcache_ttl = ::arg().asNum("negquery-cache-ttl");

  tid=pthread_self(); 
  stale=false;

  backends=BackendMakers().all(pname=="key-only");
}

void UeberBackend::die()
{
  cleanup();
  stale=true;
}

void del(DNSBackend* d)
{
  delete d;
}

void UeberBackend::cleanup()
{
  pthread_mutex_lock(&instances_lock);

  remove(instances.begin(),instances.end(),this);
  instances.resize(instances.size()-1);

  pthread_mutex_unlock(&instances_lock);

  for_each(backends.begin(),backends.end(),del);
}

// silly Solaris fix
#undef PC

// returns -1 for miss, 0 for negative match, 1 for hit
int UeberBackend::cacheHas(const Question &q, vector<DNSResourceRecord> &rrs)
{
  extern PacketCache PC;
  static AtomicCounter *qcachehit=S.getPointer("query-cache-hit");
  static AtomicCounter *qcachemiss=S.getPointer("query-cache-miss");

  if(!d_cache_ttl && ! d_negcache_ttl) {
    (*qcachemiss)++;
    return -1;
  }

  string content;
  //  L<<Logger::Warning<<"looking up: '"<<q.qname+"'|N|"+q.qtype.getName()+"|"+itoa(q.zoneId)<<endl;

  bool ret=PC.getEntry(q.qname, q.qtype, PacketCache::QUERYCACHE, content, q.zoneId);   // think about lowercasing here
  if(!ret) {
    (*qcachemiss)++;
    return -1;
  }
  (*qcachehit)++;
  if(content.empty()) // negatively cached
    return 0;
  
  std::istringstream istr(content);
  boost::archive::binary_iarchive boa(istr, boost::archive::no_header);
  rrs.clear();
  boa >> rrs;
  return 1;
}

void UeberBackend::addNegCache(const Question &q)
{
  extern PacketCache PC;
  if(!d_negcache_ttl)
    return;
  // we should also not be storing negative answers if a pipebackend does scopeMask, but we can't pass a negative scopeMask in an empty set!
  PC.insert(q.qname, q.qtype, PacketCache::QUERYCACHE, "", d_negcache_ttl, q.zoneId);
}

void UeberBackend::addCache(const Question &q, const vector<DNSResourceRecord> &rrs)
{
  extern PacketCache PC;

  if(!d_cache_ttl)
    return;

  unsigned int store_ttl = d_cache_ttl;

  //  L<<Logger::Warning<<"inserting: "<<q.qname+"|N|"+q.qtype.getName()+"|"+itoa(q.zoneId)<<endl;
  std::ostringstream ostr;
  boost::archive::binary_oarchive boa(ostr, boost::archive::no_header);

  BOOST_FOREACH(DNSResourceRecord rr, rrs) {
    if (rr.ttl < d_cache_ttl)
      store_ttl = rr.ttl;
    if (rr.scopeMask)
      return;
  }

  boa << rrs;
  PC.insert(q.qname, q.qtype, PacketCache::QUERYCACHE, ostr.str(), store_ttl, q.zoneId);
}

void UeberBackend::alsoNotifies(const string &domain, set<string> *ips)
{
  for ( vector< DNSBackend * >::iterator i = backends.begin(); i != backends.end(); ++i )
    (*i)->alsoNotifies(domain,ips);
}

UeberBackend::~UeberBackend()
{
  DLOG(L<<Logger::Error<<"UeberBackend destructor called, removing ourselves from instances, and deleting our backends"<<endl);
  cleanup();
}

// this handle is more magic than most
void UeberBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int zoneId)
{
  if(stale) {
    L<<Logger::Error<<"Stale ueberbackend received question, signalling that we want to be recycled"<<endl;
    throw PDNSException("We are stale, please recycle");
  }

  DLOG(L<<"UeberBackend received question for "<<qtype.getName()<<" of "<<qname<<endl);
  if(!d_go) {
    pthread_mutex_lock(&d_mut);
    while (d_go==false) {
      L<<Logger::Error<<"UeberBackend is blocked, waiting for 'go'"<<endl;
      pthread_cond_wait(&d_cond, &d_mut);
      L<<Logger::Error<<"Broadcast received, unblocked"<<endl;
    }
    pthread_mutex_unlock(&d_mut);
  }

  domain_id=zoneId;

  d_handle.i=0;
  d_handle.qtype=qtype;
  d_handle.qname=qname;
  d_handle.pkt_p=pkt_p;
  d_ancount=0;

  if(!backends.size()) {
    L<<Logger::Error<<Logger::NTLog<<"No database backends available - unable to answer questions."<<endl;
    stale=true; // please recycle us! 
    throw PDNSException("We are stale, please recycle");
  }
  else {
    d_question.qtype=qtype;
    d_question.qname=qname;
    d_question.zoneId=zoneId;
    int cstat=cacheHas(d_question, d_answers);
    if(cstat<0) { // nothing
      d_negcached=d_cached=false;
      d_answers.clear(); 
      (d_handle.d_hinterBackend=backends[d_handle.i++])->lookup(qtype, qname,pkt_p,zoneId);
    } 
    else if(cstat==0) {
      d_negcached=true;
      d_cached=false;
      d_answers.clear();
    }
    else {
      d_negcached=false;
      d_cached=true;
      d_cachehandleiter = d_answers.begin();
    }
  }

  d_handle.parent=this;
}

void UeberBackend::getAllDomains(vector<DomainInfo> *domains, bool include_disabled) {
  for (vector<DNSBackend*>::iterator i = backends.begin(); i != backends.end(); ++i )
  {
    (*i)->getAllDomains(domains, include_disabled);
  }
}

bool UeberBackend::get(DNSResourceRecord &rr)
{
  if(d_negcached) {
    return false; 
  }

  if(d_cached) {
    if(d_cachehandleiter != d_answers.end()) {
      rr=*d_cachehandleiter++;;
      return true;
    }
    return false;
  }
  if(!d_handle.get(rr)) {
    if(!d_ancount && !d_handle.qname.empty()) // don't cache axfr
      addNegCache(d_question);

    addCache(d_question, d_answers);
    d_answers.clear();
    return false;
  }
  d_ancount++;
  d_answers.push_back(rr);
  return true;
}

bool UeberBackend::list(const string &target, int domain_id, bool include_disabled)
{
  L<<Logger::Error<<"UeberBackend::list called, should NEVER EVER HAPPEN"<<endl;
  exit(1);
  return false;
}


AtomicCounter UeberBackend::handle::instances(0);

UeberBackend::handle::handle()
{
  //  L<<Logger::Warning<<"Handle instances: "<<instances<<endl;
  ++instances;
}

UeberBackend::handle::~handle()
{
  --instances;
}

bool UeberBackend::handle::get(DNSResourceRecord &r)
{
  DLOG(L << "Ueber get() was called for a "<<qtype.getName()<<" record" << endl);
  bool isMore=false;
  while(d_hinterBackend && !(isMore=d_hinterBackend->get(r))) { // this backend out of answers
    if(i<parent->backends.size()) {
      DLOG(L<<"Backend #"<<i<<" of "<<parent->backends.size()
           <<" out of answers, taking next"<<endl);
      
      d_hinterBackend=parent->backends[i++];
      d_hinterBackend->lookup(qtype,qname,pkt_p,parent->domain_id);
    }
    else 
      break;

    DLOG(L<<"Now asking backend #"<<i<<endl);
  }

  if(!isMore && i==parent->backends.size()) {
    DLOG(L<<"UeberBackend reached end of backends"<<endl);
    return false;
  }

  DLOG(L<<"Found an answering backend - will not try another one"<<endl);
  i=parent->backends.size(); // don't go on to the next backend
  return true;
}
