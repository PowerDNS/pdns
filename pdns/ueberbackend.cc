/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "utility.hh"

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif // HAVE_CONFIG_H

#include <string>
#include <map>
#include <sys/types.h>

#include <errno.h>
#include <iostream>
#include <sstream>
#include <functional>

#include "dns.hh"
#include "arguments.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "statbag.hh"
#include "packetcache.hh"

extern StatBag S;

vector<UeberBackend *>UeberBackend::instances;
pthread_mutex_t UeberBackend::instances_lock=PTHREAD_MUTEX_INITIALIZER;

sem_t UeberBackend::d_dynserialize;
string UeberBackend::programname;
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
  // TODO: Implement dynamic loading?
#if !defined(WIN32) && !defined(DARWIN)
  void *dlib=dlopen(name.c_str(), RTLD_NOW);
  
  if(dlib == NULL) {
    L<<Logger::Warning <<"Unable to load module '"<<name<<"': "<<dlerror() << endl; 
    return false;
  }
  
  return true;

#else
  L << Logger::Warning << "This version doesn't support dynamic loading (yet)." << endl;
   return false;

#endif // WIN32

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

/** special trick - if sd.db is set to -1, the cache is ignored */
bool UeberBackend::getSOA(const string &domain, SOAData &sd, DNSPacket *p)
{
  d_question.qtype=QType::SOA;
  d_question.qname=domain;
  d_question.zoneId=-1;
    
  if(sd.db!=(DNSBackend *)-1) {
    int cstat=cacheHas(d_question,d_answer);
    if(cstat==0) {
      return false;
    }
    else if(cstat==1) {
      // ehm 
      DNSPacket::fillSOAData(d_answer.content,sd);
      sd.domain_id=d_answer.domain_id;
      sd.ttl=d_answer.ttl;
      sd.db=0;
      return true;
    }
  }
    

  for(vector<DNSBackend *>::const_iterator i=backends.begin();i!=backends.end();++i)
    if((*i)->getSOA(domain, sd, p)) {
      DNSResourceRecord rr;
      rr.qname=domain;
      rr.qtype=QType::SOA;
      rr.content=DNSPacket::serializeSOAData(sd);
      rr.ttl=sd.ttl;
      rr.domain_id=sd.domain_id;
      addOneCache(d_question,rr);
      return true;
    }

  addNegCache(d_question); 
  return false;
}

bool UeberBackend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db)
{
  for(vector<DNSBackend *>::const_iterator i=backends.begin();i!=backends.end();++i)
    if((*i)->superMasterBackend(ip,domain,nsset,account, db))
      return true;
  return false;

}

void UeberBackend::setStatus(const string &st)
{
  s_status=st;
}

UeberBackend::UeberBackend()
{
  UeberBackend("default");
}

UeberBackend::UeberBackend(const string &pname)
{
  programname=pname;
  pthread_mutex_lock(&instances_lock);
  instances.push_back(this); // report to the static list of ourself
  pthread_mutex_unlock(&instances_lock);

  tid=pthread_self(); 
  stale=false;

  backends=BackendMakers().all();
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

int UeberBackend::cacheHas(const Question &q, DNSResourceRecord &rr)
{
  extern PacketCache PC;
  static int *qcachehit=S.getPointer("query-cache-hit");
  static int *qcachemiss=S.getPointer("query-cache-miss");

  static int negqueryttl=arg().asNum("negquery-cache-ttl");
  static int queryttl=arg().asNum("query-cache-ttl");

  if(!negqueryttl && !queryttl) {
    (*qcachemiss)++;
    return -1;
  }

  string content;
  //  L<<Logger::Warning<<"looking up: "<<q.qname+"|N|"+q.qtype.getName()+"|"+itoa(q.zoneId)<<endl;

  string key=q.qname+"|Q|"+q.qtype.getName()+"|"+itoa(q.zoneId); // perhaps work around g++ 2.95 bug

  bool ret=PC.getKey(key, content);   // think about lowercasing here

  if(!ret) {
    (*qcachemiss)++;
    return -1;
  }

  (*qcachehit)++;
  if(content.empty())
    return 0;
  rr.unSerialize(content);
  return 1;
}

void UeberBackend::addNegCache(const Question &q)
{
  extern PacketCache PC;
  static int negqueryttl=arg().asNum("negquery-cache-ttl");
  if(!negqueryttl)
    return;
  //  L<<Logger::Warning<<"negative inserting: "<<q.qname+"|N|"+q.qtype.getName()+"|"+itoa(q.zoneId)<<endl;
  PC.insert(q.qname+"|Q|"+q.qtype.getName()+"|"+itoa(q.zoneId),"",negqueryttl);
}

void UeberBackend::addOneCache(const Question &q, const DNSResourceRecord &rr)
{
  extern PacketCache PC;
  static int queryttl=arg().asNum("query-cache-ttl");
  if(!queryttl)
    return;

  PC.insert(q.qname+"|Q|"+q.qtype.getName()+"|"+itoa(q.zoneId),rr.serialize(),queryttl);
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
    throw AhuException("We are stale, please recycle");
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

  d_handle.i=0;
  d_handle.qtype=qtype;
  d_handle.qname=qname;
  d_handle.pkt_p=pkt_p;
  d_ancount=0;

  if(!backends.size()) {
    L<<Logger::Error<<Logger::NTLog<<"No database backends available - unable to answer questions."<<endl;
    stale=true; // please recycle us! 
    throw AhuException("We are stale, please recycle");
  }
  else {
    d_question.qtype=qtype;
    d_question.qname=qname;
    d_question.zoneId=zoneId;
    int cstat=cacheHas(d_question,d_answer);
    if(cstat<0) { // nothing
      d_negcached=d_cached=false;
      (d_handle.d_hinterBackend=backends[d_handle.i++])->lookup(qtype, qname,pkt_p,zoneId);
    } 
    else if(cstat==0) {
      d_negcached=true;
      d_cached=false;
    }
    else {
      d_negcached=false;
      d_cached=true;
    }
  }

  d_handle.parent=this;

}

bool UeberBackend::get(DNSResourceRecord &rr)
{
  if(d_negcached) {
    return false; 
  }

  if(d_cached) {
    rr=d_answer;
    d_negcached=true; // ugly, confusing 
    return true;
  }

  if(!d_handle.get(rr)) {
    if(!d_ancount && !d_handle.qname.empty()) // don't cache axfr
      addNegCache(d_question);

    if(d_ancount==1) {
      addOneCache(d_question,lastrr);
    }

    return false;
  }

  if(!d_ancount++) {
    lastrr=rr;
  }
  return true;
}

bool UeberBackend::list(const string &target, int domain_id)
{
  L<<Logger::Error<<"UeberBackend::list called, should NEVER EVER HAPPEN"<<endl;
  exit(1);
  return false;
}


int UeberBackend::handle::instances=0;

UeberBackend::handle::handle()
{
  //  L<<Logger::Warning<<"Handle instances: "<<instances<<endl;
  instances++;
}

UeberBackend::handle::~handle()
{
  instances--;
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
      d_hinterBackend->lookup(qtype,qname,pkt_p);
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
