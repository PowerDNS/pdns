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
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#include "auth-querycache.hh"
#include "auth-zonecache.hh"
#include "utility.hh"


#include <dlfcn.h>
#include <string>
#include <map>
#include <sys/types.h>
#include <sstream>
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

extern StatBag S;

LockGuarded<vector<UeberBackend *>> UeberBackend::d_instances;

// initially we are blocked
bool UeberBackend::d_go=false;
bool UeberBackend::s_doANYLookupsOnly=false;
std::mutex UeberBackend::d_mut;
std::condition_variable UeberBackend::d_cond;
AtomicCounter* UeberBackend::s_backendQueries = nullptr;

//! Loads a module and reports it to all UeberBackend threads
bool UeberBackend::loadmodule(const string &name)
{
  g_log<<Logger::Warning <<"Loading '"<<name<<"'" << endl;

  void *dlib=dlopen(name.c_str(), RTLD_NOW);

  if(dlib == nullptr) {
    g_log<<Logger::Error <<"Unable to load module '"<<name<<"': "<<dlerror() << endl;
    return false;
  }

  return true;
}

bool UeberBackend::loadModules(const vector<string>& modules, const string& path)
{
  for (const auto& module: modules) {
    bool res;
    if (module.find('.')==string::npos) {
      res = UeberBackend::loadmodule(path+"/lib"+module+"backend.so");
    } else if (module[0]=='/' || (module[0]=='.' && module[1]=='/') || (module[0]=='.' && module[1]=='.')) {
      // absolute or current path
      res = UeberBackend::loadmodule(module);
    } else {
      res = UeberBackend::loadmodule(path+"/"+module);
    }

    if (res == false) {
      return false;
    }
  }
  return true;
}

void UeberBackend::go()
{
  if (::arg().mustDo("consistent-backends")) {
    s_doANYLookupsOnly = true;
  }

  S.declare("backend-queries", "Number of queries sent to the backend(s)");
  s_backendQueries = S.getPointer("backend-queries");

  {
    std::unique_lock<std::mutex> l(d_mut);
    d_go = true;
  }
  d_cond.notify_all();
}

bool UeberBackend::getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial)
{
  for(auto backend : backends)
    if(backend->getDomainInfo(domain, di, getSerial))
      return true;
  return false;
}

bool UeberBackend::createDomain(const DNSName &domain, const DomainInfo::DomainKind kind, const vector<ComboAddress> &masters, const string &account)
{
  for(DNSBackend* mydb :  backends) {
    if (mydb->createDomain(domain, kind, masters, account)) {
      return true;
    }
  }
  return false;
}

bool UeberBackend::doesDNSSEC()
{
  for(auto* db :  backends) {
    if(db->doesDNSSEC())
      return true;
  }
  return false;
}

bool UeberBackend::addDomainKey(const DNSName& name, const DNSBackend::KeyData& key, int64_t& id)
{
  id = -1;
  for(DNSBackend* db :  backends) {
    if(db->addDomainKey(name, key, id))
      return true;
  }
  return false;
}
bool UeberBackend::getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys)
{
  for(DNSBackend* db :  backends) {
    if(db->getDomainKeys(name, keys))
      return true;
  }
  return false;
}

bool UeberBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta)
{
  for(DNSBackend* db :  backends) {
    if(db->getAllDomainMetadata(name, meta))
      return true;
  }
  return false;
}

bool UeberBackend::getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta)
{
  for(DNSBackend* db :  backends) {
    if(db->getDomainMetadata(name, kind, meta))
      return true;
  }
  return false;
}

bool UeberBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  for(DNSBackend* db :  backends) {
    if(db->setDomainMetadata(name, kind, meta))
      return true;
  }
  return false;
}

bool UeberBackend::activateDomainKey(const DNSName& name, unsigned int id)
{
  for(DNSBackend* db :  backends) {
    if(db->activateDomainKey(name, id))
      return true;
  }
  return false;
}

bool UeberBackend::deactivateDomainKey(const DNSName& name, unsigned int id)
{
  for(DNSBackend* db :  backends) {
    if(db->deactivateDomainKey(name, id))
      return true;
  }
  return false;
}

bool UeberBackend::publishDomainKey(const DNSName& name, unsigned int id)
{
  for(DNSBackend* db :  backends) {
    if(db->publishDomainKey(name, id))
      return true;
  }
  return false;
}

bool UeberBackend::unpublishDomainKey(const DNSName& name, unsigned int id)
{
  for(DNSBackend* db :  backends) {
    if(db->unpublishDomainKey(name, id))
      return true;
  }
  return false;
}


bool UeberBackend::removeDomainKey(const DNSName& name, unsigned int id)
{
  for(DNSBackend* db :  backends) {
    if(db->removeDomainKey(name, id))
      return true;
  }
  return false;
}


bool UeberBackend::getTSIGKey(const DNSName& name, DNSName* algorithm, string* content)
{
  for(DNSBackend* db :  backends) {
    if(db->getTSIGKey(name, algorithm, content))
      return true;
  }
  return false;
}


bool UeberBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content)
{
  for(DNSBackend* db :  backends) {
    if(db->setTSIGKey(name, algorithm, content))
      return true;
  }
  return false;
}

bool UeberBackend::deleteTSIGKey(const DNSName& name)
{
  for(DNSBackend* db :  backends) {
    if(db->deleteTSIGKey(name))
      return true;
  }
  return false;
}

bool UeberBackend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{
  for(DNSBackend* db :  backends) {
    db->getTSIGKeys(keys);
  }
  return true;
}

void UeberBackend::reload()
{
  for (auto & backend : backends)
  {
    backend->reload();
  }
}

void UeberBackend::updateZoneCache() {
  if (!g_zoneCache.isEnabled()) {
    return;
  }

  vector<tuple<DNSName, int>> zone_indices;
  g_zoneCache.setReplacePending();

  for (vector<DNSBackend*>::iterator i = backends.begin(); i != backends.end(); ++i )
  {
    vector<DomainInfo> zones;
    (*i)->getAllDomains(&zones, false, true);
    for(auto& di: zones) {
      zone_indices.emplace_back(std::move(di.zone), (int)di.id); // this cast should not be necessary
    }
  }
  g_zoneCache.replace(zone_indices);
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

  updateZoneCache();
}


void UeberBackend::getUnfreshSlaveInfos(vector<DomainInfo>* domains)
{
  for (auto & backend : backends)
  {
    backend->getUnfreshSlaveInfos( domains );
  }  
}



void UeberBackend::getUpdatedMasters(vector<DomainInfo>* domains)
{
  for (auto & backend : backends)
  {
    backend->getUpdatedMasters( domains );
  }
}

bool UeberBackend::inTransaction()
{
  for (auto* b : backends )
  {
    if(b->inTransaction())
      return true;
  }
  return false;
}

bool UeberBackend::getAuth(const DNSName &target, const QType& qtype, SOAData* sd, bool cachedOk)
{
  // A backend can respond to our authority request with the 'best' match it
  // has. For example, when asked for a.b.c.example.com. it might respond with
  // com. We then store that and keep querying the other backends in case one
  // of them has a more specific zone but don't bother asking this specific
  // backend again for b.c.example.com., c.example.com. and example.com.
  // If a backend has no match it may respond with an empty qname.
  bool found = false;
  int cstat;
  DNSName shorter(target);
  vector<pair<size_t, SOAData> > bestmatch (backends.size(), pair(target.wirelength()+1, SOAData()));
  do {
    int zoneId{-1};
    if(cachedOk && g_zoneCache.isEnabled()) {
      if (g_zoneCache.getEntry(shorter, zoneId)) {
        // Zone exists in zone cache, directly look up SOA.
        DNSZoneRecord zr;
        lookup(QType(QType::SOA), shorter, zoneId, nullptr);
        if (!get(zr)) {
          DLOG(g_log << Logger::Info << "Backend returned no SOA for zone '" << shorter.toLogString() << "', which it reported as existing " << endl);
          continue;
        }
        if (zr.dr.d_name != shorter) {
          throw PDNSException("getAuth() returned an SOA for the wrong zone. Zone '"+zr.dr.d_name.toLogString()+"' is not equal to looked up zone '"+shorter.toLogString()+"'");
        }
        // fill sd
        sd->qname = zr.dr.d_name;
        try {
          fillSOAData(zr, *sd);
        }
        catch (...) {
          g_log << Logger::Warning << "Backend returned a broken SOA for zone '" << shorter.toLogString() << "'" << endl;
          while (get(zr))
            ;
          continue;
        }
        if (backends.size() == 1) {
          sd->db = *backends.begin();
        }
        else {
          sd->db = nullptr;
        }
        // leave database handle in a consistent state
        while (get(zr))
          ;
        goto found;
      }
      // zone does not exist, try again with shorter name
      continue;
    }

    d_question.qtype = QType::SOA;
    d_question.qname = shorter;
    d_question.zoneId = zoneId;

    // Check cache
    if(cachedOk && (d_cache_ttl || d_negcache_ttl)) {
      cstat = cacheHas(d_question,d_answers);

      if(cstat == 1 && !d_answers.empty() && d_cache_ttl) {
        DLOG(g_log<<Logger::Error<<"has pos cache entry: "<<shorter<<endl);
        fillSOAData(d_answers[0], *sd);

        if (backends.size() == 1) {
          sd->db = *backends.begin();
        } else {
          sd->db = nullptr;
        }
        sd->qname = shorter;
        goto found;
      } else if(cstat == 0 && d_negcache_ttl) {
        DLOG(g_log<<Logger::Error<<"has neg cache entry: "<<shorter<<endl);
        continue;
      }
    }

    // Check backends
    {
      vector<DNSBackend *>::const_iterator i = backends.begin();
      vector<pair<size_t, SOAData> >::iterator j = bestmatch.begin();
      for(; i != backends.end() && j != bestmatch.end(); ++i, ++j) {

        DLOG(g_log<<Logger::Error<<"backend: "<<i-backends.begin()<<", qname: "<<shorter<<endl);

        if(j->first < shorter.wirelength()) {
          DLOG(g_log<<Logger::Error<<"skipped, we already found a shorter best match in this backend: "<<j->second.qname<<endl);
          continue;
        } else if(j->first == shorter.wirelength()) {
          DLOG(g_log<<Logger::Error<<"use shorter best match: "<<j->second.qname<<endl);
          *sd = j->second;
          break;
        } else {
          DLOG(g_log<<Logger::Error<<"lookup: "<<shorter<<endl);
          if((*i)->getAuth(shorter, sd)) {
            DLOG(g_log<<Logger::Error<<"got: "<<sd->qname<<endl);
            if(!sd->qname.empty() && !shorter.isPartOf(sd->qname)) {
              throw PDNSException("getAuth() returned an SOA for the wrong zone. Zone '"+sd->qname.toLogString()+"' is not part of '"+shorter.toLogString()+"'");
            }
            j->first = sd->qname.wirelength();
            j->second = *sd;
            if(sd->qname == shorter) {
              break;
            }
          } else {
            DLOG(g_log<<Logger::Error<<"no match for: "<<shorter<<endl);
          }
        }
      }

      // Add to cache
      if(i == backends.end()) {
        if(d_negcache_ttl) {
          DLOG(g_log<<Logger::Error<<"add neg cache entry:"<<shorter<<endl);
          d_question.qname=shorter;
          addNegCache(d_question);
        }
        continue;
      } else if(d_cache_ttl) {
        DLOG(g_log<<Logger::Error<<"add pos cache entry: "<<sd->qname<<endl);
        d_question.qtype = QType::SOA;
        d_question.qname = sd->qname;
        d_question.zoneId = zoneId;

        DNSZoneRecord rr;
        rr.dr.d_name = sd->qname;
        rr.dr.d_type = QType::SOA;
        rr.dr.d_content = makeSOAContent(*sd);
        rr.dr.d_ttl = sd->ttl;
        rr.domain_id = sd->domain_id;

        addCache(d_question, {rr});
      }
    }

found:
    if(found == (qtype == QType::DS) || target != shorter) {
      DLOG(g_log<<Logger::Error<<"found: "<<sd->qname<<endl);
      return true;
    } else {
      DLOG(g_log<<Logger::Error<<"chasing next: "<<sd->qname<<endl);
      found = true;
    }

  } while(shorter.chopOff());
  return found;
}

bool UeberBackend::getSOAUncached(const DNSName &domain, SOAData &sd)
{
  d_question.qtype=QType::SOA;
  d_question.qname=domain;
  d_question.zoneId=-1;

  for(auto backend : backends)
    if(backend->getSOA(domain, sd)) {
      if(domain != sd.qname) {
        throw PDNSException("getSOA() returned an SOA for the wrong zone. Question: '"+domain.toLogString()+"', answer: '"+sd.qname.toLogString()+"'");
      }
      if(d_cache_ttl) {
        DNSZoneRecord rr;
        rr.dr.d_name = sd.qname;
        rr.dr.d_type = QType::SOA;
        rr.dr.d_content = makeSOAContent(sd);
        rr.dr.d_ttl = sd.ttl;
        rr.domain_id = sd.domain_id;

        addCache(d_question, {rr});

      }
      return true;
    }

  if(d_negcache_ttl)
    addNegCache(d_question);
  return false;
}

bool UeberBackend::superMasterAdd(const AutoPrimary &primary)
{
  for(auto backend : backends)
    if(backend->superMasterAdd(primary))
      return true;
  return false;
}

bool UeberBackend::autoPrimaryRemove(const AutoPrimary &primary)
{
  for(auto backend : backends)
    if(backend->autoPrimaryRemove(primary))
      return true;
  return false;
}

bool UeberBackend::autoPrimariesList(std::vector<AutoPrimary>& primaries)
{
   for(auto backend : backends)
     if(backend->autoPrimariesList(primaries))
       return true;
   return false;
}

bool UeberBackend::superMasterBackend(const string &ip, const DNSName &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db)
{
  for(auto backend : backends)
    if(backend->superMasterBackend(ip, domain, nsset, nameserver, account, db))
      return true;
  return false;
}

UeberBackend::UeberBackend(const string &pname)
{
  {
    d_instances.lock()->push_back(this); // report to the static list of ourself
  }

  d_negcached=false;
  d_cached=false;
  d_cache_ttl = ::arg().asNum("query-cache-ttl");
  d_negcache_ttl = ::arg().asNum("negquery-cache-ttl");
  d_qtype = 0;
  d_stale = false;

  backends=BackendMakers().all(pname=="key-only");
}

static void del(DNSBackend* d)
{
  delete d;
}

void UeberBackend::cleanup()
{
  {
    auto instances = d_instances.lock();
    remove(instances->begin(), instances->end(), this);
    instances->resize(instances->size()-1);
  }

  for_each(backends.begin(),backends.end(),del);
}

// returns -1 for miss, 0 for negative match, 1 for hit
int UeberBackend::cacheHas(const Question &q, vector<DNSZoneRecord> &rrs)
{
  extern AuthQueryCache QC;

  if(!d_cache_ttl && ! d_negcache_ttl) {
    return -1;
  }

  rrs.clear();
  //  g_log<<Logger::Warning<<"looking up: '"<<q.qname+"'|N|"+q.qtype.getName()+"|"+itoa(q.zoneId)<<endl;

  bool ret=QC.getEntry(q.qname, q.qtype, rrs, q.zoneId);   // think about lowercasing here
  if(!ret) {
    return -1;
  }
  if(rrs.empty()) // negatively cached
    return 0;
  
  return 1;
}

void UeberBackend::addNegCache(const Question &q)
{
  extern AuthQueryCache QC;
  if(!d_negcache_ttl)
    return;
  // we should also not be storing negative answers if a pipebackend does scopeMask, but we can't pass a negative scopeMask in an empty set!
  QC.insert(q.qname, q.qtype, vector<DNSZoneRecord>(), d_negcache_ttl, q.zoneId);
}

void UeberBackend::addCache(const Question &q, vector<DNSZoneRecord> &&rrs)
{
  extern AuthQueryCache QC;

  if(!d_cache_ttl)
    return;

  for(const auto& rr : rrs) {
   if (rr.scopeMask)
     return;
  }

  QC.insert(q.qname, q.qtype, std::move(rrs), d_cache_ttl, q.zoneId);
}

void UeberBackend::alsoNotifies(const DNSName &domain, set<string> *ips)
{
  for (auto & backend : backends)
    backend->alsoNotifies(domain,ips);
}

UeberBackend::~UeberBackend()
{
  DLOG(g_log<<Logger::Error<<"UeberBackend destructor called, removing ourselves from instances, and deleting our backends"<<endl);
  cleanup();
}

// this handle is more magic than most
void UeberBackend::lookup(const QType &qtype,const DNSName &qname, int zoneId, DNSPacket *pkt_p)
{
  if(d_stale) {
    g_log<<Logger::Error<<"Stale ueberbackend received question, signalling that we want to be recycled"<<endl;
    throw PDNSException("We are stale, please recycle");
  }

  DLOG(g_log<<"UeberBackend received question for "<<qtype<<" of "<<qname<<endl);
  if (!d_go) {
    g_log<<Logger::Error<<"UeberBackend is blocked, waiting for 'go'"<<endl;
    std::unique_lock<std::mutex> l(d_mut);
    d_cond.wait(l, []{ return d_go == true; });
    g_log<<Logger::Error<<"Broadcast received, unblocked"<<endl;
  }

  d_qtype=qtype.getCode();

  d_handle.i=0;
  d_handle.qtype=s_doANYLookupsOnly ? QType::ANY : qtype;
  d_handle.qname=qname;
  d_handle.zoneId=zoneId;
  d_handle.pkt_p=pkt_p;

  if(!backends.size()) {
    g_log<<Logger::Error<<"No database backends available - unable to answer questions."<<endl;
    d_stale=true; // please recycle us!
    throw PDNSException("We are stale, please recycle");
  }
  else {
    d_question.qtype=d_handle.qtype;
    d_question.qname=qname;
    d_question.zoneId=d_handle.zoneId;

    int cstat=cacheHas(d_question, d_answers);
    if(cstat<0) { // nothing
      //      cout<<"UeberBackend::lookup("<<qname<<"|"<<DNSRecordContent::NumberToType(qtype.getCode())<<"): uncached"<<endl;
      d_negcached=d_cached=false;
      d_answers.clear(); 
      (d_handle.d_hinterBackend=backends[d_handle.i++])->lookup(d_handle.qtype, d_handle.qname, d_handle.zoneId, d_handle.pkt_p);
      ++(*s_backendQueries);
    } 
    else if(cstat==0) {
      //      cout<<"UeberBackend::lookup("<<qname<<"|"<<DNSRecordContent::NumberToType(qtype.getCode())<<"): NEGcached"<<endl;
      d_negcached=true;
      d_cached=false;
      d_answers.clear();
    }
    else {
      // cout<<"UeberBackend::lookup("<<qname<<"|"<<DNSRecordContent::NumberToType(qtype.getCode())<<"): CACHED"<<endl;
      d_negcached=false;
      d_cached=true;
      d_cachehandleiter = d_answers.begin();
    }
  }

  d_handle.parent=this;
}

void UeberBackend::getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled)
{
  for (auto & backend : backends)
  {
    backend->getAllDomains(domains, getSerial, include_disabled);
  }
}

bool UeberBackend::get(DNSZoneRecord &rr)
{
  // cout<<"UeberBackend::get(DNSZoneRecord) called"<<endl;
  if(d_negcached) {
    return false; 
  }

  if(d_cached) {
    while(d_cachehandleiter != d_answers.end()) {
      rr=*d_cachehandleiter++;;
      if((d_qtype == QType::ANY || rr.dr.d_type == d_qtype)) {
        return true;
      }
    }
    return false;
  }

  while(d_handle.get(rr)) {
    rr.dr.d_place=DNSResourceRecord::ANSWER;
    d_answers.push_back(rr);
    if((d_qtype == QType::ANY || rr.dr.d_type == d_qtype)) {
      return true;
    }
  }

  // cout<<"end of ueberbackend get, seeing if we should cache"<<endl;
  if(d_answers.empty()) {
    // cout<<"adding negcache"<<endl;
    addNegCache(d_question);
  }
  else {
    // cout<<"adding query cache"<<endl;
    addCache(d_question, std::move(d_answers));
  }
  d_answers.clear();
  return false;
}

bool UeberBackend::searchRecords(const string& pattern, int maxResults, vector<DNSResourceRecord>& result)
{
  bool rc = false;
  for ( vector< DNSBackend * >::iterator i = backends.begin(); result.size() < static_cast<vector<DNSResourceRecord>::size_type>(maxResults) && i != backends.end(); ++i )
    if ((*i)->searchRecords(pattern, maxResults - result.size(), result)) rc = true;
  return rc;
}

bool UeberBackend::searchComments(const string& pattern, int maxResults, vector<Comment>& result)
{
  bool rc = false;
  for ( vector< DNSBackend * >::iterator i = backends.begin(); result.size() < static_cast<vector<Comment>::size_type>(maxResults) && i != backends.end(); ++i )
    if ((*i)->searchComments(pattern, maxResults - result.size(), result)) rc = true;
  return rc;
}

AtomicCounter UeberBackend::handle::instances(0);

UeberBackend::handle::handle()
{
  //  g_log<<Logger::Warning<<"Handle instances: "<<instances<<endl;
  ++instances;
  parent=nullptr;
  d_hinterBackend=nullptr;
  pkt_p=nullptr;
  i=0;
  zoneId = -1;
}

UeberBackend::handle::~handle()
{
  --instances;
}

bool UeberBackend::handle::get(DNSZoneRecord &r)
{
  DLOG(g_log << "Ueber get() was called for a "<<qtype<<" record" << endl);
  bool isMore=false;
  while(d_hinterBackend && !(isMore=d_hinterBackend->get(r))) { // this backend out of answers
    if(i<parent->backends.size()) {
      DLOG(g_log<<"Backend #"<<i<<" of "<<parent->backends.size()
           <<" out of answers, taking next"<<endl);
      
      d_hinterBackend=parent->backends[i++];
      d_hinterBackend->lookup(qtype,qname,zoneId,pkt_p);
      ++(*s_backendQueries);
    }
    else 
      break;

    DLOG(g_log<<"Now asking backend #"<<i<<endl);
  }

  if(!isMore && i==parent->backends.size()) {
    DLOG(g_log<<"UeberBackend reached end of backends"<<endl);
    return false;
  }

  DLOG(g_log<<"Found an answering backend - will not try another one"<<endl);
  i=parent->backends.size(); // don't go on to the next backend
  return true;
}
