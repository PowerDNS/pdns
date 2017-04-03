#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cinttypes>

#include "recursor_cache.hh"
#include "misc.hh"
#include <iostream>
#include "dnsrecords.hh"
#include "arguments.hh"
#include "syncres.hh"
#include "recursor_cache.hh"
#include "cachecleaner.hh"
#include "namespaces.hh"

unsigned int MemRecursorCache::size()
{
  return (unsigned int)d_cache.size();
}

// this function is too slow to poll!
unsigned int MemRecursorCache::bytes()
{
  unsigned int ret=0;

  for(cache_t::const_iterator i=d_cache.begin(); i!=d_cache.end(); ++i) {
    ret+=sizeof(struct CacheEntry);
    ret+=(unsigned int)i->d_qname.toString().length();
    for(auto j=i->d_records.begin(); j!= i->d_records.end(); ++j)
      ret+= sizeof(*j); // XXX WRONG we don't know the stored size! j->size();
  }
  return ret;
}

// returns -1 for no hits
int32_t MemRecursorCache::get(time_t now, const DNSName &qname, const QType& qt, vector<DNSRecord>* res, const ComboAddress& who, vector<std::shared_ptr<RRSIGRecordContent>>* signatures)
{
  time_t ttd=0;
  //  cerr<<"looking up "<< qname<<"|"+qt.getName()<<"\n";

  if(!d_cachecachevalid || d_cachedqname!= qname) {
    //    cerr<<"had cache cache miss"<<endl;
    d_cachedqname=qname;
    d_cachecache=d_cache.equal_range(tie(qname));
    d_cachecachevalid=true;
  }
  //  else cerr<<"had cache cache hit!"<<endl;

  if(res)
    res->clear();

  bool haveSubnetSpecific=false;
  if(d_cachecache.first!=d_cachecache.second) {
    for(cache_t::const_iterator i=d_cachecache.first; i != d_cachecache.second; ++i) {
      if(!i->d_netmask.empty()) {
	//	cout<<"Had a subnet specific hit: "<<i->d_netmask.toString()<<", query was for "<<who.toString()<<": match "<<i->d_netmask.match(who)<<endl;
	haveSubnetSpecific=true;
      }
    }
    for(cache_t::const_iterator i=d_cachecache.first; i != d_cachecache.second; ++i)
      if(i->d_ttd > now && ((i->d_qtype == qt.getCode() || qt.getCode()==QType::ANY ||
			    (qt.getCode()==QType::ADDR && (i->d_qtype == QType::A || i->d_qtype == QType::AAAA) )) 
			    && (!haveSubnetSpecific || i->d_netmask.match(who)))
         ) {

	ttd = i->d_ttd;	
        //        cerr<<"Looking at "<<i->d_records.size()<<" records for this name"<<endl;
	for(auto k=i->d_records.begin(); k != i->d_records.end(); ++k) {
	  if(res) {
	    DNSRecord dr;
	    dr.d_name = qname;
	    dr.d_type = i->d_qtype;
	    dr.d_class = 1;
	    dr.d_content = *k; 
	    dr.d_ttl = static_cast<uint32_t>(i->d_ttd);
	    dr.d_place = DNSResourceRecord::ANSWER;
	    res->push_back(dr);
	  }
	}
      
	if(signatures)  // if you do an ANY lookup you are hosed XXXX
	  *signatures=i->d_signatures;
        if(res) {
          if(res->empty())
            moveCacheItemToFront(d_cache, i);
          else
            moveCacheItemToBack(d_cache, i);
        }
        if(qt.getCode()!=QType::ANY && qt.getCode()!=QType::ADDR) // normally if we have a hit, we are done
          break;
      }

    //    cerr<<"time left : "<<ttd - now<<", "<< (res ? res->size() : 0) <<"\n";
    return static_cast<int32_t>(ttd-now);
  }
  return -1;
}



bool MemRecursorCache::attemptToRefreshNSTTL(const QType& qt, const vector<DNSRecord>& content, const CacheEntry& stored)
{
  if(!stored.d_auth) {
    //~ cerr<<"feel free to scribble non-auth data!"<<endl;
    return false;
  }

  if(qt.getCode()!=QType::NS) {
    //~ cerr<<"Not NS record"<<endl;
    return false;
  }
  if(content.size()!=stored.d_records.size()) {
    //~ cerr<<"Not equal number of records"<<endl;
    return false;
  }
  if(stored.d_records.empty())
    return false;

  if(stored.d_ttd > content.begin()->d_ttl) {
    //~ cerr<<"attempt to LOWER TTL - fine by us"<<endl;
    return false;
  }


//  cerr<<"Returning true - update attempt!\n";
  return true;
}

void MemRecursorCache::replace(time_t now, const DNSName &qname, const QType& qt,  const vector<DNSRecord>& content, const vector<shared_ptr<RRSIGRecordContent>>& signatures, bool auth, boost::optional<Netmask> ednsmask)
{
  d_cachecachevalid=false;
  cache_t::iterator stored;
  bool isNew = false;
  auto key=boost::make_tuple(qname, qt.getCode(), ednsmask ? *ednsmask : Netmask());
  stored=d_cache.find(key);
  if(stored == d_cache.end()) {
    stored=d_cache.insert(CacheEntry(key,CacheEntry::records_t(), auth)).first;
    isNew = true;
  }

  time_t maxTTD=std::numeric_limits<time_t>::max();
  CacheEntry ce=*stored; // this is a COPY
  ce.d_qtype=qt.getCode();
  ce.d_signatures=signatures;
  
  //  cerr<<"asked to store "<< (qname.empty() ? "EMPTY" : qname.toString()) <<"|"+qt.getName()<<" -> '";
  //  cerr<<(content.empty() ? string("EMPTY CONTENT")  : content.begin()->d_content->getZoneRepresentation())<<"', auth="<<auth<<", ce.auth="<<ce.d_auth;
  //   cerr<<", ednsmask: "  <<  (ednsmask ? ednsmask->toString() : "none") <<endl;

  if(!auth && ce.d_auth) {  // unauth data came in, we have some auth data, but is it fresh?
    if(ce.d_ttd > now) { // we still have valid data, ignore unauth data
      //      cerr<<"\tStill hold valid auth data, and the new data is unauth, return\n";
      return;
    }
    else {
      ce.d_auth = false;  // new data won't be auth
    }
  }
  ce.d_records.clear();

  // limit TTL of auth->auth NSset update if needed, except for root 
  if(ce.d_auth && auth && qt.getCode()==QType::NS && !isNew && !qname.isRoot()) {
    //    cerr<<"\tLimiting TTL of auth->auth NS set replace to "<<ce.d_ttd<<endl;
    maxTTD = ce.d_ttd;
  }

  // make sure that we CAN refresh the root
  if(auth && (qname.isRoot() || !attemptToRefreshNSTTL(qt, content, ce) ) ) {
    // cerr<<"\tGot auth data, and it was not refresh attempt of an unchanged NS set, nuking storage"<<endl;
    ce.d_records.clear(); // clear non-auth data
    ce.d_auth = true;
  }
//  else cerr<<"\tNot nuking"<<endl;


  for(auto i=content.cbegin(); i != content.cend(); ++i) {

    /* Yes, we have altered the d_ttl value by adding time(nullptr) to it
       prior to calling this function, so the TTL actually holds a TTD. */
    ce.d_ttd=min(maxTTD, static_cast<time_t>(i->d_ttl));   // XXX this does weird things if TTLs differ in the set
    //    cerr<<"To store: "<<i->d_content->getZoneRepresentation()<<" with ttl/ttd "<<i->d_ttl<<", capped at: "<<maxTTD<<endl;
    ce.d_records.push_back(i->d_content);
    // there was code here that did things with TTL and auth. Unsure if it was good. XXX
  }

  if (!isNew) {
    moveCacheItemToBack(d_cache, stored);
  }
  d_cache.replace(stored, ce);
}

int MemRecursorCache::doWipeCache(const DNSName& name, bool sub, uint16_t qtype)
{
  int count=0;
  d_cachecachevalid=false;
  pair<cache_t::iterator, cache_t::iterator> range;

  if(!sub) {
    if(qtype==0xffff)
      range=d_cache.equal_range(tie(name));
    else
      range=d_cache.equal_range(tie(name, qtype));
    for(cache_t::const_iterator i=range.first; i != range.second; ) {
      count++;
      d_cache.erase(i++);
    }
  }
  else {
    for(auto iter = d_cache.lower_bound(tie(name)); iter != d_cache.end(); ) {
      if(!iter->d_qname.isPartOf(name))
	break;
      if(iter->d_qtype == qtype || qtype == 0xffff) {
	count++;
	d_cache.erase(iter++);
      }
      else 
	iter++;
    }
  }
  return count;
}

bool MemRecursorCache::doAgeCache(time_t now, const DNSName& name, uint16_t qtype, uint32_t newTTL)
{
  cache_t::iterator iter = d_cache.find(tie(name, qtype));
  if(iter == d_cache.end()) {
    return false;
  }

  CacheEntry ce = *iter;
  if(ce.d_ttd < now)
    return false;  // would be dead anyhow

  uint32_t maxTTL = static_cast<uint32_t>(ce.d_ttd - now);
  if(maxTTL > newTTL) {
    d_cachecachevalid=false;

    time_t newTTD = now + newTTL;


    if(ce.d_ttd > newTTD) // do never renew expired or older TTLs
      ce.d_ttd = newTTD;
  

    d_cache.replace(iter, ce);
    return true;
  }
  return false;
}

uint64_t MemRecursorCache::doDump(int fd)
{
  FILE* fp=fdopen(dup(fd), "w");
  if(!fp) { // dup probably failed
    return 0;
  }
  fprintf(fp, "; main record cache dump from thread follows\n;\n");
  const auto& sidx=d_cache.get<1>();

  uint64_t count=0;
  time_t now=time(0);
  for(auto i=sidx.cbegin(); i != sidx.cend(); ++i) {
    for(auto j=i->d_records.cbegin(); j != i->d_records.cend(); ++j) {
      count++;
      try {
        fprintf(fp, "%s %" PRId64 " IN %s %s ; %s\n", i->d_qname.toString().c_str(), static_cast<int64_t>(i->d_ttd - now), DNSRecordContent::NumberToType(i->d_qtype).c_str(), (*j)->getZoneRepresentation().c_str(), i->d_netmask.empty() ? "" : i->d_netmask.toString().c_str());
      }
      catch(...) {
        fprintf(fp, "; error printing '%s'\n", i->d_qname.empty() ? "EMPTY" : i->d_qname.toString().c_str());
      }
    }
  }
  fclose(fp);
  return count;
}

void MemRecursorCache::doPrune(void)
{
  d_cachecachevalid=false;

  unsigned int maxCached=::arg().asNum("max-cache-entries") / g_numThreads;
  pruneCollection(d_cache, maxCached);
}
