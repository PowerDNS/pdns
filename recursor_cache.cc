#include "recursor_cache.hh"
#include "misc.hh"
#include <iostream>
#include <boost/shared_ptr.hpp>
#include "dnsrecords.hh"
using namespace std;
using namespace boost;

#include "config.h"

#ifdef GCC_SKIP_LOCKING
#include <bits/atomicity.h>
// This code is ugly but does speedup the recursor tremendously on multi-processor systems, and even has a large effect (20, 30%) on uniprocessor 
namespace __gnu_cxx
{
  _Atomic_word
  __attribute__ ((__unused__))
  __exchange_and_add(volatile _Atomic_word* __mem, int __val)
  {
    register _Atomic_word __result=*__mem;
    *__mem+=__val;
    return __result;
  }

  void
  __attribute__ ((__unused__))
  __atomic_add(volatile _Atomic_word* __mem, int __val)
  {
    *__mem+=__val;
  }
}
#endif

DNSResourceRecord String2DNSRR(const string& qname, const QType& qt, const string& serial, uint32_t ttd)
{
  shared_ptr<DNSRecordContent> regen=DNSRecordContent::unserialize(qname,qt.getCode(), serial);
  DNSResourceRecord rr;
  rr.qname=regen->label;
  rr.ttl=ttd; 
  rr.content=regen->getZoneRepresentation();
  rr.qtype=regen->d_qtype;
  //  cerr<<"Returning: '"<<rr.qname<<"' "<<rr.qtype.getName()<<"  "<<rr.ttl<<"  '"<<rr.content<<"'\n";
  rr.content.reserve(0);
  rr.qname.reserve(0);
  return rr;
}

string DNSRR2String(const DNSResourceRecord& rr)
{
  vector<uint8_t> packet;
  
  uint16_t type=rr.qtype.getCode();
  shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(type, 1, rr.content));
  string ret=drc->serialize(rr.qname);
  //  cerr<<"stored '"<<rr.qname<<" '"<<rr.qtype.getName()<<"' '"<<rr.content<<"' as "<<ret.size()<<" bytes"<<endl;
  return ret;
}

unsigned int MemRecursorCache::size()
{
  unsigned int ret=0;
  for(cache_t::const_iterator i=d_cache.begin(); i!=d_cache.end(); ++i) {
    ret+=i->second.size();
  }
  return ret;
}

unsigned int MemRecursorCache::bytes()
{
  unsigned int ret=0;

  for(cache_t::const_iterator i=d_cache.begin(); i!=d_cache.end(); ++i) {
    ret+=i->first.length();
    for(vector<StoredRecord>::const_iterator j=i->second.begin(); j!= i->second.end(); ++j)
      ret+=j->size();
  }
  return ret;
}


int MemRecursorCache::get(time_t now, const string &qname, const QType& qt, set<DNSResourceRecord>* res)
{
  unsigned int ttd=0;
  uint16_t code=qt.getCode();
  string key(toLowerCanonic(qname)); key.append(1,'|'); key.append((char*)&code, ((char*)&code)+2);
  cache_t::const_iterator j=d_cache.find(key);
  //  cerr<<"looking up "<< toLowerCanonic(qname)+"|"+qt.getName() << endl;
  if(res)
    res->clear();

  if(j!=d_cache.end() && j->second.begin()->d_ttd>(unsigned int)now) {
    if(res) {
      for(vector<StoredRecord>::const_iterator k=j->second.begin(); k != j->second.end(); ++k) {
	DNSResourceRecord rr=String2DNSRR(qname, qt,  k->d_string, ttd=k->d_ttd); 
	//	cerr<<"Returning '"<<rr.content<<"'\n";
	res->insert(rr);
      }
    }

    //    cerr<<"time left : "<<ttd - now<<", "<< (res ? res->size() : 0) <<"\n";
    return (unsigned int)ttd-now;
  }
  
  return -1;
}
 
/* the code below is rather tricky - it basically replaces the stuff cached for qname by content, but it is special
   cased for when inserting identical records with only differing ttls, in which case the entry is not
   touched, but only given a new ttd */
void MemRecursorCache::replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content)
{
  int code=qt.getCode();
  string key(toLowerCanonic(qname)); key.append(1,'|'); key.append((char*)&code, ((char*)&code)+2);
  cache_t::iterator stored=d_cache.find(key);
  bool isNew=false;
  if(stored == d_cache.end()) {
    stored=d_cache.insert(make_pair(key,vector<StoredRecord>())).first;
    isNew=true;
  }

  pair<vector<StoredRecord>::iterator, vector<StoredRecord>::iterator> range;

  StoredRecord dr;
  for(set<DNSResourceRecord>::const_iterator i=content.begin(); i != content.end(); ++i) {
    dr.d_ttd=i->ttl;
    dr.d_string=DNSRR2String(*i);
    
    if(isNew) 
      stored->second.push_back(dr);
    else {
      range=equal_range(stored->second.begin(), stored->second.end(), dr);
      
      if(range.first != range.second) {
	for(vector<StoredRecord>::iterator j=range.first ; j!=range.second; ++j)
	  j->d_ttd=i->ttl;
      }
      else {
	stored->second.push_back(dr);
	sort(stored->second.begin(), stored->second.end());
      }
    }
  }
  if(isNew) {
    sort(stored->second.begin(), stored->second.end());
  }
  if(stored->second.capacity() != stored->second.size())
    vector<StoredRecord>(stored->second).swap(stored->second);
}
  

void MemRecursorCache::doPrune(void)
{
  unsigned int names=0;
  time_t now=time(0);
  for(cache_t::iterator j=d_cache.begin();j!=d_cache.end();){
    predicate p(now);
    j->second.erase(remove_if(j->second.begin(), j->second.end(), p), j->second.end());

    if(j->second.empty()) { // everything is gone
      d_cache.erase(j++);
      names++;
    }
    else {
      ++j;
    }
  }
  //  cache_t(d_cache).swap(d_cache);
}

