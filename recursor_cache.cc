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
    ret+=i->d_name.size();
  }
  return ret;
}

unsigned int MemRecursorCache::bytes()
{
  unsigned int ret=0;

  for(cache_t::const_iterator i=d_cache.begin(); i!=d_cache.end(); ++i) {
    ret+=i->d_name.length();
    for(vector<StoredRecord>::const_iterator j=i->d_records.begin(); j!= i->d_records.end(); ++j)
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

  if(j!=d_cache.end() && j->d_records.begin()->d_ttd>(unsigned int)now) {
    if(res) {
      for(vector<StoredRecord>::const_iterator k=j->d_records.begin(); k != j->d_records.end(); ++k) {
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
    stored=d_cache.insert(CacheEntry(key,vector<StoredRecord>())).first;
    isNew=true;
  }

  pair<vector<StoredRecord>::iterator, vector<StoredRecord>::iterator> range;

  StoredRecord dr;
  CacheEntry ce=*stored;

  for(set<DNSResourceRecord>::const_iterator i=content.begin(); i != content.end(); ++i) {
    dr.d_ttd=i->ttl;
    dr.d_string=DNSRR2String(*i);
    
    if(isNew) 
      ce.d_records.push_back(dr);
    else {
      range=equal_range(ce.d_records.begin(), ce.d_records.end(), dr);
      
      if(range.first != range.second) {
	for(vector<StoredRecord>::iterator j=range.first ; j!=range.second; ++j)
	  j->d_ttd=i->ttl;
      }
      else {
	ce.d_records.push_back(dr);
	sort(ce.d_records.begin(), ce.d_records.end());
      }
    }
  }
  if(isNew) {
    sort(ce.d_records.begin(), ce.d_records.end());
  }

  if(ce.d_records.capacity() != ce.d_records.size())
    vector<StoredRecord>(ce.d_records).swap(ce.d_records);

  d_cache.replace(stored, ce);
}



void MemRecursorCache::doPrune(void)
{
  unsigned int names=0;
  uint32_t now=(uint32_t)time(0);

//  cout<<"Going to prune!\n";

  typedef cache_t::nth_index<1>::type cache_by_ttd_t;
  cache_by_ttd_t& ttdindex=d_cache.get<1>();

  uint32_t looked(0), quickZonk(0), fullZonk(0), partialZonk(0), noZonk(0);
  DTime dt;
  dt.set(); 
  cache_by_ttd_t::iterator j;
  for(j=ttdindex.begin();j!=ttdindex.end();){
    if(j->getTTD() > now) {
//      cout<<"Done pruning, this record ("<<j->d_name<<") only needs to get killed in "<< j->getTTD() - now <<" seconds, rest will be later\n";
      break;
    }
    else 
	;
//      cout<<"Looking at '"<<j->d_name<<"', "<<now - j->getTTD()<<" seconds overdue!\n";
    looked++;
    if(j->d_records.size()==1) {
//      ttdindex.erase(j++);
      j++;
      quickZonk++;
      continue;
    }
    predicate p(now);
    CacheEntry ce=*j;

    size_t before=ce.d_records.size();
    ce.d_records.erase(remove_if(ce.d_records.begin(), ce.d_records.end(), p), ce.d_records.end());

    if(ce.d_records.empty()) { // everything is gone
//      cout<<"Zonked it entirely!\n";
//      ttdindex.erase(j++);
      j++;
      fullZonk++;
    }
    else {
      if(ce.d_records.size()!=before) {
//	cout<<"Zonked partially, putting back, new TTD: "<< ce.getTTD() - now<<endl;;
	cache_by_ttd_t::iterator here=j++;
	ttdindex.replace(here, ce);
        partialZonk++;
      }
      else {
	++j;
        noZonk++;
	break;
      }
    }
  }
  
//  cout<<"Walk took "<< dt.udiff()<<"usec\n";
  dt.set();
  ttdindex.erase(ttdindex.begin(), j);
  //  cout<<"Erase took "<< dt.udiff()<<" usec, looked: "<<looked<<", quick: "<<quickZonk<<", full: ";
  //  cout<<fullZonk<<", partial: "<<partialZonk<<", no: "<<noZonk<<"\n";
  //  cache_t(d_cache).swap(d_cache);
}

