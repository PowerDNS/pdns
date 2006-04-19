#include "recursor_cache.hh"
#include "misc.hh"
#include <iostream>
#include <boost/shared_ptr.hpp>
#include "dnsrecords.hh"
#include "arguments.hh"

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

string simpleCompress(const string& label)
{
  typedef vector<pair<unsigned int, unsigned int> > parts_t;
  parts_t parts;
  vstringtok(parts, label, ".");
  string ret;
  ret.reserve(label.size()+4);
  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    ret.append(1, (char)(i->second - i->first));
    ret.append(label.c_str() + i->first, i->second - i->first);
  }
  ret.append(1, (char)0);
  return ret;
}

void simpleExpandTo(const string& label, unsigned int frompos, string& ret)
{
  unsigned int labellen=0;
  while((labellen=label.at(frompos++))) {
    ret.append(label.c_str()+frompos, labellen);
    ret.append(1,'.');
    frompos+=labellen;
  }
}

DNSResourceRecord String2DNSRR(const string& qname, const QType& qt, const string& serial, uint32_t ttd)
{
  DNSResourceRecord rr;
  rr.ttl=ttd; 
  rr.qtype=qt;
  rr.qname=qname;

  if(rr.qtype.getCode()==QType::A) {
    uint32_t ip;
    memcpy((char*)&ip, serial.c_str(), 4);
    rr.content=U32ToIP(ntohl(ip));
  }
  else if(rr.qtype.getCode()==QType::CNAME || rr.qtype.getCode()==QType::NS || rr.qtype.getCode()==QType::PTR) {
    unsigned int frompos=0;
    unsigned char labellen;

    while((labellen=serial.at(frompos++))) {
      if((labellen & 0xc0) == 0xc0) {
	string encoded=simpleCompress(qname);
	uint16_t offset=256*(labellen & ~0xc0) + (unsigned int)serial.at(frompos++) - sizeof(dnsheader)-5;

	simpleExpandTo(encoded, offset, rr.content);
	//	cerr<<"Oops, fallback, content so far: '"<<rr.content<<"', offset: "<<offset<<", '"<<qname<<"', "<<qt.getName()<<"\n";
	break;
      }
      rr.content.append(serial.c_str()+frompos, labellen);
      frompos+=labellen;
      rr.content.append(1,'.');
    }
    if(rr.content.empty())
      rr.content=".";
  }
  else {
    shared_ptr<DNSRecordContent> regen=DNSRecordContent::unserialize(qname, qt.getCode(), serial);
    rr.content=regen->getZoneRepresentation();
  }
  rr.content.reserve(0);
  rr.qname.reserve(0);
  return rr;
}

string DNSRR2String(const DNSResourceRecord& rr)
{
  uint16_t type=rr.qtype.getCode();

  if(type==QType::A) {
    uint32_t ip;
    IpToU32(rr.content, &ip);
    return string((char*)&ip, 4);
  }
  else if(type==QType::NS) {
    NSRecordContent ar(rr.content);
    return ar.serialize(rr.qname);
  }
  else if(type==QType::CNAME) {
    CNAMERecordContent ar(rr.content);
    return ar.serialize(rr.qname);
  }
  else {
    string ret;
    shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(type, 1, rr.content));
    ret=drc->serialize(rr.qname);
  //  cerr<<"stored '"<<rr.qname<<" '"<<rr.qtype.getName()<<"' '"<<rr.content<<"' as "<<ret.size()<<" bytes"<<endl;
    return ret;
  }
}

unsigned int MemRecursorCache::size()
{
  return d_cache.size();
}

unsigned int MemRecursorCache::bytes()
{
  unsigned int ret=0;

  for(cache_t::const_iterator i=d_cache.begin(); i!=d_cache.end(); ++i) {
    ret+=i->d_qname.length();
    for(vector<StoredRecord>::const_iterator j=i->d_records.begin(); j!= i->d_records.end(); ++j)
      ret+=j->size();
  }
  return ret;
}


int MemRecursorCache::get(time_t now, const string &qname, const QType& qt, set<DNSResourceRecord>* res)
{
  unsigned int ttd=0;

  //  cerr<<"looking up "<< qname+"|"+qt.getName()<<"\n";

  if(!d_cachecachevalid || strcasecmp(d_cachedqname.c_str(), qname.c_str())) {
    //    cerr<<"had cache cache miss"<<endl;
    d_cachedqname=qname;
    d_cachecache=d_cache.equal_range(tie(qname));
    d_cachecachevalid=true;
  }
  else
    ;
  //    cerr<<"had cache cache hit!"<<endl;


  if(res)
    res->clear();

  if(d_cachecache.first!=d_cachecache.second) { 
    if(res) {
      for(cache_t::const_iterator i=d_cachecache.first; i != d_cachecache.second; ++i) 
	if(i->d_qtype == qt.getCode()) {
	  typedef cache_t::nth_index<1>::type sequence_t;
	  sequence_t& sidx=d_cache.get<1>();
	  sequence_t::iterator si=d_cache.project<1>(i);

	  for(vector<StoredRecord>::const_iterator k=i->d_records.begin(); k != i->d_records.end(); ++k) {
	    if(k->d_ttd > (uint32_t) now) {
	      DNSResourceRecord rr=String2DNSRR(qname, qt,  k->d_string, ttd=k->d_ttd); 
	      res->insert(rr);
	    }
	  }
	  if(res->empty())
	    sidx.relocate(sidx.begin(), si); 
	  else
	    sidx.relocate(sidx.end(), si); 
	  break;
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
  d_cachecachevalid=false;
  tuple<string, uint16_t> key=make_tuple(qname, qt.getCode());
  cache_t::iterator stored=d_cache.find(key);

  //  cerr<<"storing "<< qname+"|"+qt.getName()<<" -> '"<<content.begin()->content<<"'\n";

  bool isNew=false;
  if(stored == d_cache.end()) {
    stored=d_cache.insert(CacheEntry(key,vector<StoredRecord>())).first;
    isNew=true;
  }
  
  pair<vector<StoredRecord>::iterator, vector<StoredRecord>::iterator> range;

  StoredRecord dr;
  CacheEntry ce=*stored;

  if(qt.getCode()==QType::SOA || qt.getCode()==QType::CNAME)  // you can only have one (1) each of these
    ce.d_records.clear();


  for(set<DNSResourceRecord>::const_iterator i=content.begin(); i != content.end(); ++i) {
    dr.d_ttd=i->ttl;
    dr.d_string=DNSRR2String(*i);
    
    if(isNew) 
      ce.d_records.push_back(dr);
    else {
      range=equal_range(ce.d_records.begin(), ce.d_records.end(), dr);
      
      if(range.first != range.second) {
	for(vector<StoredRecord>::iterator j=range.first ; j!=range.second; ++j) {
	  if(i->ttl > j->d_ttd)
	    j->d_ttd=i->ttl;
	}
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

void MemRecursorCache::doWipeCache(const string& name)
{
  pair<cache_t::iterator, cache_t::iterator> range=d_cache.equal_range(tie(name));
  d_cache.erase(range.first, range.second);
}

void MemRecursorCache::doDumpAndClose(int fd)
{
  FILE* fp=fdopen(fd, "w");
  if(!fp) {
    close(fd);
    return;
  }

  typedef cache_t::nth_index<1>::type sequence_t;
  sequence_t& sidx=d_cache.get<1>();

  time_t now=time(0);
  for(sequence_t::const_iterator i=sidx.begin(); i != sidx.end(); ++i) {
    for(vector<StoredRecord>::const_iterator j=i->d_records.begin(); j != i->d_records.end(); ++j) {
      DNSResourceRecord rr=String2DNSRR(i->d_qname, QType(i->d_qtype), j->d_string, j->d_ttd - now);
      fprintf(fp, "%s %d IN %s %s\n", rr.qname.c_str(), rr.ttl, rr.qtype.getName().c_str(), rr.content.c_str());
    }
  }
  fclose(fp);
}

void MemRecursorCache::doSlash(int perc)
{
  doPrune();
}

void MemRecursorCache::doPrune(void)
{
  uint32_t now=(uint32_t)time(0);
  d_cachecachevalid=false;

  unsigned int maxCached=::arg().asNum("max-cache-entries");
  unsigned int toTrim=0;
  
  unsigned int cacheSize=d_cache.size();

  if(maxCached && cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
  }

  //  cout<<"Need to trim "<<toTrim<<" from cache to meet target!\n";

  typedef cache_t::nth_index<1>::type sequence_t;
  sequence_t& sidx=d_cache.get<1>();

  unsigned int tried=0, lookAt, erased=0;

  // two modes - if toTrim is 0, just look through 10000 records and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  if(toTrim)
    lookAt=5*toTrim;
  else
    lookAt=cacheSize/10;


  sequence_t::iterator iter=sidx.begin(), eiter;
  for(; iter != sidx.end() && tried < lookAt ; ++tried) {
    if(iter->getTTD() < now) {
      sidx.erase(iter++);
      erased++;
    }
    else
      ++iter;

    if(toTrim && erased > toTrim)
      break;
  }

  //  cout<<"erased "<<erased<<" records based on ttd\n";
  
  if(erased >= toTrim)
    return;

  //  if(toTrim)
  //    cout<<"Still have "<<toTrim - erased<<" entries left to erase to meet target\n";


  eiter=iter=sidx.begin();
  advance(eiter, toTrim);
  sidx.erase(iter, eiter);
}

