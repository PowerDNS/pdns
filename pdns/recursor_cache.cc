#include "recursor_cache.hh"
#include "misc.hh"
#include <iostream>
#include <boost/shared_ptr.hpp>
#include "dnsrecords.hh"
#include "arguments.hh"
#include "syncres.hh"
#include "recursor_cache.hh"
#include "cachecleaner.hh"

using namespace std;
#include "namespaces.hh"

#include "config.h"

DNSResourceRecord String2DNSRR(const string& qname, const QType& qt, const string& serial, uint32_t ttd)
{
  DNSResourceRecord rr;
  rr.ttl=ttd; 
  rr.qtype=qt;
  rr.qname=qname;

  if(rr.qtype.getCode()==QType::A && serial.size()==4) {
    uint32_t ip;
    memcpy((char*)&ip, serial.c_str(), 4);
    rr.content=U32ToIP(ntohl(ip));
  }
  else if(rr.qtype.getCode()==QType::AAAA && serial.size()==16) {
    ComboAddress tmp;
    tmp.sin4.sin_family=AF_INET6;
    memcpy(tmp.sin6.sin6_addr.s6_addr, serial.c_str(), 16);
    rr.content=tmp.toString();
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

// returns the RDATA for rr - might be compressed!
string DNSRR2String(const DNSResourceRecord& rr)
{
  uint16_t type=rr.qtype.getCode();

  if(type==QType::A) {
    uint32_t ip;
    IpToU32(rr.content, &ip);
    return string((char*)&ip, 4);
  }
  else if(type==QType::AAAA) {
    ComboAddress ca(rr.content);
    return string((char*)&ca.sin6.sin6_addr.s6_addr, 16);
  }
  else if(type==QType::NS || type==QType::CNAME)
      return simpleCompress(rr.content, rr.qname);
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
  return (unsigned int)d_cache.size();
}

unsigned int MemRecursorCache::bytes()
{
  unsigned int ret=0;

  for(cache_t::const_iterator i=d_cache.begin(); i!=d_cache.end(); ++i) {
    ret+=(unsigned int)i->d_qname.length();
    for(vector<StoredRecord>::const_iterator j=i->d_records.begin(); j!= i->d_records.end(); ++j)
      ret+=j->size();
  }
  return ret;
}

int MemRecursorCache::get(time_t now, const string &qname, const QType& qt, set<DNSResourceRecord>* res)
{
  unsigned int ttd=0;
  //  cerr<<"looking up "<< qname+"|"+qt.getName()<<"\n";

  if(!d_cachecachevalid || !pdns_iequals(d_cachedqname, qname)) {
    //    cerr<<"had cache cache miss"<<endl;
    d_cachedqname=qname;
    d_cachecache=d_cache.equal_range(tie(qname));
    d_cachecachevalid=true;
  }
  else
    //    cerr<<"had cache cache hit!"<<endl;
    ;

  if(res)
    res->clear();

  if(d_cachecache.first!=d_cachecache.second) { 
    for(cache_t::const_iterator i=d_cachecache.first; i != d_cachecache.second; ++i) 
      if(i->d_qtype == qt.getCode() || qt.getCode()==QType::ANY || 
         (qt.getCode()==QType::ADDR && (i->d_qtype == QType::A || i->d_qtype == QType::AAAA) )
         ) {     
        for(vector<StoredRecord>::const_iterator k=i->d_records.begin(); k != i->d_records.end(); ++k) {
          if(k->d_ttd < 1000000000 || k->d_ttd > (uint32_t) now) {  // FIXME what does the 100000000 number mean?
            ttd=k->d_ttd;
            if(res) {
              DNSResourceRecord rr=String2DNSRR(qname, QType(i->d_qtype),  k->d_string, ttd); 
              res->insert(rr);
            }
          }
        }
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
    return (int)ttd-now;
  }
  return -1;
}


 
bool MemRecursorCache::attemptToRefreshNSTTL(const QType& qt, const set<DNSResourceRecord>& content, const CacheEntry& stored)
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

  if(stored.d_records.begin()->d_ttd > content.begin()->ttl) {
    //~ cerr<<"attempt to LOWER TTL - fine by us"<<endl;
    return false;
  }


 // cerr<<"Returning true - update attempt!\n";
  return true;
}

/* the code below is rather tricky - it basically replaces the stuff cached for qname by content, but it is special
   cased for when inserting identical records with only differing ttls, in which case the entry is not
   touched, but only given a new ttd */
void MemRecursorCache::replace(time_t now, const string &qname, const QType& qt,  const set<DNSResourceRecord>& content, bool auth)
{
  d_cachecachevalid=false;
  tuple<string, uint16_t> key=make_tuple(qname, qt.getCode());
  cache_t::iterator stored=d_cache.find(key);

  bool isNew=false;
  if(stored == d_cache.end()) {
    stored=d_cache.insert(CacheEntry(key,vector<StoredRecord>(), auth)).first;
    isNew=true;
  }
  pair<vector<StoredRecord>::iterator, vector<StoredRecord>::iterator> range;

  StoredRecord dr;
  CacheEntry ce=*stored;

  //~ cerr<<"asked to store "<< qname+"|"+qt.getName()<<" -> '"<<content.begin()->content<<"', isnew="<<isNew<<", auth="<<auth<<", ce.auth="<<ce.d_auth<<"\n";

  if(qt.getCode()==QType::SOA || qt.getCode()==QType::CNAME)  { // you can only have one (1) each of these
    //    cerr<<"\tCleaning out existing store because of SOA and CNAME\n";
    ce.d_records.clear();
  }

  if(!auth && ce.d_auth) {  // unauth data came in, we have some auth data, but is it fresh?
    vector<StoredRecord>::iterator j;
    for(j = ce.d_records.begin() ; j != ce.d_records.end(); ++j) 
      if((time_t)j->d_ttd > now) 
        break;
    if(j != ce.d_records.end()) { // we still have valid data, ignore unauth data
      //      cerr<<"\tStill hold valid auth data, and the new data is unauth, return\n";
      return;
    }
    else {
      ce.d_auth = false;  // new data won't be auth
    }
  }

  if(auth && !attemptToRefreshNSTTL(qt, content, ce) ) {
    // cerr<<"\tGot auth data, and it was not refresh attempt of an NS record, nuking storage"<<endl;
    ce.d_records.clear(); // clear non-auth data
    ce.d_auth = true;
    isNew=true;           // data should be sorted again
  }
  else
    ; //cerr<<"\tNot nuking"<<endl;

  // cerr<<"\tHave "<<content.size()<<" records to store\n";
  for(set<DNSResourceRecord>::const_iterator i=content.begin(); i != content.end(); ++i) {
    // cerr<<"To store: "<<i->content<<endl;
    dr.d_ttd=i->ttl;
    dr.d_string=DNSRR2String(*i);
    
    if(isNew) 
      ce.d_records.push_back(dr);
    else {
      range=equal_range(ce.d_records.begin(), ce.d_records.end(), dr);

      if(range.first != range.second) {
       // cerr<<"\t\tMay need to modify TTL of stored record\n";
        for(vector<StoredRecord>::iterator j=range.first ; j!=range.second; ++j) {
          /* see http://mailman.powerdns.com/pipermail/pdns-users/2006-May/003413.html */
          if(j->d_ttd > (unsigned int) now && i->ttl > j->d_ttd && qt.getCode()==QType::NS && auth) { // don't allow auth servers to *raise* TTL of an NS record
            //~ cerr<<"\t\tNot doing so, trying to raise TTL NS\n";
            continue;
          }
          if(i->ttl > j->d_ttd || (auth && d_followRFC2181) ) { // authoritative packets can override the TTL to be lower
            //~ cerr<<"\t\tUpdating the ttl, diff="<<j->d_ttd - i->ttl<<endl;;
            j->d_ttd=i->ttl;
          }
          else {
            //~ cerr<<"\t\tNOT updating the ttl, old= " <<j->d_ttd - now <<", new: "<<i->ttl - now <<endl;
          }
        }
      }
      else {
        //~ cerr<<"\t\tThere was no exact copy of this record, so adding & sorting\n";
        ce.d_records.push_back(dr);
        sort(ce.d_records.begin(), ce.d_records.end());
      }
    }
  }

  if(isNew) {
    //    cerr<<"\tSorting (because of isNew)\n";
    sort(ce.d_records.begin(), ce.d_records.end());
  }
  
  if(ce.d_records.capacity() != ce.d_records.size())
    vector<StoredRecord>(ce.d_records).swap(ce.d_records);
  
  d_cache.replace(stored, ce);
}

int MemRecursorCache::doWipeCache(const string& name, uint16_t qtype)
{
  int count=0;
  d_cachecachevalid=false;
  pair<cache_t::iterator, cache_t::iterator> range;
  if(qtype==0xffff)
    range=d_cache.equal_range(tie(name));
  else
    range=d_cache.equal_range(tie(name, qtype));

  for(cache_t::const_iterator i=range.first; i != range.second; ) {
    count++;
    d_cache.erase(i++);
  }
  return count;
}

bool MemRecursorCache::doAgeCache(time_t now, const string& name, uint16_t qtype, int32_t newTTL)
{
  cache_t::iterator iter = d_cache.find(tie(name, qtype));
  if(iter == d_cache.end()) 
    return false;

  int32_t ttl = iter->getTTD() - now;
  if(ttl < 0) 
    return false;  // would be dead anyhow

  if(ttl > newTTL) {
    d_cachecachevalid=false;

    ttl = newTTL;
    uint32_t newTTD = now + ttl;
    
    CacheEntry ce = *iter;
    for(vector<StoredRecord>::iterator j = ce.d_records.begin() ; j != ce.d_records.end(); ++j)  {
      j->d_ttd = newTTD;
    }
    
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
  typedef cache_t::nth_index<1>::type sequence_t;
  sequence_t& sidx=d_cache.get<1>();

  uint64_t count=0;
  time_t now=time(0);
  for(sequence_t::const_iterator i=sidx.begin(); i != sidx.end(); ++i) {
    for(vector<StoredRecord>::const_iterator j=i->d_records.begin(); j != i->d_records.end(); ++j) {
      count++;
      try {
        DNSResourceRecord rr=String2DNSRR(i->d_qname, QType(i->d_qtype), j->d_string, j->d_ttd - now);
        fprintf(fp, "%s %d IN %s %s\n", rr.qname.c_str(), rr.ttl, rr.qtype.getName().c_str(), rr.content.c_str());
      }
      catch(...) {
        fprintf(fp, "; error printing '%s'\n", i->d_qname.c_str());
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

