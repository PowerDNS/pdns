#include "recursor_cache.hh"
#include "misc.hh"
#include <iostream>
#include <boost/shared_ptr.hpp>
#include "dnsrecords.hh"
using namespace std;
using namespace boost;

DNSResourceRecord String2DNSRR(const string& qname, const QType& qt, const string& serial, uint32_t ttd)
{

  shared_ptr<DNSRecordContent> regen=DNSRecordContent::unserialize(qname,qt.getCode(), serial);
  DNSResourceRecord rr;
  rr.qname=regen->label;
  rr.ttl=ttd; 
  rr.content=regen->getZoneRepresentation();
  rr.qtype=regen->d_qtype;
  //  cerr<<"Returning: '"<<rr.qname<<"' "<<rr.qtype.getName()<<"  "<<rr.ttl<<"  '"<<rr.content<<"'\n";
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
  return d_cache.size();
}

int MemRecursorCache::get(time_t now, const string &qname, const QType& qt, set<DNSResourceRecord>* res)
{
  unsigned int ttd=0;
  cache_t::const_iterator j=d_cache.find(toLower(qname)+"|"+qt.getName());
  //  cerr<<"looking up "<< toLower(qname)+"|"+qt.getName() << endl;
  if(res)
    res->clear();

  if(j!=d_cache.end() && j->first==toLower(qname)+"|"+qt.getName() && j->second.begin()->d_ttd>(unsigned int)now) {
    if(res) {
      //      cerr<<"Have something: "<< j->second.size()<< " records\n";
      for(set<StoredRecord>::const_iterator k=j->second.begin(); k != j->second.end(); ++k)
	res->insert(String2DNSRR(qname, qt,  k->d_string, ttd=k->d_ttd));
    }
    //    cerr<<"time left : "<<ttd - now<<", "<< (res ? res->size() : 0) <<"\n";
    return (unsigned int)ttd-now;
  }
  
  return -1;
}
  
void MemRecursorCache::replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content)
{
  set<StoredRecord>& stored=d_cache[toLower(qname)+"|"+qt.getName()];
  stored.clear();
  for(set<DNSResourceRecord>::const_iterator i=content.begin(); i != content.end(); ++i) {
    StoredRecord dr;
    dr.d_ttd=i->ttl;
    dr.d_string=DNSRR2String(*i);
    stored.insert(dr);
    //    cerr<<"Storing: "<< toLower(qname)+"|"+qt.getName() << " <=> "<<i->content<<", ttd="<<i->ttl<<endl;
  }
}
  
void MemRecursorCache::doPrune(void)
{
  unsigned int names=0, records=0;
  time_t now=time(0);
  for(cache_t::iterator j=d_cache.begin();j!=d_cache.end();){
    for(set<StoredRecord>::iterator k=j->second.begin();k!=j->second.end();) 
      if((unsigned int)k->d_ttd < (unsigned int) now) {
	k->d_string.prune();
	j->second.erase(k++);
	records++;
      }
      else
	++k;
    
    if(j->second.empty()) { // everything is gone
      d_cache.erase(j++);
      names++;
      
    }
    else {
      ++j;
    }
  }
}

