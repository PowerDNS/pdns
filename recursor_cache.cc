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
  cache_t::const_iterator j=d_cache.find(toLowerCanonic(qname)+"|"+qt.getName());
  //  cerr<<"looking up "<< toLowerCanonic(qname)+"|"+qt.getName() << endl;
  if(res)
    res->clear();

  if(j!=d_cache.end() && j->first==toLowerCanonic(qname)+"|"+qt.getName() && j->second.begin()->d_ttd>(unsigned int)now) {
    if(res) {
      for(set<StoredRecord>::const_iterator k=j->second.begin(); k != j->second.end(); ++k) {
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
  set<StoredRecord>& stored=d_cache[toLowerCanonic(qname)+"|"+qt.getName()];

  set<StoredRecord>::iterator k;
  typedef vector<set<StoredRecord>::iterator> touched_t;
  touched_t touched;

  // walk through new content, encode it as new
  StoredRecord dr;

  for(set<DNSResourceRecord>::const_iterator i=content.begin(); i != content.end(); ++i) {
    dr.d_ttd=i->ttl;
    dr.d_string=DNSRR2String(*i);
    k=stored.find(dr);
    if(k!=stored.end()) {           // was it there already?
      // cerr<<"updating record '"<<qname<<"' -> '"<<i->content<<"'\n";
      k->d_ttd=i->ttl;              // update ttl
      touched.push_back(k);         // note that this record is here to stay
    }
    else {
      //      cerr<<"inserting record '"<<qname<<"' -> '"<<i->content<<"'\n";
      touched.push_back(stored.insert(dr).first);  // same thing
    }
  }
  if(touched.size() != stored.size()) {
    for(k=stored.begin(); k!=stored.end(); ) {                     // walk over the stored set of records
      touched_t::const_iterator j;                                
      for(j=touched.begin(); j!=touched.end() && *j != k ; ++j);   // walk over touched iterators
      if(j==touched.end()) {                                       // this record was not there
	//	DNSResourceRecord rr=String2DNSRR(qname, qt,  k->d_string, 0); 
	//	cerr<<"removing from record '"<<qname<<"' '"<<rr.content<<"'\n";
	//      k->d_string.prune();                                      
	stored.erase(k++);                                         // cleanup
      }
      else
	++k;
    }
  }
}
  
void MemRecursorCache::doPrune(void)
{
  unsigned int names=0, records=0;
  time_t now=time(0);
  for(cache_t::iterator j=d_cache.begin();j!=d_cache.end();){
    for(set<StoredRecord>::iterator k=j->second.begin();k!=j->second.end();) 
      if((unsigned int)k->d_ttd < (unsigned int) now) {
	//	k->d_string.prune();
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

