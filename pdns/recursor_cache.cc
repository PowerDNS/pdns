#include "recursor_cache.hh"
#include "misc.hh"
#include <iostream>
using namespace std;


unsigned int MemRecursorCache::size()
{
  return d_cache.size();
}

int MemRecursorCache::get(const string &qname, const QType& qt, set<DNSResourceRecord>* res)
{
  cache_t::const_iterator j=d_cache.find(toLower(qname)+"|"+qt.getName());
  if(j!=d_cache.end() && j->first==toLower(qname)+"|"+qt.getName() && j->second.begin()->ttl>(unsigned int)time(0)) {
    if(res)
      *res=j->second;
    
    return (unsigned int)j->second.begin()->ttl-time(0);
  }
  
  return -1;
}
  
void MemRecursorCache::replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content)
{
  d_cache[toLower(qname)+"|"+qt.getName()]=content;
}
  
void MemRecursorCache::doPrune(void)
{
  unsigned int names=0, records=0;
  
  for(cache_t::iterator j=d_cache.begin();j!=d_cache.end();){
    for(set<DNSResourceRecord>::iterator k=j->second.begin();k!=j->second.end();) 
      if((unsigned int)k->ttl < (unsigned int)time(0)) {
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

