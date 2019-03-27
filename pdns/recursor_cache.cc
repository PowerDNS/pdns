#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cinttypes>

#include "syncres.hh"
#include "recursor_cache.hh"
#include "misc.hh"
#include <iostream>
#include "dnsrecords.hh"
#include "arguments.hh"
#include "recursor_cache.hh"
#include "cachecleaner.hh"
#include "namespaces.hh"

unsigned int MemRecursorCache::size() const
{
  return (unsigned int)d_cache.size();
}

size_t MemRecursorCache::ecsIndexSize() const
{
  return d_ecsIndex.size();
}

// this function is too slow to poll!
unsigned int MemRecursorCache::bytes() const
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

int32_t MemRecursorCache::handleHit(cache_t::iterator entry, const DNSName& qname, const ComboAddress& who, vector<DNSRecord>* res, vector<std::shared_ptr<RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, vState* state, bool* wasAuth)
{
  int32_t ttd = entry->d_ttd;

  if(variable && !entry->d_netmask.empty()) {
    *variable = true;
  }

  // cerr<<"Looking at "<<entry->d_records.size()<<" records for this name"<<endl;
  if (res) {
    for(const auto& k : entry->d_records) {
      DNSRecord dr;
      dr.d_name = qname;
      dr.d_type = entry->d_qtype;
      dr.d_class = QClass::IN;
      dr.d_content = k;
      dr.d_ttl = static_cast<uint32_t>(entry->d_ttd);
      dr.d_place = DNSResourceRecord::ANSWER;
      res->push_back(dr);
    }
  }

  if(signatures) { // if you do an ANY lookup you are hosed XXXX
    *signatures = entry->d_signatures;
  }

  if(authorityRecs) {
    *authorityRecs = entry->d_authorityRecs;
  }

  if (state) {
    *state = entry->d_state;
  }

  if (wasAuth) {
    *wasAuth = entry->d_auth;
  }

  moveCacheItemToBack(d_cache, entry);

  return ttd;
}

MemRecursorCache::cache_t::const_iterator MemRecursorCache::getEntryUsingECSIndex(time_t now, const DNSName &qname, uint16_t qtype, bool requireAuth, const ComboAddress& who)
{
  auto ecsIndexKey = tie(qname, qtype);
  auto ecsIndex = d_ecsIndex.find(ecsIndexKey);
  if (ecsIndex != d_ecsIndex.end() && !ecsIndex->isEmpty()) {
    /* we have netmask-specific entries, let's see if we match one */
    while (true) {
      const Netmask best = ecsIndex->lookupBestMatch(who);
      if (best.empty()) {
        /* we have nothing more specific for you */
        break;
      }
      auto key = boost::make_tuple(qname, qtype, best);
      auto entry = d_cache.find(key);
      if (entry == d_cache.end()) {
        /* ecsIndex is not up-to-date */
        ecsIndex->removeNetmask(best);
        if (ecsIndex->isEmpty()) {
          d_ecsIndex.erase(ecsIndex);
          break;
        }
        continue;
      }

      if (entry->d_ttd > now) {
        if (!requireAuth || entry->d_auth) {
          return entry;
        }
        /* we need auth data and the best match is not authoritative */
        return d_cache.end();
      }
      else {
        /* this netmask-specific entry has expired */
        moveCacheItemToFront(d_cache, entry);
        ecsIndex->removeNetmask(best);
        if (ecsIndex->isEmpty()) {
          d_ecsIndex.erase(ecsIndex);
          break;
        }
      }
    }
  }

  /* we have nothing specific, let's see if we have a generic one */
  auto key = boost::make_tuple(qname, qtype, Netmask());
  auto entry = d_cache.find(key);
  if (entry != d_cache.end()) {
    if (entry->d_ttd > now) {
      if (!requireAuth || entry->d_auth) {
        return entry;
      }
    }
    else {
      moveCacheItemToFront(d_cache, entry);
    }
  }

  /* nothing for you, sorry */
  return d_cache.end();
}

// returns -1 for no hits
std::pair<MemRecursorCache::cache_t::const_iterator, MemRecursorCache::cache_t::const_iterator> MemRecursorCache::getEntries(const DNSName &qname, const QType& qt)
{
  //  cerr<<"looking up "<< qname<<"|"+qt.getName()<<"\n";
  if(!d_cachecachevalid || d_cachedqname!= qname) {
    //    cerr<<"had cache cache miss"<<endl;
    d_cachedqname=qname;
    d_cachecache=d_cache.equal_range(tie(qname));
    d_cachecachevalid=true;
  }
  //  else cerr<<"had cache cache hit!"<<endl;

  return d_cachecache;
}

bool MemRecursorCache::entryMatches(cache_t::const_iterator& entry, uint16_t qt, bool requireAuth, const ComboAddress& who)
{
  if (requireAuth && !entry->d_auth)
    return false;

  return ((entry->d_qtype == qt || qt == QType::ANY ||
           (qt == QType::ADDR && (entry->d_qtype == QType::A || entry->d_qtype == QType::AAAA)))
          && (entry->d_netmask.empty() || entry->d_netmask.match(who)));
}

// returns -1 for no hits
int32_t MemRecursorCache::get(time_t now, const DNSName &qname, const QType& qt, bool requireAuth, vector<DNSRecord>* res, const ComboAddress& who, vector<std::shared_ptr<RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, vState* state, bool* wasAuth)
{
  time_t ttd=0;
  //  cerr<<"looking up "<< qname<<"|"+qt.getName()<<"\n";
  if(res) {
    res->clear();
  }

  const uint16_t qtype = qt.getCode();
  /* If we don't have any netmask-specific entries at all, let's just skip this
     to be able to use the nice d_cachecache hack. */
  if (qtype != QType::ANY && !d_ecsIndex.empty()) {
    if (qtype == QType::ADDR) {
      int32_t ret = -1;

      auto entryA = getEntryUsingECSIndex(now, qname, QType::A, requireAuth, who);
      if (entryA != d_cache.end()) {
        ret = handleHit(entryA, qname, who, res, signatures, authorityRecs, variable, state, wasAuth);
      }
      auto entryAAAA = getEntryUsingECSIndex(now, qname, QType::AAAA, requireAuth, who);
      if (entryAAAA != d_cache.end()) {
        int32_t ttdAAAA = handleHit(entryAAAA, qname, who, res, signatures, authorityRecs, variable, state, wasAuth);
        if (ret > 0) {
          ret = std::min(ret, ttdAAAA);
        } else {
          ret = ttdAAAA;
        }
      }
      return ret > 0 ? static_cast<int32_t>(ret-now) : ret;
    }
    else {
      auto entry = getEntryUsingECSIndex(now, qname, qtype, requireAuth, who);
      if (entry != d_cache.end()) {
        return static_cast<int32_t>(handleHit(entry, qname, who, res, signatures, authorityRecs, variable, state, wasAuth) - now);
      }
      return -1;
    }
  }

  auto entries = getEntries(qname, qt);

  if(entries.first!=entries.second) {
    for(cache_t::const_iterator i=entries.first; i != entries.second; ++i) {

      if (i->d_ttd <= now) {
        moveCacheItemToFront(d_cache, i);
        continue;
      }

      if (!entryMatches(i, qtype, requireAuth, who))
        continue;

      ttd = handleHit(i, qname, who, res, signatures, authorityRecs, variable, state, wasAuth);

      if(qt.getCode()!=QType::ANY && qt.getCode()!=QType::ADDR) // normally if we have a hit, we are done
        break;
    }

    // cerr<<"time left : "<<ttd - now<<", "<< (res ? res->size() : 0) <<"\n";
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

void MemRecursorCache::replace(time_t now, const DNSName &qname, const QType& qt, const vector<DNSRecord>& content, const vector<shared_ptr<RRSIGRecordContent>>& signatures, const std::vector<std::shared_ptr<DNSRecord>>& authorityRecs, bool auth, boost::optional<Netmask> ednsmask, time_t minTTD, vState state)
{
  d_cachecachevalid = false;
  //  cerr<<"Replacing "<<qname<<" for "<< (ednsmask ? ednsmask->toString() : "everyone") << endl;
  auto key = boost::make_tuple(qname, qt.getCode(), ednsmask ? *ednsmask : Netmask());
  bool isNew = false;
  cache_t::iterator stored = d_cache.find(key);
  if (stored == d_cache.end()) {
    stored = d_cache.insert(CacheEntry(key, CacheEntry::records_t(), auth)).first;
    isNew = true;
  }

  /* don't bother building an ecsIndex if we don't have any netmask-specific entries */
  if (ednsmask && !ednsmask->empty()) {
    auto ecsIndexKey = boost::make_tuple(qname, qt.getCode());
    auto ecsIndex = d_ecsIndex.find(ecsIndexKey);
    if (ecsIndex == d_ecsIndex.end()) {
      ecsIndex = d_ecsIndex.insert(ECSIndexEntry(qname, qt.getCode())).first;
    }
    ecsIndex->addMask(*ednsmask);
  }

  time_t maxTTD=std::numeric_limits<time_t>::max();
  CacheEntry ce=*stored; // this is a COPY
  ce.d_qtype=qt.getCode();
  ce.d_signatures=signatures;
  ce.d_authorityRecs=authorityRecs;
  ce.d_state=state;
  
  //  cerr<<"asked to store "<< (qname.empty() ? "EMPTY" : qname.toString()) <<"|"+qt.getName()<<" -> '";
  //  cerr<<(content.empty() ? string("EMPTY CONTENT")  : content.begin()->d_content->getZoneRepresentation())<<"', auth="<<auth<<", ce.auth="<<ce.d_auth;
  //  cerr<<", ednsmask: "  <<  (ednsmask ? ednsmask->toString() : "none") <<endl;

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
  //else cerr<<"\tNot nuking"<<endl;


  for(const auto i : content) {
    /* Yes, we have altered the d_ttl value by adding time(nullptr) to it
       prior to calling this function, so the TTL actually holds a TTD. */
    if (minTTD == 0 || static_cast<time_t>(i.d_ttl) >= minTTD) {
      ce.d_ttd = min(maxTTD, static_cast<time_t>(i.d_ttl));   // XXX this does weird things if TTLs differ in the set
      //    cerr<<"To store: "<<i.d_content->getZoneRepresentation()<<" with ttl/ttd "<<i.d_ttl<<", capped at: "<<maxTTD<<endl;
      ce.d_records.push_back(i.d_content);
    }
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
    pair<ecsIndex_t::iterator, ecsIndex_t::iterator> ecsIndexRange;
    if(qtype==0xffff) {
      range = d_cache.equal_range(tie(name));
      ecsIndexRange = d_ecsIndex.equal_range(tie(name));
    }
    else {
      range=d_cache.equal_range(tie(name, qtype));
      ecsIndexRange = d_ecsIndex.equal_range(tie(name, qtype));
    }
    for(cache_t::const_iterator i=range.first; i != range.second; ) {
      count++;
      d_cache.erase(i++);
    }
    for(auto i = ecsIndexRange.first; i != ecsIndexRange.second; ) {
      d_ecsIndex.erase(i++);
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
    for(auto iter = d_ecsIndex.lower_bound(tie(name)); iter != d_ecsIndex.end(); ) {
      if(!iter->d_qname.isPartOf(name))
	break;
      if(iter->d_qtype == qtype || qtype == 0xffff) {
	d_ecsIndex.erase(iter++);
      }
      else {
	iter++;
      }
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

bool MemRecursorCache::updateValidationStatus(time_t now, const DNSName &qname, const QType& qt, const ComboAddress& who, bool requireAuth, vState newState)
{
  bool updated = false;
  uint16_t qtype = qt.getCode();
  if (qtype != QType::ANY && qtype != QType::ADDR && !d_ecsIndex.empty()) {
    auto entry = getEntryUsingECSIndex(now, qname, qtype, requireAuth, who);
    if (entry == d_cache.end()) {
      return false;
    }

    entry->d_state = newState;
    return true;
  }

  auto entries = getEntries(qname, qt);

  for(auto i = entries.first; i != entries.second; ++i) {
    if (!entryMatches(i, qtype, requireAuth, who))
      continue;

    i->d_state = newState;
    updated = true;

    if(qtype != QType::ANY && qtype != QType::ADDR) // normally if we have a hit, we are done
      break;
  }

  return updated;
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
  for(const auto i : sidx) {
    for(const auto j : i.d_records) {
      count++;
      try {
        fprintf(fp, "%s %" PRId64 " IN %s %s ; (%s) auth=%i %s\n", i.d_qname.toString().c_str(), static_cast<int64_t>(i.d_ttd - now), DNSRecordContent::NumberToType(i.d_qtype).c_str(), j->getZoneRepresentation().c_str(), vStates[i.d_state], i.d_auth, i.d_netmask.empty() ? "" : i.d_netmask.toString().c_str());
      }
      catch(...) {
        fprintf(fp, "; error printing '%s'\n", i.d_qname.empty() ? "EMPTY" : i.d_qname.toString().c_str());
      }
    }
    for(const auto &sig : i.d_signatures) {
      count++;
      try {
        fprintf(fp, "%s %" PRId64 " IN RRSIG %s ; %s\n", i.d_qname.toString().c_str(), static_cast<int64_t>(i.d_ttd - now), sig->getZoneRepresentation().c_str(), i.d_netmask.empty() ? "" : i.d_netmask.toString().c_str());
      }
      catch(...) {
        fprintf(fp, "; error printing '%s'\n", i.d_qname.empty() ? "EMPTY" : i.d_qname.toString().c_str());
      }
    }
  }
  fclose(fp);
  return count;
}

void MemRecursorCache::doPrune(unsigned int keep)
{
  d_cachecachevalid=false;

  pruneCollection(*this, d_cache, keep);
}

