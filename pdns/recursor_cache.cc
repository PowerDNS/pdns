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
#include "namespaces.hh"
#include "cachecleaner.hh"

MemRecursorCache::MemRecursorCache(size_t mapsCount) : d_maps(mapsCount)
{
}

MemRecursorCache::~MemRecursorCache()
{
  try {
    typedef std::unique_ptr<lock> lock_t;
    vector<lock_t> locks;
    for (auto& map : d_maps) {
      locks.push_back(lock_t(new lock(map)));
    }
  }
  catch(...) {
  }
}

size_t MemRecursorCache::size()
{
  size_t count = 0;
  for (auto& map : d_maps) {
    count += map.d_entriesCount;
  }
  return count;
}

pair<uint64_t,uint64_t> MemRecursorCache::stats()
{
  uint64_t c = 0, a = 0;
  for (auto& map : d_maps) {
    const lock l(map);
    c += map.d_contended_count;
    a += map.d_acquired_count;
  }
  return pair<uint64_t,uint64_t>(c, a);
}

size_t MemRecursorCache::ecsIndexSize()
{
  // XXX!
  size_t count = 0;
  for (auto& map : d_maps) {
    const lock l(map);
    count += map.d_ecsIndex.size();
  }
  return count;
}

// this function is too slow to poll!
size_t MemRecursorCache::bytes()
{
  size_t ret = 0;
  for (auto& map : d_maps) {
    const lock l(map);
    for (const auto& i : map.d_map) {
      ret += sizeof(struct CacheEntry);
      ret += i.d_qname.toString().length();
      for (const auto& record : i.d_records) {
        ret += sizeof(record); // XXX WRONG we don't know the stored size!
      }
    }
  }
  return ret;
}

int32_t MemRecursorCache::handleHit(MapCombo& map, MemRecursorCache::OrderedTagIterator_t& entry, const DNSName& qname, vector<DNSRecord>* res, vector<std::shared_ptr<RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, vState* state, bool* wasAuth)
{
  // MUTEX SHOULD BE ACQUIRED
  int32_t ttd = entry->d_ttd;

  if (variable && (!entry->d_netmask.empty() || entry->d_rtag)) {
    *variable = true;
  }

  // cerr<<"Looking at "<<entry->d_records.size()<<" records for this name"<<endl;
  if (res) {
    res->reserve(res->size() + entry->d_records.size());

    for(const auto& k : entry->d_records) {
      DNSRecord dr;
      dr.d_name = qname;
      dr.d_type = entry->d_qtype;
      dr.d_class = QClass::IN;
      dr.d_content = k;
      dr.d_ttl = static_cast<uint32_t>(entry->d_ttd);
      dr.d_place = DNSResourceRecord::ANSWER;
      res->push_back(std::move(dr));
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

  moveCacheItemToBack<SequencedTag>(map.d_map, entry);

  return ttd;
}

MemRecursorCache::cache_t::const_iterator MemRecursorCache::getEntryUsingECSIndex(MapCombo& map, time_t now, const DNSName &qname, uint16_t qtype, bool requireAuth, const ComboAddress& who)
{
  // MUTEX SHOULD BE ACQUIRED
  auto ecsIndexKey = tie(qname, qtype);
  auto ecsIndex = map.d_ecsIndex.find(ecsIndexKey);
  if (ecsIndex != map.d_ecsIndex.end() && !ecsIndex->isEmpty()) {
    /* we have netmask-specific entries, let's see if we match one */
    while (true) {
      const Netmask best = ecsIndex->lookupBestMatch(who);
      if (best.empty()) {
        /* we have nothing more specific for you */
        break;
      }
      auto key = boost::make_tuple(qname, qtype, boost::none, best);
      auto entry = map.d_map.find(key);
      if (entry == map.d_map.end()) {
        /* ecsIndex is not up-to-date */
        ecsIndex->removeNetmask(best);
        if (ecsIndex->isEmpty()) {
          map.d_ecsIndex.erase(ecsIndex);
          break;
        }
        continue;
      }

      if (entry->d_ttd > now) {
        if (!requireAuth || entry->d_auth) {
          return entry;
        }
        /* we need auth data and the best match is not authoritative */
        return map.d_map.end();
      }
      else {
        /* this netmask-specific entry has expired */
        moveCacheItemToFront<SequencedTag>(map.d_map, entry);
        ecsIndex->removeNetmask(best);
        if (ecsIndex->isEmpty()) {
          map.d_ecsIndex.erase(ecsIndex);
          break;
        }
      }
    }
  }

  /* we have nothing specific, let's see if we have a generic one */
  auto key = boost::make_tuple(qname, qtype, boost::none, Netmask());
  auto entry = map.d_map.find(key);
  if (entry != map.d_map.end()) {
    if (entry->d_ttd > now) {
      if (!requireAuth || entry->d_auth) {
        return entry;
      }
    }
    else {
      moveCacheItemToFront<SequencedTag>(map.d_map, entry);
    }
  }

  /* nothing for you, sorry */
  return map.d_map.end();
}

std::pair<MemRecursorCache::NameOnlyHashedTagIterator_t, MemRecursorCache::NameOnlyHashedTagIterator_t> MemRecursorCache::getEntries(MapCombo& map, const DNSName &qname, const QType& qt, const OptTag& rtag )
{
  // MUTEX SHOULD BE ACQUIRED
  if (!map.d_cachecachevalid || map.d_cachedqname != qname || map.d_cachedrtag != rtag) {
    map.d_cachedqname = qname;
    map.d_cachedrtag = rtag;
    const auto& idx = map.d_map.get<NameOnlyHashedTag>();
    map.d_cachecache = idx.equal_range(qname);
    map.d_cachecachevalid = true;
  }
  return map.d_cachecache;
}

#include <boost/optional/optional_io.hpp>


bool MemRecursorCache::entryMatches(MemRecursorCache::OrderedTagIterator_t& entry, uint16_t qt, bool requireAuth, const ComboAddress& who)
{
  // MUTEX SHOULD BE ACQUIRED
  if (requireAuth && !entry->d_auth)
    return false;

  bool match = (entry->d_qtype == qt || qt == QType::ANY ||
                (qt == QType::ADDR && (entry->d_qtype == QType::A || entry->d_qtype == QType::AAAA)))
    && (entry->d_netmask.empty() || entry->d_netmask.match(who));
  //cerr << match << "N " << qt << ':' << entry->d_qtype << ' ' << entry->d_netmask.toString() << ':' << who.toString() << endl;
  return match;
}

bool MemRecursorCache::entryMatches(MemRecursorCache::OrderedTagIterator_t& entry, uint16_t qt, bool requireAuth, const OptTag &rtag)
{
  // MUTEX SHOULD BE ACQUIRED
  if (requireAuth && !entry->d_auth)
    return false;

  bool match = (entry->d_qtype == qt || qt == QType::ANY ||
                (qt == QType::ADDR && (entry->d_qtype == QType::A || entry->d_qtype == QType::AAAA)))
    && entry->d_rtag ==  rtag;
  //cerr << match << "T  " << qt << ':' << entry->d_qtype << ' ' << entry->d_rtag << ':' << rtag << endl;
  return match;
}

// returns -1 for no hits
int32_t MemRecursorCache::get(time_t now, const DNSName &qname, const QType& qt, bool requireAuth, vector<DNSRecord>* res, const ComboAddress& who, const OptTag& routingTag, vector<std::shared_ptr<RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, vState* state, bool* wasAuth)
{
  time_t ttd=0;
  //  cerr<<"looking up "<< qname<<"|"+qt.getName()<<"\n";
  if(res) {
    res->clear();
  }
  const uint16_t qtype = qt.getCode();

  auto& map = getMap(qname);
  const lock l(map);

  /* If we don't have any netmask-specific entries at all, let's just skip this
     to be able to use the nice d_cachecache hack. */
  if (qtype != QType::ANY && !map.d_ecsIndex.empty() && !routingTag) {
    if (qtype == QType::ADDR) {
      int32_t ret = -1;

      auto entryA = getEntryUsingECSIndex(map, now, qname, QType::A, requireAuth, who);
      if (entryA != map.d_map.end()) {
        ret = handleHit(map, entryA, qname, res, signatures, authorityRecs, variable, state, wasAuth);
      }
      auto entryAAAA = getEntryUsingECSIndex(map, now, qname, QType::AAAA, requireAuth, who);
      if (entryAAAA != map.d_map.end()) {
        int32_t ttdAAAA = handleHit(map, entryAAAA, qname, res, signatures, authorityRecs, variable, state, wasAuth);
        if (ret > 0) {
          ret = std::min(ret, ttdAAAA);
        } else {
          ret = ttdAAAA;
        }
      }
      return ret > 0 ? static_cast<int32_t>(ret-now) : ret;
    }
    else {
      auto entry = getEntryUsingECSIndex(map, now, qname, qtype, requireAuth, who);
      if (entry != map.d_map.end()) {
        return static_cast<int32_t>(handleHit(map, entry, qname, res, signatures, authorityRecs, variable, state, wasAuth) - now);
      }
      return -1;
    }
  }

  if (!routingTag) {
    auto entries = getEntries(map, qname, qt, boost::none);

    if (entries.first != entries.second) {
      for (auto i=entries.first; i != entries.second; ++i) {

        auto firstIndexIterator = map.d_map.project<OrderedTag>(i);
        if (i->d_ttd <= now) {
          moveCacheItemToFront<SequencedTag>(map.d_map, firstIndexIterator);
          continue;
        }

        if (!entryMatches(firstIndexIterator, qtype, requireAuth, who)) {
          continue;
        }

        ttd = handleHit(map, firstIndexIterator, qname, res, signatures, authorityRecs, variable, state, wasAuth);

        if (qt.getCode() != QType::ANY && qt.getCode() != QType::ADDR) { // normally if we have a hit, we are done
          break;
        }
      }

      // cerr<<"time left : "<<ttd - now<<", "<< (res ? res->size() : 0) <<"\n";
      return static_cast<int32_t>(ttd-now);
    }
  }
  else {
    auto entries = getEntries(map, qname, qt, routingTag);

    if (entries.first != entries.second) {
      for (auto i=entries.first; i != entries.second; ++i) {

        auto firstIndexIterator = map.d_map.project<OrderedTag>(i);
        if (i->d_ttd <= now) {
          moveCacheItemToFront<SequencedTag>(map.d_map, firstIndexIterator);
          continue;
        }

        if (!entryMatches(firstIndexIterator, qtype, requireAuth, routingTag)) {
          continue;
        }

        ttd = handleHit(map, firstIndexIterator, qname, res, signatures, authorityRecs, variable, state, wasAuth);

        if (qt.getCode() != QType::ANY && qt.getCode() != QType::ADDR) { // normally if we have a hit, we are done
          break;
        }
      }
      return static_cast<int32_t>(ttd-now);
    }
    // Try again without tag
    entries = getEntries(map, qname, qt, boost::none);

    if (entries.first != entries.second) {
      for (auto i=entries.first; i != entries.second; ++i) {

        auto firstIndexIterator = map.d_map.project<OrderedTag>(i);
        if (i->d_ttd <= now) {
          moveCacheItemToFront<SequencedTag>(map.d_map, firstIndexIterator);
          continue;
        }

        if (!entryMatches(firstIndexIterator, qtype, requireAuth, boost::none)) {
          continue;
        }

        ttd = handleHit(map, firstIndexIterator, qname, res, signatures, authorityRecs, variable, state, wasAuth);

        if (qt.getCode() != QType::ANY && qt.getCode() != QType::ADDR) { // normally if we have a hit, we are done
          break;
        }
      }
      return static_cast<int32_t>(ttd-now);
    }
  }
  return -1;
}

void MemRecursorCache::replace(time_t now, const DNSName &qname, const QType& qt, const vector<DNSRecord>& content, const vector<shared_ptr<RRSIGRecordContent>>& signatures, const std::vector<std::shared_ptr<DNSRecord>>& authorityRecs, bool auth, boost::optional<Netmask> ednsmask, const OptTag& routingTag, vState state)
{
  auto& map = getMap(qname);
  const lock l(map);
  
  map.d_cachecachevalid = false;
  //  cerr<<"Replacing "<<qname<<" for "<< (ednsmask ? ednsmask->toString() : "everyone") << endl;
  if (ednsmask) {
    ednsmask = ednsmask->getNormalized();
  }
  auto key = boost::make_tuple(qname, qt.getCode(), routingTag, ednsmask ? *ednsmask : Netmask());
  bool isNew = false;
  cache_t::iterator stored = map.d_map.find(key);
  if (stored == map.d_map.end()) {
    stored = map.d_map.insert(CacheEntry(key, auth)).first;
    map.d_entriesCount++;
    isNew = true;
  }

  /* if we are inserting a new entry or updating an expired one (in which case the
     ECS index might have been removed but the entry still exists because it has not
     been garbage collected yet) we might need to update the ECS index.
     Otherwise it should already be indexed and we don't need to update it.
  */
  if (isNew || stored->d_ttd <= now) {
    /* don't bother building an ecsIndex if we don't have any netmask-specific entries */
    if (!routingTag && ednsmask && !ednsmask->empty()) {
      auto ecsIndexKey = boost::make_tuple(qname, qt.getCode());
      auto ecsIndex = map.d_ecsIndex.find(ecsIndexKey);
      if (ecsIndex == map.d_ecsIndex.end()) {
        ecsIndex = map.d_ecsIndex.insert(ECSIndexEntry(qname, qt.getCode())).first;
      }
      ecsIndex->addMask(*ednsmask);
    }
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
      //  cerr<<"\tStill hold valid auth data, and the new data is unauth, return\n";
      return;
    }
    else {
      ce.d_auth = false;  // new data won't be auth
    }
  }

  // refuse any attempt to *raise* the TTL of auth NS records, as it would make it possible
  // for an auth to keep a "ghost" zone alive forever, even after the delegation is gone from
  // the parent
  // BUT make sure that we CAN refresh the root
  if(ce.d_auth && auth && qt.getCode()==QType::NS && !isNew && !qname.isRoot()) {
    //    cerr<<"\tLimiting TTL of auth->auth NS set replace to "<<ce.d_ttd<<endl;
    maxTTD = ce.d_ttd;
  }

  if(auth) {
    ce.d_auth = true;
  }

  ce.d_records.clear();
  ce.d_records.reserve(content.size());

  for(const auto i : content) {
    /* Yes, we have altered the d_ttl value by adding time(nullptr) to it
       prior to calling this function, so the TTL actually holds a TTD. */
    ce.d_ttd=min(maxTTD, static_cast<time_t>(i.d_ttl));   // XXX this does weird things if TTLs differ in the set
    //cerr<<"To store: "<<i.d_content->getZoneRepresentation()<<" with ttl/ttd "<<i.d_ttl<<", capped at: "<<maxTTD<<endl;
    ce.d_records.push_back(i.d_content);
  }

  if (!isNew) {
    moveCacheItemToBack<SequencedTag>(map.d_map, stored);
  }
  map.d_map.replace(stored, ce);
}

size_t MemRecursorCache::doWipeCache(const DNSName& name, bool sub, uint16_t qtype)
{
  size_t count = 0;

  if (!sub) {
    auto& map = getMap(name);
    const lock l(map);
    map.d_cachecachevalid = false;
    auto& idx = map.d_map.get<NameOnlyHashedTag>();
    size_t n = idx.erase(name);
    count += n;
    map.d_entriesCount -= n;
    if (qtype == 0xffff) {
      auto& ecsIdx = map.d_ecsIndex.get<OrderedTag>();
      auto ecsIndexRange = ecsIdx.equal_range(name);
      ecsIdx.erase(ecsIndexRange.first, ecsIndexRange.second);
    }
    else {
      auto& ecsIdx = map.d_ecsIndex.get<HashedTag>();
      auto ecsIndexRange = ecsIdx.equal_range(tie(name, qtype));
      ecsIdx.erase(ecsIndexRange.first, ecsIndexRange.second);
    }
  }
  else {
    for (auto& map : d_maps) {
      const lock l(map);
      map.d_cachecachevalid = false;
      auto& idx = map.d_map.get<OrderedTag>();
      for (auto i = idx.lower_bound(name); i != idx.end(); ) {
        if (!i->d_qname.isPartOf(name))
          break;
        if (i->d_qtype == qtype || qtype == 0xffff) {
          count++;
          i = idx.erase(i);
          map.d_entriesCount--;
        } else {
          ++i;
        }
      }
      auto& ecsIdx = map.d_ecsIndex.get<OrderedTag>();
      for (auto i = ecsIdx.lower_bound(name); i != ecsIdx.end(); ) {
        if (!i->d_qname.isPartOf(name))
          break;
        if (i->d_qtype == qtype || qtype == 0xffff) {
          i = ecsIdx.erase(i);
        } else {
          ++i;
        }
      }
    }
  }
  return count;
}

// Name should be doLimitTime or so
bool MemRecursorCache::doAgeCache(time_t now, const DNSName& name, uint16_t qtype, uint32_t newTTL)
{
  auto& map = getMap(name);
  const lock l(map);
  cache_t::iterator iter = map.d_map.find(tie(name, qtype));
  if (iter == map.d_map.end()) {
    return false;
  }

  CacheEntry ce = *iter;
  if (ce.d_ttd < now)
    return false;  // would be dead anyhow

  uint32_t maxTTL = static_cast<uint32_t>(ce.d_ttd - now);
  if (maxTTL > newTTL) {
    map.d_cachecachevalid = false;

    time_t newTTD = now + newTTL;

    if (ce.d_ttd > newTTD) {
      ce.d_ttd = newTTD;
      map.d_map.replace(iter, ce);
    }
    return true;
  }
  return false;
}

bool MemRecursorCache::updateValidationStatus(time_t now, const DNSName &qname, const QType& qt, const ComboAddress& who, const OptTag& routingTag, bool requireAuth, vState newState, boost::optional<time_t> capTTD)
{
  auto& map = getMap(qname);
  const lock l(map);

  bool updated = false;
  uint16_t qtype = qt.getCode();
  if (qtype != QType::ANY && qtype != QType::ADDR && !map.d_ecsIndex.empty() && !routingTag) {
    auto entry = getEntryUsingECSIndex(map, now, qname, qtype, requireAuth, who);
    if (entry == map.d_map.end()) {
      return false;
    }

    entry->d_state = newState;
    if (capTTD) {
      entry->d_ttd = std::min(entry->d_ttd, *capTTD);
    }
    return true;
  }

  auto entries = getEntries(map, qname, qt, routingTag);

  for(auto i = entries.first; i != entries.second; ++i) {
    auto firstIndexIterator = map.d_map.project<OrderedTag>(i);

    if (routingTag) {
      if (!entryMatches(firstIndexIterator, qtype, requireAuth, routingTag)) {
        continue;
      }
    } else {
      if (!entryMatches(firstIndexIterator, qtype, requireAuth, who))
        continue;
    }

    i->d_state = newState;
    if (capTTD) {
      i->d_ttd = std::min(i->d_ttd, *capTTD);
    }
    updated = true;

    if(qtype != QType::ANY && qtype != QType::ADDR) // normally if we have a hit, we are done
      break;
  }

  return updated;
}

uint64_t MemRecursorCache::doDump(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if(!fp) { // dup probably failed
    close(newfd);
    return 0;
  }

  fprintf(fp.get(), "; main record cache dump follows\n;\n");
  uint64_t count = 0;

  for (auto& map : d_maps) {
    const lock l(map);
    const auto& sidx = map.d_map.get<SequencedTag>();

    time_t now = time(0);
    for (const auto i : sidx) {
      for (const auto j : i.d_records) {
        count++;
        try {
          fprintf(fp.get(), "%s %" PRId64 " IN %s %s ; (%s) auth=%i %s\n", i.d_qname.toString().c_str(), static_cast<int64_t>(i.d_ttd - now), DNSRecordContent::NumberToType(i.d_qtype).c_str(), j->getZoneRepresentation().c_str(), vStates[i.d_state], i.d_auth, i.d_netmask.empty() ? "" : i.d_netmask.toString().c_str());
        }
        catch(...) {
          fprintf(fp.get(), "; error printing '%s'\n", i.d_qname.empty() ? "EMPTY" : i.d_qname.toString().c_str());
        }
      }
      for (const auto &sig : i.d_signatures) {
        count++;
        try {
          fprintf(fp.get(), "%s %" PRId64 " IN RRSIG %s ; %s\n", i.d_qname.toString().c_str(), static_cast<int64_t>(i.d_ttd - now), sig->getZoneRepresentation().c_str(), i.d_netmask.empty() ? "" : i.d_netmask.toString().c_str());
        }
        catch(...) {
          fprintf(fp.get(), "; error printing '%s'\n", i.d_qname.empty() ? "EMPTY" : i.d_qname.toString().c_str());
        }
      }
    }
  }
  return count;
}

void MemRecursorCache::doPrune(size_t keep)
{
  //size_t maxCached = d_maxEntries;
  size_t cacheSize = size();
  pruneMutexCollectionsVector<SequencedTag>(*this, d_maps, keep, cacheSize);
}

