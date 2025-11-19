/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <cinttypes>

#include "negcache.hh"
#include "misc.hh"
#include "cachecleaner.hh"
#include "rec-taskqueue.hh"

// For a description on how ServeStale works, see recursor_cache.cc, the general structure is the same.
uint16_t NegCache::s_maxServedStaleExtensions;

NegCache::NegCache(size_t mapsCount) :
  d_maps(mapsCount == 0 ? 1 : mapsCount)
{
}

size_t NegCache::size() const
{
  size_t count = 0;
  for (const auto& map : d_maps) {
    count += map.getEntriesCount();
  }
  return count;
}

/*!
 * Set ne to the NegCacheEntry for the last label in qname and return true if there
 * was one.
 *
 * \param qname    The name to look up (only the last label is used)
 * \param now      A timeval with the current time, to check if an entry is expired
 * \param ne       A NegCacheEntry that is filled when there is a cache entry
 * \return         true if ne was filled out, false otherwise
 */
bool NegCache::getRootNXTrust(const DNSName& qname, const struct timeval& now, NegCacheEntry& negEntry, bool serveStale, bool refresh)
{
  // Never deny the root.
  if (qname.isRoot()) {
    return false;
  }

  DNSName lastLabel = qname.getLastLabel();
  NegCacheEntry found;
  // An 'ENT' QType entry, used as "whole name" in the neg-cache context.
  auto exists = get(lastLabel, QType::ENT, now, found, true, serveStale, refresh);
  if (exists && found.d_auth.isRoot()) {
    negEntry = std::move(found);
    return true;
  }
  return false;
}

void NegCache::updateStaleEntry(time_t now, negcache_t::iterator& entry, QType qtype)
{
  // We need to take care an infrequently access stale item cannot be extended past
  // s_maxServedStaleExtension * s_serveStaleExtensionPeriod
  // We we look how old the entry is, and increase d_servedStale accordingly, taking care not to overflow
  const time_t howlong = std::max(static_cast<time_t>(1), now - entry->d_ttd);
  const uint32_t extension = std::max(1U, std::min(entry->d_orig_ttl, s_serveStaleExtensionPeriod));
  entry->d_servedStale = std::min(entry->d_servedStale + 1 + (howlong / extension), static_cast<time_t>(s_maxServedStaleExtensions));
  entry->d_ttd = now + std::min(entry->d_orig_ttl, s_serveStaleExtensionPeriod);

  if (qtype == QType::ENT) {
    qtype = QType::A;
  }

  pushAlmostExpiredTask(entry->d_name, qtype, entry->d_ttd, Netmask());
}

/*!
 * Set ne to the NegCacheEntry for the qname|qtype tuple and return true
 *
 * \param qname    The name to look up
 * \param qtype    The qtype to look up
 * \param now      A timeval with the current time, to check if an entry is expired
 * \param ne       A NegCacheEntry that is filled when there is a cache entry
 * \return         true if ne was filled out, false otherwise
 */
bool NegCache::get(const DNSName& qname, QType qtype, const struct timeval& now, NegCacheEntry& negEntry, bool typeMustMatch, bool serveStale, bool refresh)
{
  auto& map = getMap(qname);
  auto content = map.lock();

  const auto& idx = content->d_map.get<NegCacheEntry>();
  auto range = idx.equal_range(qname);

  for (auto ni = range.first; ni != range.second; ++ni) {
    // We have an entry
    if ((!typeMustMatch && ni->d_qtype == QType::ENT) || ni->d_qtype == qtype) {
      // We match the QType or the whole name is denied
      auto firstIndexIterator = content->d_map.project<CompositeKey>(ni);

      // this checks ttd, but also takes into account serve-stale
      if (!ni->isEntryUsable(now.tv_sec, serveStale)) {
        // Outdated
        moveCacheItemToFront<SequenceTag>(content->d_map, firstIndexIterator);
        continue;
      }
      // If we are serving this record stale (or *should*) and the ttd has passed increase ttd to
      // the future and remember that we did. Also push a refresh task.
      if ((serveStale || ni->d_servedStale > 0) && ni->d_ttd <= now.tv_sec && ni->d_servedStale < s_maxServedStaleExtensions) {
        updateStaleEntry(now.tv_sec, firstIndexIterator, qtype);
      }
      if (now.tv_sec < ni->d_ttd) {
        // Not expired
        negEntry = *ni;
        moveCacheItemToBack<SequenceTag>(content->d_map, firstIndexIterator);
        // when refreshing, we consider served-stale entries outdated
        return !refresh || ni->d_servedStale <= 0;
      }
    }
  }
  return false;
}

/*!
 * Places ne into the negative cache, possibly overriding an existing entry.
 *
 * \param ne The NegCacheEntry to add to the cache
 */
void NegCache::add(const NegCacheEntry& negEntry)
{
  bool inserted = false;
  auto& map = getMap(negEntry.d_name);
  auto content = map.lock();
  inserted = lruReplacingInsert<SequenceTag>(content->d_map, negEntry);
  if (inserted) {
    map.incEntriesCount();
  }
}

/*!
 * Update the validation state of an existing entry with the provided state.
 *
 * \param qname The name of the entry to replace
 * \param qtype The type of the entry to replace
 * \param newState The new validation state
 */
void NegCache::updateValidationStatus(const DNSName& qname, const QType qtype, const vState newState, boost::optional<time_t> capTTD)
{
  auto map = getMap(qname).lock();
  auto range = map->d_map.equal_range(std::tie(qname, qtype));

  if (range.first != range.second) {
    range.first->d_validationState = newState;
    if (capTTD) {
      range.first->d_ttd = std::min(range.first->d_ttd, *capTTD);
    }
  }
}

/*!
 * Returns the amount of entries in the cache
 *
 * \param qname The name of the entries to be counted
 */
size_t NegCache::count(const DNSName& qname)
{
  auto& map = getMap(qname);
  auto content = map.lock();
  return content->d_map.count(std::tie(qname));
}

/*!
 * Returns the amount of entries in the cache for qname+qtype
 *
 * \param qname The name of the entries to be counted
 * \param qtype The type of the entries to be counted
 */
size_t NegCache::count(const DNSName& qname, const QType qtype)
{
  auto& map = getMap(qname);
  auto content = map.lock();
  return content->d_map.count(std::tie(qname, qtype));
}

/*!
 * Remove all entries for name from the cache. If subtree is true, wipe all names
 * underneath it.
 *
 * \param name    The DNSName of the entries to wipe
 * \param subtree Should all entries under name be removed?
 */
size_t NegCache::wipe(const DNSName& name, bool subtree)
{
  size_t ret = 0;
  if (subtree) {
    for (auto& map : d_maps) {
      auto lockedMap = map.lock();
      for (auto i = lockedMap->d_map.lower_bound(std::tie(name)); i != lockedMap->d_map.end();) {
        if (!i->d_name.isPartOf(name)) {
          break;
        }
        i = lockedMap->d_map.erase(i);
        ret++;
        map.decEntriesCount();
      }
    }
    return ret;
  }

  auto& map = getMap(name);
  auto content = map.lock();
  auto range = content->d_map.equal_range(std::tie(name));
  auto iter = range.first;
  while (iter != range.second) {
    iter = content->d_map.erase(iter);
    ret++;
    map.decEntriesCount();
  }
  return ret;
}

size_t NegCache::wipeTyped(const DNSName& qname, QType qtype)
{
  size_t ret = 0;
  auto& map = getMap(qname);
  auto content = map.lock();
  auto range = content->d_map.equal_range(std::tie(qname));
  auto iter = range.first;
  while (iter != range.second) {
    if (iter->d_qtype == QType::ENT || iter->d_qtype == qtype) {
      iter = content->d_map.erase(iter);
      ++ret;
      map.decEntriesCount();
    }
    else {
      ++iter;
    }
  }
  return ret;
}

/*!
 * Clear the negative cache
 */
void NegCache::clear()
{
  for (auto& map : d_maps) {
    auto lockedMap = map.lock();
    lockedMap->d_map.clear();
    map.clearEntriesCount();
  }
}

/*!
 * Perform some cleanup in the cache, removing stale entries
 *
 * \param maxEntries The maximum number of entries that may exist in the cache.
 */
void NegCache::prune(time_t now, size_t maxEntries)
{
  size_t cacheSize = size();
  pruneMutexCollectionsVector<SequenceTag>(now, d_maps, maxEntries, cacheSize);
}

/*!
 * Writes the whole negative cache to fd
 *
 * \param fd A pointer to an open FILE object
 */
size_t NegCache::doDump(int fileDesc, size_t maxCacheEntries, time_t now)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }
  fprintf(filePtr.get(), "; negcache dump follows\n;\n");

  size_t ret = 0;

  size_t shard = 0;
  size_t min = std::numeric_limits<size_t>::max();
  size_t max = 0;
  for (auto& map : d_maps) {
    auto lockedMap = map.lock();
    const auto shardSize = lockedMap->d_map.size();
    fprintf(filePtr.get(), "; negcache shard %zu; size %zu\n", shard, shardSize);
    min = std::min(min, shardSize);
    max = std::max(max, shardSize);
    shard++;
    auto& sidx = lockedMap->d_map.get<SequenceTag>();
    for (const NegCacheEntry& negEntry : sidx) {
      ret++;
      int64_t ttl = negEntry.d_ttd - now;
      fprintf(filePtr.get(), "%s %" PRId64 " IN %s VIA %s ; (%s) origttl=%" PRIu32 " ss=%hu\n", negEntry.d_name.toString().c_str(), ttl, negEntry.d_qtype.toString().c_str(), negEntry.d_auth.toString().c_str(), vStateToString(negEntry.d_validationState).c_str(), negEntry.d_orig_ttl, negEntry.d_servedStale);
      for (const auto& rec : negEntry.authoritySOA.records) {
        fprintf(filePtr.get(), "%s %" PRId64 " IN %s %s ; (%s)\n", rec.d_name.toString().c_str(), ttl, DNSRecordContent::NumberToType(rec.d_type).c_str(), rec.getContent()->getZoneRepresentation().c_str(), vStateToString(negEntry.d_validationState).c_str());
      }
      for (const auto& sig : negEntry.authoritySOA.signatures) {
        fprintf(filePtr.get(), "%s %" PRId64 " IN RRSIG %s ;\n", sig.d_name.toString().c_str(), ttl, sig.getContent()->getZoneRepresentation().c_str());
      }
      for (const auto& rec : negEntry.DNSSECRecords.records) {
        fprintf(filePtr.get(), "%s %" PRId64 " IN %s %s ; (%s)\n", rec.d_name.toString().c_str(), ttl, DNSRecordContent::NumberToType(rec.d_type).c_str(), rec.getContent()->getZoneRepresentation().c_str(), vStateToString(negEntry.d_validationState).c_str());
      }
      for (const auto& sig : negEntry.DNSSECRecords.signatures) {
        fprintf(filePtr.get(), "%s %" PRId64 " IN RRSIG %s ;\n", sig.d_name.toString().c_str(), ttl, sig.getContent()->getZoneRepresentation().c_str());
      }
    }
  }
  fprintf(filePtr.get(), "; negcache size: %zu/%zu shards: %zu min/max shard size: %zu/%zu\n", size(), maxCacheEntries, d_maps.size(), min, max);
  return ret;
}
