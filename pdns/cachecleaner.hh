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
#pragma once

#include <cmath>
#include <boost/multi_index_container.hpp>

#include "dnsname.hh"
#include "lock.hh"

// this function can clean any cache that has an isStale() method on its entries, a preRemoval() method and a 'sequence' index as its second index
// the ritual is that the oldest entries are in *front* of the sequence collection, so on a hit, move an item to the end
// and optionally, on a miss, move it to the beginning
template <typename S, typename T>
void pruneCollection(T& collection, size_t maxCached, size_t scanFraction = 1000)
{
  const time_t now = time(nullptr);
  size_t toTrim = 0;
  const size_t cacheSize = collection.size();

  if (cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
  }

  auto& sidx = collection.template get<S>();

  // two modes - if toTrim is 0, just look through 1/scanFraction of all records
  // and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  const size_t lookAt = toTrim ? 5 * toTrim : cacheSize / scanFraction;
  size_t tried = 0;
  size_t erased = 0;

  for (auto iter = sidx.begin(); iter != sidx.end() && tried < lookAt; ++tried) {
    if (iter->isStale(now)) {
      iter = sidx.erase(iter);
      erased++;
    }
    else {
      ++iter;
    }

    if (toTrim && erased >= toTrim) {
      break;
    }
  }

  if (erased >= toTrim) { // done
    return;
  }

  toTrim -= erased;

  // just lob it off from the beginning
  auto iter = sidx.begin();
  for (size_t i = 0; i < toTrim && iter != sidx.end(); i++) {
    iter = sidx.erase(iter);
  }
}

// note: this expects iterator from first index
template <typename S, typename T>
void moveCacheItemToFrontOrBack(T& collection, typename T::iterator& iter, bool front)
{
  auto& sidx = collection.template get<S>();
  auto siter = collection.template project<S>(iter);
  if (front) {
    sidx.relocate(sidx.begin(), siter); // at the beginning of the delete queue
  }
  else {
    sidx.relocate(sidx.end(), siter); // back
  }
}

template <typename S, typename T>
void moveCacheItemToFront(T& collection, typename T::iterator& iter)
{
  moveCacheItemToFrontOrBack<S>(collection, iter, true);
}

template <typename S, typename T>
void moveCacheItemToBack(T& collection, typename T::iterator& iter)
{
  moveCacheItemToFrontOrBack<S>(collection, iter, false);
}

template <typename S, typename T>
uint64_t pruneLockedCollectionsVector(std::vector<T>& maps)
{
  uint64_t totErased = 0;
  time_t now = time(nullptr);

  for (auto& shard : maps) {
    auto map = shard.d_map.write_lock();

    uint64_t lookAt = (map->size() + 9) / 10; // Look at 10% of this shard
    uint64_t erased = 0;

    auto& sidx = boost::multi_index::get<S>(*map);
    for (auto i = sidx.begin(); i != sidx.end() && lookAt > 0; lookAt--) {
      if (i->ttd < now) {
        i = sidx.erase(i);
        erased++;
      }
      else {
        ++i;
      }
    }
    totErased += erased;
  }

  return totErased;
}

template <typename S, typename T>
uint64_t pruneMutexCollectionsVector(time_t now, std::vector<T>& maps, uint64_t maxCached, uint64_t cacheSize)
{
  uint64_t totErased = 0;
  uint64_t toTrim = 0;
  uint64_t lookAt = 0;

  // two modes - if toTrim is 0, just look through 10%  of the cache and nuke everything that is expired
  // otherwise, scan first max(5*toTrim, 10%) records, and stop once we've nuked enough
  if (cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
    lookAt = std::max(5 * toTrim, cacheSize / 10);
  }
  else {
    lookAt = cacheSize / 10;
  }

  const uint64_t numberOfShards = maps.size();
  if (numberOfShards == 0 || cacheSize == 0) {
    return 0;
  }

  // first we scan a fraction of the shards for expired entries orderded by LRU
  for (auto& content : maps) {
    auto shard = content.lock();
    const auto shardSize = shard->d_map.size();
    const uint64_t toScanForThisShard = std::ceil(lookAt * ((1.0 * shardSize) / cacheSize));
    shard->invalidate();
    auto& sidx = boost::multi_index::get<S>(shard->d_map);
    uint64_t erased = 0;
    uint64_t lookedAt = 0;
    for (auto i = sidx.begin(); i != sidx.end(); lookedAt++) {
      if (i->isStale(now)) {
        shard->preRemoval(*i);
        i = sidx.erase(i);
        erased++;
        content.decEntriesCount();
      }
      else {
        ++i;
      }

      if (lookedAt >= toScanForThisShard) {
        break;
      }
    }
    totErased += erased;
  }

  if (totErased >= toTrim) { // done
    return totErased;
  }

  toTrim -= totErased;

  // It was not enough, so we need to remove entries that are not
  // expired, still using the LRU index.

  // From here on cacheSize is the total number of entries in the
  // shards that still need to be cleaned. When a shard is processed,
  // we subtract its original size from cacheSize as we use this value
  // to compute the fraction of the next shards to clean. This way
  // rounding issues do not cause over or undershoot of the target.
  //
  // Suppose we have 10 perfectly balanced shards, each filled with
  // 100 entries. So cacheSize is 1000. When cleaning 10%, after shard
  // 0 we still need to process 900 entries, spread out of 9
  // shards. So cacheSize becomes 900, and toTrim 90, since we cleaned
  // 10 items from shard 0. Our fraction remains 10%. For the last
  // shard, we would end up with cacheSize 100, and to clean 10.
  //
  // When the balance is not perfect, e.g. shard 0 has 54 entries, we
  // would clean 5 entries due to rounding, and for the remaining
  // shards we start with cacheSize 946 and toTrim 95: the fraction
  // becomes slightly larger than 10%, since we "missed" one item in
  // shard 0.

  cacheSize -= totErased;

  for (auto& content : maps) {
    auto shard = content.lock();
    const auto shardSize = shard->d_map.size();

    const uint64_t toTrimForThisShard = std::round(static_cast<double>(toTrim) * shardSize / cacheSize);
    // See explanation above
    cacheSize -= shardSize;
    if (toTrimForThisShard == 0) {
      continue;
    }
    shard->invalidate();
    auto& sidx = boost::multi_index::get<S>(shard->d_map);
    size_t removed = 0;
    for (auto i = sidx.begin(); i != sidx.end() && removed < toTrimForThisShard; removed++) {
      shard->preRemoval(*i);
      i = sidx.erase(i);
      content.decEntriesCount();
      ++totErased;
      if (--toTrim == 0) {
        return totErased;
      }
    }
  }
  return totErased;
}

template <typename T>
uint64_t purgeLockedCollectionsVector(std::vector<T>& maps)
{
  uint64_t delcount = 0;

  for (auto& shard : maps) {
    auto map = shard.d_map.write_lock();
    delcount += map->size();
    map->clear();
  }

  return delcount;
}

template <typename N, typename T>
uint64_t purgeLockedCollectionsVector(std::vector<T>& maps, const std::string& match)
{
  uint64_t delcount = 0;
  std::string prefix(match);
  prefix.resize(prefix.size() - 1);
  DNSName dprefix(prefix);
  for (auto& shard : maps) {
    auto map = shard.d_map.write_lock();
    auto& idx = boost::multi_index::get<N>(*map);
    auto iter = idx.lower_bound(dprefix);
    auto start = iter;

    for (; iter != idx.end(); ++iter) {
      if (!iter->qname.isPartOf(dprefix)) {
        break;
      }
      delcount++;
    }
    idx.erase(start, iter);
  }

  return delcount;
}

template <typename N, typename T>
uint64_t purgeExactLockedCollection(T& shard, const DNSName& qname)
{
  uint64_t delcount = 0;
  auto map = shard.d_map.write_lock();
  auto& idx = boost::multi_index::get<N>(*map);
  auto range = idx.equal_range(qname);
  if (range.first != range.second) {
    delcount += distance(range.first, range.second);
    idx.erase(range.first, range.second);
  }

  return delcount;
}

template <typename S, typename Index>
bool lruReplacingInsert(Index& index, const typename Index::value_type& value)
{
  auto inserted = index.insert(value);
  if (!inserted.second) {
    moveCacheItemToBack<S>(index, inserted.first);
    index.replace(inserted.first, value);
    return false;
  }
  return true;
}
