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

#include <boost/multi_index_container.hpp>

#include "dnsname.hh"
#include "lock.hh"

// this function can clean any cache that has a getTTD() method on its entries, a preRemoval() method and a 'sequence' index as its second index
// the ritual is that the oldest entries are in *front* of the sequence collection, so on a hit, move an item to the end
// on a miss, move it to the beginning
template <typename S, typename C, typename T> void pruneCollection(C& container, T& collection, size_t maxCached, size_t scanFraction = 1000)
{
  const time_t now = time(0);
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
  size_t tried = 0, erased = 0;

  for (auto iter = sidx.begin(); iter != sidx.end() && tried < lookAt ; ++tried) {
    if (iter->getTTD() < now) {
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
template <typename S, typename T> void moveCacheItemToFrontOrBack(T& collection, typename T::iterator& iter, bool front)
{
  typedef typename T::template index<S>::type sequence_t;
  sequence_t& sidx=collection.template get<S>();
  typename sequence_t::iterator si=collection.template project<S>(iter);
  if(front)
    sidx.relocate(sidx.begin(), si); // at the beginning of the delete queue
  else
    sidx.relocate(sidx.end(), si);  // back
}

template <typename S, typename T> void moveCacheItemToFront(T& collection, typename T::iterator& iter)
{
  moveCacheItemToFrontOrBack<S>(collection, iter, true);
}

template <typename S, typename T> void moveCacheItemToBack(T& collection, typename T::iterator& iter)
{
  moveCacheItemToFrontOrBack<S>(collection, iter, false);
}

template <typename S, typename T> uint64_t pruneLockedCollectionsVector(std::vector<T>& maps)
{
  uint64_t totErased = 0;
  time_t now = time(nullptr);

  for(auto& mc : maps) {
    auto map = mc.d_map.write_lock();

    uint64_t lookAt = (map->size() + 9) / 10; // Look at 10% of this shard
    uint64_t erased = 0;

    auto& sidx = boost::multi_index::get<S>(*map);
    for(auto i = sidx.begin(); i != sidx.end() && lookAt > 0; lookAt--) {
      if(i->ttd < now) {
        i = sidx.erase(i);
        erased++;
      } else {
        ++i;
      }
    }
    totErased += erased;
  }

  return totErased;
}

template <typename S, typename C, typename T> uint64_t pruneMutexCollectionsVector(C& container, std::vector<T>& maps, uint64_t maxCached, uint64_t cacheSize)
{
  time_t now = time(nullptr);
  uint64_t totErased = 0;
  uint64_t toTrim = 0;
  uint64_t lookAt = 0;

  // two modes - if toTrim is 0, just look through 10%  of the cache and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  if (cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
    lookAt = 5 * toTrim;
  } else {
    lookAt = cacheSize / 10;
  }

  uint64_t maps_size = maps.size();
  if (maps_size == 0) {
    return 0;
  }

  for (auto& content : maps) {
    auto mc = content.lock();
    mc->invalidate();
    auto& sidx = boost::multi_index::get<S>(mc->d_map);
    uint64_t erased = 0, lookedAt = 0;
    for (auto i = sidx.begin(); i != sidx.end(); lookedAt++) {
      if (i->getTTD() < now) {
        container.preRemoval(*mc, *i);
        i = sidx.erase(i);
        erased++;
        --content.d_entriesCount;
      } else {
        ++i;
      }

      if (toTrim && erased >= toTrim / maps_size)
        break;

      if (lookedAt > lookAt / maps_size)
        break;
    }
    totErased += erased;
    if (toTrim && totErased >= toTrim)
      break;
  }

  if (totErased >= toTrim) { // done
    return totErased;
  }

  toTrim -= totErased;

  while (true) {
    size_t pershard = toTrim / maps_size + 1;
    for (auto& content : maps) {
      auto mc = content.lock();
      mc->invalidate();
      auto& sidx = boost::multi_index::get<S>(mc->d_map);
      size_t removed = 0;
      for (auto i = sidx.begin(); i != sidx.end() && removed < pershard; removed++) {
        container.preRemoval(*mc, *i);
        i = sidx.erase(i);
        --content.d_entriesCount;
        totErased++;
        toTrim--;
        if (toTrim == 0) {
          return totErased;
        }
      }
    }
  }
  // Not reached
  return totErased;
}

template <typename T> uint64_t purgeLockedCollectionsVector(std::vector<T>& maps)
{
  uint64_t delcount=0;

  for(auto& mc : maps) {
    auto map = mc.d_map.write_lock();
    delcount += map->size();
    map->clear();
  }

  return delcount;
}

template <typename N, typename T> uint64_t purgeLockedCollectionsVector(std::vector<T>& maps, const std::string& match)
{
  uint64_t delcount=0;
  std::string prefix(match);
  prefix.resize(prefix.size()-1);
  DNSName dprefix(prefix);
  for(auto& mc : maps) {
    auto map = mc.d_map.write_lock();
    auto& idx = boost::multi_index::get<N>(*map);
    auto iter = idx.lower_bound(dprefix);
    auto start = iter;

    for(; iter != idx.end(); ++iter) {
      if(!iter->qname.isPartOf(dprefix)) {
        break;
      }
      delcount++;
    }
    idx.erase(start, iter);
  }

  return delcount;
}

template <typename N, typename T> uint64_t purgeExactLockedCollection(T& mc, const DNSName& qname)
{
  uint64_t delcount=0;
  auto map = mc.d_map.write_lock();
  auto& idx = boost::multi_index::get<N>(*map);
  auto range = idx.equal_range(qname);
  if(range.first != range.second) {
    delcount += distance(range.first, range.second);
    idx.erase(range.first, range.second);
  }

  return delcount;
}

template<typename S, typename Index>
bool lruReplacingInsert(Index& i, const typename Index::value_type& x)
{
  auto inserted = i.insert(x);
  if (!inserted.second) {
    moveCacheItemToBack<S>(i, inserted.first);
    i.replace(inserted.first, x);
    return false;
  }
  return true;
}
