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

#include "lock.hh"

// this function can clean any cache that has a getTTD() method on its entries, a preRemoval() method and a 'sequence' index as its second index
// the ritual is that the oldest entries are in *front* of the sequence collection, so on a hit, move an item to the end
// on a miss, move it to the beginning
template <typename C, typename T> void pruneCollection(C& container, T& collection, unsigned int maxCached, unsigned int scanFraction=1000)
{
  time_t now=time(0);
  unsigned int toTrim=0;
  
  unsigned int cacheSize=collection.size();

  if(cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
  }

//  cout<<"Need to trim "<<toTrim<<" from cache to meet target!\n";

  typedef typename T::template nth_index<1>::type sequence_t;
  sequence_t& sidx=collection.template get<1>();

  unsigned int tried=0, lookAt, erased=0;

  // two modes - if toTrim is 0, just look through 1/scanFraction of all records 
  // and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  if(toTrim)
    lookAt=5*toTrim;
  else
    lookAt=cacheSize/scanFraction;

  typename sequence_t::iterator iter=sidx.begin(), eiter;
  for(; iter != sidx.end() && tried < lookAt ; ++tried) {
    if(iter->getTTD() < now) {
      container.preRemoval(*iter);
      sidx.erase(iter++);
      erased++;
    }
    else
      ++iter;

    if(toTrim && erased >= toTrim)
      break;
  }

  //cout<<"erased "<<erased<<" records based on ttd\n";
  
  if(erased >= toTrim) // done
    return;

  toTrim -= erased;

  //if(toTrim)
    // cout<<"Still have "<<toTrim - erased<<" entries left to erase to meet target\n"; 

  eiter=iter=sidx.begin();
  std::advance(eiter, toTrim);
  // just lob it off from the beginning
  for (auto i = iter; ; ) {
    if (i == eiter) {
      break;
    }

    container.preRemoval(*i);
    sidx.erase(i++);
  }
}

// note: this expects iterator from first index, and sequence MUST be second index!
template <typename T> void moveCacheItemToFrontOrBack(T& collection, typename T::iterator& iter, bool front)
{
  typedef typename T::template nth_index<1>::type sequence_t;
  sequence_t& sidx=collection.template get<1>();
  typename sequence_t::iterator si=collection.template project<1>(iter);
  if(front)
    sidx.relocate(sidx.begin(), si); // at the beginning of the delete queue
  else
    sidx.relocate(sidx.end(), si);  // back
}

template <typename T> void moveCacheItemToFront(T& collection, typename T::iterator& iter)
{
  moveCacheItemToFrontOrBack(collection, iter, true);
}

template <typename T> void moveCacheItemToBack(T& collection, typename T::iterator& iter)
{
  moveCacheItemToFrontOrBack(collection, iter, false);
}

template <typename T> uint64_t pruneLockedCollectionsVector(vector<T>& maps, uint64_t maxCached, uint64_t cacheSize)
{
  time_t now = time(nullptr);
  uint64_t totErased = 0;
  uint64_t toTrim = 0;
  uint64_t lookAt = 0;

  // two modes - if toTrim is 0, just look through 10%  of the cache and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  if (maxCached && cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
    lookAt = 5 * toTrim;
  } else {
    lookAt = cacheSize / 10;
  }

  for(auto& mc : maps) {
    WriteLock wl(&mc.d_mut);
    auto& sidx = boost::multi_index::get<2>(mc.d_map);
    uint64_t erased = 0, lookedAt = 0;
    for(auto i = sidx.begin(); i != sidx.end(); lookedAt++) {
      if(i->ttd < now) {
        i = sidx.erase(i);
        erased++;
      } else {
        ++i;
      }

      if(toTrim && erased > toTrim / maps.size())
        break;

      if(lookedAt > lookAt / maps.size())
        break;
    }
    totErased += erased;
  }

  return totErased;
}

template <typename T> uint64_t purgeLockedCollectionsVector(vector<T>& maps)
{
  uint64_t delcount=0;

  for(auto& mc : maps) {
    WriteLock wl(&mc.d_mut);
    delcount += mc.d_map.size();
    mc.d_map.clear();
  }

  return delcount;
}

template <typename T> uint64_t purgeLockedCollectionsVector(vector<T>& maps, const std::string& match)
{
  uint64_t delcount=0;
  string prefix(match);
  prefix.resize(prefix.size()-1);
  DNSName dprefix(prefix);
  for(auto& mc : maps) {
    WriteLock wl(&mc.d_mut);
    auto& idx = boost::multi_index::get<1>(mc.d_map);
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

template <typename T> uint64_t purgeExactLockedCollection(T& mc, const DNSName& qname)
{
  uint64_t delcount=0;
  WriteLock wl(&mc.d_mut);
  auto& idx = boost::multi_index::get<1>(mc.d_map);
  auto range = idx.equal_range(qname);
  if(range.first != range.second) {
    delcount += distance(range.first, range.second);
    idx.erase(range.first, range.second);
  }

  return delcount;
}

template<typename Index>
std::pair<typename Index::iterator,bool>
lruReplacingInsert(Index& i,const typename Index::value_type& x)
{
  std::pair<typename Index::iterator,bool> res = i.insert(x);
  if (!res.second) {
    moveCacheItemToBack(i, res.first);
    res.second = i.replace(res.first, x);
  }
  return res;
}
