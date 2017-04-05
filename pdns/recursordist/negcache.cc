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
#include "negcache.hh"
#include "misc.hh"
#include "cachecleaner.hh"

/*!
 * Set ne to the NegCacheEntry for the last label in qname and return true
 *
 * \param qname    The name to look up (only the last label is used)
 * \param now      A timeval with the current time, to check if an entry is expired
 * \param ne       A NegCacheEntry that is filled when there is a cache entry
 * \return         true if ne was filled out, false otherwise
 */
bool NegCache::getRootNXTrust(const DNSName& qname, const struct timeval& now, NegCacheEntry& ne) {
  // An 'ENT' QType entry, used as "whole name" in the neg-cache context.
  static const QType qtnull(0);
  pair<negcache_t::const_iterator, negcache_t::const_iterator> range;
  DNSName lastLabel = qname.getLastLabel();
  range.first = d_negcache.find(tie(lastLabel, qtnull));

  if (range.first != d_negcache.end() &&
      range.first->d_auth.isRoot()) {
    if ((uint32_t)now.tv_sec < range.first->d_ttd) {
      ne = *range.first;
      moveCacheItemToBack(d_negcache, range.first);
      return true;
    }
    moveCacheItemToFront(d_negcache, range.first);
  }
  return false;
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
bool NegCache::get(const DNSName& qname, const QType& qtype, const struct timeval& now, NegCacheEntry& ne) {
  auto range = d_negcache.equal_range(tie(qname));
  negcache_t::iterator ni = range.first;

  while (ni != range.second) {
    // We have an entry
    if (ni->d_qtype.getCode() == 0 || ni->d_qtype == qtype) {
      // We match the QType or the whole name is denied
      if((uint32_t) now.tv_sec < ni->d_ttd) {
        // Not expired
        ne = *ni;
        moveCacheItemToBack(d_negcache, ni);
        return true;
      }
      // expired
      moveCacheItemToFront(d_negcache, ni);
    }
    ni++;
  }
  return false;
}

/*!
 * Places ne into the negative cache, possibly overriding an existing entry.
 *
 * \param ne The NegCacheEntry to add to the cache
 */
void NegCache::add(const NegCacheEntry& ne) {
  replacing_insert(d_negcache, ne);
}

/*!
 * Returns the amount of entries in the cache
 */
uint64_t NegCache::count(const DNSName& qname) const {
  return d_negcache.count(tie(qname));
}

/*!
 * Remove all entries for name from the cache. If subtree is true, wipe all names
 * underneath it.
 *
 * \param name    The DNSName of the entries to wipe
 * \param subtree Should all entries under name be removed?
 */
uint64_t NegCache::wipe(const DNSName& name, bool subtree) {
  uint64_t ret(0);
  if (subtree) {
    for (auto i = d_negcache.lower_bound(tie(name)); i != d_negcache.end();) {
      if(!i->d_name.isPartOf(name))
        break;
      i = d_negcache.erase(i);
      ret++;
    }
    return ret;
  }

  ret = count(name);
  auto range = d_negcache.equal_range(tie(name));
  d_negcache.erase(range.first, range.second);
  return ret;
}

/*!
 * Clear the negative cache
 */
void NegCache::clear() {
  d_negcache.clear();
}

/*!
 * Perform some cleanup in the cache, removing stale entries
 *
 * \param maxEntries The maximum number of entries that may exist in the cache.
 */
void NegCache::prune(unsigned int maxEntries) {
  pruneCollection(d_negcache, maxEntries, 200);
}

/*!
 * Writes the whole negative cache to fp
 *
 * \param fp A pointer to an open FILE object
 */
uint64_t NegCache::dumpToFile(FILE* fp) {
  uint64_t ret(0);
  time_t now = time(0);
  negcache_sequence_t& sidx = d_negcache.get<1>();
  for(const NegCacheEntry& ne : sidx) {
    ret++;
    fprintf(fp, "%s %d IN %s VIA %s\n", ne.d_name.toString().c_str(), (unsigned int) (ne.d_ttd - now), ne.d_qtype.getName().c_str(), ne.d_auth.toString().c_str());
  }
  return ret;
}
