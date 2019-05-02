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
#include "utility.hh"

/*!
 * Set ne to the NegCacheEntry for the last label in qname and return true if there
 * was one.
 *
 * \param qname    The name to look up (only the last label is used)
 * \param now      A timeval with the current time, to check if an entry is expired
 * \param ne       A NegCacheEntry that is filled when there is a cache entry
 * \return         true if ne was filled out, false otherwise
 */
bool NegCache::getRootNXTrust(const DNSName& qname, const struct timeval& now, const NegCacheEntry** ne) {
  // Never deny the root.
  if (qname.isRoot())
    return false;

  // An 'ENT' QType entry, used as "whole name" in the neg-cache context.
  static const QType qtnull(0);
  DNSName lastLabel = qname.getLastLabel();
  negcache_t::const_iterator ni = d_negcache.find(tie(lastLabel, qtnull));

  while (ni != d_negcache.end() &&
         ni->d_name == lastLabel &&
         ni->d_auth.isRoot() &&
         ni->d_qtype == qtnull) {
    // We have something
    if ((uint32_t)now.tv_sec < ni->d_ttd) {
      *ne = &(*ni);
      moveCacheItemToBack(d_negcache, ni);
      return true;
    }
    moveCacheItemToFront(d_negcache, ni);
    ++ni;
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
bool NegCache::get(const DNSName& qname, const QType& qtype, const struct timeval& now, const NegCacheEntry** ne, bool typeMustMatch) {
  const auto& idx = d_negcache.get<2>();
  auto range = idx.equal_range(qname);
  auto ni = range.first;

  while (ni != range.second) {
    // We have an entry
    if ((!typeMustMatch && ni->d_qtype.getCode() == 0) || ni->d_qtype == qtype) {
      // We match the QType or the whole name is denied
      auto firstIndexIterator = d_negcache.project<0>(ni);

      if((uint32_t) now.tv_sec < ni->d_ttd) {
        // Not expired
        *ne = &(*ni);
        moveCacheItemToBack(d_negcache, firstIndexIterator);
        return true;
      }
      // expired
      moveCacheItemToFront(d_negcache, firstIndexIterator);
    }
    ++ni;
  }
  return false;
}

/*!
 * Places ne into the negative cache, possibly overriding an existing entry.
 *
 * \param ne The NegCacheEntry to add to the cache
 */
void NegCache::add(const NegCacheEntry& ne) {
  lruReplacingInsert(d_negcache, ne);
}

/*!
 * Update the validation state of an existing entry with the provided state.
 *
 * \param qname The name of the entry to replace
 * \param qtype The type of the entry to replace
 * \param newState The new validation state
 */
void NegCache::updateValidationStatus(const DNSName& qname, const QType& qtype, const vState newState, boost::optional<uint32_t> capTTD) {
  auto range = d_negcache.equal_range(tie(qname, qtype));

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
uint64_t NegCache::count(const DNSName& qname) const {
  return d_negcache.count(tie(qname));
}

/*!
 * Returns the amount of entries in the cache for qname+qtype
 *
 * \param qname The name of the entries to be counted
 * \param qtype The type of the entries to be counted
 */
uint64_t NegCache::count(const DNSName& qname, const QType qtype) const {
  return d_negcache.count(tie(qname, qtype));
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
  pruneCollection(*this, d_negcache, maxEntries, 200);
}

/*!
 * Writes the whole negative cache to fp
 *
 * \param fp A pointer to an open FILE object
 */
uint64_t NegCache::dumpToFile(FILE* fp) {
  uint64_t ret(0);
  struct timeval now;
  Utility::gettimeofday(&now, nullptr);

  negcache_sequence_t& sidx = d_negcache.get<1>();
  for(const NegCacheEntry& ne : sidx) {
    ret++;
    fprintf(fp, "%s %" PRId64 " IN %s VIA %s ; (%s)\n", ne.d_name.toString().c_str(), static_cast<int64_t>(ne.d_ttd - now.tv_sec), ne.d_qtype.getName().c_str(), ne.d_auth.toString().c_str(), vStates[ne.d_validationState]);
    for (const auto& rec : ne.DNSSECRecords.records) {
      fprintf(fp, "%s %" PRId64 " IN %s %s ; (%s)\n", ne.d_name.toString().c_str(), static_cast<int64_t>(ne.d_ttd - now.tv_sec), DNSRecordContent::NumberToType(rec.d_type).c_str(), rec.d_content->getZoneRepresentation().c_str(), vStates[ne.d_validationState]);
    }
    for (const auto& sig : ne.DNSSECRecords.signatures) {
      fprintf(fp, "%s %" PRId64 " IN RRSIG %s ;\n", ne.d_name.toString().c_str(), static_cast<int64_t>(ne.d_ttd - now.tv_sec), sig.d_content->getZoneRepresentation().c_str());
    }
  }
  return ret;
}
