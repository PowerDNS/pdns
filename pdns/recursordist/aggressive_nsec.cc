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

#include "aggressive_nsec.hh"
#include "cachecleaner.hh"
#include "recursor_cache.hh"
#include "logger.hh"
#include "validate.hh"

std::unique_ptr<AggressiveNSECCache> g_aggressiveNSECCache{nullptr};

/* this is defined in syncres.hh and we are not importing that here */
extern std::unique_ptr<MemRecursorCache> g_recCache;

std::shared_ptr<AggressiveNSECCache::ZoneEntry> AggressiveNSECCache::getBestZone(const DNSName& zone)
{
  std::shared_ptr<AggressiveNSECCache::ZoneEntry> entry{nullptr};
  {
    TryReadLock rl(d_lock);
    if (!rl.gotIt()) {
      return entry;
    }

    auto got = d_zones.lookup(zone);
    if (got) {
      return *got;
    }
  }
  return entry;
}

std::shared_ptr<AggressiveNSECCache::ZoneEntry> AggressiveNSECCache::getZone(const DNSName& zone)
{
  {
    ReadLock rl(d_lock);
    auto got = d_zones.lookup(zone);
    if (got && *got && (*got)->d_zone == zone) {
      return *got;
    }
  }

  auto entry = std::make_shared<ZoneEntry>(zone);

  {
    WriteLock wl(d_lock);
    /* it might have been inserted in the mean time */
    auto got = d_zones.lookup(zone);
    if (got && *got && (*got)->d_zone == zone) {
      return *got;
    }
    d_zones.add(zone, std::shared_ptr<ZoneEntry>(entry));
    return entry;
  }
}

void AggressiveNSECCache::updateEntriesCount()
{
  /* need to be called while holding a write lock */
  uint64_t counter = 0;
  d_zones.visit([&counter](const SuffixMatchTree<std::shared_ptr<ZoneEntry>>& node) {
    if (node.d_value) {
      counter += node.d_value->d_entries.size();
    }
  });
  d_entriesCount = counter;
}

void AggressiveNSECCache::removeZoneInfo(const DNSName& zone, bool subzones)
{
  WriteLock rl(d_lock);

  if (subzones) {
    d_zones.remove(zone, true);
    updateEntriesCount();
  }
  else {
    auto got = d_zones.lookup(zone);
    if (!got || !*got || (*got)->d_zone != zone) {
      return;
    }

    /* let's increase the ref count of the shared pointer
       so we get the lock, remove the zone from the tree,
       then release the lock before the entry is deleted */
    auto entry = *got;
    {
      std::lock_guard<std::mutex> lock(entry->d_lock);
      auto removed = entry->d_entries.size();
      d_zones.remove(zone, false);
      d_entriesCount -= removed;
    }
  }
}

void AggressiveNSECCache::prune(time_t now)
{
  uint64_t maxNumberOfEntries = d_maxEntries;
  std::vector<DNSName> emptyEntries;

  uint64_t erased = 0;
  uint64_t lookedAt = 0;
  uint64_t toLook = std::max(d_entriesCount / 5U, static_cast<uint64_t>(1U));

  if (d_entriesCount > maxNumberOfEntries) {
    uint64_t toErase = d_entriesCount - maxNumberOfEntries;
    toLook = toErase * 5;
    // we are full, scan at max 5 * toErase entries and stop once we have nuked enough

    WriteLock rl(d_lock);
    d_zones.visit([now, &erased, toErase, toLook, &lookedAt, &emptyEntries](const SuffixMatchTree<std::shared_ptr<ZoneEntry>>& node) {
      if (!node.d_value || erased > toErase || lookedAt > toLook) {
        return;
      }

      {
        std::lock_guard<std::mutex> lock(node.d_value->d_lock);
        auto& sidx = boost::multi_index::get<ZoneEntry::SequencedTag>(node.d_value->d_entries);
        for (auto it = sidx.begin(); it != sidx.end(); ++lookedAt) {
          if (erased >= toErase || lookedAt >= toLook) {
            break;
          }

          if (it->d_ttd < now) {
            it = sidx.erase(it);
            ++erased;
          }
          else {
            ++it;
          }
        }
      }

      if (node.d_value->d_entries.size() == 0) {
        emptyEntries.push_back(node.d_value->d_zone);
      }
    });
  }
  else {
    // we are not full, just look through 10% of the cache and nuke everything that is expired
    WriteLock rl(d_lock);

    d_zones.visit([now, &erased, toLook, &lookedAt, &emptyEntries](const SuffixMatchTree<std::shared_ptr<ZoneEntry>>& node) {
      if (!node.d_value) {
        return;
      }

      {
        std::lock_guard<std::mutex> lock(node.d_value->d_lock);

        auto& sidx = boost::multi_index::get<ZoneEntry::SequencedTag>(node.d_value->d_entries);
        for (auto it = sidx.begin(); it != sidx.end(); ++lookedAt) {
          if (lookedAt >= toLook) {
            break;
          }
          if (it->d_ttd < now || lookedAt > toLook) {
            it = sidx.erase(it);
            ++erased;
          }
          else {
            ++it;
          }
        }
      }

      if (node.d_value->d_entries.size() == 0) {
        emptyEntries.push_back(node.d_value->d_zone);
      }
    });
  }

  d_entriesCount -= erased;

  if (!emptyEntries.empty()) {
    WriteLock rl(d_lock);
    for (const auto& entry : emptyEntries) {
      d_zones.remove(entry);
    }
  }
}

static bool isMinimallyCoveringNSEC(const DNSName& owner, const std::shared_ptr<NSECRecordContent>& nsec)
{
  /* this test only covers Cloudflare's ones (https://blog.cloudflare.com/black-lies/),
     we might need to cover more cases described in rfc4470 as well, but the name generation algorithm
     is not clearly defined there */
  const auto& storage = owner.getStorage();
  const auto& nextStorage = nsec->d_next.getStorage();
  if (nextStorage.size() <= 2 || storage.size() != (nextStorage.size() - 2)) {
    return false;
  }

  if (nextStorage.at(0) != 1 || static_cast<uint8_t>(nextStorage.at(1)) != static_cast<uint8_t>(0)) {
    return false;
  }

  if (nextStorage.compare(2, nextStorage.size() - 2, storage) != 0) {
    return false;
  }

  return true;
}

static bool isMinimallyCoveringNSEC3(const DNSName& owner, const std::shared_ptr<NSEC3RecordContent>& nsec)
{
  std::string ownerHash(owner.getStorage().c_str(), owner.getStorage().size());
  const std::string& nextHash = nsec->d_nexthash;

  incrementHash(ownerHash);
  incrementHash(ownerHash);

  return ownerHash == nextHash;
}

void AggressiveNSECCache::insertNSEC(const DNSName& zone, const DNSName& owner, const DNSRecord& record, const std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures, bool nsec3)
{
  if (signatures.empty()) {
    return;
  }

  std::shared_ptr<AggressiveNSECCache::ZoneEntry> entry = getZone(zone);
  {
    std::lock_guard<std::mutex> lock(entry->d_lock);
    if (nsec3 && !entry->d_nsec3) {
      d_entriesCount -= entry->d_entries.size();
      entry->d_entries.clear();
      entry->d_nsec3 = true;
    }

    DNSName next;
    if (!nsec3) {
      auto content = getRR<NSECRecordContent>(record);
      if (!content) {
        throw std::runtime_error("Error getting the content from a NSEC record");
      }

      next = content->d_next;
      if (next.canonCompare(owner) && next != zone) {
        /* not accepting a NSEC whose next domain name is before the owner
           unless the next domain name is the apex, sorry */
        return;
      }

      if (isMinimallyCoveringNSEC(owner, content)) {
        /* not accepting minimally covering answers since they only deny one name */
        return;
      }
    }
    else {
      auto content = getRR<NSEC3RecordContent>(record);
      if (!content) {
        throw std::runtime_error("Error getting the content from a NSEC3 record");
      }

      if (content->isOptOut()) {
        /* doesn't prove anything, sorry */
        return;
      }

      if (g_maxNSEC3Iterations && content->d_iterations > g_maxNSEC3Iterations) {
        /* can't use that */
        return;
      }

      if (isMinimallyCoveringNSEC3(owner, content)) {
        /* not accepting minimally covering answers since they only deny one name */
        return;
      }

      // XXX: Ponder storing everything in raw form, without the zone instead. It still needs to be a DNSName for NSEC, though,
      // but doing the conversion on cache hits only might be faster
      next = DNSName(toBase32Hex(content->d_nexthash)) + zone;

      if (entry->d_iterations != content->d_iterations || entry->d_salt != content->d_salt) {
        entry->d_iterations = content->d_iterations;
        entry->d_salt = content->d_salt;

        // Clearing the existing entries since we can't use them, and it's likely a rollover
        // If it instead is different servers using different parameters, well, too bad.
        d_entriesCount -= entry->d_entries.size();
        entry->d_entries.clear();
      }
    }

    /* the TTL is already a TTD by now */
    if (!nsec3 && isWildcardExpanded(owner.countLabels(), signatures.at(0))) {
      DNSName realOwner = getNSECOwnerName(owner, signatures);
      auto pair = entry->d_entries.insert({record.d_content, signatures, std::move(realOwner), std::move(next), record.d_ttl});
      if (pair.second) {
        ++d_entriesCount;
      }
    }
    else {
      auto pair = entry->d_entries.insert({record.d_content, signatures, owner, std::move(next), record.d_ttl});
      if (pair.second) {
        ++d_entriesCount;
      }
    }
  }
}

bool AggressiveNSECCache::getNSECBefore(time_t now, std::shared_ptr<AggressiveNSECCache::ZoneEntry>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry)
{
  std::unique_lock<std::mutex> lock(zoneEntry->d_lock, std::try_to_lock);
  if (!lock.owns_lock() || zoneEntry->d_entries.empty()) {
    return false;
  }

#if 0
  LOG("We have:"<<endl);
  for (const auto& ent : zoneEntry->d_entries) {
    LOG("- "<<ent.d_owner<<" -> "<<ent.d_next<<endl);
  }
  LOG("=> end of list, looking for the lower bound to "<<name<<endl);
#endif
  auto& idx = zoneEntry->d_entries.get<ZoneEntry::OrderedTag>();
  auto it = idx.lower_bound(name);
  bool end = false;
  bool wrapped = false;

  if (it == idx.begin() && it->d_owner != name) {
    it = idx.end();
    // we know the map is not empty
    it--;
    // might be that owner > name && name < next
    // can't go further, but perhaps we wrapped?
    wrapped = true;
  }

  while (!end && !wrapped && (it == idx.end() || (it->d_owner != name && !it->d_owner.canonCompare(name)))) {
    if (it == idx.begin()) {
      end = true;
      break;
    }
    else {
      it--;
    }
  }

  if (end) {
    return false;
  }

  if (it->d_ttd <= now) {
    moveCacheItemToFront<ZoneEntry::SequencedTag>(zoneEntry->d_entries, it);
    return false;
  }

  entry = *it;
  moveCacheItemToBack<ZoneEntry::SequencedTag>(zoneEntry->d_entries, it);
  return true;
}

bool AggressiveNSECCache::getNSEC3(time_t now, std::shared_ptr<AggressiveNSECCache::ZoneEntry>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry)
{
  std::unique_lock<std::mutex> lock(zoneEntry->d_lock, std::try_to_lock);
  if (!lock.owns_lock() || zoneEntry->d_entries.empty()) {
    return false;
  }

  auto& idx = zoneEntry->d_entries.get<ZoneEntry::HashedTag>();
  auto entries = idx.equal_range(name);

  for (auto it = entries.first; it != entries.second; ++it) {

    if (it->d_owner != name) {
      continue;
    }

    auto firstIndexIterator = zoneEntry->d_entries.project<ZoneEntry::OrderedTag>(it);
    if (it->d_ttd <= now) {
      moveCacheItemToBack<ZoneEntry::SequencedTag>(zoneEntry->d_entries, firstIndexIterator);
      return false;
    }

    entry = *it;
    moveCacheItemToBack<ZoneEntry::SequencedTag>(zoneEntry->d_entries, firstIndexIterator);
    return true;
  }

  return false;
}

static void addToRRSet(const time_t now, std::vector<DNSRecord>& recordSet, std::vector<std::shared_ptr<RRSIGRecordContent>> signatures, const DNSName& owner, bool doDNSSEC, std::vector<DNSRecord>& ret, DNSResourceRecord::Place place = DNSResourceRecord::AUTHORITY)
{
  uint32_t ttl = 0;

  for (auto& record : recordSet) {
    if (record.d_class != QClass::IN) {
      continue;
    }

    record.d_ttl -= now;
    record.d_name = owner;
    ttl = record.d_ttl;
    record.d_place = place;
    ret.push_back(std::move(record));
  }

  if (doDNSSEC) {
    for (auto& signature : signatures) {
      DNSRecord dr;
      dr.d_type = QType::RRSIG;
      dr.d_name = owner;
      dr.d_ttl = ttl;
      dr.d_content = std::move(signature);
      dr.d_place = place;
      dr.d_class = QClass::IN;
      ret.push_back(std::move(dr));
    }
  }
}

static void addRecordToRRSet(time_t now, const DNSName& owner, const QType& type, uint32_t ttl, std::shared_ptr<DNSRecordContent>& content, std::vector<std::shared_ptr<RRSIGRecordContent>> signatures, bool doDNSSEC, std::vector<DNSRecord>& ret)
{
  DNSRecord nsecRec;
  nsecRec.d_type = type.getCode();
  nsecRec.d_name = owner;
  nsecRec.d_ttl = ttl;
  nsecRec.d_content = std::move(content);
  nsecRec.d_place = DNSResourceRecord::AUTHORITY;
  nsecRec.d_class = QClass::IN;
  ret.push_back(std::move(nsecRec));

  if (doDNSSEC) {
    for (auto& signature : signatures) {
      DNSRecord dr;
      dr.d_type = QType::RRSIG;
      dr.d_name = owner;
      dr.d_ttl = ttl;
      dr.d_content = std::move(signature);
      dr.d_place = DNSResourceRecord::AUTHORITY;
      dr.d_class = QClass::IN;
      ret.push_back(std::move(dr));
    }
  }
}

#define LOG(x)                     \
  if (g_dnssecLOG) {               \
    g_log << Logger::Warning << x; \
  }

bool AggressiveNSECCache::synthesizeFromNSEC3Wildcard(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC, ZoneEntry::CacheEntry& nextCloser, const DNSName& wildcardName)
{
  vState cachedState;

  std::vector<DNSRecord> wcSet;
  std::vector<std::shared_ptr<RRSIGRecordContent>> wcSignatures;

  if (g_recCache->get(now, wildcardName, type, true, &wcSet, ComboAddress("127.0.0.1"), false, boost::none, doDNSSEC ? &wcSignatures : nullptr, nullptr, nullptr, &cachedState) <= 0 || cachedState != vState::Secure) {
    LOG("Unfortunately we don't have a valid entry for " << wildcardName << ", so we cannot synthesize from that wildcard" << endl);
    return false;
  }

  addToRRSet(now, wcSet, wcSignatures, name, doDNSSEC, ret, DNSResourceRecord::ANSWER);
  /* no need for closest encloser proof, the wildcard is there */
  addRecordToRRSet(now, nextCloser.d_owner, QType::NSEC3, nextCloser.d_ttd - now, nextCloser.d_record, nextCloser.d_signatures, doDNSSEC, ret);
  /* and of course we won't deny the wildcard either */

  LOG("Synthesized valid answer from NSEC3s and wildcard!" << endl);
  ++d_nsec3WildcardHits;
  return true;
}

bool AggressiveNSECCache::synthesizeFromNSECWildcard(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC, ZoneEntry::CacheEntry& nsec, const DNSName& wildcardName)
{
  vState cachedState;

  std::vector<DNSRecord> wcSet;
  std::vector<std::shared_ptr<RRSIGRecordContent>> wcSignatures;

  if (g_recCache->get(now, wildcardName, type, true, &wcSet, ComboAddress("127.0.0.1"), false, boost::none, doDNSSEC ? &wcSignatures : nullptr, nullptr, nullptr, &cachedState) <= 0 || cachedState != vState::Secure) {
    LOG("Unfortunately we don't have a valid entry for " << wildcardName << ", so we cannot synthesize from that wildcard" << endl);
    return false;
  }

  addToRRSet(now, wcSet, wcSignatures, name, doDNSSEC, ret, DNSResourceRecord::ANSWER);
  addRecordToRRSet(now, nsec.d_owner, QType::NSEC, nsec.d_ttd - now, nsec.d_record, nsec.d_signatures, doDNSSEC, ret);

  LOG("Synthesized valid answer from NSECs and wildcard!" << endl);
  ++d_nsecWildcardHits;
  return true;
}

bool AggressiveNSECCache::getNSEC3Denial(time_t now, std::shared_ptr<AggressiveNSECCache::ZoneEntry>& zoneEntry, std::vector<DNSRecord>& soaSet, std::vector<std::shared_ptr<RRSIGRecordContent>>& soaSignatures, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC)
{
  DNSName zone;
  std::string salt;
  uint16_t iterations;

  {
    std::unique_lock<std::mutex> lock(zoneEntry->d_lock, std::try_to_lock);
    if (!lock.owns_lock()) {
      return false;
    }
    salt = zoneEntry->d_salt;
    zone = zoneEntry->d_zone;
    iterations = zoneEntry->d_iterations;
  }

  auto nameHash = DNSName(toBase32Hex(hashQNameWithSalt(salt, iterations, name))) + zone;

  ZoneEntry::CacheEntry exactNSEC3;
  if (getNSEC3(now, zoneEntry, nameHash, exactNSEC3)) {
    LOG("Found a direct NSEC3 match for " << nameHash);
    auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(exactNSEC3.d_record);
    if (!nsec3 || nsec3->d_iterations != iterations || nsec3->d_salt != salt) {
      LOG(" but the content is not valid, or has a different salt or iterations count" << endl);
      return false;
    }

    if (!isTypeDenied(nsec3, type)) {
      LOG(" but the requested type (" << type.getName() << ") does exist" << endl);
      return false;
    }

    const DNSName signer = getSigner(exactNSEC3.d_signatures);
    if (type != QType::DS && isNSEC3AncestorDelegation(signer, exactNSEC3.d_owner, nsec3)) {
      /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
         Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
         nonexistence of any RRs below that zone cut, which include all RRs at
         that (original) owner name other than DS RRs, and all RRs below that
         owner name regardless of type.
      */
      LOG(" but this is an ancestor delegation NSEC3" << endl);
      return false;
    }

    LOG(": done!" << endl);
    ++d_nsec3Hits;
    res = RCode::NoError;
    addToRRSet(now, soaSet, soaSignatures, zone, doDNSSEC, ret);
    addRecordToRRSet(now, exactNSEC3.d_owner, QType::NSEC3, exactNSEC3.d_ttd - now, exactNSEC3.d_record, exactNSEC3.d_signatures, doDNSSEC, ret);
    return true;
  }

  LOG("No direct NSEC3 match found for " << nameHash << ", looking for closest encloser" << endl);
  DNSName closestEncloser(name);
  bool found = false;
  ZoneEntry::CacheEntry closestNSEC3;
  while (!found && closestEncloser.chopOff()) {
    auto closestHash = DNSName(toBase32Hex(hashQNameWithSalt(salt, iterations, closestEncloser))) + zone;

    if (getNSEC3(now, zoneEntry, closestHash, closestNSEC3)) {
      LOG("Found closest encloser at " << closestEncloser << " (" << closestHash << ")" << endl);

      auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(closestNSEC3.d_record);
      if (!nsec3 || nsec3->d_iterations != iterations || nsec3->d_salt != salt) {
        LOG(" but the content is not valid, or has a different salt or iterations count" << endl);
        break;
      }

      found = true;
      break;
    }
  }

  if (!found) {
    LOG("Nothing found for the closest encloser in NSEC3 aggressive cache either" << endl);
    return false;
  }

  unsigned int labelIdx = name.countLabels() - closestEncloser.countLabels();
  if (labelIdx < 1) {
    return false;
  }

  DNSName nsecFound;
  DNSName nextCloser(closestEncloser);
  nextCloser.prependRawLabel(name.getRawLabel(labelIdx - 1));
  auto nextCloserHash = toBase32Hex(hashQNameWithSalt(salt, iterations, nextCloser));
  LOG("Looking for a NSEC3 covering the next closer " << nextCloser << " (" << nextCloserHash << ")" << endl);

  ZoneEntry::CacheEntry nextCloserEntry;
  if (!getNSECBefore(now, zoneEntry, DNSName(nextCloserHash) + zone, nextCloserEntry)) {
    LOG("Nothing found for the next closer in NSEC3 aggressive cache" << endl);
    return false;
  }

  if (!isCoveredByNSEC3Hash(DNSName(nextCloserHash) + zone, nextCloserEntry.d_owner, nextCloserEntry.d_next)) {
    LOG("No covering record found for the next closer in NSEC3 aggressive cache" << endl);
    return false;
  }

  auto nextCloserNsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(nextCloserEntry.d_record);
  if (!nextCloserNsec3 || nextCloserNsec3->d_iterations != iterations || nextCloserNsec3->d_salt != salt) {
    LOG("The NSEC3 covering the next closer is not valid, or has a different salt or iterations count, bailing out" << endl);
    return false;
  }

  DNSName wildcard(g_wildcarddnsname + closestEncloser);
  auto wcHash = toBase32Hex(hashQNameWithSalt(salt, iterations, wildcard));
  LOG("Looking for a NSEC3 covering the wildcard " << wildcard << " (" << wcHash << ")" << endl);

  ZoneEntry::CacheEntry wcEntry;
  if (!getNSECBefore(now, zoneEntry, DNSName(wcHash) + zone, wcEntry)) {
    LOG("Nothing found for the wildcard in NSEC3 aggressive cache" << endl);
    return false;
  }

  if ((DNSName(wcHash) + zone) == wcEntry.d_owner) {
    LOG("Found an exact match for the wildcard");

    auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(wcEntry.d_record);
    if (!nsec3 || nsec3->d_iterations != iterations || nsec3->d_salt != salt) {
      LOG(" but the content is not valid, or has a different salt or iterations count" << endl);
      return false;
    }

    if (!isTypeDenied(nsec3, type)) {
      LOG(" but the requested type (" << type.getName() << ") does exist" << endl);
      return synthesizeFromNSEC3Wildcard(now, name, type, ret, res, doDNSSEC, nextCloserEntry, wildcard);
    }

    res = RCode::NoError;
    LOG(endl);
  }
  else {
    if (!isCoveredByNSEC3Hash(DNSName(wcHash) + zone, wcEntry.d_owner, wcEntry.d_next)) {
      LOG("No covering record found for the wildcard in aggressive cache" << endl);
      return false;
    }

    auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(wcEntry.d_record);
    if (!nsec3 || nsec3->d_iterations != iterations || nsec3->d_salt != salt) {
      LOG("The content of the NSEC3 covering the wildcard is not valid, or has a different salt or iterations count" << endl);
      return false;
    }

    res = RCode::NXDomain;
  }

  addToRRSet(now, soaSet, soaSignatures, zone, doDNSSEC, ret);
  addRecordToRRSet(now, closestNSEC3.d_owner, QType::NSEC3, closestNSEC3.d_ttd - now, closestNSEC3.d_record, closestNSEC3.d_signatures, doDNSSEC, ret);
  addRecordToRRSet(now, nextCloserEntry.d_owner, QType::NSEC3, nextCloserEntry.d_ttd - now, nextCloserEntry.d_record, nextCloserEntry.d_signatures, doDNSSEC, ret);
  addRecordToRRSet(now, wcEntry.d_owner, QType::NSEC3, wcEntry.d_ttd - now, wcEntry.d_record, wcEntry.d_signatures, doDNSSEC, ret);

  LOG("Found valid NSEC3s covering the requested name and type!" << endl);
  ++d_nsec3Hits;
  return true;
}

bool AggressiveNSECCache::getDenial(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, const ComboAddress& who, const boost::optional<std::string>& routingTag, bool doDNSSEC)
{
  auto zoneEntry = getBestZone(name);
  if (!zoneEntry || zoneEntry->d_entries.empty()) {
    return false;
  }

  vState cachedState;
  std::vector<DNSRecord> soaSet;
  std::vector<std::shared_ptr<RRSIGRecordContent>> soaSignatures;
  /* we might not actually need the SOA if we find a matching wildcard, but let's not bother for now */
  if (g_recCache->get(now, zoneEntry->d_zone, QType::SOA, true, &soaSet, who, false, routingTag, doDNSSEC ? &soaSignatures : nullptr, nullptr, nullptr, &cachedState) <= 0 || cachedState != vState::Secure) {
    LOG("No valid SOA found for " << zoneEntry->d_zone << ", which is the best match for " << name << endl);
    return false;
  }

  if (zoneEntry->d_nsec3) {
    return getNSEC3Denial(now, zoneEntry, soaSet, soaSignatures, name, type, ret, res, doDNSSEC);
  }

  ZoneEntry::CacheEntry entry;
  ZoneEntry::CacheEntry wcEntry;
  bool covered = false;
  bool needWildcard = false;

  LOG("Looking for a NSEC before " << name);
  if (!getNSECBefore(now, zoneEntry, name, entry)) {
    LOG(": nothing found in the aggressive cache" << endl);
    return false;
  }

  auto content = std::dynamic_pointer_cast<NSECRecordContent>(entry.d_record);
  if (!content) {
    return false;
  }

  LOG(": found a possible NSEC at " << entry.d_owner << " ");
  auto denial = matchesNSEC(name, type.getCode(), entry.d_owner, content, entry.d_signatures);
  if (denial == dState::NODENIAL || denial == dState::INCONCLUSIVE) {
    LOG(" but it does no cover us" << endl);
    return false;
  }
  else if (denial == dState::NXQTYPE) {
    covered = true;
    LOG(" and it proves that the type does not exist" << endl);
    res = RCode::NoError;
  }
  else if (denial == dState::NXDOMAIN) {
    LOG(" and it proves that the name does not exist" << endl);
    DNSName closestEncloser = getClosestEncloserFromNSEC(name, entry.d_owner, entry.d_next);
    DNSName wc = g_wildcarddnsname + closestEncloser;

    LOG("Now looking for a NSEC before the wildcard " << wc);
    if (!getNSECBefore(now, zoneEntry, wc, wcEntry)) {
      LOG(": nothing found in the aggressive cache" << endl);
      return false;
    }

    LOG(": found a possible NSEC at " << wcEntry.d_owner << " ");

    auto nsecContent = std::dynamic_pointer_cast<NSECRecordContent>(wcEntry.d_record);

    denial = matchesNSEC(wc, type.getCode(), wcEntry.d_owner, nsecContent, wcEntry.d_signatures);
    if (denial == dState::NODENIAL || denial == dState::INCONCLUSIVE) {

      if (wcEntry.d_owner == wc) {
        LOG(" proving that the wildcard does exist" << endl);
        return synthesizeFromNSECWildcard(now, name, type, ret, res, doDNSSEC, entry, wc);
      }

      LOG(" but it does no cover us" << endl);

      return false;
    }
    else if (denial == dState::NXQTYPE) {
      LOG(" and it proves that there is a matching wildcard, but the type does not exist" << endl);
      covered = true;
      res = RCode::NoError;
    }
    else if (denial == dState::NXDOMAIN) {
      LOG(" and it proves that there is no matching wildcard" << endl);
      covered = true;
      res = RCode::NXDomain;
    }

    if (wcEntry.d_owner != wc && wcEntry.d_owner != entry.d_owner) {
      needWildcard = true;
    }
  }

  if (!covered) {
    return false;
  }

  ret.reserve(ret.size() + soaSet.size() + soaSignatures.size() + /* NSEC */ 1 + entry.d_signatures.size() + (needWildcard ? (/* NSEC */ 1 + wcEntry.d_signatures.size()) : 0));

  addToRRSet(now, soaSet, soaSignatures, zoneEntry->d_zone, doDNSSEC, ret);
  addRecordToRRSet(now, entry.d_owner, QType::NSEC, entry.d_ttd - now, entry.d_record, entry.d_signatures, doDNSSEC, ret);

  if (needWildcard) {
    addRecordToRRSet(now, wcEntry.d_owner, QType::NSEC, wcEntry.d_ttd - now, wcEntry.d_record, wcEntry.d_signatures, doDNSSEC, ret);
  }

  LOG("Found valid NSECs covering the requested name and type!" << endl);
  ++d_nsecHits;
  return true;
}

size_t AggressiveNSECCache::dumpToFile(std::unique_ptr<FILE, int (*)(FILE*)>& fp, const struct timeval& now)
{
  size_t ret = 0;

  ReadLock rl(d_lock);
  d_zones.visit([&ret, now, &fp](const SuffixMatchTree<std::shared_ptr<ZoneEntry>>& node) {
    if (!node.d_value) {
      return;
    }

    std::lock_guard<std::mutex> lock(node.d_value->d_lock);
    fprintf(fp.get(), "; Zone %s\n", node.d_value->d_zone.toString().c_str());

    for (const auto& entry : node.d_value->d_entries) {
      int64_t ttl = entry.d_ttd - now.tv_sec;
      try {
        fprintf(fp.get(), "%s %" PRId64 " IN %s %s\n", entry.d_owner.toString().c_str(), ttl, node.d_value->d_nsec3 ? "NSEC3" : "NSEC", entry.d_record->getZoneRepresentation().c_str());
        for (const auto& signature : entry.d_signatures) {
          fprintf(fp.get(), "- RRSIG %s\n", signature->getZoneRepresentation().c_str());
        }
        ++ret;
      }
      catch (const std::exception& e) {
        fprintf(fp.get(), "; Error dumping record from zone %s: %s\n", node.d_value->d_zone.toString().c_str(), e.what());
      }
      catch (...) {
        fprintf(fp.get(), "; Error dumping record from zone %s\n", node.d_value->d_zone.toString().c_str());
      }
    }
  });

  return ret;
}
