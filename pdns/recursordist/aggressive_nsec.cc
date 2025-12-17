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
#include <climits>

#include "aggressive_nsec.hh"
#include "cachecleaner.hh"
#include "recursor_cache.hh"
#include "logger.hh"
#include "validate.hh"

std::unique_ptr<AggressiveNSECCache> g_aggressiveNSECCache{nullptr};
uint64_t AggressiveNSECCache::s_nsec3DenialProofMaxCost{0};
uint8_t AggressiveNSECCache::s_maxNSEC3CommonPrefix = AggressiveNSECCache::s_default_maxNSEC3CommonPrefix;

/* this is defined in syncres.hh and we are not importing that here */
extern std::unique_ptr<MemRecursorCache> g_recCache;

std::shared_ptr<LockGuarded<AggressiveNSECCache::ZoneEntry>> AggressiveNSECCache::getBestZone(const DNSName& zone)
{
  std::shared_ptr<LockGuarded<AggressiveNSECCache::ZoneEntry>> entry{nullptr};
  {
    auto zones = d_zones.try_read_lock();
    if (!zones.owns_lock()) {
      return entry;
    }

    auto got = zones->lookup(zone);
    if (got) {
      return *got;
    }
  }
  return entry;
}

std::shared_ptr<LockGuarded<AggressiveNSECCache::ZoneEntry>> AggressiveNSECCache::getZone(const DNSName& zone)
{
  {
    auto zones = d_zones.read_lock();
    auto got = zones->lookup(zone);
    if (got && *got) {
      auto locked = (*got)->lock();
      if (locked->d_zone == zone) {
        return *got;
      }
    }
  }

  auto entry = std::make_shared<LockGuarded<ZoneEntry>>(zone);

  {
    auto zones = d_zones.write_lock();
    /* it might have been inserted in the mean time */
    auto got = zones->lookup(zone);
    if (got && *got) {
      auto locked = (*got)->lock();
      if (locked->d_zone == zone) {
        return *got;
      }
    }
    zones->add(zone, std::shared_ptr<LockGuarded<ZoneEntry>>(entry));
    return entry;
  }
}

void AggressiveNSECCache::updateEntriesCount(SuffixMatchTree<std::shared_ptr<LockGuarded<ZoneEntry>>>& zones)
{
  uint64_t counter = 0;
  zones.visit([&counter](const SuffixMatchTree<std::shared_ptr<LockGuarded<ZoneEntry>>>& node) {
    if (node.d_value) {
      counter += node.d_value->lock()->d_entries.size();
    }
  });
  d_entriesCount = counter;
}

void AggressiveNSECCache::removeZoneInfo(const DNSName& zone, bool subzones)
{
  auto zones = d_zones.write_lock();

  if (subzones) {
    zones->remove(zone, true);
    updateEntriesCount(*zones);
  }
  else {
    auto got = zones->lookup(zone);
    if (!got || !*got) {
      return;
    }

    /* let's increase the ref count of the shared pointer
       so we get the lock, remove the zone from the tree,
       then release the lock before the entry is deleted */
    auto entry = *got;
    {
      auto locked = (*got)->lock();
      if (locked->d_zone != zone) {
        return;
      }
      auto removed = locked->d_entries.size();
      zones->remove(zone, false);
      d_entriesCount -= removed;
    }
  }
}

void AggressiveNSECCache::prune(time_t now)
{
  uint64_t maxNumberOfEntries = d_maxEntries;
  std::vector<DNSName> emptyEntries;
  uint64_t erased = 0;

  auto zones = d_zones.write_lock();
  // To start, just look through 10% of each zone and nuke everything that is expired
  zones->visit([now, &erased, &emptyEntries](const SuffixMatchTree<std::shared_ptr<LockGuarded<ZoneEntry>>>& node) {
    if (!node.d_value) {
      return;
    }

    auto zoneEntry = node.d_value->lock();
    auto& sidx = boost::multi_index::get<ZoneEntry::SequencedTag>(zoneEntry->d_entries);
    const auto toLookAtForThisZone = (zoneEntry->d_entries.size() + 9) / 10;
    uint64_t lookedAt = 0;
    for (auto it = sidx.begin(); it != sidx.end() && lookedAt < toLookAtForThisZone; ++lookedAt) {
      if (it->d_ttd <= now) {
        it = sidx.erase(it);
        ++erased;
      }
      else {
        ++it;
      }
    }

    if (zoneEntry->d_entries.empty()) {
      emptyEntries.push_back(zoneEntry->d_zone);
    }
  });

  d_entriesCount -= erased;

  // If we are still above try harder by nuking entries from each zone in LRU order
  auto entriesCount = d_entriesCount.load();
  if (entriesCount > maxNumberOfEntries) {
    erased = 0;
    uint64_t toErase = entriesCount - maxNumberOfEntries;
    zones->visit([&erased, &toErase, &entriesCount, &emptyEntries](const SuffixMatchTree<std::shared_ptr<LockGuarded<ZoneEntry>>>& node) {
      if (!node.d_value || entriesCount == 0) {
        return;
      }
      auto zoneEntry = node.d_value->lock();
      const auto zoneSize = zoneEntry->d_entries.size();
      auto& sidx = boost::multi_index::get<ZoneEntry::SequencedTag>(zoneEntry->d_entries);
      const auto toTrimForThisZone = static_cast<uint64_t>(std::round(static_cast<double>(toErase) * static_cast<double>(zoneSize) / static_cast<double>(entriesCount)));
      if (entriesCount < zoneSize) {
        throw std::runtime_error("Inconsistent aggressive cache " + std::to_string(entriesCount) + " " + std::to_string(zoneSize));
      }
      // This is comparable to what cachecleaner.hh::pruneMutexCollectionsVector() is doing, look there for an explanation
      entriesCount -= zoneSize;
      uint64_t trimmedFromThisZone = 0;
      for (auto it = sidx.begin(); it != sidx.end() && trimmedFromThisZone < toTrimForThisZone;) {
        it = sidx.erase(it);
        ++erased;
        ++trimmedFromThisZone;
        if (--toErase == 0) {
          break;
        }
      }
      if (zoneEntry->d_entries.empty()) {
        emptyEntries.push_back(zoneEntry->d_zone);
      }
    });

    d_entriesCount -= erased;
  }

  if (!emptyEntries.empty()) {
    for (const auto& entry : emptyEntries) {
      zones->remove(entry);
    }
  }
}

static bool isMinimallyCoveringNSEC(const DNSName& owner, const std::shared_ptr<const NSECRecordContent>& nsec)
{
  /* this test only covers Cloudflare's ones (https://blog.cloudflare.com/black-lies/),
     we might need to cover more cases described in rfc4470 as well, but the name generation algorithm
     is not clearly defined there */
  const auto& storage = owner.getStorage();
  const auto& nextStorage = nsec->d_next.getStorage();

  // is the next name at least two octets long?
  if (nextStorage.size() <= 2 || storage.size() != (nextStorage.size() - 2)) {
    return false;
  }

  // does the next name start with a one-octet long label containing a zero, i.e. `\000`?
  if (nextStorage.at(0) != 1 || static_cast<uint8_t>(nextStorage.at(1)) != static_cast<uint8_t>(0)) {
    return false;
  }

  // is the rest of the next name identical to the owner name, i.e. is the next name the owner name prefixed by '\000.'?
  if (nextStorage.compare(2, nextStorage.size() - 2, storage) != 0) {
    return false;
  }

  return true;
}

static bool commonPrefixIsLong(const string& one, const string& two, size_t bound)
{
  size_t length = 0;
  const auto minLength = std::min(one.length(), two.length());

  for (size_t i = 0; i < minLength; i++) {
    const auto byte1 = one.at(i);
    const auto byte2 = two.at(i);
    // shortcut
    if (byte1 == byte2) {
      length += CHAR_BIT;
      if (length > bound) {
        return true;
      }
      continue;
    }
    // bytes differ, let's look at the bits
    for (ssize_t j = CHAR_BIT - 1; j >= 0; j--) {
      const auto bit1 = byte1 & (1 << j);
      const auto bit2 = byte2 & (1 << j);
      if (bit1 != bit2) {
        return length > bound;
      }
      length++;
      if (length > bound) {
        return true;
      }
    }
  }
  return length > bound;
}

// If the NSEC3 hashes have a long common prefix, they deny only a small subset of all possible hashes
// So don't take the trouble to store those.
bool AggressiveNSECCache::isSmallCoveringNSEC3(const DNSName& owner, const std::string& nextHash)
{
  std::string ownerHash(fromBase32Hex(owner.getRawLabel(0)));
  // Special case: empty zone, so the single NSEC3 covers everything. Prefix is long but we still want it cached.
  if (ownerHash == nextHash) {
    return false;
  }
  return commonPrefixIsLong(ownerHash, nextHash, AggressiveNSECCache::s_maxNSEC3CommonPrefix);
}

void AggressiveNSECCache::insertNSEC(const DNSName& zone, const DNSName& owner, const DNSRecord& record, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, bool nsec3, const DNSName& qname, QType qtype)
{
  if (nsec3 && nsec3Disabled()) {
    return;
  }
  if (signatures.empty()) {
    return;
  }

  std::shared_ptr<LockGuarded<AggressiveNSECCache::ZoneEntry>> entry = getZone(zone);
  {
    auto zoneEntry = entry->lock();
    if (nsec3 && !zoneEntry->d_nsec3) {
      d_entriesCount -= zoneEntry->d_entries.size();
      zoneEntry->d_entries.clear();
      zoneEntry->d_nsec3 = true;
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

      if (isSmallCoveringNSEC3(owner, content->d_nexthash)) {
        /* not accepting small covering answers since they only deny a small subset */
        return;
      }

      // XXX: Ponder storing everything in raw form, without the zone instead. It still needs to be a DNSName for NSEC, though,
      // but doing the conversion on cache hits only might be faster
      next = DNSName(toBase32Hex(content->d_nexthash)) + zone;

      if (zoneEntry->d_iterations != content->d_iterations || zoneEntry->d_salt != content->d_salt) {
        zoneEntry->d_iterations = content->d_iterations;
        zoneEntry->d_salt = content->d_salt;

        // Clearing the existing entries since we can't use them, and it's likely a rollover
        // If it instead is different servers using different parameters, well, too bad.
        d_entriesCount -= zoneEntry->d_entries.size();
        zoneEntry->d_entries.clear();
      }
    }

    /* the TTL is already a TTD by now */
    if (!nsec3 && isWildcardExpanded(owner.countLabels(), *signatures.at(0))) {
      DNSName realOwner = getNSECOwnerName(owner, signatures);
      auto pair = zoneEntry->d_entries.insert({record.getContent(), signatures, realOwner, next, qname, record.d_ttl, qtype});
      if (pair.second) {
        ++d_entriesCount;
      }
      else {
        zoneEntry->d_entries.replace(pair.first, {record.getContent(), signatures, std::move(realOwner), std::move(next), qname, record.d_ttl, qtype});
      }
    }
    else {
      auto pair = zoneEntry->d_entries.insert({record.getContent(), signatures, owner, next, qname, record.d_ttl, qtype});
      if (pair.second) {
        ++d_entriesCount;
      }
      else {
        zoneEntry->d_entries.replace(pair.first, {record.getContent(), signatures, owner, std::move(next), qname, record.d_ttl, qtype});
      }
    }
  }
}

bool AggressiveNSECCache::getNSECBefore(time_t now, std::shared_ptr<LockGuarded<AggressiveNSECCache::ZoneEntry>>& zone, const DNSName& name, ZoneEntry::CacheEntry& entry)
{
  auto zoneEntry = zone->try_lock();
  if (!zoneEntry.owns_lock() || zoneEntry->d_entries.empty()) {
    return false;
  }

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

  auto firstIndexIterator = zoneEntry->d_entries.project<ZoneEntry::OrderedTag>(it);
  if (it->d_ttd <= now) {
    moveCacheItemToFront<ZoneEntry::SequencedTag>(zoneEntry->d_entries, firstIndexIterator);
    return false;
  }

  entry = *it;
  moveCacheItemToBack<ZoneEntry::SequencedTag>(zoneEntry->d_entries, firstIndexIterator);
  return true;
}

bool AggressiveNSECCache::getNSEC3(time_t now, std::shared_ptr<LockGuarded<AggressiveNSECCache::ZoneEntry>>& zone, const DNSName& name, ZoneEntry::CacheEntry& entry)
{
  auto zoneEntry = zone->try_lock();
  if (!zoneEntry.owns_lock() || zoneEntry->d_entries.empty()) {
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
      moveCacheItemToFront<ZoneEntry::SequencedTag>(zoneEntry->d_entries, firstIndexIterator);
      return false;
    }

    entry = *it;
    moveCacheItemToBack<ZoneEntry::SequencedTag>(zoneEntry->d_entries, firstIndexIterator);
    return true;
  }

  return false;
}

static void addToRRSet(const time_t now, std::vector<DNSRecord>& recordSet, const MemRecursorCache::SigRecs& signatures, const DNSName& owner, bool doDNSSEC, std::vector<DNSRecord>& ret, DNSResourceRecord::Place place = DNSResourceRecord::AUTHORITY)
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
    for (const auto& signature : *signatures) {
      DNSRecord dr;
      dr.d_type = QType::RRSIG;
      dr.d_name = owner;
      dr.d_ttl = ttl;
      dr.setContent(signature);
      dr.d_place = place;
      dr.d_class = QClass::IN;
      ret.push_back(std::move(dr));
    }
  }
}

static void addRecordToRRSet(const DNSName& owner, const QType& type, uint32_t ttl, std::shared_ptr<const DNSRecordContent>& content, std::vector<std::shared_ptr<const RRSIGRecordContent>> signatures, bool doDNSSEC, std::vector<DNSRecord>& ret)
{
  DNSRecord nsecRec;
  nsecRec.d_type = type.getCode();
  nsecRec.d_name = owner;
  nsecRec.d_ttl = ttl;
  nsecRec.setContent(std::move(content));
  nsecRec.d_place = DNSResourceRecord::AUTHORITY;
  nsecRec.d_class = QClass::IN;
  ret.push_back(std::move(nsecRec));

  if (doDNSSEC) {
    for (auto& signature : signatures) {
      DNSRecord dr;
      dr.d_type = QType::RRSIG;
      dr.d_name = owner;
      dr.d_ttl = ttl;
      dr.setContent(std::move(signature));
      dr.d_place = DNSResourceRecord::AUTHORITY;
      dr.d_class = QClass::IN;
      ret.push_back(std::move(dr));
    }
  }
}

bool AggressiveNSECCache::synthesizeFromNSEC3Wildcard(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC, ZoneEntry::CacheEntry& nextCloser, const DNSName& wildcardName, const OptLog& log)
{
  vState cachedState;

  std::vector<DNSRecord> wcSet;
  MemRecursorCache::SigRecs wcSignatures = MemRecursorCache::s_emptySigRecs;

  if (g_recCache->get(now, wildcardName, type, MemRecursorCache::RequireAuth, &wcSet, ComboAddress("127.0.0.1"), boost::none, doDNSSEC ? &wcSignatures : nullptr, nullptr, nullptr, &cachedState) <= 0 || cachedState != vState::Secure) {
    VLOG(log, name << ": Unfortunately we don't have a valid entry for " << wildcardName << ", so we cannot synthesize from that wildcard" << endl);
    return false;
  }

  addToRRSet(now, wcSet, std::move(wcSignatures), name, doDNSSEC, ret, DNSResourceRecord::ANSWER);
  /* no need for closest encloser proof, the wildcard is there */
  // coverity[store_truncates_time_t]
  addRecordToRRSet(nextCloser.d_owner, QType::NSEC3, nextCloser.d_ttd - now, nextCloser.d_record, nextCloser.d_signatures, doDNSSEC, ret);
  /* and of course we won't deny the wildcard either */

  VLOG(log, name << ": Synthesized valid answer from NSEC3s and wildcard!" << endl);
  ++d_nsec3WildcardHits;
  res = RCode::NoError;
  return true;
}

bool AggressiveNSECCache::synthesizeFromNSECWildcard(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC, ZoneEntry::CacheEntry& nsec, const DNSName& wildcardName, const OptLog& log)
{
  vState cachedState;

  std::vector<DNSRecord> wcSet;
  MemRecursorCache::SigRecs wcSignatures = MemRecursorCache::s_emptySigRecs;

  if (g_recCache->get(now, wildcardName, type, MemRecursorCache::RequireAuth, &wcSet, ComboAddress("127.0.0.1"), boost::none, doDNSSEC ? &wcSignatures : nullptr, nullptr, nullptr, &cachedState) <= 0 || cachedState != vState::Secure) {
    VLOG(log, name << ": Unfortunately we don't have a valid entry for " << wildcardName << ", so we cannot synthesize from that wildcard" << endl);
    return false;
  }

  addToRRSet(now, wcSet, wcSignatures, name, doDNSSEC, ret, DNSResourceRecord::ANSWER);
  // coverity[store_truncates_time_t]
  addRecordToRRSet(nsec.d_owner, QType::NSEC, nsec.d_ttd - now, nsec.d_record, nsec.d_signatures, doDNSSEC, ret);

  VLOG(log, name << ": Synthesized valid answer from NSECs and wildcard!" << endl);
  ++d_nsecWildcardHits;
  res = RCode::NoError;
  return true;
}

bool AggressiveNSECCache::getNSEC3Denial(time_t now, std::shared_ptr<LockGuarded<AggressiveNSECCache::ZoneEntry>>& zoneEntry, std::vector<DNSRecord>& soaSet, const MemRecursorCache::SigRecs& soaSignatures, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC, const OptLog& log, pdns::validation::ValidationContext& validationContext)
{
  DNSName zone;
  std::string salt;
  uint16_t iterations;

  {
    auto entry = zoneEntry->try_lock();
    if (!entry.owns_lock()) {
      return false;
    }
    salt = entry->d_salt;
    zone = entry->d_zone;
    iterations = entry->d_iterations;
  }

  const auto zoneLabelsCount = zone.countLabels();
  if (s_nsec3DenialProofMaxCost != 0) {
    const auto worstCaseIterations = getNSEC3DenialProofWorstCaseIterationsCount(name.countLabels() - zoneLabelsCount, iterations, salt.length());
    if (worstCaseIterations > s_nsec3DenialProofMaxCost) {
      // skip NSEC3 aggressive cache for expensive NSEC3 parameters: "if you want us to take the pain of PRSD away from you, you need to make it cheap for us to do so"
      VLOG(log, name << ": Skipping aggressive use of the NSEC3 cache since the zone parameters are too expensive" << endl);
      return false;
    }
  }

  auto nameHash = DNSName(toBase32Hex(getHashFromNSEC3(name, iterations, salt, validationContext))) + zone;

  ZoneEntry::CacheEntry exactNSEC3;
  if (getNSEC3(now, zoneEntry, nameHash, exactNSEC3)) {
    VLOG(log, name << ": Found a direct NSEC3 match for " << nameHash << " inserted by " << exactNSEC3.d_qname << '/' << exactNSEC3.d_qtype);
    auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(exactNSEC3.d_record);
    if (!nsec3 || nsec3->d_iterations != iterations || nsec3->d_salt != salt) {
      VLOG_NO_PREFIX(log, " but the content is not valid, or has a different salt or iterations count" << endl);
      return false;
    }

    if (!isTypeDenied(*nsec3, type)) {
      VLOG_NO_PREFIX(log, " but the requested type (" << type.toString() << ") does exist" << endl);
      return false;
    }

    const DNSName signer = getSigner(exactNSEC3.d_signatures);
    /* here we need to allow an ancestor NSEC3 proving that a DS does not exist as it is an
       exact match for the name */
    if (type != QType::DS && isNSEC3AncestorDelegation(signer, exactNSEC3.d_owner, *nsec3)) {
      /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
         Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
         nonexistence of any RRs below that zone cut, which include all RRs at
         that (original) owner name other than DS RRs, and all RRs below that
         owner name regardless of type.
      */
      VLOG_NO_PREFIX(log, " but this is an ancestor delegation NSEC3" << endl);
      return false;
    }

    if (type == QType::DS && !name.isRoot() && signer == name) {
      VLOG_NO_PREFIX(log, " but this NSEC3 comes from the child zone and cannot be used to deny a DS");
      return false;
    }

    VLOG_NO_PREFIX(log, ": done!" << endl);
    ++d_nsec3Hits;
    res = RCode::NoError;
    addToRRSet(now, soaSet, soaSignatures, zone, doDNSSEC, ret);
    addRecordToRRSet(exactNSEC3.d_owner, QType::NSEC3, exactNSEC3.d_ttd - now, exactNSEC3.d_record, exactNSEC3.d_signatures, doDNSSEC, ret);
    return true;
  }

  VLOG(log, name << ": No direct NSEC3 match found for " << nameHash << ", looking for closest encloser" << endl);
  DNSName closestEncloser(name);
  bool found = false;
  ZoneEntry::CacheEntry closestNSEC3;
  auto remainingLabels = closestEncloser.countLabels() - 1;
  while (!found && closestEncloser.chopOff() && remainingLabels >= zoneLabelsCount) {
    auto closestHash = DNSName(toBase32Hex(getHashFromNSEC3(closestEncloser, iterations, salt, validationContext))) + zone;
    remainingLabels--;

    if (getNSEC3(now, zoneEntry, closestHash, closestNSEC3)) {
      VLOG(log, name << ": Found closest encloser at " << closestEncloser << " (" << closestHash << ") inserted by " << closestNSEC3.d_qname << '/' << closestNSEC3.d_qtype << endl);

      auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(closestNSEC3.d_record);
      if (!nsec3 || nsec3->d_iterations != iterations || nsec3->d_salt != salt) {
        VLOG_NO_PREFIX(log, " but the content is not valid, or has a different salt or iterations count" << endl);
        break;
      }

      const DNSName signer = getSigner(closestNSEC3.d_signatures);
      /* This time we do not allow any ancestor NSEC3, as if the closest encloser is a delegation
         NS we know nothing about the names in the child zone. */
      if (isNSEC3AncestorDelegation(signer, closestNSEC3.d_owner, *nsec3)) {
        /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
           Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
           nonexistence of any RRs below that zone cut, which include all RRs at
           that (original) owner name other than DS RRs, and all RRs below that
           owner name regardless of type.
        */
        VLOG_NO_PREFIX(log, " but this is an ancestor delegation NSEC3" << endl);
        break;
      }

      if (type == QType::DS && !name.isRoot() && signer == name) {
        VLOG_NO_PREFIX(log, " but this NSEC3 comes from the child zone and cannot be used to deny a DS");
        return false;
      }

      found = true;
      break;
    }
  }

  if (!found) {
    VLOG(log, name << ": Nothing found for the closest encloser in NSEC3 aggressive cache either" << endl);
    return false;
  }

  unsigned int labelIdx = name.countLabels() - closestEncloser.countLabels();
  if (labelIdx < 1) {
    return false;
  }

  DNSName nsecFound;
  DNSName nextCloser(closestEncloser);
  nextCloser.prependRawLabel(name.getRawLabel(labelIdx - 1));
  auto nextCloserHash = toBase32Hex(getHashFromNSEC3(nextCloser, iterations, salt, validationContext));
  VLOG(log, name << ": Looking for a NSEC3 covering the next closer " << nextCloser << " (" << nextCloserHash << ")" << endl);

  ZoneEntry::CacheEntry nextCloserEntry;
  if (!getNSECBefore(now, zoneEntry, DNSName(nextCloserHash) + zone, nextCloserEntry)) {
    VLOG(log, name << ": Nothing found for the next closer in NSEC3 aggressive cache" << endl);
    return false;
  }

  if (!isCoveredByNSEC3Hash(DNSName(nextCloserHash) + zone, nextCloserEntry.d_owner, nextCloserEntry.d_next)) {
    VLOG(log, name << ": No covering record found for the next closer in NSEC3 aggressive cache" << endl);
    return false;
  }

  auto nextCloserNsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(nextCloserEntry.d_record);
  if (!nextCloserNsec3 || nextCloserNsec3->d_iterations != iterations || nextCloserNsec3->d_salt != salt) {
    VLOG(log, name << ": The NSEC3 covering the next closer is not valid, or has a different salt or iterations count, bailing out" << endl);
    return false;
  }

  const DNSName nextCloserSigner = getSigner(nextCloserEntry.d_signatures);
  if (type == QType::DS && !name.isRoot() && nextCloserSigner == name) {
    VLOG(log, " but this NSEC3 comes from the child zone and cannot be used to deny a DS");
    return false;
  }

  /* An ancestor NSEC3 would be fine here, since it does prove that there is no delegation at the next closer
     name (we don't insert opt-out NSEC3s into the cache). */
  DNSName wildcard(g_wildcarddnsname + closestEncloser);
  auto wcHash = toBase32Hex(getHashFromNSEC3(wildcard, iterations, salt, validationContext));
  VLOG(log, name << ": Looking for a NSEC3 covering the wildcard " << wildcard << " (" << wcHash << ")" << endl);

  ZoneEntry::CacheEntry wcEntry;
  if (!getNSECBefore(now, zoneEntry, DNSName(wcHash) + zone, wcEntry)) {
    VLOG(log, name << ": Nothing found for the wildcard in NSEC3 aggressive cache" << endl);
    return false;
  }

  if ((DNSName(wcHash) + zone) == wcEntry.d_owner) {
    VLOG(log, name << ": Found an exact match for the wildcard");

    auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(wcEntry.d_record);
    if (!nsec3 || nsec3->d_iterations != iterations || nsec3->d_salt != salt) {
      VLOG_NO_PREFIX(log, " but the content is not valid, or has a different salt or iterations count" << endl);
      return false;
    }

    const DNSName wcSigner = getSigner(wcEntry.d_signatures);
    /* It's an exact match for the wildcard, so it does exist. If we are looking for a DS
       an ancestor NSEC3 is fine, otherwise it does not prove anything. */
    if (type != QType::DS && isNSEC3AncestorDelegation(wcSigner, wcEntry.d_owner, *nsec3)) {
      /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
         Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
         nonexistence of any RRs below that zone cut, which include all RRs at
         that (original) owner name other than DS RRs, and all RRs below that
         owner name regardless of type.
      */
      VLOG_NO_PREFIX(log, " but the NSEC3 covering the wildcard is an ancestor delegation NSEC3, bailing out" << endl);
      return false;
    }

    if (type == QType::DS && !name.isRoot() && wcSigner == name) {
      VLOG_NO_PREFIX(log, " but this wildcard NSEC3 comes from the child zone and cannot be used to deny a DS");
      return false;
    }

    if (!isTypeDenied(*nsec3, type)) {
      VLOG_NO_PREFIX(log, " but the requested type (" << type.toString() << ") does exist" << endl);
      return synthesizeFromNSEC3Wildcard(now, name, type, ret, res, doDNSSEC, nextCloserEntry, wildcard, log);
    }

    res = RCode::NoError;
    VLOG(log, endl);
  }
  else {
    if (!isCoveredByNSEC3Hash(DNSName(wcHash) + zone, wcEntry.d_owner, wcEntry.d_next)) {
      VLOG(log, name << ": No covering record found for the wildcard in aggressive cache" << endl);
      return false;
    }

    auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(wcEntry.d_record);
    if (!nsec3 || nsec3->d_iterations != iterations || nsec3->d_salt != salt) {
      VLOG(log, name << ": The content of the NSEC3 covering the wildcard is not valid, or has a different salt or iterations count" << endl);
      return false;
    }

    const DNSName wcSigner = getSigner(wcEntry.d_signatures);
    if (type == QType::DS && !name.isRoot() && wcSigner == name) {
      VLOG_NO_PREFIX(log, " but this wildcard NSEC3 comes from the child zone and cannot be used to deny a DS");
      return false;
    }

    /* We have a NSEC3 proving that the wildcard does not exist. An ancestor NSEC3 would be fine here, since it does prove
       that there is no delegation at the wildcard name (we don't insert opt-out NSEC3s into the cache). */
    res = RCode::NXDomain;
  }

  addToRRSet(now, soaSet, soaSignatures, zone, doDNSSEC, ret);
  addRecordToRRSet(closestNSEC3.d_owner, QType::NSEC3, closestNSEC3.d_ttd - now, closestNSEC3.d_record, closestNSEC3.d_signatures, doDNSSEC, ret);

  /* no need to include the same NSEC3 twice */
  if (nextCloserEntry.d_owner != closestNSEC3.d_owner) {
    addRecordToRRSet(nextCloserEntry.d_owner, QType::NSEC3, nextCloserEntry.d_ttd - now, nextCloserEntry.d_record, nextCloserEntry.d_signatures, doDNSSEC, ret);
  }
  if (wcEntry.d_owner != closestNSEC3.d_owner && wcEntry.d_owner != nextCloserEntry.d_owner) {
    // coverity[store_truncates_time_t]
    addRecordToRRSet(wcEntry.d_owner, QType::NSEC3, wcEntry.d_ttd - now, wcEntry.d_record, wcEntry.d_signatures, doDNSSEC, ret);
  }

  VLOG(log, name << ": Found valid NSEC3s covering the requested name and type!" << endl);
  ++d_nsec3Hits;
  return true;
}

bool AggressiveNSECCache::getDenial(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, const ComboAddress& who, const boost::optional<std::string>& routingTag, bool doDNSSEC, pdns::validation::ValidationContext& validationContext, const OptLog& log)
{
  std::shared_ptr<LockGuarded<ZoneEntry>> zoneEntry;
  if (type == QType::DS) {
    DNSName parent(name);
    parent.chopOff();
    zoneEntry = getBestZone(parent);
  }
  else {
    zoneEntry = getBestZone(name);
  }

  if (!zoneEntry) {
    return false;
  }

  DNSName zone;
  bool nsec3;
  {
    auto entry = zoneEntry->try_lock();
    if (!entry.owns_lock()) {
      return false;
    }
    if (entry->d_entries.empty()) {
      return false;
    }
    zone = entry->d_zone;
    nsec3 = entry->d_nsec3;
  }

  vState cachedState;
  std::vector<DNSRecord> soaSet;
  MemRecursorCache::SigRecs soaSignatures = MemRecursorCache::s_emptySigRecs;
  /* we might not actually need the SOA if we find a matching wildcard, but let's not bother for now */
  if (g_recCache->get(now, zone, QType::SOA, MemRecursorCache::RequireAuth, &soaSet, who, routingTag, doDNSSEC ? &soaSignatures : nullptr, nullptr, nullptr, &cachedState) <= 0 || cachedState != vState::Secure) {
    VLOG(log, name << ": No valid SOA found for " << zone << ", which is the best match for " << name << endl);
    return false;
  }

  if (nsec3) {
    return getNSEC3Denial(now, zoneEntry, soaSet, soaSignatures, name, type, ret, res, doDNSSEC, log, validationContext);
  }

  ZoneEntry::CacheEntry entry;
  ZoneEntry::CacheEntry wcEntry;
  bool covered = false;
  bool needWildcard = false;

  VLOG(log, name << ": Looking for a NSEC before " << name);
  if (!getNSECBefore(now, zoneEntry, name, entry)) {
    VLOG_NO_PREFIX(log, ": nothing found in the aggressive cache" << endl);
    return false;
  }

  auto content = std::dynamic_pointer_cast<const NSECRecordContent>(entry.d_record);
  if (!content) {
    return false;
  }

  VLOG_NO_PREFIX(log, ": found a possible NSEC at " << entry.d_owner << " inserted by " << entry.d_qname << '/' << entry.d_qtype << ' ');
  // note that matchesNSEC() takes care of ruling out ancestor NSECs for us
  auto denial = matchesNSEC(name, type.getCode(), entry.d_owner, *content, entry.d_signatures, log);
  if (denial == dState::NODENIAL || denial == dState::INCONCLUSIVE) {
    VLOG_NO_PREFIX(log, " but it does not cover us" << endl);
    return false;
  }
  else if (denial == dState::NXQTYPE) {
    covered = true;
    VLOG_NO_PREFIX(log, " and it proves that the type does not exist" << endl);
    res = RCode::NoError;
  }
  else if (denial == dState::NXDOMAIN) {
    VLOG_NO_PREFIX(log, " and it proves that the name does not exist" << endl);
    DNSName closestEncloser = getClosestEncloserFromNSEC(name, entry.d_owner, entry.d_next);
    DNSName wc = g_wildcarddnsname + closestEncloser;

    VLOG(log, name << ": Now looking for a NSEC before the wildcard " << wc);
    if (!getNSECBefore(now, zoneEntry, wc, wcEntry)) {
      VLOG_NO_PREFIX(log, ": nothing found in the aggressive cache" << endl);
      return false;
    }

    VLOG_NO_PREFIX(log, ": found a possible NSEC at " << wcEntry.d_owner << " ");

    auto nsecContent = std::dynamic_pointer_cast<const NSECRecordContent>(wcEntry.d_record);

    denial = matchesNSEC(wc, type.getCode(), wcEntry.d_owner, *nsecContent, wcEntry.d_signatures, log);
    if (denial == dState::NODENIAL || denial == dState::INCONCLUSIVE) {

      if (wcEntry.d_owner == wc) {
        VLOG_NO_PREFIX(log, " proving that the wildcard does exist" << endl);
        return synthesizeFromNSECWildcard(now, name, type, ret, res, doDNSSEC, entry, wc, log);
      }

      VLOG_NO_PREFIX(log, " but it does no cover us" << endl);

      return false;
    }
    else if (denial == dState::NXQTYPE) {
      VLOG_NO_PREFIX(log, " and it proves that there is a matching wildcard, but the type does not exist" << endl);
      covered = true;
      res = RCode::NoError;
    }
    else if (denial == dState::NXDOMAIN) {
      VLOG_NO_PREFIX(log, " and it proves that there is no matching wildcard" << endl);
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

  ret.reserve(ret.size() + soaSet.size() + soaSignatures->size() + /* NSEC */ 1 + entry.d_signatures.size() + (needWildcard ? (/* NSEC */ 1 + wcEntry.d_signatures.size()) : 0));

  addToRRSet(now, soaSet, soaSignatures, zone, doDNSSEC, ret);
  // coverity[store_truncates_time_t]
  addRecordToRRSet(entry.d_owner, QType::NSEC, entry.d_ttd - now, entry.d_record, entry.d_signatures, doDNSSEC, ret);

  if (needWildcard) {
    // coverity[store_truncates_time_t]
    addRecordToRRSet(wcEntry.d_owner, QType::NSEC, wcEntry.d_ttd - now, wcEntry.d_record, wcEntry.d_signatures, doDNSSEC, ret);
  }

  VLOG(log, name << ": Found valid NSECs covering the requested name and type!" << endl);
  ++d_nsecHits;
  return true;
}

size_t AggressiveNSECCache::dumpToFile(pdns::UniqueFilePtr& filePtr, const struct timeval& now)
{
  size_t ret = 0;

  auto zones = d_zones.read_lock();
  zones->visit([&ret, now, &filePtr](const SuffixMatchTree<std::shared_ptr<LockGuarded<ZoneEntry>>>& node) {
    if (!node.d_value) {
      return;
    }

    auto zone = node.d_value->lock();
    fprintf(filePtr.get(), "; Zone %s\n", zone->d_zone.toString().c_str());

    for (const auto& entry : zone->d_entries) {
      int64_t ttl = entry.d_ttd - now.tv_sec;
      try {
        fprintf(filePtr.get(), "%s %" PRId64 " IN %s %s by %s/%s\n", entry.d_owner.toString().c_str(), ttl, zone->d_nsec3 ? "NSEC3" : "NSEC", entry.d_record->getZoneRepresentation().c_str(), entry.d_qname.toString().c_str(), entry.d_qtype.toString().c_str());
        for (const auto& signature : entry.d_signatures) {
          fprintf(filePtr.get(), "- RRSIG %s\n", signature->getZoneRepresentation().c_str());
        }
        ++ret;
      }
      catch (const std::exception& e) {
        fprintf(filePtr.get(), "; Error dumping record from zone %s: %s\n", zone->d_zone.toString().c_str(), e.what());
      }
      catch (...) {
        fprintf(filePtr.get(), "; Error dumping record from zone %s\n", zone->d_zone.toString().c_str());
      }
    }
  });

  return ret;
}
