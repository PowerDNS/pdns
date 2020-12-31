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

#include "aggressive_nsec.hh"
#include "cachecleaner.hh"
#include "recursor_cache.hh"
#include "validate.hh"

std::unique_ptr<AggressiveNSECCache> g_aggressiveNSECCache{nullptr};

/* this is defined in syncres.hh and we are not importing that here */
extern std::unique_ptr<MemRecursorCache> g_recCache;

std::shared_ptr<AggressiveNSECCache::ZoneEntry> AggressiveNSECCache::getBestZone(const DNSName& zone)
{
  std::shared_ptr<AggressiveNSECCache::ZoneEntry> entry{nullptr};
  {
    ReadLock rl(d_lock);
    auto got = d_zones.lookup(zone);
    if (got) {
      return *got;
    }
  }
  return entry;
}

std::shared_ptr<AggressiveNSECCache::ZoneEntry> AggressiveNSECCache::getZone(const DNSName& zone)
{
  std::shared_ptr<AggressiveNSECCache::ZoneEntry> entry{nullptr};
  {
    ReadLock rl(d_lock);
    auto got = d_zones.lookup(zone);
    if (got && *got && (*got)->d_zone == zone) {
      return *got;
    }
  }

  entry = std::make_shared<ZoneEntry>();
  entry->d_zone = zone;

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

void AggressiveNSECCache::insertNSEC(const DNSName& zone, const DNSName& owner, const DNSRecord& record, const std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures, bool nsec3)
{
  if (signatures.empty()) {
    return;
  }

  std::shared_ptr<AggressiveNSECCache::ZoneEntry> entry = getZone(zone);
  {
    std::lock_guard<std::mutex> lock(entry->d_lock);
    if (nsec3 && !entry->d_nsec3) {
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

#warning Ponder storing everything in raw form, without the zone instead. It still needs to be a DNSName for NSEC, though
      next = DNSName(toBase32Hex(content->d_nexthash)) + zone;
      entry->d_iterations = content->d_iterations;
      entry->d_salt = content->d_salt;
    }

    /* the TTL is already a TTD by now */
    if (!nsec3 && isWildcardExpanded(owner.countLabels(), signatures.at(0))) {
      DNSName realOwner = getNSECOwnerName(owner, signatures);
      entry->d_entries.insert({record.d_content, signatures, std::move(realOwner), std::move(next), record.d_ttl});
    }
    else {
      entry->d_entries.insert({record.d_content, signatures, owner, std::move(next), record.d_ttl});
    }
  }
}

bool AggressiveNSECCache::getNSECBefore(time_t now, std::shared_ptr<AggressiveNSECCache::ZoneEntry>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry) {

  std::lock_guard<std::mutex> lock(zoneEntry->d_lock);
  if (zoneEntry->d_entries.empty()) {
    return false;
  }

#if 1
  cerr<<"We have:"<<endl;
  for (const auto& ent : zoneEntry->d_entries) {
    cerr<<"- "<<ent.d_owner<<" -> "<<ent.d_next<<endl;
  }
  cerr<<"=> end of list, looking for the lower bound to "<<name<<endl;
#endif
  auto& idx = zoneEntry->d_entries.get<ZoneEntry::OrderedTag>();
  auto it = idx.lower_bound(name);
  bool end = false;
  bool wrapped = false;

  if (it == idx.begin() && it->d_owner != name) {
    //cerr<<"the lower bound is already the first entry, let's if the end is a wrap"<<endl;
    it = idx.end();
    // we know the map is not empty
    it--;
    // might be that owner > name && name < next
    // can't go further, but perhaps we wrapped?
    wrapped = true;
  }

  while (!end && !wrapped && (it == idx.end() || (it->d_owner != name && !it->d_owner.canonCompare(name))))
  {
    if (it == idx.begin()) {
      end = true;
      break;
    }
    else {
      it--;
      // cerr<<"looping with "<<it->d_owner<<endl;
    }
  }

  if (end) {
    //cerr<<"nothing left"<<endl;
    return false;
  }

  //cerr<<"considering "<<it->d_owner<<" "<<it->d_next<<endl;

  if (it->d_ttd <= now) {
    //cerr<<"not using it"<<endl;
    moveCacheItemToFront<ZoneEntry::SequencedTag>(zoneEntry->d_entries, it);
    return false;
  }

  entry = *it;
  moveCacheItemToBack<ZoneEntry::SequencedTag>(zoneEntry->d_entries, it);
  return true;
}

bool AggressiveNSECCache::getNSEC3(time_t now, std::shared_ptr<AggressiveNSECCache::ZoneEntry>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry) {

  std::lock_guard<std::mutex> lock(zoneEntry->d_lock);
  if (zoneEntry->d_entries.empty()) {
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

static void addToRRSet(const time_t now, std::vector<DNSRecord>& recordSet, std::vector<std::shared_ptr<RRSIGRecordContent>> signatures, const DNSName& owner, bool doDNSSEC, std::vector<DNSRecord>& ret)
{
  uint32_t ttl = 0;

  for (auto& record : recordSet) {
    if (record.d_class != QClass::IN) {
      continue;
    }

    record.d_ttl -= now;
    ttl = record.d_ttl;
    record.d_place = DNSResourceRecord::AUTHORITY;
    ret.push_back(std::move(record));
  }

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

bool AggressiveNSECCache::getNSEC3Denial(time_t now, std::shared_ptr<AggressiveNSECCache::ZoneEntry>& zoneEntry, std::vector<DNSRecord>& soaSet, std::vector<std::shared_ptr<RRSIGRecordContent>>& soaSignatures, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC)
{
  const auto& salt = zoneEntry->d_salt;
  const auto iterations = zoneEntry->d_iterations;
  const auto& zone = zoneEntry->d_zone;

  auto nameHash = DNSName(toBase32Hex(hashQNameWithSalt(salt, iterations, name))) + zone;

  cerr<<"looking for nsec3 "<<nameHash<<endl;
  ZoneEntry::CacheEntry exactNSEC3;
  if (getNSEC3(now, zoneEntry, nameHash, exactNSEC3)) {
    cerr<<"found direct match "<<nameHash<<endl;
    auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(exactNSEC3.d_record);
    if (!nsec3) {
      return false;
    }

    if (!isTypeDenied(nsec3, type)) {
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
      return false;
    }

    cerr<<"Direct match, done!"<<endl;
    res = RCode::NoError;
    addToRRSet(now, soaSet, soaSignatures, zoneEntry->d_zone, doDNSSEC, ret);
    addRecordToRRSet(now, exactNSEC3.d_owner, QType::NSEC3, exactNSEC3.d_ttd - now, exactNSEC3.d_record, exactNSEC3.d_signatures, doDNSSEC, ret);
    return true;
  }

  cerr<<"no direct match, looking for closest encloser"<<endl;
  DNSName closestEncloser(name);
  bool found = false;
  ZoneEntry::CacheEntry closestNSEC3;
  while (!found && closestEncloser.chopOff()) {
    auto closestHash = DNSName(toBase32Hex(hashQNameWithSalt(salt, iterations, closestEncloser))) + zone;
    cerr<<"looking for nsec3 "<<closestHash<<endl;

    if (getNSEC3(now, zoneEntry, closestHash, closestNSEC3)) {
      cerr<<"found next closest encloser at "<<closestEncloser<<endl;
      found = true;
      break;
    }
  }

  if (!found) {
    cerr<<"nothing found in aggressive cache either"<<endl;
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
  cerr<<"looking for a NSEC3 covering the next closer "<<nextCloser<<": "<<nextCloserHash<<endl;

  ZoneEntry::CacheEntry nextCloserEntry;
  if (!getNSECBefore(now, zoneEntry, DNSName(nextCloserHash) + zone, nextCloserEntry)) {
    cerr<<"nothing found for the next closer in aggressive cache"<<endl;
    return false;
  }

  if (!isCoveredByNSEC3Hash(DNSName(nextCloserHash) + zone, nextCloserEntry.d_owner, nextCloserEntry.d_next)) {
    cerr<<"no covering record found for the next closer in aggressive cache"<<endl;
    return false;
  }

  DNSName wildcard(g_wildcarddnsname + closestEncloser);
  auto wcHash = toBase32Hex(hashQNameWithSalt(salt, iterations, wildcard));
  cerr<<"looking for a NSEC3 covering the wildcard "<<wildcard<<": "<<wcHash<<endl;

  ZoneEntry::CacheEntry wcEntry;
  if (!getNSECBefore(now, zoneEntry, DNSName(wcHash) + zone, wcEntry)) {
    cerr<<"nothing found for the wildcard in aggressive cache"<<endl;
    return false;
  }

  if ((DNSName(wcHash) + zone) == wcEntry.d_owner) {
    auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(wcEntry.d_record);
    if (!nsec3) {
      return false;
    }

    if (!isTypeDenied(nsec3, type)) {
      return false;
    }

    res = RCode::NoError;
  }
  else {
    if (!isCoveredByNSEC3Hash(DNSName(wcHash) + zone, wcEntry.d_owner, wcEntry.d_next)) {
      cerr<<"no covering record found for the wildcard in aggressive cache"<<endl;
      return false;
    }
    res = RCode::NXDomain;
  }

  addToRRSet(now, soaSet, soaSignatures, zoneEntry->d_zone, doDNSSEC, ret);
  addRecordToRRSet(now, closestNSEC3.d_owner, QType::NSEC3, closestNSEC3.d_ttd - now, closestNSEC3.d_record, closestNSEC3.d_signatures, doDNSSEC, ret);
  addRecordToRRSet(now, nextCloserEntry.d_owner, QType::NSEC3, nextCloserEntry.d_ttd - now, nextCloserEntry.d_record, nextCloserEntry.d_signatures, doDNSSEC, ret);
  addRecordToRRSet(now, wcEntry.d_owner, QType::NSEC3, wcEntry.d_ttd - now, wcEntry.d_record, wcEntry.d_signatures, doDNSSEC, ret);

  cerr<<"Done!"<<endl;
  return true;
}

bool AggressiveNSECCache::getDenial(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, const ComboAddress& who, const boost::optional<std::string>& routingTag, bool doDNSSEC)
{
  auto zoneEntry = getBestZone(name);
  if (!zoneEntry) {
    cerr<<"zone info not found"<<endl;
    return false;
  }

  vState cachedState;
  std::vector<DNSRecord> soaSet;
  std::vector<std::shared_ptr<RRSIGRecordContent>> soaSignatures;
  if (g_recCache->get(now, zoneEntry->d_zone, QType::SOA, true, &soaSet, who, false, routingTag, doDNSSEC ? &soaSignatures : nullptr, nullptr, nullptr, &cachedState) <= 0 || cachedState != vState::Secure) {
    cerr<<"could not find SOA"<<endl;
    return false;
  }

  if (zoneEntry->d_nsec3) {
    cerr<<"nsec 3"<<endl;
    return getNSEC3Denial(now, zoneEntry, soaSet, soaSignatures, name, type, ret, res, doDNSSEC);
  }

  ZoneEntry::CacheEntry entry;
  ZoneEntry::CacheEntry wcEntry;
  bool covered = false;
  bool needWildcard = false;

  cerr<<"looking for nsec before "<<name<<endl;
  if (!getNSECBefore(now, zoneEntry, name, entry)) {
    cerr<<"nothing found in aggressive cache either"<<endl;
    return false;
  }

  auto content = std::dynamic_pointer_cast<NSECRecordContent>(entry.d_record);
  if (!content) {
    return false;
  }

  cerr<<"nsecFound "<<entry.d_owner<<endl;
  auto denial = matchesNSEC(name, type.getCode(), entry.d_owner, content, entry.d_signatures);
  if (denial == dState::NODENIAL || denial == dState::INCONCLUSIVE) {
    cerr<<"no dice"<<endl;
    return false;
  }
  else if (denial == dState::NXQTYPE) {
    covered = true;
    cerr<<"nx qtype"<<endl;
    res = RCode::NoError;
  }
  else if (denial == dState::NXDOMAIN) {
    const DNSName commonLabels = entry.d_owner.getCommonLabels(entry.d_next);
    DNSName wc(name);
    auto labelsCount = wc.countLabels();
    auto commonLabelsCount = commonLabels.countLabels();
    while (labelsCount > commonLabelsCount) {
      if (!wc.chopOff()) {
        break;
      }
      --labelsCount;
    }
    wc = g_wildcarddnsname + wc;

    cerr<<"looking for nsec before "<<wc<<endl;
    if (!getNSECBefore(now, zoneEntry, wc, wcEntry)) {
      cerr<<"nothing found in aggressive cache for Wildcard"<<endl;
      return false;
    }

    cerr<<"wc nsec found "<<wcEntry.d_owner<<endl;
    if (wcEntry.d_owner == entry.d_owner) {
      covered = true;
      res = RCode::NXDomain;
    }
    else {
      auto nsecContent = std::dynamic_pointer_cast<NSECRecordContent>(wcEntry.d_record);
      denial = matchesNSEC(wc, type.getCode(), wcEntry.d_owner, nsecContent, wcEntry.d_signatures);
      if (denial == dState::NODENIAL || denial == dState::INCONCLUSIVE) {
        /* too complicated for now */
        /* we would need:
           - to store wildcard entries in the non-expanded form in the record cache, in addition to their expanded form ;
           - do a lookup to retrieve them ;
           - expand them and the NSEC
        */
        return false;
      }
      else if (denial == dState::NXQTYPE) {
        covered = true;
        res = RCode::NoError;
      }
      else if (denial == dState::NXDOMAIN) {
        covered = true;
        res = RCode::NXDomain;
      }

      if (wcEntry.d_owner != wc) {
        needWildcard = true;
      }
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

  return true;
}
