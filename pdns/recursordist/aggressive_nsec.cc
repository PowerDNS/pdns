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
    }
    else {
      auto content = getRR<NSEC3RecordContent>(record);
      if (!content) {
        throw std::runtime_error("Error getting the content from a NSEC3 record");
      }
      next = DNSName(content->d_nexthash) + zone;
      entry->d_iterations = content->d_iterations;
      entry->d_salt = content->d_salt;
    }

    /* the TTL is already a TTD by now */
    entry->d_entries.insert({record.d_content, signatures, owner, std::move(next), record.d_ttl});
  }
}

bool AggressiveNSECCache::getNSECBefore(time_t now, std::shared_ptr<AggressiveNSECCache::ZoneEntry>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry) {

  std::lock_guard<std::mutex> lock(zoneEntry->d_lock);
  if (zoneEntry->d_entries.empty()) {
    return false;
  }

  auto& idx = zoneEntry->d_entries.get<ZoneEntry::OrderedTag>();
  auto it = idx.lower_bound(name);
  bool end = false;

  while (!end && (it == idx.end() || (it->d_owner != name && !it->d_owner.canonCompare(name))))
  {
    if (it == idx.end()) {
      cerr<<"GOT END"<<endl;
    }
    else {
      cerr<<"got "<<it->d_owner<<endl;
    }

    if (it == idx.begin()) {
      // can't go further, but perhaps we wrapped?
      it = idx.end();
      it--;
      if (!it->d_owner.canonCompare(name) && it->d_next.canonCompare(name)) {
        break;
      }
      end = true;
      break;
    }
    else {
      it--;
       cerr<<"looping with "<<it->d_owner<<endl;
    }
  }

  if (end) {
     cerr<<"nothing left"<<endl;
    return false;
  }

  cerr<<"considering "<<it->d_owner<<" "<<it->d_next<<endl;

  if (it->d_ttd <= now) {
     cerr<<"not using it"<<endl;
    return false;
  }

  entry = *it;
  return true;
}

bool AggressiveNSECCache::getDenial(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>&ret, int& res, const ComboAddress& who, const boost::optional<std::string>& routingTag, bool doDNSSEC)
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
    return false;
    //return doAggressiveNSEC3Cache(prefix, qname, qtype, zone, salt, iterations, ret, res, state);
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
  if (denial == dState::NXQTYPE) {
    covered = true;
    res = RCode::NoError;
  }
  else if (denial == dState::NXDOMAIN) {
    if (name.countLabels() > 1) {
      DNSName wc(name);
      wc.chopOff();
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
        if (wcEntry.d_owner == wc) {
#warning FIXME: if the wc does exist but the type does not, it is actually quite simple
          /* too complicated for now */
          return false;
        }
        else if (isCoveredByNSEC(wc, wcEntry.d_owner, wcEntry.d_next)) {
          cerr<<"next is "<<wcEntry.d_next<<endl;
          covered = true;
          res = RCode::NXDomain;
          needWildcard = true;
        }
      }
    }
  }

  if (!covered) {
    return false;
  }

  uint32_t ttl=0;

  ret.reserve(ret.size() + soaSet.size() + soaSignatures.size() + /* NSEC */ 1 + entry.d_signatures.size() + (needWildcard ? (/* NSEC */ 1 + wcEntry.d_signatures.size()) : 0));

  for (auto& record : soaSet) {
    if (record.d_class != QClass::IN) {
      continue;
    }

    record.d_ttl -= now;
    ttl = record.d_ttl;
    ret.push_back(std::move(record));
  }

  if (doDNSSEC) {
    for (auto& signature : soaSignatures) {
      DNSRecord dr;
      dr.d_type = QType::RRSIG;
      dr.d_name = zoneEntry->d_zone;
      dr.d_ttl = ttl;
      dr.d_content = std::move(signature);
      dr.d_place = DNSResourceRecord::AUTHORITY;
      dr.d_class = QClass::IN;
      ret.push_back(std::move(dr));
    }
  }

  DNSRecord nsecRec;
  nsecRec.d_type = QType::NSEC;
  nsecRec.d_name = entry.d_owner;
  nsecRec.d_ttl = entry.d_ttd - now;
  ttl = nsecRec.d_ttl;
  nsecRec.d_content = std::move(entry.d_record);
  nsecRec.d_place = DNSResourceRecord::AUTHORITY;
  nsecRec.d_class = QClass::IN;
  ret.push_back(std::move(nsecRec));

  if (doDNSSEC) {
    for (auto& signature : entry.d_signatures) {
      DNSRecord dr;
      dr.d_type = QType::RRSIG;
      dr.d_name = entry.d_owner;
      dr.d_ttl = ttl;
      dr.d_content = std::move(signature);
      dr.d_place = DNSResourceRecord::AUTHORITY;
      dr.d_class = QClass::IN;
      ret.push_back(std::move(dr));
    }
  }

  if (needWildcard) {
    DNSRecord wcNsecRec;
    wcNsecRec.d_type = QType::NSEC;
    wcNsecRec.d_name = wcEntry.d_owner;
    wcNsecRec.d_ttl = wcEntry.d_ttd - now;
    ttl = wcNsecRec.d_ttl;
    wcNsecRec.d_content = std::move(wcEntry.d_record);
    wcNsecRec.d_place = DNSResourceRecord::AUTHORITY;
    wcNsecRec.d_class = QClass::IN;
    ret.push_back(std::move(wcNsecRec));

    if (doDNSSEC) {
      for (auto& signature : wcEntry.d_signatures) {
        DNSRecord dr;
        dr.d_type = QType::RRSIG;
        dr.d_name = wcEntry.d_owner;
        dr.d_ttl = ttl;
        dr.d_content = std::move(signature);
        dr.d_place = DNSResourceRecord::AUTHORITY;
        dr.d_class = QClass::IN;
        ret.push_back(std::move(dr));
      }
    }
  }

  return true;
}

#if 0

bool SyncRes::doAggressiveNSEC3Cache(const std::string& prefix, const DNSName& qname, const QType& qtype, const DNSName& zone, const std::string& salt, uint16_t iterations, vector<DNSRecord>&ret, int& res, vState& state)
{
#warning FIXME: nsec3
  cerr<<"nsec3, sorry"<<endl;
  if (g_maxNSEC3Iterations && iterations > g_maxNSEC3Iterations) {
    return false;
  }

  vector<DNSRecord> cset;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  vState cachedState;

  auto qnameHash = toBase32Hex(hashQNameWithSalt(salt, iterations, qname));

  cerr<<"looking for nsec3 "<<(DNSName(qnameHash) + zone)<<endl;
  DNSName nsec3Found;
  if (g_recCache->get(d_now.tv_sec, DNSName(qnameHash) + zone, QType::NSEC3, true, &cset, d_cacheRemote, false, d_routingTag, d_doDNSSEC ? &signatures : nullptr, nullptr, nullptr, &cachedState, nullptr, &zone) > 0) {
    cerr<<"found direct match "<<qnameHash<<endl;
    if (cachedState == vState::Secure) {
      cerr<<"but not secure"<<endl;
      return false;
    }

    return false;
  }

  cerr<<"no direct match, looking for closest encloser"<<endl;
  DNSName closestEncloser(qname);
  bool found = false;
  while (!found && closestEncloser.chopOff()) {
    auto closestHash = toBase32Hex(hashQNameWithSalt(salt, iterations, closestEncloser));
    cerr<<"looking for nsec3 "<<(DNSName(closestHash) + zone)<<endl;

    if (g_recCache->get(d_now.tv_sec, DNSName(closestHash) + zone, QType::NSEC3, true, &cset, d_cacheRemote, false, d_routingTag, d_doDNSSEC ? &signatures : nullptr, nullptr, nullptr, &cachedState, nullptr, &zone) > 0) {
      cerr<<"found direct match for closest encloser "<<closestHash<<endl;
      found = true;
      break;
    }
  }

  if (!found) {
    cerr<<"nothing found in aggressive cache either"<<endl;
    return false;
  }

  unsigned int labelIdx = qname.countLabels() - closestEncloser.countLabels();
  if (labelIdx < 1) {
    return false;
  }

  DNSName nsecFound;
  DNSName nextCloser(closestEncloser);
  nextCloser.prependRawLabel(qname.getRawLabel(labelIdx - 1));
  auto nextCloserHash = toBase32Hex(hashQNameWithSalt(salt, iterations, nextCloser));
  cerr<<"looking for a NSEC3 covering the next closer "<<nextCloser<<": "<<nextCloserHash<<endl;

  if (!g_recCache->getNSECBefore(d_now.tv_sec, zone, DNSName(nextCloserHash) + zone, QType::NSEC3, nsecFound, cset, signatures, cachedState)) {
    cerr<<"nothing found for the next closer in aggressive cache"<<endl;
    return false;
  }

  DNSName wildcard(g_wildcarddnsname + closestEncloser);
  auto wcHash = toBase32Hex(hashQNameWithSalt(salt, iterations, wildcard));
  cerr<<"looking for a NSEC3 covering the wildcard "<<wildcard<<": "<<wcHash<<endl;

  if (!g_recCache->getNSECBefore(d_now.tv_sec, zone, DNSName(wcHash) + zone, QType::NSEC3, nsecFound, cset, signatures, cachedState)) {
    cerr<<"nothing found for the wildcard in aggressive cache"<<endl;
    return false;
  }

  return false;
}

bool SyncRes::doAggressiveNSECCacheCheck(const std::string& prefix, const DNSName& qname, const QType& qtype, vector<DNSRecord>&ret, int& res, vState& state)
{
  if (!g_aggressiveNSECCache) {
    cerr<<"no aggressive NSEC"<<endl;
    return false;
  }

  DNSName zone(qname);
  std::string salt;
  uint16_t iterations = 0;
  bool nsec3 = false;
  if (!g_aggressiveNSECCache->getBestZoneInfo(zone, nsec3, salt, iterations)) {
    cerr<<"zone info not found"<<endl;
    return false;
  }

  vState cachedState;
  std::vector<DNSRecord> soaSet;
  std::vector<std::shared_ptr<RRSIGRecordContent>> soaSignatures;
  if (g_recCache->get(d_now.tv_sec, zone, QType::SOA, true, &soaSet, d_cacheRemote, false, d_routingTag, d_doDNSSEC ? &soaSignatures : nullptr, nullptr, nullptr, &cachedState) <= 0 || cachedState != vState::Secure) {
    cerr<<"could not find SOA"<<endl;
    return false;
  }

  vector<DNSRecord> cset;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;

  if (nsec3) {
    return doAggressiveNSEC3Cache(prefix, qname, qtype, zone, salt, iterations, ret, res, state);
  }

  DNSName nsecFound;
  std::vector<DNSRecord> wcSet;
  std::vector<std::shared_ptr<RRSIGRecordContent>> wcSignatures;

   cerr<<"looking for nsec before "<<qname<<endl;
   if (!g_recCache->getNSECBefore(d_now.tv_sec, zone, qname, QType::NSEC, nsecFound, cset, signatures, cachedState)) {
     cerr<<"nothing found in aggressive cache either"<<endl;
    return false;
  }

   cerr<<"nsecFound "<<nsecFound<<endl;
  if (cset.empty() || cachedState != vState::Secure) {
    return false;
  }

  bool covered = false;
   cerr<<"Got "<<cset.size()<<" records"<<endl;
  const auto& nsecRecord = cset.at(0);
  auto content = getRR<NSECRecordContent>(nsecRecord);
  if (!content) {
    return false;
  }

   cerr<<"next is "<<content->d_next<<endl;
  auto denial = matchesNSEC(qname, qtype.getCode(), nsecRecord, signatures);
  if (denial == dState::NXQTYPE) {
    covered = true;
    res = RCode::NoError;
  }
  else if (denial == dState::NXDOMAIN) {
    if (qname.countLabels() > 1) {
      DNSName wc = qname;
      wc.chopOff();
      wc = g_wildcarddnsname + wc;

       cerr<<"looking for nsec before "<<wc<<endl;
      DNSName wcNSEC;
      if (!g_recCache->getNSECBefore(d_now.tv_sec, zone, wc, QType::NSEC, wcNSEC, wcSet, wcSignatures, cachedState)) {
         cerr<<"nothing found in aggressive cache for Wildcard"<<endl;
        return false;
      }

      if (wcSet.empty() || cachedState != vState::Secure) {
        cerr<<"nothing usable"<<endl;
        return false;
      }

      cerr<<"wc nsec found "<<wcNSEC<<endl;
      if (wcNSEC == nsecFound) {
        wcSet.clear();
        wcSignatures.clear();
        covered = true;
        res = RCode::NXDomain;
      }
      else {
        const auto& wcNsecRecord = wcSet.at(0);
        auto wcContent = getRR<NSECRecordContent>(wcNsecRecord);
        if (!wcContent) {
          return false;
        }

        if (wcNSEC == wc) {
          /* too complicated for now */
          return false;
        }
        else if (isCoveredByNSEC(wc, wcNsecRecord.d_name, wcContent->d_next)) {
          cerr<<"next is "<<wcContent->d_next<<endl;
          covered = true;
          res = RCode::NXDomain;
        }
      }
    }
  }

  if (!covered) {
    return false;
  }

  LOG(prefix<<qname<<": Found aggressive NSEC cache hit for "<<qtype.getName()<<endl);

  uint32_t ttl=0;
  uint32_t capTTL = std::numeric_limits<uint32_t>::max();

  ret.reserve(ret.size() + soaSet.size() + soaSignatures.size() + cset.size() + signatures.size() + wcSet.size() + wcSignatures.size());

  for (auto& record : soaSet) {
    if (record.d_class != QClass::IN) {
      continue;
    }

    record.d_ttl -= d_now.tv_sec;
    record.d_ttl = std::min(record.d_ttl, capTTL);
    ttl = record.d_ttl;
    ret.push_back(std::move(record));
  }

  for (auto& signature : soaSignatures) {
    DNSRecord dr;
    dr.d_type = QType::RRSIG;
    dr.d_name = zone;
    dr.d_ttl = ttl;
    dr.d_content = std::move(signature);
    dr.d_place = DNSResourceRecord::ANSWER;
    dr.d_class = QClass::IN;
    ret.push_back(std::move(dr));
  }

  for (auto& record : cset) {
    if (record.d_class != QClass::IN) {
      continue;
    }

    record.d_ttl -= d_now.tv_sec;
    record.d_ttl = std::min(record.d_ttl, capTTL);
    ttl = record.d_ttl;
    ret.push_back(std::move(record));
  }

  for (auto& signature : signatures) {
    DNSRecord dr;
    dr.d_type = QType::RRSIG;
    dr.d_name = qname;
    dr.d_ttl = ttl;
    dr.d_content = std::move(signature);
    dr.d_place = DNSResourceRecord::ANSWER;
    dr.d_class = QClass::IN;
    ret.push_back(std::move(dr));
  }

  for (auto& record : wcSet) {
    if (record.d_class != QClass::IN) {
      continue;
    }

    record.d_ttl -= d_now.tv_sec;
    record.d_ttl = std::min(record.d_ttl, capTTL);
    ttl = record.d_ttl;
    ret.push_back(std::move(record));
  }

  for (auto& signature : wcSignatures) {
    DNSRecord dr;
    dr.d_type = QType::RRSIG;
    dr.d_name = qname;
    dr.d_ttl = ttl;
    dr.d_content = std::move(signature);
    dr.d_place = DNSResourceRecord::ANSWER;
    dr.d_class = QClass::IN;
    ret.push_back(std::move(dr));
  }

  /* we would have given up otherwise */
  state = vState::Secure;

  return true;
}

#endif
