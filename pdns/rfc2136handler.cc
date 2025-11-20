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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnswriter.hh"
#include "packethandler.hh"
#include "qtype.hh"
#include "dnspacket.hh"
#include "auth-caches.hh"
#include "statbag.hh"
#include "dnsseckeeper.hh"
#include "base64.hh"
#include "base32.hh"

#include "misc.hh"
#include "arguments.hh"
#include "resolver.hh"
#include "dns_random.hh"
#include "backends/gsql/ssql.hh"
#include "communicator.hh"
#include "query-local-address.hh"
#include "gss_context.hh"
#include "auth-main.hh"

std::mutex PacketHandler::s_rfc2136lock;

// Context data for RFC2136 operation
struct updateContext {
  DomainInfo di{};
  bool isPresigned{false};

  // The following may be modified
  bool narrow{false};
  bool haveNSEC3{false};
  NSEC3PARAMRecordContent ns3pr{};
  bool updatedSerial{false};

  // Logging-related fields
  std::string msgPrefix;
};

static void increaseSerial(const string& soaEditSetting, const updateContext& ctx);

// Implement section 3.2.1 and 3.2.2 of RFC2136
// NOLINTNEXTLINE(readability-identifier-length)
static int checkUpdatePrerequisites(const DNSRecord* rr, DomainInfo* di)
{
  if (rr->d_ttl != 0) {
    return RCode::FormErr;
  }

  // 3.2.1 and 3.2.2 check content length.
  if ((rr->d_class == QClass::NONE || rr->d_class == QClass::ANY) && rr->d_clen != 0) {
    return RCode::FormErr;
  }

  bool foundRecord = false;
  DNSResourceRecord rec;
  di->backend->lookup(QType(QType::ANY), rr->d_name, di->id);
  while (di->backend->get(rec)) {
    if (rec.qtype.getCode() == QType::ENT) {
      continue;
    }
    if ((rr->d_type != QType::ANY && rec.qtype == rr->d_type) || rr->d_type == QType::ANY) {
      foundRecord = true;
      di->backend->lookupEnd();
      break;
    }
  }

  // Section 3.2.1
  if (rr->d_class == QClass::ANY && !foundRecord) {
    if (rr->d_type == QType::ANY) {
      return RCode::NXDomain;
    }
    if (rr->d_type != QType::ANY) {
      return RCode::NXRRSet;
    }
  }

  // Section 3.2.2
  if (rr->d_class == QClass::NONE && foundRecord) {
    if (rr->d_type == QType::ANY) {
      return RCode::YXDomain;
    }
    if (rr->d_type != QType::ANY) {
      return RCode::YXRRSet;
    }
  }

  return RCode::NoError;
}

// Method implements section 3.4.1 of RFC2136
// NOLINTNEXTLINE(readability-identifier-length)
static int checkUpdatePrescan(const DNSRecord* rr)
{
  // The RFC stats that d_class != ZCLASS, but we only support the IN class.
  if (rr->d_class != QClass::IN && rr->d_class != QClass::NONE && rr->d_class != QClass::ANY) {
    return RCode::FormErr;
  }

  auto qtype = QType(rr->d_type);

  if (!qtype.isSupportedType()) {
    return RCode::FormErr;
  }

  if ((rr->d_class == QClass::NONE || rr->d_class == QClass::ANY) && rr->d_ttl != 0) {
    return RCode::FormErr;
  }

  if (rr->d_class == QClass::ANY && rr->d_clen != 0) {
    return RCode::FormErr;
  }

  if (qtype.isMetadataType()) {
    return RCode::FormErr;
  }

  if (rr->d_class != QClass::ANY && qtype.getCode() == QType::ANY) {
    return RCode::FormErr;
  }

  return RCode::NoError;
}

// Implements section 3.4.2 of RFC2136
// Due to large complexity, this is stuck in multiple routines.

static bool mayPerformUpdate(const DNSRecord* rr, const updateContext& ctx) // NOLINT(readability-identifier-length)
{
  auto rrType = QType(rr->d_type);

  if (rrType == QType::NSEC || rrType == QType::NSEC3) {
    g_log << Logger::Warning << ctx.msgPrefix << "Trying to add/update/delete " << rr->d_name << "|" << rrType.toString() << ". These are generated records, ignoring!" << endl;
    return false;
  }

  if (!ctx.isPresigned && rrType == QType::RRSIG) {
    g_log << Logger::Warning << ctx.msgPrefix << "Trying to add/update/delete " << rr->d_name << "|" << rrType.toString() << " in non-presigned zone, ignoring!" << endl;
    return false;
  }

  if ((rrType == QType::NSEC3PARAM || rrType == QType::DNSKEY) && rr->d_name != ctx.di.zone.operator const DNSName&()) {
    g_log << Logger::Warning << ctx.msgPrefix << "Trying to add/update/delete " << rr->d_name << "|" << rrType.toString() << ", " << rrType.toString() << " must be at zone apex, ignoring!" << endl;
    return false;
  }

  return true;
}

// 3.4.2.2 QClass::IN means insert or update
// Caller has checked that we are allowed to insert the record and has handled
// the NSEC3PARAM case already.
// ctx is not const, may update updateSerial
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static uint performInsert(const DNSRecord* rr, updateContext& ctx, vector<DNSResourceRecord>& rrset, set<DNSName>& insnonterm, set<DNSName>& delnonterm) // NOLINT(readability-identifier-length)
{
  uint changedRecords = 0;
  DNSResourceRecord rec;
  auto rrType = QType(rr->d_type);

  bool foundRecord = false;
  ctx.di.backend->lookup(rrType, rr->d_name, ctx.di.id);
  while (ctx.di.backend->get(rec)) {
    rrset.push_back(rec);
    foundRecord = true;
  }

  if (foundRecord) {
    switch (rrType) {
    case QType::SOA: {
      // SOA updates require the serial to be higher than the current
      SOAData sdOld;
      SOAData sdUpdate;
      DNSResourceRecord* oldRec = &rrset.front();
      fillSOAData(oldRec->content, sdOld);
      oldRec->setContent(rr->getContent()->getZoneRepresentation());
      fillSOAData(oldRec->content, sdUpdate);
      if (rfc1982LessThan(sdOld.serial, sdUpdate.serial)) {
        ctx.di.backend->replaceRRSet(ctx.di.id, oldRec->qname, oldRec->qtype, rrset);
        ctx.updatedSerial = true;
        changedRecords++;
        g_log << Logger::Notice << ctx.msgPrefix << "Replacing SOA record " << rr->d_name << "|" << rrType.toString() << endl;
      }
      else {
        g_log << Logger::Notice << ctx.msgPrefix << "Provided serial (" << sdUpdate.serial << ") is older than the current serial (" << sdOld.serial << "), ignoring SOA update." << endl;
      }
    } break;
    case QType::CNAME: {
      // It's not possible to have multiple CNAME's with the same NAME. So we always update.
      int changedCNames = 0;
      for (auto& i : rrset) { // NOLINT(readability-identifier-length)
        if (i.ttl != rr->d_ttl || i.content != rr->getContent()->getZoneRepresentation()) {
          i.ttl = rr->d_ttl;
          i.setContent(rr->getContent()->getZoneRepresentation());
          changedCNames++;
        }
      }
      if (changedCNames > 0) {
        ctx.di.backend->replaceRRSet(ctx.di.id, rr->d_name, rrType, rrset);
        g_log << Logger::Notice << ctx.msgPrefix << "Replacing CNAME record " << rr->d_name << "|" << rrType.toString() << endl;
        changedRecords += changedCNames;
      }
      else {
        g_log << Logger::Notice << ctx.msgPrefix << "Replace for CNAME record " << rr->d_name << "|" << rrType.toString() << " requested, but no changes made." << endl;
      }
    } break;
    default: {
      // In any other case, we must check if the TYPE and RDATA match to provide an update (which effectively means an update of TTL)
      int updateTTL = 0;
      foundRecord = false;
      bool lowerCase = false;
      switch (rrType.getCode()) {
      case QType::MX:
      case QType::PTR:
      case QType::SRV:
        lowerCase = true;
        break;
      }
      string content = rr->getContent()->getZoneRepresentation();
      if (lowerCase) {
        content = toLower(content);
      }
      for (auto& i : rrset) { // NOLINT(readability-identifier-length)
        if (rrType != i.qtype.getCode()) {
          continue;
        }
        if (!foundRecord) {
          string icontent = i.getZoneRepresentation();
          if (lowerCase) {
            icontent = toLower(icontent);
          }
          if (icontent == content) {
            foundRecord = true;
          }
        }
        if (i.ttl != rr->d_ttl) {
          i.ttl = rr->d_ttl;
          updateTTL++;
        }
      }
      if (updateTTL > 0) {
        ctx.di.backend->replaceRRSet(ctx.di.id, rr->d_name, rrType, rrset);
        g_log << Logger::Notice << ctx.msgPrefix << "Updating TTLs for " << rr->d_name << "|" << rrType.toString() << endl;
        changedRecords += updateTTL;
      }
      else if (foundRecord) {
        g_log << Logger::Notice << ctx.msgPrefix << "Replace for recordset " << rr->d_name << "|" << rrType.toString() << " requested, but no changes made." << endl;
      }
    } break;
    }

    // ReplaceRRSet dumps our ordername and auth flag, so we need to correct it if we have changed records.
    // We can take the auth flag from the first RR in the set, as the name is different, so should the auth be.
    if (changedRecords > 0) {
      bool auth = rrset.front().auth;

      if (ctx.haveNSEC3) {
        DNSName ordername;
        if (!ctx.narrow) {
          ordername = DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, rr->d_name)));
        }

        if (ctx.narrow) {
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), auth, QType::ANY, false);
        }
        else {
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, ordername, auth, QType::ANY, true);
        }
        if (!auth || rrType == QType::DS) {
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::NS, !ctx.narrow);
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::A, !ctx.narrow);
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::AAAA, !ctx.narrow);
        }
      }
      else { // NSEC
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, rr->d_name.makeRelative(ctx.di.zone), auth, QType::ANY, false);
        if (!auth || rrType == QType::DS) {
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::A, false);
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::AAAA, false);
        }
      }
    }
  } // if (foundRecord)

  // If we haven't found a record that matches, we must add it.
  if (!foundRecord) {
    g_log << Logger::Notice << ctx.msgPrefix << "Adding record " << rr->d_name << "|" << rrType.toString() << endl;
    delnonterm.insert(rr->d_name); // always remove any ENT's in the place where we're going to add a record.
    auto newRec = DNSResourceRecord::fromWire(*rr);
    newRec.domain_id = ctx.di.id;
    newRec.auth = (rr->d_name == ctx.di.zone.operator const DNSName&() || rrType.getCode() != QType::NS);
    ctx.di.backend->feedRecord(newRec, DNSName());
    changedRecords++;

    // because we added a record, we need to fix DNSSEC data.
    DNSName shorter(rr->d_name);
    bool auth = newRec.auth;
    bool fixDS = (rrType == QType::DS);

    if (ctx.di.zone.operator const DNSName&() != shorter) { // Everything at APEX is auth=1 && no ENT's
      do {
        if (ctx.di.zone.operator const DNSName&() == shorter) {
          break;
        }

        bool foundShorter = false;
        ctx.di.backend->lookup(QType(QType::ANY), shorter, ctx.di.id);
        while (ctx.di.backend->get(rec)) {
          if (rec.qname == rr->d_name && rec.qtype == QType::DS) {
            fixDS = true;
          }
          if (shorter != rr->d_name) {
            foundShorter = true;
          }
          if (rec.qtype == QType::NS) { // are we inserting below a delegate?
            auth = false;
          }
        }

        if (!foundShorter && auth && shorter != rr->d_name) { // haven't found any record at current level, insert ENT.
          insnonterm.insert(shorter);
        }
        if (foundShorter) {
          break; // if we find a shorter record, we can stop searching
        }
      } while (shorter.chopOff());
    }

    if (ctx.haveNSEC3) {
      DNSName ordername;
      if (!ctx.narrow) {
        ordername = DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, rr->d_name)));
      }

      if (ctx.narrow) {
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), auth, QType::ANY, false);
      }
      else {
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, ordername, auth, QType::ANY, true);
      }

      if (fixDS) {
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, ordername, true, QType::DS, !ctx.narrow);
      }

      if (!auth) {
        if (ctx.ns3pr.d_flags != 0) {
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::NS, !ctx.narrow);
        }
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::A, !ctx.narrow);
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::AAAA, !ctx.narrow);
      }
    }
    else { // NSEC
      DNSName ordername = rr->d_name.makeRelative(ctx.di.zone);
      ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, ordername, auth, QType::ANY, false);
      if (fixDS) {
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, ordername, true, QType::DS, false);
      }
      if (!auth) {
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::A, false);
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr->d_name, DNSName(), false, QType::AAAA, false);
      }
    }

    // If we insert an NS, all the records below it become non auth - so, we're inserting a delegate.
    // Auth can only be false when the rr->d_name is not the zone
    if (!auth && rrType == QType::NS) {
      DLOG(g_log << ctx.msgPrefix << "Going to fix auth flags below " << rr->d_name << endl);
      insnonterm.clear(); // No ENT's are needed below delegates (auth=0)
      vector<DNSName> qnames;
      ctx.di.backend->listSubZone(ZoneName(rr->d_name), ctx.di.id);
      while (ctx.di.backend->get(rec)) {
        if (rec.qtype.getCode() != QType::ENT && rec.qtype.getCode() != QType::DS && rr->d_name != rec.qname) { // Skip ENT, DS and our already corrected record.
          qnames.push_back(rec.qname);
        }
      }
      for (const auto& qname : qnames) {
        if (ctx.haveNSEC3) {
          DNSName ordername;
          if (!ctx.narrow) {
            ordername = DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, qname)));
          }

          if (ctx.narrow) {
            ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, qname, DNSName(), auth, QType::ANY, false);
          }
          else {
            ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, qname, ordername, auth, QType::ANY, true);
          }

          if (ctx.ns3pr.d_flags != 0) {
            ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, qname, DNSName(), false, QType::NS, !ctx.narrow);
          }
        }
        else { // NSEC
          DNSName ordername = DNSName(qname).makeRelative(ctx.di.zone);
          ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, qname, ordername, false, QType::NS, false);
        }

        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, qname, DNSName(), false, QType::A, ctx.haveNSEC3 && !ctx.narrow);
        ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, qname, DNSName(), false, QType::AAAA, ctx.haveNSEC3 && !ctx.narrow);
      }
    }
  }

  return changedRecords;
}

// Delete records - section 3.4.2.3 and 3.4.2.4 with the exception of the 'always leave 1 NS rule' as that's handled by
// the code that calls this performUpdate().
// Caller has checked that we are allowed to delete the record and has handled
// the NSEC3PARAM case already.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static uint performDelete(const DNSRecord* rr, const updateContext& ctx, vector<DNSResourceRecord>& rrset, set<DNSName>& insnonterm, set<DNSName>& delnonterm) // NOLINT(readability-identifier-length)
{
  vector<DNSResourceRecord> recordsToDelete;
  DNSResourceRecord rec;
  auto rrType = QType(rr->d_type);

  ctx.di.backend->lookup(rrType, rr->d_name, ctx.di.id);
  while (ctx.di.backend->get(rec)) {
    if (rr->d_class == QClass::ANY) { // 3.4.2.3
      if (rec.qname == ctx.di.zone.operator const DNSName&() && (rec.qtype == QType::NS || rec.qtype == QType::SOA)) { // Never delete all SOA and NS's
        rrset.push_back(rec);
      }
      else {
        recordsToDelete.push_back(rec);
      }
    }
    if (rr->d_class == QClass::NONE) { // 3.4.2.4
      auto repr = rec.getZoneRepresentation();
      if (rec.qtype == QType::TXT) {
        DLOG(g_log << ctx.msgPrefix << "Adjusting TXT content from [" << repr << "]" << endl);
        auto drc = DNSRecordContent::make(rec.qtype.getCode(), QClass::IN, repr);
        auto ser = drc->serialize(rec.qname, true, true);
        auto rc = DNSRecordContent::deserialize(rec.qname, rec.qtype.getCode(), ser); // NOLINT(readability-identifier-length)
        repr = rc->getZoneRepresentation(true);
        DLOG(g_log << ctx.msgPrefix << "Adjusted TXT content to [" << repr << "]" << endl);
      }
      DLOG(g_log << ctx.msgPrefix << "Matching RR in RRset - (adjusted) representation from request=[" << repr << "], rr->getContent()->getZoneRepresentation()=[" << rr->getContent()->getZoneRepresentation() << "]" << endl);
      if (rrType == rec.qtype && repr == rr->getContent()->getZoneRepresentation()) {
        recordsToDelete.push_back(rec);
      }
      else {
        rrset.push_back(rec);
      }
    }
  }

  if (recordsToDelete.empty()) {
    g_log << Logger::Notice << ctx.msgPrefix << "Deletion for record " << rr->d_name << "|" << rrType.toString() << " requested, but not found." << endl;
    return 0;
  }

  ctx.di.backend->replaceRRSet(ctx.di.id, rr->d_name, rrType, rrset);
  g_log << Logger::Notice << ctx.msgPrefix << "Deleting record " << rr->d_name << "|" << rrType.toString() << endl;

  // If we've removed a delegate, we need to reset ordername/auth for some records.
  if (rrType == QType::NS && rr->d_name != ctx.di.zone.operator const DNSName&()) {
    vector<DNSName> belowOldDelegate;
    vector<DNSName> nsRecs;
    vector<DNSName> updateAuthFlag;
    ctx.di.backend->listSubZone(ZoneName(rr->d_name), ctx.di.id);
    while (ctx.di.backend->get(rec)) {
      if (rec.qtype.getCode() != QType::ENT) { // skip ENT records, they are always auth=false
        belowOldDelegate.push_back(rec.qname);
      }
      if (rec.qtype.getCode() == QType::NS && rec.qname != rr->d_name) {
        nsRecs.push_back(rec.qname);
      }
    }

    for (auto& belowOldDel : belowOldDelegate) {
      bool isBelowDelegate = false;
      for (const auto& ns : nsRecs) { // NOLINT(readability-identifier-length)
        if (ns.isPartOf(belowOldDel)) {
          isBelowDelegate = true;
          break;
        }
      }
      if (!isBelowDelegate) {
        updateAuthFlag.push_back(belowOldDel);
      }
    }

    for (const auto& changeRec : updateAuthFlag) {
      DNSName ordername;
      if (ctx.haveNSEC3) {
        if (!ctx.narrow) {
          ordername = DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, changeRec)));
        }
      }
      else { // NSEC
        ordername = changeRec.makeRelative(ctx.di.zone);
      }
      ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, changeRec, ordername, true, QType::ANY, ctx.haveNSEC3 && !ctx.narrow);
    }
  }

  // Fix ENT records.
  // We must check if we have a record below the current level and if we removed the 'last' record
  // on that level. If so, we must insert an ENT record.
  // We take extra care here to not 'include' the record that we just deleted. Some backends will still return it as they only reload on a commit.
  bool foundDeeper = false;
  bool foundOtherWithSameName = false;
  ctx.di.backend->listSubZone(ZoneName(rr->d_name), ctx.di.id);
  while (ctx.di.backend->get(rec)) {
    if (rec.qname == rr->d_name && count(recordsToDelete.begin(), recordsToDelete.end(), rec) == 0) {
      foundOtherWithSameName = true;
    }
    if (rec.qname != rr->d_name && rec.qtype.getCode() != QType::NS) { //Skip NS records, as this would be a delegate that we can ignore as this does not require us to create a ENT
      foundDeeper = true;
    }
  }

  if (foundDeeper && !foundOtherWithSameName) {
    insnonterm.insert(rr->d_name);
  }
  else if (!foundOtherWithSameName) {
    // If we didn't have to insert an ENT, we might have deleted a record at very deep level
    // and we must then clean up the ENT's above the deleted record.
    DNSName shorter(rr->d_name);
    while (shorter != ctx.di.zone.operator const DNSName&()) {
      shorter.chopOff();
      bool foundRealRR = false;
      bool foundEnt = false;

      // The reason for a listSubZone here is because might go up the tree and find the ENT of another branch
      // consider these non ENT-records:
      // b.c.d.e.test.com
      // b.d.e.test.com
      // if we delete b.c.d.e.test.com, we go up to d.e.test.com and then find b.d.e.test.com because that's below d.e.test.com.
      // At that point we can stop deleting ENT's because the tree is in tact again.
      ctx.di.backend->listSubZone(ZoneName(shorter), ctx.di.id);

      while (ctx.di.backend->get(rec)) {
        if (rec.qtype.getCode() != QType::ENT) {
          foundRealRR = true;
        }
        else {
          foundEnt = true;
        }
      }
      if (!foundRealRR) {
        if (foundEnt) { // only delete the ENT if we actually found one.
          delnonterm.insert(shorter);
        }
      }
      else {
        break;
      }
    }
  }

  return recordsToDelete.size();
}

static void updateENT(const updateContext& ctx, set<DNSName>& insnonterm, set<DNSName>& delnonterm)
{
  if (insnonterm.empty() && delnonterm.empty()) {
    return;
  }

  DLOG(g_log << ctx.msgPrefix << "Updating ENT records - " << insnonterm.size() << "|" << delnonterm.size() << endl);
  ctx.di.backend->updateEmptyNonTerminals(ctx.di.id, insnonterm, delnonterm, false);
  for (const auto& insert : insnonterm) {
    string hashed;
    if (ctx.haveNSEC3) {
      DNSName ordername;
      if (!ctx.narrow) {
        ordername = DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, insert)));
      }
      ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, insert, ordername, true, QType::ANY, !ctx.narrow);
    }
  }
}

static uint performUpdate(DNSSECKeeper& dsk, const DNSRecord* rr, updateContext& ctx) // NOLINT(readability-identifier-length)
{
  if (!mayPerformUpdate(rr, ctx)) {
    return 0;
  }

  auto rrType = QType(rr->d_type);

  // Decide which action to take.
  // 3.4.2.2 QClass::IN means insert or update
  bool insertAction = rr->d_class == QClass::IN;
  bool deleteAction = (rr->d_class == QClass::ANY || rr->d_class == QClass::NONE) && rrType != QType::SOA; // never delete a SOA.

  if (!insertAction && !deleteAction) {
    return 0; // nothing to do!
  }

  // Special processing for NSEC3PARAM
  if (rrType == QType::NSEC3PARAM) {
    if (insertAction) {
      g_log << Logger::Notice << ctx.msgPrefix << "Adding/updating NSEC3PARAM for zone, resetting ordernames." << endl;

      ctx.ns3pr = NSEC3PARAMRecordContent(rr->getContent()->getZoneRepresentation(), ctx.di.zone);
      // adding a NSEC3 will cause narrow mode to be dropped, as you cannot specify that in a NSEC3PARAM record
      ctx.narrow = false;
      dsk.setNSEC3PARAM(ctx.di.zone, ctx.ns3pr, ctx.narrow);
      ctx.haveNSEC3 = true;
    }
    else {
      g_log << Logger::Notice << ctx.msgPrefix << "Deleting NSEC3PARAM from zone, resetting ordernames." << endl;
      // Be sure to use a ZoneName with a variant matching the domain we are
      // working on, for the sake of unsetNSEC3PARAM.
      ZoneName zonename(rr->d_name, ctx.di.zone.getVariant());
      if (rr->d_class == QClass::ANY) {
        dsk.unsetNSEC3PARAM(zonename);
      }
      else { // rr->d_class == QClass::NONE then
        NSEC3PARAMRecordContent nsec3rr(rr->getContent()->getZoneRepresentation(), ctx.di.zone);
        if (ctx.haveNSEC3 && ctx.ns3pr.getZoneRepresentation() == nsec3rr.getZoneRepresentation()) {
          dsk.unsetNSEC3PARAM(zonename);
        }
        else {
          return 0;
        }
      }

      // Update NSEC3 variables, other RR's in this update package might need them as well.
      ctx.narrow = false;
      ctx.haveNSEC3 = false;
    }

    string error;
    string info;
    if (!dsk.rectifyZone(ctx.di.zone, error, info, false)) {
      throw PDNSException("Failed to rectify '" + ctx.di.zone.toLogString() + "': " + error);
    }
    return 1;
  }

  uint changedRecords = 0;
  vector<DNSResourceRecord> rrset;
  // used to (at the end) fix ENT records.
  set<DNSName> delnonterm;
  set<DNSName> insnonterm;

  if (insertAction) {
    DLOG(g_log << ctx.msgPrefix << "Add/Update record (QClass == IN) " << rr->d_name << "|" << rrType.toString() << endl);
    changedRecords = performInsert(rr, ctx, rrset, insnonterm, delnonterm);
  }
  else {
    DLOG(g_log << ctx.msgPrefix << "Deleting records: " << rr->d_name << "; QClass:" << rr->d_class << "; rrType: " << rrType.toString() << endl);
    changedRecords = performDelete(rr, ctx, rrset, insnonterm, delnonterm);
  }

  //Insert and delete ENT's
  updateENT(ctx, insnonterm, delnonterm);

  return changedRecords;
}

static int forwardPacket(UeberBackend& B, const updateContext& ctx, const DNSPacket& p) // NOLINT(readability-identifier-length)
{
  vector<string> forward;
  B.getDomainMetadata(p.qdomainzone, "FORWARD-DNSUPDATE", forward);

  if (forward.empty() && !::arg().mustDo("forward-dnsupdate")) {
    g_log << Logger::Notice << ctx.msgPrefix << "Not configured to forward to primary, returning Refused." << endl;
    return RCode::Refused;
  }

  for (const auto& remote : ctx.di.primaries) {
    g_log << Logger::Notice << ctx.msgPrefix << "Forwarding packet to primary " << remote << endl;

    if (!pdns::isQueryLocalAddressFamilyEnabled(remote.sin4.sin_family)) {
      continue;
    }
    auto local = pdns::getQueryLocalAddress(remote.sin4.sin_family, 0);
    int sock = makeQuerySocket(local, false); // create TCP socket. RFC2136 section 6.2 seems to be ok with this.
    if (sock < 0) {
      g_log << Logger::Error << ctx.msgPrefix << "Error creating socket: " << stringerror() << endl;
      continue;
    }

    if (connect(sock, (const struct sockaddr*)&remote, remote.getSocklen()) < 0) { // NOLINT(cppcoreguidelines-pro-type-cstyle-cast): less ugly than a reinterpret_cast + const_cast combination which would require a linter annotation anyway
      g_log << Logger::Error << ctx.msgPrefix << "Failed to connect to " << remote.toStringWithPort() << ": " << stringerror() << endl;
      try {
        closesocket(sock);
      }
      catch (const PDNSException& e) {
        g_log << Logger::Error << "Error closing primary forwarding socket after connect() failed: " << e.reason << endl;
      }
      continue;
    }

    DNSPacket l_forwardPacket(p);
    l_forwardPacket.setID(dns_random_uint16());
    l_forwardPacket.setRemote(&remote);
    uint16_t len = htons(l_forwardPacket.getString().length());
    string buffer((const char*)&len, 2); // NOLINT(cppcoreguidelines-pro-type-cstyle-cast): less ugly than a reinterpret_cast which would require a linter annotation anyway
    buffer.append(l_forwardPacket.getString());
    if (write(sock, buffer.c_str(), buffer.length()) < 0) {
      g_log << Logger::Error << ctx.msgPrefix << "Unable to forward update message to " << remote.toStringWithPort() << ", error:" << stringerror() << endl;
      try {
        closesocket(sock);
      }
      catch (const PDNSException& e) {
        g_log << Logger::Error << "Error closing primary forwarding socket after write() failed: " << e.reason << endl;
      }
      continue;
    }

    int res = waitForData(sock, 10, 0);
    if (res == 0) {
      g_log << Logger::Error << ctx.msgPrefix << "Timeout waiting for reply from primary at " << remote.toStringWithPort() << endl;
      try {
        closesocket(sock);
      }
      catch (const PDNSException& e) {
        g_log << Logger::Error << "Error closing primary forwarding socket after a timeout occurred: " << e.reason << endl;
      }
      continue;
    }
    if (res < 0) {
      g_log << Logger::Error << ctx.msgPrefix << "Error waiting for answer from primary at " << remote.toStringWithPort() << ", error:" << stringerror() << endl;
      try {
        closesocket(sock);
      }
      catch (const PDNSException& e) {
        g_log << Logger::Error << "Error closing primary forwarding socket after an error occurred: " << e.reason << endl;
      }
      continue;
    }

    std::array<unsigned char, 2> lenBuf{};
    ssize_t recvRes = recv(sock, lenBuf.data(), lenBuf.size(), 0);
    if (recvRes < 0 || static_cast<size_t>(recvRes) < lenBuf.size()) {
      g_log << Logger::Error << ctx.msgPrefix << "Could not receive data (length) from primary at " << remote.toStringWithPort() << ", error:" << stringerror() << endl;
      try {
        closesocket(sock);
      }
      catch (const PDNSException& e) {
        g_log << Logger::Error << "Error closing primary forwarding socket after recv() failed: " << e.reason << endl;
      }
      continue;
    }
    size_t packetLen = lenBuf[0] * 256 + lenBuf[1];

    buffer.resize(packetLen);
    recvRes = recv(sock, &buffer.at(0), packetLen, 0);
    if (recvRes < 0) {
      g_log << Logger::Error << ctx.msgPrefix << "Could not receive data (dnspacket) from primary at " << remote.toStringWithPort() << ", error:" << stringerror() << endl;
      try {
        closesocket(sock);
      }
      catch (const PDNSException& e) {
        g_log << Logger::Error << "Error closing primary forwarding socket after recv() failed: " << e.reason << endl;
      }
      continue;
    }
    try {
      closesocket(sock);
    }
    catch (const PDNSException& e) {
      g_log << Logger::Error << "Error closing primary forwarding socket: " << e.reason << endl;
    }

    try {
      MOADNSParser mdp(false, buffer.data(), static_cast<unsigned int>(recvRes));
      g_log << Logger::Info << ctx.msgPrefix << "Forward update message to " << remote.toStringWithPort() << ", result was RCode " << mdp.d_header.rcode << endl;
      return mdp.d_header.rcode;
    }
    catch (...) {
      g_log << Logger::Error << ctx.msgPrefix << "Failed to parse response packet from primary at " << remote.toStringWithPort() << endl;
      continue;
    }
  }
  g_log << Logger::Error << ctx.msgPrefix << "Failed to forward packet to primary(s). Returning ServFail." << endl;
  return RCode::ServFail;
}

static bool isUpdateAllowed(UeberBackend& UBackend, const updateContext& ctx, DNSPacket& packet)
{
  // Check permissions - IP based
  vector<string> allowedRanges;

  UBackend.getDomainMetadata(packet.qdomainzone, "ALLOW-DNSUPDATE-FROM", allowedRanges);
  if (!::arg()["allow-dnsupdate-from"].empty()) {
    stringtok(allowedRanges, ::arg()["allow-dnsupdate-from"], ", \t");
  }

  NetmaskGroup nmg;
  for (const auto& range : allowedRanges) {
    nmg.addMask(range);
  }

  if (!nmg.match(packet.getInnerRemote())) {
    g_log << Logger::Error << ctx.msgPrefix << "Remote not listed in allow-dnsupdate-from or domainmetadata. Sending REFUSED" << endl;
    return false;
  }

  // Check permissions - TSIG based.
  vector<string> tsigKeys;
  UBackend.getDomainMetadata(packet.qdomainzone, "TSIG-ALLOW-DNSUPDATE", tsigKeys);
  if (!tsigKeys.empty()) {
    bool validKey = false;

    TSIGRecordContent trc;
    DNSName inputkey;
    string message;
    if (!packet.getTSIGDetails(&trc, &inputkey)) {
      g_log << Logger::Error << ctx.msgPrefix << "TSIG key required, but packet does not contain key. Sending REFUSED" << endl;
      return false;
    }
#ifdef ENABLE_GSS_TSIG
    if (g_doGssTSIG && packet.d_tsig_algo == TSIG_GSS) {
      GssName inputname(packet.d_peer_principal); // match against principal since GSS requires that
      for (const auto& key : tsigKeys) {
        if (inputname.match(key)) {
          validKey = true;
          break;
        }
      }
    }
    else
#endif
    {
      for (const auto& key : tsigKeys) {
        if (inputkey == DNSName(key)) { // because checkForCorrectTSIG has already been performed earlier on, if the name of the key matches with the domain given it is valid.
          validKey = true;
          break;
        }
      }
    }

    if (!validKey) {
      g_log << Logger::Error << ctx.msgPrefix << "TSIG key (" << inputkey << ") required, but no matching key found in domainmetadata, tried " << tsigKeys.size() << ". Sending REFUSED" << endl;
      return false;
    }
  }
  else if (::arg().mustDo("dnsupdate-require-tsig")) {
    g_log << Logger::Error << ctx.msgPrefix << "TSIG key required, but domain is not secured with TSIG. Sending REFUSED" << endl;
    return false;
  }

  if (tsigKeys.empty() && packet.d_havetsig) {
    g_log << Logger::Warning << ctx.msgPrefix << "TSIG is provided, but domain is not secured with TSIG. Processing continues" << endl;
  }

  return true;
}

static uint8_t updatePrereqCheck323(MOADNSParser& mdp, const updateContext& ctx)
{
  using rrSetKey_t = pair<DNSName, QType>;
  using rrVector_t = vector<DNSResourceRecord>;
  using RRsetMap_t = std::map<rrSetKey_t, rrVector_t>;
  RRsetMap_t preReqRRsets;

  for (const auto& rec : mdp.d_answers) {
    const DNSRecord* dnsRecord = &rec;
    if (dnsRecord->d_place == DNSResourceRecord::ANSWER) {
      // Last line of 3.2.3
      if (dnsRecord->d_class != QClass::IN && dnsRecord->d_class != QClass::NONE && dnsRecord->d_class != QClass::ANY) {
        return RCode::FormErr;
      }

      if (dnsRecord->d_class == QClass::IN) {
        rrSetKey_t key = {dnsRecord->d_name, QType(dnsRecord->d_type)};
        rrVector_t* vec = &preReqRRsets[key];
        vec->push_back(DNSResourceRecord::fromWire(*dnsRecord));
      }
    }
  }

  if (!preReqRRsets.empty()) {
    RRsetMap_t zoneRRsets;
    for (auto& preReqRRset : preReqRRsets) {
      rrSetKey_t rrSet = preReqRRset.first;
      rrVector_t* vec = &preReqRRset.second;

      DNSResourceRecord rec;
      ctx.di.backend->lookup(QType(QType::ANY), rrSet.first, ctx.di.id);
      size_t foundRR{0};
      size_t matchRR{0};
      while (ctx.di.backend->get(rec)) {
        if (rec.qtype == rrSet.second) {
          foundRR++;
          for (auto& rrItem : *vec) {
            rrItem.ttl = rec.ttl; // The compare one line below also compares TTL, so we make them equal because TTL is not user within prerequisite checks.
            if (rrItem == rec) {
              matchRR++;
            }
          }
        }
      }
      if (matchRR != foundRR || foundRR != vec->size()) {
        g_log << Logger::Error << ctx.msgPrefix << "Failed PreRequisites check (RRs differ), returning NXRRSet" << endl;
        return RCode::NXRRSet;
      }
    }
  }
  return RCode::NoError;
}

static uint8_t updateRecords(MOADNSParser& mdp, DNSSECKeeper& dsk, uint& changedRecords, const std::unique_ptr<AuthLua4>& update_policy_lua, DNSPacket& packet, updateContext& ctx)
{
  vector<const DNSRecord*> cnamesToAdd;
  vector<const DNSRecord*> nonCnamesToAdd;
  vector<const DNSRecord*> nsRRtoDelete;

  bool anyRecordProcessed{false};
  bool anyRecordAcceptedByLua{false};
  for (const auto& answer : mdp.d_answers) {
    const DNSRecord* dnsRecord = &answer;
    if (dnsRecord->d_place == DNSResourceRecord::AUTHORITY) {
      anyRecordProcessed = true;
      /* see if it's permitted by policy */
      if (update_policy_lua != nullptr) {
        if (!update_policy_lua->updatePolicy(dnsRecord->d_name, QType(dnsRecord->d_type), ctx.di.zone.operator const DNSName&(), packet)) {
          g_log << Logger::Warning << ctx.msgPrefix << "Refusing update for " << dnsRecord->d_name << "/" << QType(dnsRecord->d_type).toString() << ": Not permitted by policy" << endl;
          continue;
        }
        g_log << Logger::Debug << ctx.msgPrefix << "Accepting update for " << dnsRecord->d_name << "/" << QType(dnsRecord->d_type).toString() << ": Permitted by policy" << endl;
        anyRecordAcceptedByLua = true;
      }

      if (dnsRecord->d_class == QClass::NONE && dnsRecord->d_type == QType::NS && dnsRecord->d_name == ctx.di.zone.operator const DNSName&()) {
        nsRRtoDelete.push_back(dnsRecord);
      }
      else if (dnsRecord->d_class == QClass::IN && dnsRecord->d_ttl > 0) {
        if (dnsRecord->d_type == QType::CNAME) {
          cnamesToAdd.push_back(dnsRecord);
        }
        else {
          nonCnamesToAdd.push_back(dnsRecord);
        }
      }
      else {
        changedRecords += performUpdate(dsk, dnsRecord, ctx);
      }
    }
  }

  if (update_policy_lua != nullptr) {
    // If the Lua update policy script has been invoked, and has rejected
    // everything, better return Refused.
    if (anyRecordProcessed && !anyRecordAcceptedByLua) {
      return RCode::Refused;
    }
  }

  for (const auto& resrec : cnamesToAdd) {
    DNSResourceRecord rec;
    ctx.di.backend->lookup(QType(QType::ANY), resrec->d_name, ctx.di.id);
    while (ctx.di.backend->get(rec)) {
      if (rec.qtype != QType::CNAME && rec.qtype != QType::ENT && rec.qtype != QType::RRSIG) {
        // leave database handle in a consistent state
        ctx.di.backend->lookupEnd();
        g_log << Logger::Warning << ctx.msgPrefix << "Refusing update for " << resrec->d_name << "/" << QType(resrec->d_type).toString() << ": Data other than CNAME exists for the same name" << endl;
        return RCode::Refused;
      }
    }
    changedRecords += performUpdate(dsk, resrec, ctx);
  }
  for (const auto& resrec : nonCnamesToAdd) {
    DNSResourceRecord rec;
    ctx.di.backend->lookup(QType(QType::CNAME), resrec->d_name, ctx.di.id);
    while (ctx.di.backend->get(rec)) {
      if (rec.qtype == QType::CNAME && resrec->d_type != QType::RRSIG) {
        // leave database handle in a consistent state
        ctx.di.backend->lookupEnd();
        g_log << Logger::Warning << ctx.msgPrefix << "Refusing update for " << resrec->d_name << "/" << QType(resrec->d_type).toString() << ": CNAME exists for the same name" << endl;
        return RCode::Refused;
      }
    }
    changedRecords += performUpdate(dsk, resrec, ctx);
  }

  if (!nsRRtoDelete.empty()) {
    vector<DNSResourceRecord> nsRRInZone;
    DNSResourceRecord rec;
    ctx.di.backend->lookup(QType(QType::NS), ctx.di.zone.operator const DNSName&(), ctx.di.id);
    while (ctx.di.backend->get(rec)) {
      nsRRInZone.push_back(rec);
    }
    if (nsRRInZone.size() > nsRRtoDelete.size()) { // only delete if the NS's we delete are less then what we have in the zone (3.4.2.4)
      for (auto& inZone : nsRRInZone) {
        for (auto& resrec : nsRRtoDelete) {
          if (inZone.getZoneRepresentation() == resrec->getContent()->getZoneRepresentation()) {
            changedRecords += performUpdate(dsk, resrec, ctx);
          }
        }
      }
    }
  }

  return RCode::NoError;
}

int PacketHandler::processUpdate(DNSPacket& packet)
{
  if (!::arg().mustDo("dnsupdate")) {
    return RCode::Refused;
  }

  updateContext ctx{};
  string msgPrefix = "UPDATE (" + std::to_string(packet.d.id) + ") from " + packet.getRemoteString() + " for " + packet.qdomainzone.toLogString() + ": ";
  ctx.msgPrefix = std::move(msgPrefix);

  g_log << Logger::Info << ctx.msgPrefix << "Processing started." << endl;

  // if there is policy, we delegate all checks to it
  if (this->d_update_policy_lua == nullptr) {
    if (!isUpdateAllowed(B, ctx, packet)) {
      return RCode::Refused;
    }
  }

  // RFC2136 uses the same DNS Header and Message as defined in RFC1035.
  // This means we can use the MOADNSParser to parse the incoming packet. The result is that we have some different
  // variable names during the use of our MOADNSParser.
  MOADNSParser mdp(false, packet.getString());
  if (mdp.d_header.qdcount != 1) {
    g_log << Logger::Warning << ctx.msgPrefix << "Zone Count is not 1, sending FormErr" << endl;
    return RCode::FormErr;
  }

  if (packet.qtype.getCode() != QType::SOA) { // RFC2136 2.3 - ZTYPE must be SOA
    g_log << Logger::Warning << ctx.msgPrefix << "Query ZTYPE is not SOA, sending FormErr" << endl;
    return RCode::FormErr;
  }

  if (packet.qclass != QClass::IN) {
    g_log << Logger::Warning << ctx.msgPrefix << "Class is not IN, sending NotAuth" << endl;
    return RCode::NotAuth;
  }

  ctx.di.backend = nullptr;
  if (!B.getDomainInfo(packet.qdomainzone, ctx.di) || (ctx.di.backend == nullptr)) {
    g_log << Logger::Error << ctx.msgPrefix << "Can't determine backend for domain '" << packet.qdomainzone << "' (or backend does not support DNS update operation)" << endl;
    return RCode::NotAuth;
  }
  // ctx.di field valid from now on

  if (ctx.di.kind == DomainInfo::Secondary) {
    return forwardPacket(B, ctx, packet);
  }

  // Check if all the records provided are within the zone
  for (const auto& answer : mdp.d_answers) {
    const DNSRecord* dnsRecord = &answer;
    // Skip this check for other field types (like the TSIG -  which is in the additional section)
    // For a TSIG, the label is the dnskey, so it does not pass the endOn validation.
    if (dnsRecord->d_place != DNSResourceRecord::ANSWER && dnsRecord->d_place != DNSResourceRecord::AUTHORITY) {
      continue;
    }

    if (!dnsRecord->d_name.isPartOf(ctx.di.zone)) {
      g_log << Logger::Error << ctx.msgPrefix << "Received update/record out of zone, sending NotZone." << endl;
      return RCode::NotZone;
    }
  }

  auto lock = std::scoped_lock(s_rfc2136lock); //TODO: i think this lock can be per zone, not for everything
  g_log << Logger::Info << ctx.msgPrefix << "starting transaction." << endl;
  if (!ctx.di.backend->startTransaction(packet.qdomainzone, UnknownDomainID)) { // Not giving the domain_id means that we do not delete the existing records.
    g_log << Logger::Error << ctx.msgPrefix << "Backend for domain " << packet.qdomainzone << " does not support transaction. Can't do Update packet." << endl;
    return RCode::NotImp;
  }

  // 3.2.1 and 3.2.2 - Prerequisite check
  for (const auto& answer : mdp.d_answers) {
    const DNSRecord* dnsRecord = &answer;
    if (dnsRecord->d_place == DNSResourceRecord::ANSWER) {
      int res = checkUpdatePrerequisites(dnsRecord, &ctx.di);
      if (res > 0) {
        g_log << Logger::Error << ctx.msgPrefix << "Failed PreRequisites check for " << dnsRecord->d_name << ", returning " << RCode::to_s(res) << endl;
        ctx.di.backend->abortTransaction();
        return res;
      }
    }
  }

  // 3.2.3 - Prerequisite check - this is outside of updatePrerequisitesCheck because we check an RRSet and not the RR.
  if (auto rcode = updatePrereqCheck323(mdp, ctx); rcode != RCode::NoError) {
    ctx.di.backend->abortTransaction();
    return rcode;
  }

  // 3.4 - Prescan & Add/Update/Delete records - is all done within a try block.
  try {
    // 3.4.1 - Prescan section
    for (const auto& answer : mdp.d_answers) {
      const DNSRecord* dnsRecord = &answer;
      if (dnsRecord->d_place == DNSResourceRecord::AUTHORITY) {
        int res = checkUpdatePrescan(dnsRecord);
        if (res > 0) {
          g_log << Logger::Error << ctx.msgPrefix << "Failed prescan check, returning " << res << endl;
          ctx.di.backend->abortTransaction();
          return res;
        }
      }
    }

    ctx.isPresigned = d_dk.isPresigned(ctx.di.zone);
    ctx.narrow = false;
    ctx.haveNSEC3 = d_dk.getNSEC3PARAM(ctx.di.zone, &ctx.ns3pr, &ctx.narrow);
    ctx.updatedSerial = false;
    // all ctx fields valid from now on

    string soaEditSetting;
    d_dk.getSoaEdit(ctx.di.zone, soaEditSetting);

    // 3.4.2 - Perform the updates.
    // There's a special condition where deleting the last NS record at zone apex is never deleted (3.4.2.4)
    // This means we must do it outside the normal performUpdate() because that focusses only on a separate RR.

    // Another special case is the addition of both a CNAME and a non-CNAME for the same name (#6270)
    set<DNSName> cn; // NOLINT(readability-identifier-length)
    set<DNSName> nocn;
    for (const auto& rr : mdp.d_answers) { // NOLINT(readability-identifier-length)
      if (rr.d_place == DNSResourceRecord::AUTHORITY && rr.d_class == QClass::IN && rr.d_ttl > 0) {
        // Addition
        if (rr.d_type == QType::CNAME) {
          cn.insert(rr.d_name);
        }
        else if (rr.d_type != QType::RRSIG) {
          nocn.insert(rr.d_name);
        }
      }
    }
    for (auto const& n : cn) { // NOLINT(readability-identifier-length)
      if (nocn.count(n) > 0) {
        g_log << Logger::Error << ctx.msgPrefix << "Refusing update, found CNAME and non-CNAME addition" << endl;
        ctx.di.backend->abortTransaction();
        return RCode::FormErr;
      }
    }

    uint changedRecords = 0;
    if (auto rcode = updateRecords(mdp, d_dk, changedRecords, d_update_policy_lua, packet, ctx); rcode != RCode::NoError) {
      ctx.di.backend->abortTransaction();
      return rcode;
    }

    // Section 3.6 - Update the SOA serial - outside of performUpdate because we do a SOA update for the complete update message
    if (changedRecords != 0 && !ctx.updatedSerial) {
      increaseSerial(soaEditSetting, ctx);
      changedRecords++;
    }

    if (changedRecords != 0) {
      if (!ctx.di.backend->commitTransaction()) {
        g_log << Logger::Error << ctx.msgPrefix << "Failed to commit updates!" << endl;
        return RCode::ServFail;
      }

      S.deposit("dnsupdate-changes", static_cast<int>(changedRecords));

      DNSSECKeeper::clearMetaCache(ctx.di.zone);
      // Purge the records!
      purgeAuthCaches(ctx.di.zone.operator const DNSName&().toString() + "$");

      // Notify secondaries
      if (ctx.di.kind == DomainInfo::Primary) {
        vector<string> notify;
        B.getDomainMetadata(packet.qdomainzone, "NOTIFY-DNSUPDATE", notify);
        if (!notify.empty() && notify.front() == "1") {
          Communicator.notifyDomain(ctx.di.zone, &B);
        }
      }

      g_log << Logger::Info << ctx.msgPrefix << "Update completed, " << changedRecords << " changed records committed." << endl;
    }
    else {
      //No change, no commit, we perform abort() because some backends might like this more.
      g_log << Logger::Info << ctx.msgPrefix << "Update completed, 0 changes, rolling back." << endl;
      ctx.di.backend->abortTransaction();
    }
    return RCode::NoError; //rfc 2136 3.4.2.5
  }
  catch (SSqlException& e) {
    g_log << Logger::Error << ctx.msgPrefix << "Caught SSqlException: " << e.txtReason() << "; Sending ServFail!" << endl;
    ctx.di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (DBException& e) {
    g_log << Logger::Error << ctx.msgPrefix << "Caught DBException: " << e.reason << "; Sending ServFail!" << endl;
    ctx.di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (PDNSException& e) {
    g_log << Logger::Error << ctx.msgPrefix << "Caught PDNSException: " << e.reason << "; Sending ServFail!" << endl;
    ctx.di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (std::exception& e) {
    g_log << Logger::Error << ctx.msgPrefix << "Caught std:exception: " << e.what() << "; Sending ServFail!" << endl;
    ctx.di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (...) {
    g_log << Logger::Error << ctx.msgPrefix << "Caught unknown exception when performing update. Sending ServFail!" << endl;
    ctx.di.backend->abortTransaction();
    return RCode::ServFail;
  }
}

static void increaseSerial(const string& soaEditSetting, const updateContext& ctx)
{
  SOAData sd; // NOLINT(readability-identifier-length)
  if (!ctx.di.backend->getSOA(ctx.di.zone, ctx.di.id, sd)) {
    throw PDNSException("SOA-Serial update failed because there was no SOA. Wowie.");
  }

  uint32_t oldSerial = sd.serial;

  vector<string> soaEdit2136Setting;
  ctx.di.backend->getDomainMetadata(ctx.di.zone, "SOA-EDIT-DNSUPDATE", soaEdit2136Setting);
  string soaEdit2136 = "DEFAULT";
  string soaEdit;
  if (!soaEdit2136Setting.empty()) {
    soaEdit2136 = soaEdit2136Setting[0];
    if (pdns_iequals(soaEdit2136, "SOA-EDIT") || pdns_iequals(soaEdit2136, "SOA-EDIT-INCREASE")) {
      if (soaEditSetting.empty()) {
        g_log << Logger::Error << ctx.msgPrefix << "Using " << soaEdit2136 << " for SOA-EDIT-DNSUPDATE increase on DNS update, but SOA-EDIT is not set for domain \"" << ctx.di.zone << "\". Using DEFAULT for SOA-EDIT-DNSUPDATE" << endl;
        soaEdit2136 = "DEFAULT";
      }
      else {
        soaEdit = soaEditSetting;
      }
    }
  }

  DNSResourceRecord rr; // NOLINT(readability-identifier-length)
  if (makeIncreasedSOARecord(sd, soaEdit2136, soaEdit, rr)) {
    ctx.di.backend->replaceRRSet(ctx.di.id, rr.qname, rr.qtype, vector<DNSResourceRecord>(1, rr));
    g_log << Logger::Notice << ctx.msgPrefix << "Increasing SOA serial (" << oldSerial << " -> " << sd.serial << ")" << endl;

    //Correct ordername + auth flag
    DNSName ordername;
    if (ctx.haveNSEC3) {
      if (!ctx.narrow) {
        ordername = DNSName(toBase32Hex(hashQNameWithSalt(ctx.ns3pr, rr.qname)));
      }
    }
    else { // NSEC
      ordername = rr.qname.makeRelative(ctx.di.zone);
    }
    ctx.di.backend->updateDNSSECOrderNameAndAuth(ctx.di.id, rr.qname, ordername, true, QType::ANY, ctx.haveNSEC3 && !ctx.narrow);
  }
}
