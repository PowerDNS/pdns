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

#include "validate.hh"
#include "misc.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "rec-lua-conf.hh"
#include "base32.hh"
#include "logger.hh"

time_t g_signatureInceptionSkew{0};
uint16_t g_maxNSEC3Iterations{0};
uint16_t g_maxRRSIGsPerRecordToConsider{0};
uint16_t g_maxNSEC3sPerRecordToConsider{0};
uint16_t g_maxDNSKEYsToConsider{0};
uint16_t g_maxDSsToConsider{0};

static bool isAZoneKey(const DNSKEYRecordContent& key)
{
  /* rfc4034 Section 2.1.1:
     "Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value 1,
     then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
     owner name MUST be the name of a zone.  If bit 7 has value 0, then
     the DNSKEY record holds some other type of DNS public key and MUST
     NOT be used to verify RRSIGs that cover RRsets."

     Let's check that this is a ZONE key, even though there is no other
     types of DNSKEYs at the moment.
  */
  return (key.d_flags & 256) != 0;
}

static bool isRevokedKey(const DNSKEYRecordContent& key)
{
  /* rfc5011 Section 3 */
  return (key.d_flags & 128) != 0;
}

static vector<shared_ptr<const DNSKEYRecordContent > > getByTag(const skeyset_t& keys, uint16_t tag, uint8_t algorithm, const OptLog& log)
{
  vector<shared_ptr<const DNSKEYRecordContent>> ret;

  for (const auto& key : keys) {
    if (!isAZoneKey(*key)) {
      VLOG(log, "Key for tag "<<std::to_string(tag)<<" and algorithm "<<std::to_string(algorithm)<<" is not a zone key, skipping"<<endl;);
      continue;
    }

    if (isRevokedKey(*key)) {
      VLOG(log, "Key for tag "<<std::to_string(tag)<<" and algorithm "<<std::to_string(algorithm)<<" has been revoked, skipping"<<endl;);
      continue;
    }

    if (key->d_protocol == 3 && key->getTag() == tag && key->d_algorithm == algorithm) {
      ret.push_back(key);
    }
  }

  return ret;
}

bool isCoveredByNSEC3Hash(const std::string& hash, const std::string& beginHash, const std::string& nextHash)
{
  return ((beginHash < hash && hash < nextHash) ||          // no wrap          BEGINNING --- HASH -- END
          (nextHash > hash  && beginHash > nextHash) ||  // wrap             HASH --- END --- BEGINNING
          (nextHash < beginHash  && beginHash < hash) || // wrap other case  END --- BEGINNING --- HASH
          (beginHash == nextHash && hash != beginHash));   // "we have only 1 NSEC3 record, LOL!"
}

bool isCoveredByNSEC3Hash(const DNSName& name, const DNSName& beginHash, const DNSName& nextHash)
{
  return ((beginHash.canonCompare(name) && name.canonCompare(nextHash)) ||          // no wrap          BEGINNING --- HASH -- END
          (name.canonCompare(nextHash) && nextHash.canonCompare(beginHash)) ||  // wrap             HASH --- END --- BEGINNING
          (nextHash.canonCompare(beginHash) && beginHash.canonCompare(name)) || // wrap other case  END --- BEGINNING --- HASH
          (beginHash == nextHash && name != beginHash));   // "we have only 1 NSEC3 record, LOL!"
}

bool isCoveredByNSEC(const DNSName& name, const DNSName& begin, const DNSName& next)
{
  return ((begin.canonCompare(name) && name.canonCompare(next)) ||  // no wrap          BEGINNING --- NAME --- NEXT
          (name.canonCompare(next) && next.canonCompare(begin)) ||  // wrap             NAME --- NEXT --- BEGINNING
          (next.canonCompare(begin) && begin.canonCompare(name)) || // wrap other case  NEXT --- BEGINNING --- NAME
          (begin == next && name != begin));                        // "we have only 1 NSEC record, LOL!"
}

static bool nsecProvesENT(const DNSName& name, const DNSName& begin, const DNSName& next)
{
  /* if name is an ENT:
     - begin < name
     - next is a child of name
  */
  return begin.canonCompare(name) && next != name && next.isPartOf(name);
}

[[nodiscard]] std::string getHashFromNSEC3(const DNSName& qname, uint16_t iterations, const std::string& salt, pdns::validation::ValidationContext& context)
{
  std::string result;

  if (g_maxNSEC3Iterations != 0 && iterations > g_maxNSEC3Iterations) {
    return result;
  }

  auto key = std::tuple(qname, salt, iterations);
  auto iter = context.d_nsec3Cache.find(key);
  if (iter != context.d_nsec3Cache.end()) {
    return iter->second;
  }

  if (context.d_nsec3IterationsRemainingQuota < iterations) {
    // we throw here because we cannot take the risk that the result
    // be cached, since a different query can try to validate the
    // same result with a bigger NSEC3 iterations quota
    throw pdns::validation::TooManySEC3IterationsException();
  }

  result = hashQNameWithSalt(salt, iterations, qname);
  context.d_nsec3IterationsRemainingQuota -= iterations;
  context.d_nsec3Cache[key] = result;
  return result;
}

[[nodiscard]] static std::string getHashFromNSEC3(const DNSName& qname, const NSEC3RecordContent& nsec3, pdns::validation::ValidationContext& context)
{
  return getHashFromNSEC3(qname, nsec3.d_iterations, nsec3.d_salt, context);
}

/* There is no delegation at this exact point if:
   - the name exists but the NS type is not set
   - the name does not exist
   One exception, if the name is covered by an opt-out NSEC3
   it doesn't prove that an insecure delegation doesn't exist.
*/
bool denialProvesNoDelegation(const DNSName& zone, const std::vector<DNSRecord>& dsrecords, pdns::validation::ValidationContext& context)
{
  uint16_t nsec3sConsidered = 0;

  for (const auto& record : dsrecords) {
    if (record.d_type == QType::NSEC) {
      const auto nsec = getRR<NSECRecordContent>(record);
      if (!nsec) {
        continue;
      }

      if (record.d_name == zone) {
        return !nsec->isSet(QType::NS);
      }

      if (isCoveredByNSEC(zone, record.d_name, nsec->d_next)) {
        return true;
      }
    }
    else if (record.d_type == QType::NSEC3) {
      const auto nsec3 = getRR<NSEC3RecordContent>(record);
      if (!nsec3) {
        continue;
      }

      if (g_maxNSEC3sPerRecordToConsider > 0 && nsec3sConsidered >= g_maxNSEC3sPerRecordToConsider) {
        context.d_limitHit = true;
        return false;
      }
      nsec3sConsidered++;

      const string hash = getHashFromNSEC3(zone, *nsec3, context);
      if (hash.empty()) {
        return false;
      }

      const string beginHash = fromBase32Hex(record.d_name.getRawLabels()[0]);
      if (beginHash == hash) {
        return !nsec3->isSet(QType::NS);
      }

      if (isCoveredByNSEC3Hash(hash, beginHash, nsec3->d_nexthash)) {
        return !(nsec3->isOptOut());
      }
    }
  }

  return false;
}

/* RFC 4035 section-5.3.4:
   "If the number of labels in an RRset's owner name is greater than the
   Labels field of the covering RRSIG RR, then the RRset and its
   covering RRSIG RR were created as a result of wildcard expansion."
*/
bool isWildcardExpanded(unsigned int labelCount, const RRSIGRecordContent& sign)
{
  return sign.d_labels < labelCount;
}

static bool isWildcardExpanded(const DNSName& owner, const std::vector<std::shared_ptr<const RRSIGRecordContent> >& signatures)
{
  if (signatures.empty()) {
    return false;
  }

  const auto& sign = signatures.at(0);
  unsigned int labelsCount = owner.countLabels();
  return isWildcardExpanded(labelsCount, *sign);
}

bool isWildcardExpandedOntoItself(const DNSName& owner, unsigned int labelCount, const RRSIGRecordContent& sign)
{
  /* this is a wildcard alright, but it has not been expanded */
  return owner.isWildcard() && (labelCount - 1) == sign.d_labels;
}

static bool isWildcardExpandedOntoItself(const DNSName& owner, const std::vector<std::shared_ptr<const RRSIGRecordContent> >& signatures)
{
  if (signatures.empty()) {
    return false;
  }

  const auto& sign = signatures.at(0);
  unsigned int labelsCount = owner.countLabels();
  return isWildcardExpandedOntoItself(owner, labelsCount, *sign);
}

/* if this is a wildcard NSEC, the owner name has been modified
   to match the name. Make sure we use the original '*' form. */
DNSName getNSECOwnerName(const DNSName& initialOwner, const std::vector<std::shared_ptr<const RRSIGRecordContent> >& signatures)
{
  DNSName result = initialOwner;

  if (signatures.empty()) {
    return result;
  }

  const auto& sign = signatures.at(0);
  unsigned int labelsCount = initialOwner.countLabels();
  if (sign && sign->d_labels < labelsCount) {
    do {
      result.chopOff();
      labelsCount--;
    }
    while (sign->d_labels < labelsCount);

    result = g_wildcarddnsname + result;
  }

  return result;
}

static bool isNSECAncestorDelegation(const DNSName& signer, const DNSName& owner, const NSECRecordContent& nsec)
{
  return nsec.isSet(QType::NS) &&
    !nsec.isSet(QType::SOA) &&
    signer.countLabels() < owner.countLabels();
}

bool isNSEC3AncestorDelegation(const DNSName& signer, const DNSName& owner, const NSEC3RecordContent& nsec3)
{
  return nsec3.isSet(QType::NS) &&
    !nsec3.isSet(QType::SOA) &&
    signer.countLabels() < owner.countLabels();
}

static bool provesNoDataWildCard(const DNSName& qname, const uint16_t qtype, const DNSName& closestEncloser, const cspmap_t& validrrsets, const OptLog& log)
{
  const DNSName wildcard = g_wildcarddnsname + closestEncloser;
  VLOG(log, qname << ": Trying to prove that there is no data in wildcard for "<<qname<<"/"<<QType(qtype)<<endl);
  for (const auto& validset : validrrsets) {
    VLOG(log, qname << ": Do have: "<<validset.first.first<<"/"<<DNSRecordContent::NumberToType(validset.first.second)<<endl);
    if (validset.first.second == QType::NSEC) {
      for (const auto& record : validset.second.records) {
        VLOG(log, ":\t"<<record->getZoneRepresentation()<<endl);
        auto nsec = std::dynamic_pointer_cast<const NSECRecordContent>(record);
        if (!nsec) {
          continue;
        }

        DNSName owner = getNSECOwnerName(validset.first.first, validset.second.signatures);
        if (owner != wildcard) {
          continue;
        }

        VLOG(log, qname << ":\tWildcard matches");
        if (qtype == 0 || isTypeDenied(*nsec, QType(qtype))) {
          VLOG_NO_PREFIX(log, " and proves that the type did not exist"<<endl);
          return true;
        }
        VLOG_NO_PREFIX(log, " BUT the type did exist!"<<endl);
        return false;
      }
    }
  }

  return false;
}

DNSName getClosestEncloserFromNSEC(const DNSName& name, const DNSName& owner, const DNSName& next)
{
  DNSName commonWithOwner(name.getCommonLabels(owner));
  DNSName commonWithNext(name.getCommonLabels(next));
  if (commonWithOwner.countLabels() >= commonWithNext.countLabels()) {
    return commonWithOwner;
  }
  return commonWithNext;
}

/*
  This function checks whether the non-existence of a wildcard covering qname|qtype
  is proven by the NSEC records in validrrsets.
*/
static bool provesNoWildCard(const DNSName& qname, const uint16_t qtype, const DNSName& closestEncloser, const cspmap_t & validrrsets, const OptLog& log)
{
  VLOG(log, qname << ": Trying to prove that there is no wildcard for "<<qname<<"/"<<QType(qtype)<<endl);
  const DNSName wildcard = g_wildcarddnsname + closestEncloser;
  for (const auto& validset : validrrsets) {
    VLOG(log, qname << ": Do have: "<<validset.first.first<<"/"<<DNSRecordContent::NumberToType(validset.first.second)<<endl);
    if (validset.first.second == QType::NSEC) {
      for (const auto& records : validset.second.records) {
        VLOG(log, qname << ":\t"<<records->getZoneRepresentation()<<endl);
        auto nsec = std::dynamic_pointer_cast<const NSECRecordContent>(records);
        if (!nsec) {
          continue;
        }

        const DNSName owner = getNSECOwnerName(validset.first.first, validset.second.signatures);
        VLOG(log, qname << ": Comparing owner: "<<owner<<" with target: "<<wildcard<<endl);

        if (qname != owner && qname.isPartOf(owner) && nsec->isSet(QType::DNAME)) {
          /* rfc6672 section 5.3.2: DNAME Bit in NSEC Type Map

             In any negative response, the NSEC or NSEC3 [RFC5155] record type
             bitmap SHOULD be checked to see that there was no DNAME that could
             have been applied.  If the DNAME bit in the type bitmap is set and
             the query name is a subdomain of the closest encloser that is
             asserted, then DNAME substitution should have been done, but the
             substitution has not been done as specified.
          */
          VLOG(log, qname << ":\tThe qname is a subdomain of the NSEC and the DNAME bit is set"<<endl);
          return false;
        }

        if (wildcard != owner && isCoveredByNSEC(wildcard, owner, nsec->d_next)) {
          VLOG(log, qname << ":\tWildcard is covered"<<endl);
          return true;
        }
      }
    }
  }

  return false;
}

/*
  This function checks whether the non-existence of a wildcard covering qname|qtype
  is proven by the NSEC3 records in validrrsets.
  If `wildcardExists` is not NULL, if will be set to true if a wildcard exists
  for this qname but doesn't have this qtype.
*/
static bool provesNSEC3NoWildCard(const DNSName& closestEncloser, uint16_t const qtype, const cspmap_t& validrrsets, bool* wildcardExists, const OptLog& log, pdns::validation::ValidationContext& context)
{
  auto wildcard = g_wildcarddnsname + closestEncloser;
  VLOG(log, closestEncloser << ": Trying to prove that there is no wildcard for "<<wildcard<<"/"<<QType(qtype)<<endl);

  for (const auto& validset : validrrsets) {
    VLOG(log, closestEncloser << ": Do have: "<<validset.first.first<<"/"<<DNSRecordContent::NumberToType(validset.first.second)<<endl);
    if (validset.first.second == QType::NSEC3) {
      for (const auto& records : validset.second.records) {
        VLOG(log, closestEncloser << ":\t"<<records->getZoneRepresentation()<<endl);
        auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(records);
        if (!nsec3) {
          continue;
        }

        const DNSName signer = getSigner(validset.second.signatures);
        if (!validset.first.first.isPartOf(signer) || !closestEncloser.isPartOf(signer)) {
          continue;
        }

        string hash = getHashFromNSEC3(wildcard, *nsec3, context);
        if (hash.empty()) {
          VLOG(log, closestEncloser << ": Unsupported hash, ignoring"<<endl);
          return false;
        }
        VLOG(log, closestEncloser << ":\tWildcard hash: "<<toBase32Hex(hash)<<endl);
        string beginHash=fromBase32Hex(validset.first.first.getRawLabels()[0]);
        VLOG(log, closestEncloser << ":\tNSEC3 hash: "<<toBase32Hex(beginHash)<<" -> "<<toBase32Hex(nsec3->d_nexthash)<<endl);

        if (beginHash == hash) {
          VLOG(log, closestEncloser << ":\tWildcard hash matches");
          if (wildcardExists != nullptr) {
            *wildcardExists = true;
          }

          /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
             Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
             nonexistence of any RRs below that zone cut, which include all RRs at
             that (original) owner name other than DS RRs, and all RRs below that
             owner name regardless of type.
          */
          if (qtype != QType::DS && isNSEC3AncestorDelegation(signer, validset.first.first, *nsec3)) {
            /* this is an "ancestor delegation" NSEC3 RR */
            VLOG_NO_PREFIX(log, " BUT an ancestor delegation NSEC3 RR can only deny the existence of a DS"<<endl);
            return false;
          }

          if (qtype == 0 || isTypeDenied(*nsec3, QType(qtype))) {
            VLOG_NO_PREFIX(log, " and proves that the type did not exist"<<endl);
            return true;
          }
          VLOG_NO_PREFIX(log, " BUT the type did exist!"<<endl);
          return false;
        }

        if (isCoveredByNSEC3Hash(hash, beginHash, nsec3->d_nexthash)) {
          VLOG(log, closestEncloser << ":\tWildcard hash is covered"<<endl);
          return true;
        }
      }
    }
  }

  return false;
}

dState matchesNSEC(const DNSName& name, uint16_t qtype, const DNSName& nsecOwner, const NSECRecordContent& nsec, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, const OptLog& log)
{
  const DNSName signer = getSigner(signatures);
  if (!name.isPartOf(signer) || !nsecOwner.isPartOf(signer)) {
    return dState::INCONCLUSIVE;
  }

  const DNSName owner = getNSECOwnerName(nsecOwner, signatures);
  /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
     Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
     nonexistence of any RRs below that zone cut, which include all RRs at
     that (original) owner name other than DS RRs, and all RRs below that
     owner name regardless of type.
  */
  if (name.isPartOf(owner) && isNSECAncestorDelegation(signer, owner, nsec)) {
    /* this is an "ancestor delegation" NSEC RR */
    if (qtype != QType::DS || name != owner) {
      VLOG_NO_PREFIX(log, "An ancestor delegation NSEC RR can only deny the existence of a DS"<<endl);
      return dState::NODENIAL;
    }
  }

  /* check if the type is denied */
  if (name == owner) {
    if (!isTypeDenied(nsec, QType(qtype))) {
      VLOG_NO_PREFIX(log, "does _not_ deny existence of type "<<QType(qtype)<<endl);
      return dState::NODENIAL;
    }

    if (qtype == QType::DS && signer == name) {
      VLOG_NO_PREFIX(log, "the NSEC comes from the child zone and cannot be used to deny a DS"<<endl);
      return dState::NODENIAL;
    }

    VLOG_NO_PREFIX(log, "Denies existence of type "<<QType(qtype)<<endl);
    return dState::NXQTYPE;
  }

  if (name.isPartOf(owner) && nsec.isSet(QType::DNAME)) {
    /* rfc6672 section 5.3.2: DNAME Bit in NSEC Type Map

       In any negative response, the NSEC or NSEC3 [RFC5155] record type
       bitmap SHOULD be checked to see that there was no DNAME that could
       have been applied.  If the DNAME bit in the type bitmap is set and
       the query name is a subdomain of the closest encloser that is
       asserted, then DNAME substitution should have been done, but the
       substitution has not been done as specified.
    */
    VLOG(log, "the DNAME bit is set and the query name is a subdomain of that NSEC");
    return dState::NODENIAL;
  }

  if (isCoveredByNSEC(name, owner, nsec.d_next)) {
    VLOG_NO_PREFIX(log, name << ": is covered by ("<<owner<<" to "<<nsec.d_next<<")");

    if (nsecProvesENT(name, owner, nsec.d_next)) {
      VLOG_NO_PREFIX(log, " denies existence of type "<<name<<"/"<<QType(qtype)<<" by proving that "<<name<<" is an ENT"<<endl);
      return dState::NXQTYPE;
    }

    return dState::NXDOMAIN;
  }

  return dState::INCONCLUSIVE;
}

[[nodiscard]] uint64_t getNSEC3DenialProofWorstCaseIterationsCount(uint8_t maxLabels, uint16_t iterations, size_t saltLength)
{
  return static_cast<uint64_t>((iterations + 1U + (saltLength > 0 ? 1U : 0U))) * maxLabels;
}

/*
  This function checks whether the existence of qname|qtype is denied by the NSEC and NSEC3
  in validrrsets.
  - If `referralToUnsigned` is true and qtype is QType::DS, this functions returns NODENIAL
  if a NSEC or NSEC3 proves that the name exists but no NS type exists, as specified in RFC 5155 section 8.9.
  - If `wantsNoDataProof` is set but a NSEC proves that the whole name does not exist, the function will return
  NXQTYPE if the name is proven to be ENT and NXDOMAIN otherwise.
  - If `needWildcardProof` is false, the proof that a wildcard covering this qname|qtype is not checked. It is
  useful when we have a positive answer synthesized from a wildcard and we only need to prove that the exact
  name does not exist.
*/
dState getDenial(const cspmap_t &validrrsets, const DNSName& qname, const uint16_t qtype, bool referralToUnsigned, bool wantsNoDataProof, pdns::validation::ValidationContext& context, const OptLog& log, bool needWildcardProof, unsigned int wildcardLabelsCount) // NOLINT(readability-function-cognitive-complexity): https://github.com/PowerDNS/pdns/issues/12791
{
  bool nsec3Seen = false;
  if (!needWildcardProof && wildcardLabelsCount == 0) {
    throw PDNSException("Invalid wildcard labels count for the validation of a positive answer synthesized from a wildcard");
  }

  uint8_t numberOfLabelsOfParentZone{std::numeric_limits<uint8_t>::max()};
  uint16_t nsec3sConsidered = 0;
  for (const auto& validset : validrrsets) {
    VLOG(log, qname << ": Do have: "<<validset.first.first<<"/"<<DNSRecordContent::NumberToType(validset.first.second)<<endl);

    if (validset.first.second==QType::NSEC) {
      for (const auto& record : validset.second.records) {
        VLOG(log, qname << ":\t"<<record->getZoneRepresentation()<<endl);

        if (validset.second.signatures.empty()) {
          continue;
        }

        auto nsec = std::dynamic_pointer_cast<const NSECRecordContent>(record);
        if (!nsec) {
          continue;
        }

        const DNSName owner = getNSECOwnerName(validset.first.first, validset.second.signatures);
        const DNSName signer = getSigner(validset.second.signatures);
        if (!validset.first.first.isPartOf(signer) || !owner.isPartOf(signer) || !qname.isPartOf(signer)) {
           continue;
        }

        /* The NSEC is either a delegation one, from the parent zone, and
         * must have the NS bit set but not the SOA one, or a regular NSEC
         * either at apex (signer == owner) or with the SOA or NS bits clear.
         */
        const bool notApex = signer.countLabels() < owner.countLabels();
        if (notApex && nsec->isSet(QType::NS) && nsec->isSet(QType::SOA)) {
          VLOG(log, qname << ": However, that NSEC is not at the apex and has both the NS and the SOA bits set!"<<endl);
          continue;
        }

        /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
           Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
           nonexistence of any RRs below that zone cut, which include all RRs at
           that (original) owner name other than DS RRs, and all RRs below that
           owner name regardless of type.
        */
        if (qname.isPartOf(owner) && isNSECAncestorDelegation(signer, owner, *nsec)) {
          /* this is an "ancestor delegation" NSEC RR */
          if (qtype != QType::DS || qname != owner) {
            VLOG(log, qname << ": An ancestor delegation NSEC RR can only deny the existence of a DS"<<endl);
            return dState::NODENIAL;
          }
        }

        if (qtype == QType::DS && !qname.isRoot() && signer == qname) {
          VLOG(log, qname << ": A NSEC RR from the child zone cannot deny the existence of a DS"<<endl);
          continue;
        }

        /* check if the type is denied */
        if (qname == owner) {
          if (!isTypeDenied(*nsec, QType(qtype))) {
            VLOG(log, qname << ": Does _not_ deny existence of type "<<QType(qtype)<<endl);
            return dState::NODENIAL;
          }

          VLOG(log, qname << ": Denies existence of type "<<QType(qtype)<<endl);

          /*
           * RFC 4035 Section 2.3:
           * The bitmap for the NSEC RR at a delegation point requires special
           * attention.  Bits corresponding to the delegation NS RRset and any
           * RRsets for which the parent zone has authoritative data MUST be set
           */
          if (referralToUnsigned && qtype == QType::DS) {
            if (!nsec->isSet(QType::NS)) {
              VLOG(log, qname << ": However, no NS record exists at this level!"<<endl);
              return dState::NODENIAL;
            }
          }

          /* we know that the name exists (but this qtype doesn't) so except
             if the answer was generated by a wildcard expansion, no wildcard
             could have matched (rfc4035 section 5.4 bullet 1) */
          if (needWildcardProof && (!isWildcardExpanded(owner, validset.second.signatures) || isWildcardExpandedOntoItself(owner, validset.second.signatures))) {
            needWildcardProof = false;
          }

          if (!needWildcardProof) {
            return dState::NXQTYPE;
          }

          DNSName closestEncloser = getClosestEncloserFromNSEC(qname, owner, nsec->d_next);
          if (provesNoWildCard(qname, qtype, closestEncloser, validrrsets, log)) {
            return dState::NXQTYPE;
          }

          VLOG(log, qname << ": But the existence of a wildcard is not denied for "<<qname<<"/"<<endl);
          return dState::NODENIAL;
        }

        if (qname.isPartOf(owner) && nsec->isSet(QType::DNAME)) {
          /* rfc6672 section 5.3.2: DNAME Bit in NSEC Type Map

             In any negative response, the NSEC or NSEC3 [RFC5155] record type
             bitmap SHOULD be checked to see that there was no DNAME that could
             have been applied.  If the DNAME bit in the type bitmap is set and
             the query name is a subdomain of the closest encloser that is
             asserted, then DNAME substitution should have been done, but the
             substitution has not been done as specified.
          */
          VLOG(log, qname << ": The DNAME bit is set and the query name is a subdomain of that NSEC"<< endl);
          return dState::NODENIAL;
        }

        /* check if the whole NAME is denied existing */
        if (isCoveredByNSEC(qname, owner, nsec->d_next)) {
          VLOG(log, qname<< ": Is covered by ("<<owner<<" to "<<nsec->d_next<<") ");

          if (nsecProvesENT(qname, owner, nsec->d_next)) {
            if (wantsNoDataProof) {
              /* if the name is an ENT and we received a NODATA answer,
                 we are fine with a NSEC proving that the name does not exist. */
              VLOG_NO_PREFIX(log, "Denies existence of type "<<qname<<"/"<<QType(qtype)<<" by proving that "<<qname<<" is an ENT"<<endl);
              return dState::NXQTYPE;
            }
            /* but for a NXDOMAIN proof, this doesn't make sense! */
            VLOG_NO_PREFIX(log, "but it tries to deny the existence of "<<qname<<" by proving that "<<qname<<" is an ENT, this does not make sense!"<<endl);
            return dState::NODENIAL;
          }

          if (!needWildcardProof) {
            VLOG_NO_PREFIX(log, "and we did not need a wildcard proof"<<endl);
            return dState::NXDOMAIN;
          }

          VLOG_NO_PREFIX(log, "but we do need a wildcard proof so ");
          DNSName closestEncloser = getClosestEncloserFromNSEC(qname, owner, nsec->d_next);
          if (wantsNoDataProof) {
            VLOG_NO_PREFIX(log, "looking for NODATA proof"<<endl);
            if (provesNoDataWildCard(qname, qtype, closestEncloser, validrrsets, log)) {
              return dState::NXQTYPE;
            }
          }
          else {
            VLOG_NO_PREFIX(log, "looking for NO wildcard proof"<<endl);
            if (provesNoWildCard(qname, qtype, closestEncloser, validrrsets, log)) {
              return dState::NXDOMAIN;
            }
          }

          VLOG(log, qname << ": But the existence of a wildcard is not denied for "<<qname<<"/"<<endl);
          return dState::NODENIAL;
        }

        VLOG(log, qname << ": Did not deny existence of "<<QType(qtype)<<", "<<validset.first.first<<"?="<<qname<<", "<<nsec->isSet(qtype)<<", next: "<<nsec->d_next<<endl);
      }
    } else if(validset.first.second==QType::NSEC3) {
      for (const auto& record : validset.second.records) {
        VLOG(log, qname << ":\t"<<record->getZoneRepresentation()<<endl);
        auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(record);
        if (!nsec3) {
          continue;
        }

        if (validset.second.signatures.empty()) {
          continue;
        }

        const DNSName& hashedOwner = validset.first.first;
        const DNSName signer = getSigner(validset.second.signatures);
        if (!hashedOwner.isPartOf(signer)) {
          VLOG(log, qname << ": Owner "<<hashedOwner<<" is not part of the signer "<<signer<<", ignoring"<<endl);
          continue;
        }
        numberOfLabelsOfParentZone = std::min(numberOfLabelsOfParentZone, static_cast<uint8_t>(signer.countLabels()));

        if (!qname.isPartOf(signer)) {
          continue;
        }

        if (qtype == QType::DS && !qname.isRoot() && signer == qname) {
          VLOG(log, qname << ": A NSEC3 RR from the child zone cannot deny the existence of a DS"<<endl);
          continue;
        }

        if (g_maxNSEC3sPerRecordToConsider > 0 && nsec3sConsidered >= g_maxNSEC3sPerRecordToConsider) {
          VLOG(log, qname << ": Too many NSEC3s for this record"<<endl);
          context.d_limitHit = true;
          return dState::NODENIAL;
        }
        nsec3sConsidered++;

        string hash = getHashFromNSEC3(qname, *nsec3, context);
        if (hash.empty()) {
          VLOG(log, qname << ": Unsupported hash, ignoring"<<endl);
          return dState::INSECURE;
        }

        nsec3Seen = true;

        VLOG(log, qname << ":\tquery hash: "<<toBase32Hex(hash)<<endl);
        string beginHash = fromBase32Hex(hashedOwner.getRawLabels()[0]);

        // If the name exists, check if the qtype is denied
        if (beginHash == hash) {

          /* The NSEC3 is either a delegation one, from the parent zone, and
           * must have the NS bit set but not the SOA one, or a regular NSEC3
           * either at apex (signer == owner) or with the SOA or NS bits clear.
           */
          const bool notApex = signer.countLabels() < qname.countLabels();
          if (notApex && nsec3->isSet(QType::NS) && nsec3->isSet(QType::SOA)) {
            VLOG(log, qname << ": However, that NSEC3 is not at the apex and has both the NS and the SOA bits set!"<<endl);
            continue;
          }

          /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
             Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
             nonexistence of any RRs below that zone cut, which include all RRs at
             that (original) owner name other than DS RRs, and all RRs below that
             owner name regardless of type.
          */
          if (qtype != QType::DS && isNSEC3AncestorDelegation(signer, qname, *nsec3)) {
            /* this is an "ancestor delegation" NSEC3 RR */
            VLOG(log, qname << ": An ancestor delegation NSEC3 RR can only deny the existence of a DS"<<endl);
            return dState::NODENIAL;
          }

          if (!isTypeDenied(*nsec3, QType(qtype))) {
            VLOG(log, qname << ": Does _not_ deny existence of type "<<QType(qtype)<<" for name "<<qname<<" (not opt-out)."<<endl);
            return dState::NODENIAL;
          }

          VLOG(log, qname << ": Denies existence of type "<<QType(qtype)<<" for name "<<qname<<" (not opt-out)."<<endl);

          /*
           * RFC 5155 section 8.9:
           * If there is an NSEC3 RR present in the response that matches the
           * delegation name, then the validator MUST ensure that the NS bit is
           * set and that the DS bit is not set in the Type Bit Maps field of the
           * NSEC3 RR.
           */
          if (referralToUnsigned && qtype == QType::DS) {
            if (!nsec3->isSet(QType::NS)) {
              VLOG(log, qname << ": However, no NS record exists at this level!"<<endl);
              return dState::NODENIAL;
            }
          }

          return dState::NXQTYPE;
        }
      }
    }
  }

  /* if we have no NSEC3 records, we are done */
  if (!nsec3Seen) {
    return dState::NODENIAL;
  }

  DNSName closestEncloser(qname);
  bool found = false;
  if (needWildcardProof) {
    /* We now need to look for a NSEC3 covering the closest (provable) encloser
       RFC 5155 section-7.2.1
       RFC 7129 section-5.5
    */
    VLOG(log, qname << ": Now looking for the closest encloser for "<<qname<<endl);

    while (!found && closestEncloser.chopOff() && closestEncloser.countLabels() >= numberOfLabelsOfParentZone) {
      nsec3sConsidered = 0;

      for(const auto& validset : validrrsets) {
        if(validset.first.second==QType::NSEC3) {
          for(const auto& record : validset.second.records) {
            VLOG(log, qname << ":\t"<<record->getZoneRepresentation()<<endl);
            auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(record);
            if (!nsec3) {
              continue;
            }

            const DNSName signer = getSigner(validset.second.signatures);
            if (!validset.first.first.isPartOf(signer)) {
              VLOG(log, qname << ": Owner "<<validset.first.first<<" is not part of the signer "<<signer<<", ignoring"<<endl);
              continue;
            }

            if (!closestEncloser.isPartOf(signer)) {
              continue;
            }

            if (g_maxNSEC3sPerRecordToConsider > 0 && nsec3sConsidered >= g_maxNSEC3sPerRecordToConsider) {
              VLOG(log, qname << ": Too many NSEC3s for this record"<<endl);
              context.d_limitHit = true;
              return dState::NODENIAL;
            }
            nsec3sConsidered++;

            string hash = getHashFromNSEC3(closestEncloser, *nsec3, context);
            if (hash.empty()) {
              VLOG(log, qname << ": Unsupported hash, ignoring"<<endl);
              return dState::INSECURE;
            }

            string beginHash=fromBase32Hex(validset.first.first.getRawLabels()[0]);

            VLOG(log, qname << ": Comparing "<<toBase32Hex(hash)<<" ("<<closestEncloser<<") against "<<toBase32Hex(beginHash)<<endl);
            if (beginHash == hash) {
              /* If the closest encloser is a delegation NS we know nothing about the names in the child zone. */
              if (isNSEC3AncestorDelegation(signer, validset.first.first, *nsec3)) {
                VLOG(log, qname << ": An ancestor delegation NSEC3 RR can only deny the existence of a DS"<<endl);
                continue;
              }

              VLOG(log, qname << ": Closest encloser for "<<qname<<" is "<<closestEncloser<<endl);
              found = true;

              if (nsec3->isSet(QType::DNAME)) {
                /* rfc6672 section 5.3.2: DNAME Bit in NSEC Type Map

                   In any negative response, the NSEC or NSEC3 [RFC5155] record type
                   bitmap SHOULD be checked to see that there was no DNAME that could
                   have been applied.  If the DNAME bit in the type bitmap is set and
                   the query name is a subdomain of the closest encloser that is
                   asserted, then DNAME substitution should have been done, but the
                   substitution has not been done as specified.
                */
                VLOG(log, qname << ":\tThe closest encloser NSEC3 has the DNAME bit is set"<<endl);
                return dState::NODENIAL;
              }

              break;
            }
          }
        }
        if (found) {
          break;
        }
      }
    }
  }
  else {
    /* RFC 5155 section-7.2.6:
       "It is not necessary to return an NSEC3 RR that matches the closest encloser,
       as the existence of this closest encloser is proven by the presence of the
       expanded wildcard in the response.
    */
    found = true;
    unsigned int closestEncloserLabelsCount = closestEncloser.countLabels();
    while (wildcardLabelsCount > 0 && closestEncloserLabelsCount > wildcardLabelsCount) {
      closestEncloser.chopOff();
      closestEncloserLabelsCount--;
    }
  }

  bool nextCloserFound = false;
  bool isOptOut = false;

  if (found) {
    /* now that we have found the closest (provable) encloser,
       we can construct the next closer (RFC7129 section-5.5) name
       and look for a NSEC3 RR covering it */
    unsigned int labelIdx = qname.countLabels() - closestEncloser.countLabels();
    if (labelIdx >= 1) {
      DNSName nextCloser(closestEncloser);
      nextCloser.prependRawLabel(qname.getRawLabel(labelIdx - 1));
      nsec3sConsidered = 0;
      VLOG(log, qname << ":Looking for a NSEC3 covering the next closer name "<<nextCloser<<endl);

      for (const auto& validset : validrrsets) {
        if (validset.first.second == QType::NSEC3) {
          for (const auto& record : validset.second.records) {
            VLOG(log, qname << ":\t"<<record->getZoneRepresentation()<<endl);
            auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(record);
            if (!nsec3) {
              continue;
            }

            if (g_maxNSEC3sPerRecordToConsider > 0 && nsec3sConsidered >= g_maxNSEC3sPerRecordToConsider) {
              VLOG(log, qname << ": Too many NSEC3s for this record"<<endl);
              context.d_limitHit = true;
              return dState::NODENIAL;
            }
            nsec3sConsidered++;

            string hash = getHashFromNSEC3(nextCloser, *nsec3, context);
            if (hash.empty()) {
              VLOG(log, qname << ": Unsupported hash, ignoring"<<endl);
              return dState::INSECURE;
            }

            const DNSName signer = getSigner(validset.second.signatures);
            if (!validset.first.first.isPartOf(signer)) {
              VLOG(log, qname << ": Owner "<<validset.first.first<<" is not part of the signer "<<signer<<", ignoring"<<endl);
              continue;
            }

            if (!nextCloser.isPartOf(signer)) {
              continue;
            }

            string beginHash=fromBase32Hex(validset.first.first.getRawLabels()[0]);

            VLOG(log, qname << ": Comparing "<<toBase32Hex(hash)<<" against "<<toBase32Hex(beginHash)<<" -> "<<toBase32Hex(nsec3->d_nexthash)<<endl);
            if (isCoveredByNSEC3Hash(hash, beginHash, nsec3->d_nexthash)) {
              VLOG(log, qname << ": Denies existence of name "<<qname<<"/"<<QType(qtype));
              nextCloserFound = true;

              if (nsec3->isOptOut()) {
                VLOG_NO_PREFIX(log, " but is opt-out!");
                isOptOut = true;
              }

              VLOG_NO_PREFIX(log, endl);
              break;
            }
            VLOG(log, qname << ": Did not cover us ("<<qname<<"), start="<<validset.first.first<<", us="<<toBase32Hex(hash)<<", end="<<toBase32Hex(nsec3->d_nexthash)<<endl);
          }
        }
        if (nextCloserFound) {
          break;
        }
      }
    }
  }

  if (nextCloserFound) {
    bool wildcardExists = false;
    /* RFC 7129 section-5.6 */
    if (needWildcardProof && !provesNSEC3NoWildCard(closestEncloser, qtype, validrrsets, &wildcardExists, log, context)) {
      if (!isOptOut) {
        VLOG(log, qname << ": But the existence of a wildcard is not denied for "<<qname<<"/"<<QType(qtype)<<endl);
        return dState::NODENIAL;
      }
    }

    if (isOptOut) {
      return dState::OPTOUT;
    }
    if (wildcardExists) {
      return dState::NXQTYPE;
    }
    return dState::NXDOMAIN;
  }

  // There were no valid NSEC(3) records
  return dState::NODENIAL;
}

bool isRRSIGNotExpired(const time_t now, const RRSIGRecordContent& sig)
{
  return rfc1982LessThanOrEqual<uint32_t>(now, sig.d_sigexpire);
}

bool isRRSIGIncepted(const time_t now, const RRSIGRecordContent& sig)
{
  return rfc1982LessThanOrEqual<uint32_t>(sig.d_siginception - g_signatureInceptionSkew, now);
}

namespace {
[[nodiscard]] bool checkSignatureInceptionAndExpiry(const DNSName& qname, time_t now, const RRSIGRecordContent& sig, vState& ede, const OptLog& log)
{
  /* rfc4035:
     - The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
     - The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
  */
  vState localEDE = vState::Indeterminate;
  if (!isRRSIGIncepted(now, sig)) {
    localEDE = vState::BogusSignatureNotYetValid;
  }
  else if (!isRRSIGNotExpired(now, sig)) {
    localEDE = vState::BogusSignatureExpired;
  }
  if (localEDE == vState::Indeterminate) {
    return true;
  }
  ede = localEDE;
  VLOG(log, qname << ": Signature is "<<(ede == vState::BogusSignatureNotYetValid ? "not yet valid" : "expired")<<" (inception: "<<sig.d_siginception<<", inception skew: "<<g_signatureInceptionSkew<<", expiration: "<<sig.d_sigexpire<<", now: "<<now<<")"<<endl);
  return false;
}

[[nodiscard]] bool checkSignatureWithKey(const DNSName& qname, const RRSIGRecordContent& sig, const DNSKEYRecordContent& key, const std::string& msg, vState& ede, const OptLog& log)
{
  bool result = false;
  try {
    auto dke = DNSCryptoKeyEngine::makeFromPublicKeyString(key.d_algorithm, key.d_key);
    result = dke->verify(msg, sig.d_signature);
    VLOG(log, qname << ": Signature by key with tag "<<sig.d_tag<<" and algorithm "<<DNSSECKeeper::algorithm2name(sig.d_algorithm)<<" was " << (result ? "" : "NOT ")<<"valid"<<endl);
    if (!result) {
      ede = vState::BogusNoValidRRSIG;
    }
  }
  catch (const std::exception& e) {
    VLOG(log, qname << ": Could not make a validator for signature: "<<e.what()<<endl);
    ede = vState::BogusUnsupportedDNSKEYAlgo;
  }
  return result;
}

}

vState validateWithKeySet(time_t now, const DNSName& name, const sortedRecords_t& toSign, const vector<shared_ptr<const RRSIGRecordContent> >& signatures, const skeyset_t& keys, const OptLog& log, pdns::validation::ValidationContext& context, bool validateAllSigs)
{
  bool missingKey = false;
  bool isValid = false;
  bool allExpired = true;
  bool noneIncepted = true;
  uint16_t signaturesConsidered = 0;

  for (const auto& signature : signatures) {
    unsigned int labelCount = name.countLabels();
    if (signature->d_labels > labelCount) {
      VLOG(log, name<<": Discarding invalid RRSIG whose label count is "<<signature->d_labels<<" while the RRset owner name has only "<<labelCount<<endl);
      continue;
    }

    vState ede = vState::Indeterminate;
    if (!DNSCryptoKeyEngine::isAlgorithmSupported(signature->d_algorithm)) {
        continue;
    }
    if (!checkSignatureInceptionAndExpiry(name, now, *signature, ede, log)) {
      if (isRRSIGIncepted(now, *signature)) {
        noneIncepted = false;
      }
      if (isRRSIGNotExpired(now, *signature)) {
        allExpired = false;
      }
      continue;
    }

    if (g_maxRRSIGsPerRecordToConsider > 0 && signaturesConsidered >= g_maxRRSIGsPerRecordToConsider) {
      VLOG(log, name<<": We have already considered "<<std::to_string(signaturesConsidered)<<" RRSIG"<<addS(signaturesConsidered)<<" for this record, stopping now"<<endl;);
      // possibly going Bogus, the RRSIGs have not been validated so Insecure would be wrong
      context.d_limitHit = true;
      break;
    }
    signaturesConsidered++;
    context.d_validationsCounter++;

    auto keysMatchingTag = getByTag(keys, signature->d_tag, signature->d_algorithm, log);

    if (keysMatchingTag.empty()) {
      VLOG(log, name << ": No key provided for "<<signature->d_tag<<" and algorithm "<<std::to_string(signature->d_algorithm)<<endl;);
      missingKey = true;
      continue;
    }

    string msg = getMessageForRRSET(name, *signature, toSign, true);
    uint16_t dnskeysConsidered = 0;
    for (const auto& key : keysMatchingTag) {
      if (g_maxDNSKEYsToConsider > 0 && dnskeysConsidered >= g_maxDNSKEYsToConsider) {
        VLOG(log, name << ": We have already considered "<<std::to_string(dnskeysConsidered)<<" DNSKEY"<<addS(dnskeysConsidered)<<" for tag "<<std::to_string(signature->d_tag)<<" and algorithm "<<std::to_string(signature->d_algorithm)<<", not considering the remaining ones for this signature"<<endl;);
        if (!isValid) {
          context.d_limitHit = true;
        }
        return isValid ? vState::Secure : vState::BogusNoValidRRSIG;
      }
      dnskeysConsidered++;

      bool signIsValid = checkSignatureWithKey(name, *signature, *key, msg, ede, log);

      if (signIsValid) {
        isValid = true;
        VLOG(log, name<< ": Validated "<<name<<"/"<<DNSRecordContent::NumberToType(signature->d_type)<<endl);
        //	  cerr<<"valid"<<endl;
        //	  cerr<<"! validated "<<i->first.first<<"/"<<)<<endl;
      }
      else {
        VLOG(log, name << ": signature invalid"<<endl);
        if (isRRSIGIncepted(now, *signature)) {
          noneIncepted = false;
        }
        if (isRRSIGNotExpired(now, *signature)) {
          allExpired = false;
        }
      }

      if (signIsValid && !validateAllSigs) {
        return vState::Secure;
      }
    }
  }

  if (isValid) {
    return vState::Secure;
  }
  if (missingKey) {
    return vState::BogusNoValidRRSIG;
  }
  if (noneIncepted) {
    // ede should be vState::BogusSignatureNotYetValid
    return vState::BogusSignatureNotYetValid;
  }
  if (allExpired) {
    // ede should be vState::BogusSignatureExpired);
    return vState::BogusSignatureExpired;
  }

  return vState::BogusNoValidRRSIG;
}

bool getTrustAnchor(const map<DNSName,dsset_t>& anchors, const DNSName& zone, dsset_t &res)
{
  const auto& iter = anchors.find(zone);

  if (iter == anchors.cend()) {
    return false;
  }

  res = iter->second;
  return true;
}

bool haveNegativeTrustAnchor(const map<DNSName,std::string>& negAnchors, const DNSName& zone, std::string& reason)
{
  const auto& iter = negAnchors.find(zone);

  if (iter == negAnchors.cend()) {
    return false;
  }

  reason = iter->second;
  return true;
}

vState validateDNSKeysAgainstDS(time_t now, const DNSName& zone, const dsset_t& dsset, const skeyset_t& tkeys, const sortedRecords_t& toSign, const vector<shared_ptr<const RRSIGRecordContent> >& sigs, skeyset_t& validkeys, const OptLog& log, pdns::validation::ValidationContext& context) // NOLINT(readability-function-cognitive-complexity)
{
  /*
   * Check all DNSKEY records against all DS records and place all DNSKEY records
   * that have DS records (that we support the algo for) in the tentative key storage
   */
  uint16_t dssConsidered = 0;
  for (const auto& dsrc : dsset) {
    if (g_maxDSsToConsider > 0 && dssConsidered > g_maxDSsToConsider) {
      VLOG(log, zone << ": We have already considered "<<std::to_string(dssConsidered)<<" DS"<<addS(dssConsidered)<<", not considering the remaining ones"<<endl;);
      return vState::BogusNoValidDNSKEY;
    }
    ++dssConsidered;

    uint16_t dnskeysConsidered = 0;
    auto record = getByTag(tkeys, dsrc.d_tag, dsrc.d_algorithm, log);
    // cerr<<"looking at DS with tag "<<dsrc.d_tag<<", algo "<<DNSSECKeeper::algorithm2name(dsrc.d_algorithm)<<", digest "<<std::to_string(dsrc.d_digesttype)<<" for "<<zone<<", got "<<r.size()<<" DNSKEYs for tag"<<endl;

    for (const auto& drc : record) {
      bool isValid = false;
      bool dsCreated = false;
      DSRecordContent dsrc2;

      if (g_maxDNSKEYsToConsider > 0 && dnskeysConsidered >= g_maxDNSKEYsToConsider) {
        VLOG(log, zone << ": We have already considered "<<std::to_string(dnskeysConsidered)<<" DNSKEY"<<addS(dnskeysConsidered)<<" for tag "<<std::to_string(dsrc.d_tag)<<" and algorithm "<<std::to_string(dsrc.d_algorithm)<<", not considering the remaining ones for this DS"<<endl;);
        // we need to break because we can have a partially validated set
        // where the KSK signs the ZSK(s), and even if we don't
        // we are going to try to get the correct EDE status (revoked, expired, ...)
        context.d_limitHit = true;
        break;
      }
      dnskeysConsidered++;

      try {
        dsrc2 = makeDSFromDNSKey(zone, *drc, dsrc.d_digesttype);
        dsCreated = true;
        isValid = dsrc == dsrc2;
      }
      catch (const std::exception &e) {
        VLOG(log, zone << ": Unable to make DS from DNSKey: "<<e.what()<<endl);
      }

      if (isValid) {
        VLOG(log, zone << ": got valid DNSKEY (it matches the DS) with tag "<<dsrc.d_tag<<" and algorithm "<<std::to_string(dsrc.d_algorithm)<<" for "<<zone<<endl);

        validkeys.insert(drc);
      }
      else {
        if (dsCreated) {
          VLOG(log, zone << ": DNSKEY did not match the DS, parent DS: "<<dsrc.getZoneRepresentation() << " ! = "<<dsrc2.getZoneRepresentation()<<endl);
        }
      }
    }
  }

  vState ede = vState::BogusNoValidDNSKEY;

  //    cerr<<"got "<<validkeys.size()<<"/"<<tkeys.size()<<" valid/tentative keys"<<endl;
  // these counts could be off if we somehow ended up with
  // duplicate keys. Should switch to a type that prevents that.
  if (!tkeys.empty() && validkeys.size() < tkeys.size()) {
    // this should mean that we have one or more DS-validated DNSKEYs
    // but not a fully validated DNSKEY set, yet
    // one of these valid DNSKEYs should be able to validate the
    // whole set
    uint16_t signaturesConsidered = 0;
    for (const auto& sig : sigs) {
      if (!DNSCryptoKeyEngine::isAlgorithmSupported(sig->d_algorithm)) {
        continue;
      }
      if (!checkSignatureInceptionAndExpiry(zone, now, *sig, ede, log)) {
        continue;
      }

      //        cerr<<"got sig for keytag "<<i->d_tag<<" matching "<<getByTag(tkeys, i->d_tag).size()<<" keys of which "<<getByTag(validkeys, i->d_tag).size()<<" valid"<<endl;
      auto bytag = getByTag(validkeys, sig->d_tag, sig->d_algorithm, log);

      if (bytag.empty()) {
        continue;
      }

      if (g_maxRRSIGsPerRecordToConsider > 0 && signaturesConsidered >= g_maxRRSIGsPerRecordToConsider) {
        VLOG(log, zone << ": We have already considered "<<std::to_string(signaturesConsidered)<<" RRSIG"<<addS(signaturesConsidered)<<" for this record, stopping now"<<endl;);
        // possibly going Bogus, the RRSIGs have not been validated so Insecure would be wrong
        context.d_limitHit = true;
        return vState::BogusNoValidDNSKEY;
      }

      string msg = getMessageForRRSET(zone, *sig, toSign);
      uint16_t dnskeysConsidered = 0;
      for (const auto& key : bytag) {
        if (g_maxDNSKEYsToConsider > 0 && dnskeysConsidered >= g_maxDNSKEYsToConsider) {
          VLOG(log, zone << ": We have already considered "<<std::to_string(dnskeysConsidered)<<" DNSKEY"<<addS(dnskeysConsidered)<<" for tag "<<std::to_string(sig->d_tag)<<" and algorithm "<<std::to_string(sig->d_algorithm)<<", not considering the remaining ones for this signature"<<endl;);
          context.d_limitHit = true;
          return vState::BogusNoValidDNSKEY;
        }
        dnskeysConsidered++;

        if (g_maxRRSIGsPerRecordToConsider > 0 && signaturesConsidered >= g_maxRRSIGsPerRecordToConsider) {
          VLOG(log, zone << ": We have already considered "<<std::to_string(signaturesConsidered)<<" RRSIG"<<addS(signaturesConsidered)<<" for this record, stopping now"<<endl;);
          // possibly going Bogus, the RRSIGs have not been validated so Insecure would be wrong
          context.d_limitHit = true;
          return vState::BogusNoValidDNSKEY;
        }
        //          cerr<<"validating : ";
        bool signIsValid = checkSignatureWithKey(zone, *sig, *key, msg, ede, log);
        signaturesConsidered++;
        context.d_validationsCounter++;

        if (signIsValid) {
          VLOG(log, zone << ": Validation succeeded - whole DNSKEY set is valid"<<endl);
          validkeys = tkeys;
          break;
        }
        VLOG(log, zone << ": Validation did not succeed!"<<endl);
      }

      if (validkeys.size() == tkeys.size()) {
        // we validated the whole DNSKEY set already */
        break;
      }
      //        if(validkeys.empty()) cerr<<"did not manage to validate DNSKEY set based on DS-validated KSK, only passing KSK on"<<endl;
    }
  }

  if (validkeys.size() < tkeys.size()) {
    /* so we failed to validate the whole set, let's try to find out why exactly */
    bool dnskeyAlgoSupported = false;
    bool dsDigestSupported = false;

    for (const auto& dsrc : dsset)
    {
      if (DNSCryptoKeyEngine::isAlgorithmSupported(dsrc.d_algorithm)) {
        dnskeyAlgoSupported = true;
        if (DNSCryptoKeyEngine::isDigestSupported(dsrc.d_digesttype)) {
          dsDigestSupported = true;
        }
      }
    }

    if (!dnskeyAlgoSupported) {
      return vState::BogusUnsupportedDNSKEYAlgo;
    }
    if (!dsDigestSupported) {
      return vState::BogusUnsupportedDSDigestType;
    }

    bool zoneKey = false;
    bool notRevoked = false;
    bool validProtocol = false;

    for (const auto& key : tkeys) {
      if (!isAZoneKey(*key)) {
        continue;
      }
      zoneKey = true;

      if (isRevokedKey(*key)) {
        continue;
      }
      notRevoked = true;

      if (key->d_protocol != 3) {
        continue;
      }
      validProtocol = true;
    }

    if (!zoneKey) {
      return vState::BogusNoZoneKeyBitSet;
    }
    if (!notRevoked) {
      return vState::BogusRevokedDNSKEY;
    }
    if (!validProtocol) {
      return vState::BogusInvalidDNSKEYProtocol;
    }

    return ede;
  }

  return vState::Secure;
}

bool isSupportedDS(const DSRecordContent& dsrec, const OptLog& log)
{
  if (!DNSCryptoKeyEngine::isAlgorithmSupported(dsrec.d_algorithm)) {
    VLOG(log, "Discarding DS "<<dsrec.d_tag<<" because we don't support algorithm number "<<std::to_string(dsrec.d_algorithm)<<endl);
    return false;
  }

  if (!DNSCryptoKeyEngine::isDigestSupported(dsrec.d_digesttype)) {
    VLOG(log, "Discarding DS "<<dsrec.d_tag<<" because we don't support digest number "<<std::to_string(dsrec.d_digesttype)<<endl);
    return false;
  }

  return true;
}

DNSName getSigner(const std::vector<std::shared_ptr<const RRSIGRecordContent> >& signatures)
{
  for (const auto& sig : signatures) {
    if (sig) {
      return sig->d_signer;
    }
  }

  return {};
}

const std::string& vStateToString(vState state)
{
  static const std::vector<std::string> vStates = {"Indeterminate", "Insecure", "Secure", "NTA", "TA", "Bogus - No valid DNSKEY", "Bogus - Invalid denial", "Bogus - Unable to get DSs", "Bogus - Unable to get DNSKEYs", "Bogus - Self Signed DS", "Bogus - No RRSIG", "Bogus - No valid RRSIG", "Bogus - Missing negative indication", "Bogus - Signature not yet valid", "Bogus - Signature expired", "Bogus - Unsupported DNSKEY algorithm", "Bogus - Unsupported DS digest type", "Bogus - No zone key bit set", "Bogus - Revoked DNSKEY", "Bogus - Invalid DNSKEY Protocol" };
  return vStates.at(static_cast<size_t>(state));
}

std::ostream& operator<<(std::ostream &ostr, const vState dstate)
{
  ostr<<vStateToString(dstate);
  return ostr;
}

std::ostream& operator<<(std::ostream &ostr, const dState dstate)
{
  static const std::vector<std::string> dStates = {"no denial", "inconclusive", "nxdomain", "nxqtype", "empty non-terminal", "insecure", "opt-out"};
  ostr<<dStates.at(static_cast<size_t>(dstate));
  return ostr;
}

void updateDNSSECValidationState(vState& state, const vState stateUpdate)
{
  if (stateUpdate == vState::TA) {
    state = vState::Secure;
  }
  else if (stateUpdate == vState::NTA) {
    state = vState::Insecure;
  }
  else if (vStateIsBogus(stateUpdate) || state == vState::Indeterminate) {
    state = stateUpdate;
  }
  else if (stateUpdate == vState::Insecure) {
    if (!vStateIsBogus(state)) {
      state = vState::Insecure;
    }
  }
}
