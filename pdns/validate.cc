#include "validate.hh"
#include "misc.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "rec-lua-conf.hh"
#include "base32.hh"
#include "logger.hh"

time_t g_signatureInceptionSkew{0};
uint16_t g_maxNSEC3Iterations{0};

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

bool isCoveredByNSEC3Hash(const std::string& h, const std::string& beginHash, const std::string& nextHash)
{
  return ((beginHash < h && h < nextHash) ||          // no wrap          BEGINNING --- HASH -- END
          (nextHash > h  && beginHash > nextHash) ||  // wrap             HASH --- END --- BEGINNING
          (nextHash < beginHash  && beginHash < h) || // wrap other case  END --- BEGINNING --- HASH
          (beginHash == nextHash && h != beginHash));   // "we have only 1 NSEC3 record, LOL!"
}

bool isCoveredByNSEC3Hash(const DNSName& h, const DNSName& beginHash, const DNSName& nextHash)
{
  return ((beginHash.canonCompare(h) && h.canonCompare(nextHash)) ||          // no wrap          BEGINNING --- HASH -- END
          (h.canonCompare(nextHash) && nextHash.canonCompare(beginHash)) ||  // wrap             HASH --- END --- BEGINNING
          (nextHash.canonCompare(beginHash) && beginHash.canonCompare(h)) || // wrap other case  END --- BEGINNING --- HASH
          (beginHash == nextHash && h != beginHash));   // "we have only 1 NSEC3 record, LOL!"
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

using nsec3HashesCache = std::map<std::tuple<DNSName, std::string, uint16_t>, std::string>;

static std::string getHashFromNSEC3(const DNSName& qname, const NSEC3RecordContent& nsec3, nsec3HashesCache& cache)
{
  std::string result;

  if (g_maxNSEC3Iterations && nsec3.d_iterations > g_maxNSEC3Iterations) {
    return result;
  }

  auto key = std::make_tuple(qname, nsec3.d_salt, nsec3.d_iterations);
  auto it = cache.find(key);
  if (it != cache.end())
  {
    return it->second;
  }

  result = hashQNameWithSalt(nsec3.d_salt, nsec3.d_iterations, qname);
  cache[key] = result;
  return result;
}

/* There is no delegation at this exact point if:
   - the name exists but the NS type is not set
   - the name does not exist
   One exception, if the name is covered by an opt-out NSEC3
   it doesn't prove that an insecure delegation doesn't exist.
*/
bool denialProvesNoDelegation(const DNSName& zone, const std::vector<DNSRecord>& dsrecords)
{
  nsec3HashesCache cache;

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

      const string h = getHashFromNSEC3(zone, *nsec3, cache);
      if (h.empty()) {
        return false;
      }

      const string beginHash = fromBase32Hex(record.d_name.getRawLabels()[0]);
      if (beginHash == h) {
        return !nsec3->isSet(QType::NS);
      }

      if (isCoveredByNSEC3Hash(h, beginHash, nsec3->d_nexthash)) {
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
  if (sign.d_labels < labelCount) {
    return true;
  }

  return false;
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
  if (owner.isWildcard() && (labelCount - 1) == sign.d_labels) {
    /* this is a wildcard alright, but it has not been expanded */
    return true;
  }
  return false;
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
  for (const auto& v : validrrsets) {
    VLOG(log, qname << ": Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);
    if (v.first.second == QType::NSEC) {
      for (const auto& r : v.second.records) {
        VLOG(log, ":\t"<<r->getZoneRepresentation()<<endl);
        auto nsec = std::dynamic_pointer_cast<const NSECRecordContent>(r);
        if (!nsec) {
          continue;
        }

        DNSName owner = getNSECOwnerName(v.first.first, v.second.signatures);
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
  for (const auto& v : validrrsets) {
    VLOG(log, qname << ": Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);
    if (v.first.second == QType::NSEC) {
      for (const auto& r : v.second.records) {
        VLOG(log, qname << ":\t"<<r->getZoneRepresentation()<<endl);
        auto nsec = std::dynamic_pointer_cast<const NSECRecordContent>(r);
        if (!nsec) {
          continue;
        }

        const DNSName owner = getNSECOwnerName(v.first.first, v.second.signatures);
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
static bool provesNSEC3NoWildCard(const DNSName& closestEncloser, uint16_t const qtype, const cspmap_t& validrrsets, bool* wildcardExists, nsec3HashesCache& cache, const OptLog& log)
{
  auto wildcard = g_wildcarddnsname + closestEncloser;
  VLOG(log, closestEncloser << ": Trying to prove that there is no wildcard for "<<wildcard<<"/"<<QType(qtype)<<endl);

  for (const auto& v : validrrsets) {
    VLOG(log, closestEncloser << ": Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);
    if (v.first.second == QType::NSEC3) {
      for (const auto& r : v.second.records) {
        VLOG(log, closestEncloser << ":\t"<<r->getZoneRepresentation()<<endl);
        auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(r);
        if (!nsec3) {
          continue;
        }

        const DNSName signer = getSigner(v.second.signatures);
        if (!v.first.first.isPartOf(signer)) {
          continue;
        }

        string h = getHashFromNSEC3(wildcard, *nsec3, cache);
        if (h.empty()) {
          return false;
        }
        VLOG(log, closestEncloser << ":\tWildcard hash: "<<toBase32Hex(h)<<endl);
        string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);
        VLOG(log, closestEncloser << ":\tNSEC3 hash: "<<toBase32Hex(beginHash)<<" -> "<<toBase32Hex(nsec3->d_nexthash)<<endl);

        if (beginHash == h) {
          VLOG(log, closestEncloser << ":\tWildcard hash matches");
          if (wildcardExists) {
            *wildcardExists = true;
          }

          /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
             Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
             nonexistence of any RRs below that zone cut, which include all RRs at
             that (original) owner name other than DS RRs, and all RRs below that
             owner name regardless of type.
          */
          if (qtype != QType::DS && isNSEC3AncestorDelegation(signer, v.first.first, *nsec3)) {
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

        if (isCoveredByNSEC3Hash(h, beginHash, nsec3->d_nexthash)) {
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
    if (!(qtype == QType::DS && name == owner)) {
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

dState getDenial(const cspmap_t &validrrsets, const DNSName& qname, const uint16_t qtype, bool referralToUnsigned, bool wantsNoDataProof, const OptLog& log, bool needWildcardProof, unsigned int wildcardLabelsCount)
{
  nsec3HashesCache cache;
  bool nsec3Seen = false;
  if (!needWildcardProof && wildcardLabelsCount == 0) {
    throw PDNSException("Invalid wildcard labels count for the validation of a positive answer synthesized from a wildcard");
  }

  for (const auto& v : validrrsets) {
    VLOG(log, qname << ": Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);

    if (v.first.second==QType::NSEC) {
      for (const auto& r : v.second.records) {
        VLOG(log, qname << ":\t"<<r->getZoneRepresentation()<<endl);

        if (v.second.signatures.empty()) {
          continue;
        }

        auto nsec = std::dynamic_pointer_cast<const NSECRecordContent>(r);
        if (!nsec) {
          continue;
        }

        const DNSName owner = getNSECOwnerName(v.first.first, v.second.signatures);
        const DNSName signer = getSigner(v.second.signatures);
        if (!v.first.first.isPartOf(signer) || !owner.isPartOf(signer) ) {
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
          if (!(qtype == QType::DS && qname == owner)) {
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
          if (needWildcardProof && (!isWildcardExpanded(owner, v.second.signatures) || isWildcardExpandedOntoItself(owner, v.second.signatures))) {
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
            else {
              /* but for a NXDOMAIN proof, this doesn't make sense! */
              VLOG_NO_PREFIX(log, "but it tries to deny the existence of "<<qname<<" by proving that "<<qname<<" is an ENT, this does not make sense!"<<endl);
              return dState::NODENIAL;
            }
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

        VLOG(log, qname << ": Did not deny existence of "<<QType(qtype)<<", "<<v.first.first<<"?="<<qname<<", "<<nsec->isSet(qtype)<<", next: "<<nsec->d_next<<endl);
      }
    } else if(v.first.second==QType::NSEC3) {
      for (const auto& r : v.second.records) {
        VLOG(log, qname << ":\t"<<r->getZoneRepresentation()<<endl);
        auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(r);
        if (!nsec3) {
          continue;
        }

        if (v.second.signatures.empty()) {
          continue;
        }

        const DNSName& hashedOwner = v.first.first;
        const DNSName signer = getSigner(v.second.signatures);
        if (!hashedOwner.isPartOf(signer)) {
          VLOG(log, qname << ": Owner "<<hashedOwner<<" is not part of the signer "<<signer<<", ignoring"<<endl);
          continue;
        }

        if (qtype == QType::DS && !qname.isRoot() && signer == qname) {
          VLOG(log, qname << ": A NSEC3 RR from the child zone cannot deny the existence of a DS"<<endl);
          continue;
        }

        string h = getHashFromNSEC3(qname, *nsec3, cache);
        if (h.empty()) {
          VLOG(log, qname << ": Unsupported hash, ignoring"<<endl);
          return dState::INSECURE;
        }

        nsec3Seen = true;

        VLOG(log, qname << ":\tquery hash: "<<toBase32Hex(h)<<endl);
        string beginHash = fromBase32Hex(hashedOwner.getRawLabels()[0]);

        // If the name exists, check if the qtype is denied
        if (beginHash == h) {

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

    while (found == false && closestEncloser.chopOff()) {

      for(const auto& v : validrrsets) {
        if(v.first.second==QType::NSEC3) {
          for(const auto& r : v.second.records) {
            VLOG(log, qname << ":\t"<<r->getZoneRepresentation()<<endl);
            auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(r);
            if (!nsec3) {
              continue;
            }

            const DNSName signer = getSigner(v.second.signatures);
            if (!v.first.first.isPartOf(signer)) {
              VLOG(log, qname << ": Owner "<<v.first.first<<" is not part of the signer "<<signer<<", ignoring"<<endl);
              continue;
            }

            string h = getHashFromNSEC3(closestEncloser, *nsec3, cache);
            if (h.empty()) {
              return dState::INSECURE;
            }

            string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);

            VLOG(log, qname << ": Comparing "<<toBase32Hex(h)<<" ("<<closestEncloser<<") against "<<toBase32Hex(beginHash)<<endl);
            if (beginHash == h) {
              /* If the closest encloser is a delegation NS we know nothing about the names in the child zone. */
              if (isNSEC3AncestorDelegation(signer, v.first.first, *nsec3)) {
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
        if (found == true) {
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

  if (found == true) {
    /* now that we have found the closest (provable) encloser,
       we can construct the next closer (RFC7129 section-5.5) name
       and look for a NSEC3 RR covering it */
    unsigned int labelIdx = qname.countLabels() - closestEncloser.countLabels();
    if (labelIdx >= 1) {
      DNSName nextCloser(closestEncloser);
      nextCloser.prependRawLabel(qname.getRawLabel(labelIdx - 1));
      VLOG(log, qname << ":Looking for a NSEC3 covering the next closer name "<<nextCloser<<endl);

      for(const auto& v : validrrsets) {
        if(v.first.second==QType::NSEC3) {
          for(const auto& r : v.second.records) {
            VLOG(log, qname << ":\t"<<r->getZoneRepresentation()<<endl);
            auto nsec3 = std::dynamic_pointer_cast<const NSEC3RecordContent>(r);
            if(!nsec3)
              continue;

            string h = getHashFromNSEC3(nextCloser, *nsec3, cache);
            if (h.empty()) {
              return dState::INSECURE;
            }

            const DNSName signer = getSigner(v.second.signatures);
            if (!v.first.first.isPartOf(signer)) {
              VLOG(log, qname << ": Owner "<<v.first.first<<" is not part of the signer "<<signer<<", ignoring"<<endl);
              continue;
            }

            string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);

            VLOG(log, qname << ": Comparing "<<toBase32Hex(h)<<" against "<<toBase32Hex(beginHash)<<" -> "<<toBase32Hex(nsec3->d_nexthash)<<endl);
            if (isCoveredByNSEC3Hash(h, beginHash, nsec3->d_nexthash)) {
              VLOG(log, qname << ": Denies existence of name "<<qname<<"/"<<QType(qtype));
              nextCloserFound = true;

              if (nsec3->isOptOut()) {
                VLOG_NO_PREFIX(log, " but is opt-out!");
                isOptOut = true;
              }

              VLOG_NO_PREFIX(log, endl);
              break;
            }
            VLOG(log, qname << ": Did not cover us ("<<qname<<"), start="<<v.first.first<<", us="<<toBase32Hex(h)<<", end="<<toBase32Hex(nsec3->d_nexthash)<<endl);
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
    if (needWildcardProof && !provesNSEC3NoWildCard(closestEncloser, qtype, validrrsets, &wildcardExists, cache, log)) {
      if (!isOptOut) {
        VLOG(log, qname << ": But the existence of a wildcard is not denied for "<<qname<<"/"<<QType(qtype)<<endl);
        return dState::NODENIAL;
      }
    }

    if (isOptOut) {
      return dState::OPTOUT;
    }
    else {
      if (wildcardExists) {
        return dState::NXQTYPE;
      }
      return dState::NXDOMAIN;
    }
  }

  // There were no valid NSEC(3) records
  return dState::NODENIAL;
}

bool isRRSIGNotExpired(const time_t now, const RRSIGRecordContent& sig)
{
  // Should use https://www.rfc-editor.org/rfc/rfc4034.txt section 3.1.5
  return sig.d_sigexpire >= now;
}

bool isRRSIGIncepted(const time_t now, const RRSIGRecordContent& sig)
{
  // Should use https://www.rfc-editor.org/rfc/rfc4034.txt section 3.1.5
  return sig.d_siginception - g_signatureInceptionSkew <= now;
}

static bool checkSignatureWithKey(const DNSName& qname, time_t now, const RRSIGRecordContent& sig, const DNSKEYRecordContent& key, const std::string& msg, vState& ede, const OptLog& log)
{
  bool result = false;
  try {
    /* rfc4035:
       - The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
       - The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
    */
    if (isRRSIGIncepted(now, sig) && isRRSIGNotExpired(now, sig)) {
      auto dke = DNSCryptoKeyEngine::makeFromPublicKeyString(key.d_algorithm, key.d_key);
      result = dke->verify(msg, sig.d_signature);
      VLOG(log, qname << ": Signature by key with tag "<<sig.d_tag<<" and algorithm "<<DNSSECKeeper::algorithm2name(sig.d_algorithm)<<" was " << (result ? "" : "NOT ")<<"valid"<<endl);
      if (!result) {
        ede = vState::BogusNoValidRRSIG;
      }
    }
    else {
      ede = ((sig.d_siginception - g_signatureInceptionSkew) > now) ? vState::BogusSignatureNotYetValid : vState::BogusSignatureExpired;
      VLOG(log, qname << ": Signature is "<<(ede == vState::BogusSignatureNotYetValid ? "not yet valid" : "expired")<<" (inception: "<<sig.d_siginception<<", inception skew: "<<g_signatureInceptionSkew<<", expiration: "<<sig.d_sigexpire<<", now: "<<now<<")"<<endl);
     }
  }
  catch (const std::exception& e) {
    VLOG(log, qname << ": Could not make a validator for signature: "<<e.what()<<endl);
    ede = vState::BogusUnsupportedDNSKEYAlgo;
  }
  return result;
}

vState validateWithKeySet(time_t now, const DNSName& name, const sortedRecords_t& toSign, const vector<shared_ptr<const RRSIGRecordContent> >& signatures, const skeyset_t& keys, const OptLog& log, bool validateAllSigs)
{
  bool foundKey = false;
  bool isValid = false;
  bool allExpired = true;
  bool noneIncepted = true;

  for(const auto& signature : signatures) {
    unsigned int labelCount = name.countLabels();
    if (signature->d_labels > labelCount) {
      VLOG(log, name<<": Discarding invalid RRSIG whose label count is "<<signature->d_labels<<" while the RRset owner name has only "<<labelCount<<endl);
      continue;
    }

    auto keysMatchingTag = getByTag(keys, signature->d_tag, signature->d_algorithm, log);

    if (keysMatchingTag.empty()) {
      VLOG(log, name<<"No key provided for "<<signature->d_tag<<" and algorithm "<<std::to_string(signature->d_algorithm)<<endl;);
      continue;
    }

    string msg = getMessageForRRSET(name, *signature, toSign, true);
    for (const auto& key : keysMatchingTag) {
      vState ede;
      bool signIsValid = checkSignatureWithKey(name, now, *signature, *key, msg, ede, log);
      foundKey = true;

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
  if (!foundKey) {
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

// returns vState
// should return vState, zone cut and validated keyset
// i.e. www.7bits.nl -> insecure/7bits.nl/[]
//      www.powerdnssec.org -> secure/powerdnssec.org/[keys]
//      www.dnssec-failed.org -> bogus/dnssec-failed.org/[]

cspmap_t harvestCSPFromRecs(const vector<DNSRecord>& recs)
{
  cspmap_t cspmap;
  for(const auto& rec : recs) {
    //        cerr<<"res "<<rec.d_name<<"/"<<rec.d_type<<endl;
    if(rec.d_type == QType::OPT) continue;

    if(rec.d_type == QType::RRSIG) {
      auto rrc = getRR<RRSIGRecordContent>(rec);
      if (rrc) {
        cspmap[{rec.d_name,rrc->d_type}].signatures.push_back(rrc);
      }
    }
    else {
      cspmap[{rec.d_name, rec.d_type}].records.insert(rec.getContent());
    }
  }
  return cspmap;
}

bool getTrustAnchor(const map<DNSName,dsmap_t>& anchors, const DNSName& zone, dsmap_t &res)
{
  const auto& it = anchors.find(zone);

  if (it == anchors.cend()) {
    return false;
  }

  res = it->second;
  return true;
}

bool haveNegativeTrustAnchor(const map<DNSName,std::string>& negAnchors, const DNSName& zone, std::string& reason)
{
  const auto& it = negAnchors.find(zone);

  if (it == negAnchors.cend()) {
    return false;
  }

  reason = it->second;
  return true;
}

vState validateDNSKeysAgainstDS(time_t now, const DNSName& zone, const dsmap_t& dsmap, const skeyset_t& tkeys, const sortedRecords_t& toSign, const vector<shared_ptr<const RRSIGRecordContent> >& sigs, skeyset_t& validkeys, const OptLog& log)
{
  /*
   * Check all DNSKEY records against all DS records and place all DNSKEY records
   * that have DS records (that we support the algo for) in the tentative key storage
   */
  for (const auto& dsrc : dsmap)
  {
    auto r = getByTag(tkeys, dsrc.d_tag, dsrc.d_algorithm, log);
    // cerr<<"looking at DS with tag "<<dsrc.d_tag<<", algo "<<DNSSECKeeper::algorithm2name(dsrc.d_algorithm)<<", digest "<<std::to_string(dsrc.d_digesttype)<<" for "<<zone<<", got "<<r.size()<<" DNSKEYs for tag"<<endl;

    for (const auto& drc : r)
    {
      bool isValid = false;
      bool dsCreated = false;
      DSRecordContent dsrc2;
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
  if (validkeys.size() < tkeys.size())
  {
    // this should mean that we have one or more DS-validated DNSKEYs
    // but not a fully validated DNSKEY set, yet
    // one of these valid DNSKEYs should be able to validate the
    // whole set
    for (const auto& sig : sigs)
    {
      //        cerr<<"got sig for keytag "<<i->d_tag<<" matching "<<getByTag(tkeys, i->d_tag).size()<<" keys of which "<<getByTag(validkeys, i->d_tag).size()<<" valid"<<endl;
      auto bytag = getByTag(validkeys, sig->d_tag, sig->d_algorithm, log);

      if (bytag.empty()) {
        continue;
      }

      string msg = getMessageForRRSET(zone, *sig, toSign);
      for (const auto& key : bytag) {
        //          cerr<<"validating : ";
        bool signIsValid = checkSignatureWithKey(zone, now, *sig, *key, msg, ede, log);

        if (signIsValid) {
          VLOG(log, zone << ": Validation succeeded - whole DNSKEY set is valid"<<endl);
          validkeys = tkeys;
          break;
        }
        else {
          VLOG(log, zone << ": Validation did not succeed!"<<endl);
        }
      }
      //        if(validkeys.empty()) cerr<<"did not manage to validate DNSKEY set based on DS-validated KSK, only passing KSK on"<<endl;
    }
  }

  if (validkeys.size() < tkeys.size()) {
    /* so we failed to validate the whole set, let's try to find out why exactly */
    bool dnskeyAlgoSupported = false;
    bool dsDigestSupported = false;

    for (const auto& dsrc : dsmap)
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

bool isSupportedDS(const DSRecordContent& ds, const OptLog& log)
{
  if (!DNSCryptoKeyEngine::isAlgorithmSupported(ds.d_algorithm)) {
    VLOG(log, "Discarding DS "<<ds.d_tag<<" because we don't support algorithm number "<<std::to_string(ds.d_algorithm)<<endl);
    return false;
  }

  if (!DNSCryptoKeyEngine::isDigestSupported(ds.d_digesttype)) {
    VLOG(log, "Discarding DS "<<ds.d_tag<<" because we don't support digest number "<<std::to_string(ds.d_digesttype)<<endl);
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

  return DNSName();
}

const std::string& vStateToString(vState state)
{
  static const std::vector<std::string> vStates = {"Indeterminate", "Insecure", "Secure", "NTA", "TA", "Bogus - No valid DNSKEY", "Bogus - Invalid denial", "Bogus - Unable to get DSs", "Bogus - Unable to get DNSKEYs", "Bogus - Self Signed DS", "Bogus - No RRSIG", "Bogus - No valid RRSIG", "Bogus - Missing negative indication", "Bogus - Signature not yet valid", "Bogus - Signature expired", "Bogus - Unsupported DNSKEY algorithm", "Bogus - Unsupported DS digest type", "Bogus - No zone key bit set", "Bogus - Revoked DNSKEY", "Bogus - Invalid DNSKEY Protocol" };
  return vStates.at(static_cast<size_t>(state));
}

std::ostream& operator<<(std::ostream &os, const vState d)
{
  os<<vStateToString(d);
  return os;
}

std::ostream& operator<<(std::ostream &os, const dState d)
{
  static const std::vector<std::string> dStates = {"no denial", "inconclusive", "nxdomain", "nxqtype", "empty non-terminal", "insecure", "opt-out"};
  os<<dStates.at(static_cast<size_t>(d));
  return os;
}

void updateDNSSECValidationState(vState& state, const vState stateUpdate)
{
  if (stateUpdate == vState::TA) {
    state = vState::Secure;
  }
  else if (stateUpdate == vState::NTA) {
    state = vState::Insecure;
  }
  else if (vStateIsBogus(stateUpdate)) {
    state = stateUpdate;
  }
  else if (state == vState::Indeterminate) {
    state = stateUpdate;
  }
  else if (stateUpdate == vState::Insecure) {
    if (!vStateIsBogus(state)) {
      state = vState::Insecure;
    }
  }
}
