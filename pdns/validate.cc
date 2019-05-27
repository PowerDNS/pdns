#include "validate.hh"
#include "misc.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "rec-lua-conf.hh"
#include "base32.hh"
#include "logger.hh"
bool g_dnssecLOG{false};
time_t g_signatureInceptionSkew{0};
uint16_t g_maxNSEC3Iterations{0};

#define LOG(x) if(g_dnssecLOG) { g_log <<Logger::Warning << x; }

const char *dStates[]={"nodata", "nxdomain", "nxqtype", "empty non-terminal", "insecure", "opt-out"};
const char *vStates[]={"Indeterminate", "Bogus", "Insecure", "Secure", "NTA", "TA"};

static vector<shared_ptr<DNSKEYRecordContent > > getByTag(const skeyset_t& keys, uint16_t tag, uint8_t algorithm)
{
  vector<shared_ptr<DNSKEYRecordContent>> ret;
  for(const auto& key : keys)
    if(key->d_protocol == 3 && key->getTag() == tag && key->d_algorithm == algorithm)
      ret.push_back(key);
  return ret;
}

static bool isCoveredByNSEC3Hash(const std::string& h, const std::string& beginHash, const std::string& nextHash)
{
  return ((beginHash < h && h < nextHash) ||          // no wrap          BEGINNING --- HASH -- END
          (nextHash > h  && beginHash > nextHash) ||  // wrap             HASH --- END --- BEGINNING
          (nextHash < beginHash  && beginHash < h) || // wrap other case  END --- BEGINNING --- HASH
          (beginHash == nextHash && h != beginHash));   // "we have only 1 NSEC3 record, LOL!"
}

static bool isCoveredByNSEC(const DNSName& name, const DNSName& begin, const DNSName& next)
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

static std::string getHashFromNSEC3(const DNSName& qname, const std::shared_ptr<NSEC3RecordContent>& nsec3)
{
  std::string result;

  if (g_maxNSEC3Iterations && nsec3->d_iterations > g_maxNSEC3Iterations) {
    return result;
  }

  return hashQNameWithSalt(nsec3->d_salt, nsec3->d_iterations, qname);
}

/* There is no delegation at this exact point if:
   - the name exists but the NS type is not set
   - the name does not exist
   One exception, if the name is covered by an opt-out NSEC3
   it doesn't prove that an insecure delegation doesn't exist.
*/
bool denialProvesNoDelegation(const DNSName& zone, const std::vector<DNSRecord>& dsrecords)
{
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

      const string h = getHashFromNSEC3(zone, nsec3);
      if (h.empty()) {
        return false;
      }

      const string beginHash = fromBase32Hex(record.d_name.getRawLabels()[0]);
      if (beginHash == h) {
        return !nsec3->isSet(QType::NS);
      }

      if (isCoveredByNSEC3Hash(h, beginHash, nsec3->d_nexthash)) {
        return !(nsec3->d_flags & 1);
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
bool isWildcardExpanded(unsigned int labelCount, const std::shared_ptr<RRSIGRecordContent>& sign)
{
  if (sign && sign->d_labels < labelCount) {
    return true;
  }

  return false;
}

static bool isWildcardExpanded(const DNSName& owner, const std::vector<std::shared_ptr<RRSIGRecordContent> >& signatures)
{
  if (signatures.empty()) {
    return false;
  }

  const auto& sign = signatures.at(0);
  unsigned int labelsCount = owner.countLabels();
  return isWildcardExpanded(labelsCount, sign);
}

bool isWildcardExpandedOntoItself(const DNSName& owner, unsigned int labelCount, const std::shared_ptr<RRSIGRecordContent>& sign)
{
  if (owner.isWildcard() && (labelCount - 1) == sign->d_labels) {
    /* this is a wildcard alright, but it has not been expanded */
    return true;
  }
  return false;
}

static bool isWildcardExpandedOntoItself(const DNSName& owner, const std::vector<std::shared_ptr<RRSIGRecordContent> >& signatures)
{
  if (signatures.empty()) {
    return false;
  }

  const auto& sign = signatures.at(0);
  unsigned int labelsCount = owner.countLabels();
  return isWildcardExpandedOntoItself(owner, labelsCount, sign);
}

/* if this is a wildcard NSEC, the owner name has been modified
   to match the name. Make sure we use the original '*' form. */
static DNSName getNSECOwnerName(const DNSName& initialOwner, const std::vector<std::shared_ptr<RRSIGRecordContent> >& signatures)
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

static bool isNSECAncestorDelegation(const DNSName& signer, const DNSName& owner, const std::shared_ptr<NSECRecordContent>& nsec)
{
  return nsec->isSet(QType::NS) &&
    !nsec->isSet(QType::SOA) &&
    signer.countLabels() < owner.countLabels();
}

static bool isNSEC3AncestorDelegation(const DNSName& signer, const DNSName& owner, const std::shared_ptr<NSEC3RecordContent>& nsec3)
{
  return nsec3->isSet(QType::NS) &&
    !nsec3->isSet(QType::SOA) &&
    signer.countLabels() < owner.countLabels();
}

static bool provesNoDataWildCard(const DNSName& qname, const uint16_t qtype, const cspmap_t& validrrsets)
{
  LOG("Trying to prove that there is no data in wildcard for "<<qname<<"/"<<QType(qtype).getName()<<endl);
  for (const auto& v : validrrsets) {
    LOG("Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);
    if (v.first.second == QType::NSEC) {
      for (const auto& r : v.second.records) {
        LOG("\t"<<r->getZoneRepresentation()<<endl);
        auto nsec = std::dynamic_pointer_cast<NSECRecordContent>(r);
        if (!nsec) {
          continue;
        }

        if (!v.first.first.isWildcard()) {
          continue;
        }
        DNSName wildcard = getNSECOwnerName(v.first.first, v.second.signatures);
        if (qname.countLabels() < wildcard.countLabels()) {
          continue;
        }

        wildcard.chopOff();

        if (qname.isPartOf(wildcard)) {
          LOG("\tWildcard matches");
          if (qtype == 0 || !nsec->isSet(qtype)) {
            LOG(" and proves that the type did not exist"<<endl);
            return true;
          }
          LOG(" BUT the type did exist!"<<endl);
          return false;
        }
      }
    }
  }

  return false;
}

/*
  This function checks whether the non-existence of a wildcard covering qname|qtype
  is proven by the NSEC records in validrrsets.
*/
static bool provesNoWildCard(const DNSName& qname, const uint16_t qtype, const cspmap_t & validrrsets)
{
  LOG("Trying to prove that there is no wildcard for "<<qname<<"/"<<QType(qtype).getName()<<endl);
  for (const auto& v : validrrsets) {
    LOG("Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);
    if (v.first.second == QType::NSEC) {
      for (const auto& r : v.second.records) {
        LOG("\t"<<r->getZoneRepresentation()<<endl);
        auto nsec = std::dynamic_pointer_cast<NSECRecordContent>(r);
        if (!nsec) {
          continue;
        }

        const DNSName owner = getNSECOwnerName(v.first.first, v.second.signatures);
        /*
          A NSEC can only prove the non-existence of a wildcard with at least the same
          number of labels than the intersection of its owner name and next name.
        */
        const DNSName commonLabels = owner.getCommonLabels(nsec->d_next);
        unsigned int commonLabelsCount = commonLabels.countLabels();

        DNSName wildcard(qname);
        unsigned int wildcardLabelsCount = wildcard.countLabels();
        while (wildcard.chopOff() && wildcardLabelsCount >= commonLabelsCount) {
          DNSName target = g_wildcarddnsname + wildcard;

          LOG("Comparing owner: "<<owner<<" with target: "<<target<<endl);

          if (isCoveredByNSEC(target, owner, nsec->d_next)) {
            LOG("\tWildcard is covered"<<endl);
            return true;
          }
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
static bool provesNSEC3NoWildCard(DNSName wildcard, uint16_t const qtype, const cspmap_t & validrrsets, bool * wildcardExists=nullptr)
{
  wildcard = g_wildcarddnsname + wildcard;
  LOG("Trying to prove that there is no wildcard for "<<wildcard<<"/"<<QType(qtype).getName()<<endl);

  for (const auto& v : validrrsets) {
    LOG("Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);
    if (v.first.second == QType::NSEC3) {
      for (const auto& r : v.second.records) {
        LOG("\t"<<r->getZoneRepresentation()<<endl);
        auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(r);
        if (!nsec3) {
          continue;
        }

        const DNSName signer = getSigner(v.second.signatures);
        if (!v.first.first.isPartOf(signer))
          continue;

        string h = getHashFromNSEC3(wildcard, nsec3);
        if (h.empty()) {
          return false;
        }
        LOG("\tWildcard hash: "<<toBase32Hex(h)<<endl);
        string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);
        LOG("\tNSEC3 hash: "<<toBase32Hex(beginHash)<<" -> "<<toBase32Hex(nsec3->d_nexthash)<<endl);

        if (beginHash == h) {
          LOG("\tWildcard hash matches");
          if (wildcardExists) {
            *wildcardExists = true;
          }
          if (qtype == 0 || !nsec3->isSet(qtype)) {
            LOG(" and proves that the type did not exist"<<endl);
            return true;
          }
          LOG(" BUT the type did exist!"<<endl);
          return false;
        }

        if (isCoveredByNSEC3Hash(h, beginHash, nsec3->d_nexthash)) {
          LOG("\tWildcard hash is covered"<<endl);
          return true;
        }
      }
    }
  }

  return false;
}

/*
  This function checks whether the existence of qname|qtype is denied by the NSEC and NSEC3
  in validrrsets.
  - If `referralToUnsigned` is true and qtype is QType::DS, this functions returns NODATA
  if a NSEC or NSEC3 proves that the name exists but no NS type exists, as specified in RFC 5155 section 8.9.
  - If `wantsNoDataProof` is set but a NSEC proves that the whole name does not exist, the function will return
  NXQTYPE is the name is proven to be ENT and NXDOMAIN otherwise.
  - If `needWildcardProof` is false, the proof that a wildcard covering this qname|qtype is not checked. It is
  useful when we have a positive answer synthetized from a wildcard and we only need to prove that the exact
  name does not exist.
*/
dState getDenial(const cspmap_t &validrrsets, const DNSName& qname, const uint16_t qtype, bool referralToUnsigned, bool wantsNoDataProof, bool needWildcardProof, unsigned int wildcardLabelsCount)
{
  bool nsec3Seen = false;
  if (!needWildcardProof && wildcardLabelsCount == 0) {
    throw PDNSException("Invalid wildcard labels count for the validation of a positive answer synthetized from a wildcard");
  }

  for(const auto& v : validrrsets) {
    LOG("Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);

    if(v.first.second==QType::NSEC) {
      for(const auto& r : v.second.records) {
        LOG("\t"<<r->getZoneRepresentation()<<endl);
        auto nsec = std::dynamic_pointer_cast<NSECRecordContent>(r);
        if(!nsec)
          continue;

        const DNSName signer = getSigner(v.second.signatures);
        if (!v.first.first.isPartOf(signer))
          continue;

        const DNSName owner = getNSECOwnerName(v.first.first, v.second.signatures);
        /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
           Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
           nonexistence of any RRs below that zone cut, which include all RRs at
           that (original) owner name other than DS RRs, and all RRs below that
           owner name regardless of type.
        */
        if (qtype != QType::DS && (qname == owner || qname.isPartOf(owner)) && isNSECAncestorDelegation(signer, owner, nsec)) {
          LOG("type is "<<QType(qtype).getName()<<", NS is "<<std::to_string(nsec->isSet(QType::NS))<<", SOA is "<<std::to_string(nsec->isSet(QType::SOA))<<", signer is "<<signer<<", owner name is "<<owner<<endl);
          /* this is an "ancestor delegation" NSEC RR */
          LOG("An ancestor delegation NSEC RR can only deny the existence of a DS"<<endl);
          return NODATA;
        }

        /* check if the type is denied */
        if(qname == owner) {
          if (nsec->isSet(qtype)) {
            LOG("Does _not_ deny existence of type "<<QType(qtype).getName()<<endl);
            return NODATA;
          }

          LOG("Denies existence of type "<<QType(qtype).getName()<<endl);

          /* RFC 6840 section 4.3 */
          if (nsec->isSet(QType::CNAME)) {
            LOG("However a CNAME exists"<<endl);
            return NODATA;
          }

          /*
           * RFC 4035 Section 2.3:
           * The bitmap for the NSEC RR at a delegation point requires special
           * attention.  Bits corresponding to the delegation NS RRset and any
           * RRsets for which the parent zone has authoritative data MUST be set
           */
          if (referralToUnsigned && qtype == QType::DS && !nsec->isSet(QType::NS)) {
            LOG("However, no NS record exists at this level!"<<endl);
            return NODATA;
          }

          /* we know that the name exists (but this qtype doesn't) so except
             if the answer was generated by a wildcard expansion, no wildcard
             could have matched (rfc4035 section 5.4 bullet 1) */
          if (!isWildcardExpanded(owner, v.second.signatures) || isWildcardExpandedOntoItself(owner, v.second.signatures)) {
            needWildcardProof = false;
          }

          if (!needWildcardProof || provesNoWildCard(qname, qtype, validrrsets)) {
            return NXQTYPE;
          }

          LOG("But the existence of a wildcard is not denied for "<<qname<<"/"<<endl);
          return NODATA;
        }

        /* check if the whole NAME is denied existing */
        if(isCoveredByNSEC(qname, owner, nsec->d_next)) {
          LOG(qname<<" is covered ");
          /* if the name is an ENT and we received a NODATA answer,
             we are fine with a NSEC proving that the name does not exist. */
          if (wantsNoDataProof && nsecProvesENT(qname, owner, nsec->d_next)) {
            LOG("Denies existence of type "<<qname<<"/"<<QType(qtype).getName()<<" by proving that "<<qname<<" is an ENT"<<endl);
            return NXQTYPE;
          }

          if (!needWildcardProof) {
            LOG("and we did not need a wildcard proof"<<endl);
            return NXDOMAIN;
          }

          LOG("but we do need a wildcard proof so ");
          if (wantsNoDataProof) {
            LOG("looking for NODATA proof"<<endl);
            if (provesNoDataWildCard(qname, qtype, validrrsets)) {
              return NXQTYPE;
            }
          }
          else {
            LOG("looking for NO wildcard proof"<<endl);
            if (provesNoWildCard(qname, qtype, validrrsets)) {
              return NXDOMAIN;
            }
          }

          LOG("But the existence of a wildcard is not denied for "<<qname<<"/"<<QType(qtype).getName()<<endl);
          return NODATA;
        }

        LOG("Did not deny existence of "<<QType(qtype).getName()<<", "<<owner<<"?="<<qname<<", "<<nsec->isSet(qtype)<<", next: "<<nsec->d_next<<endl);
      }
    } else if(v.first.second==QType::NSEC3) {
      for(const auto& r : v.second.records) {
        LOG("\t"<<r->getZoneRepresentation()<<endl);
        auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(r);
        if(!nsec3)
          continue;

        const DNSName signer = getSigner(v.second.signatures);
        if (!v.first.first.isPartOf(signer)) {
          LOG("Owner "<<v.first.first<<" is not part of the signer "<<signer<<", ignoring"<<endl);
          continue;
        }

        string h = getHashFromNSEC3(qname, nsec3);
        if (h.empty()) {
          LOG("Unsupported hash, ignoring"<<endl);
          return INSECURE;
        }

        nsec3Seen = true;

        //              cerr<<"Salt length: "<<nsec3->d_salt.length()<<", iterations: "<<nsec3->d_iterations<<", hashed: "<<qname<<endl;
        LOG("\tquery hash: "<<toBase32Hex(h)<<endl);
        string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);

        /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
           Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
           nonexistence of any RRs below that zone cut, which include all RRs at
           that (original) owner name other than DS RRs, and all RRs below that
           owner name regardless of type.
        */
        if (qtype != QType::DS && beginHash == h && isNSEC3AncestorDelegation(signer, v.first.first, nsec3)) {
          LOG("type is "<<QType(qtype).getName()<<", NS is "<<std::to_string(nsec3->isSet(QType::NS))<<", SOA is "<<std::to_string(nsec3->isSet(QType::SOA))<<", signer is "<<signer<<", owner name is "<<v.first.first<<endl);
          /* this is an "ancestor delegation" NSEC3 RR */
          LOG("An ancestor delegation NSEC3 RR can only deny the existence of a DS"<<endl);
          return NODATA;
        }

        // If the name exists, check if the qtype is denied
        if(beginHash == h) {
          if (nsec3->isSet(qtype)) {
            LOG("Does _not_ deny existence of type "<<QType(qtype).getName()<<" for name "<<qname<<" (not opt-out)."<<endl);
            return NODATA;
          }

          LOG("Denies existence of type "<<QType(qtype).getName()<<" for name "<<qname<<" (not opt-out)."<<endl);

          /* RFC 6840 section 4.3 */
          if (nsec3->isSet(QType::CNAME)) {
            LOG("However a CNAME exists"<<endl);
            return NODATA;
          }

          /*
           * RFC 5155 section 8.9:
           * If there is an NSEC3 RR present in the response that matches the
           * delegation name, then the validator MUST ensure that the NS bit is
           * set and that the DS bit is not set in the Type Bit Maps field of the
           * NSEC3 RR.
           */
          if (referralToUnsigned && qtype == QType::DS && !nsec3->isSet(QType::NS)) {
            LOG("However, no NS record exists at this level!"<<endl);
            return NODATA;
          }

          return NXQTYPE;
        }
      }
    }
  }

  /* if we have no NSEC3 records, we are done */
  if (!nsec3Seen) {
    return NODATA;
  }

  DNSName closestEncloser(qname);
  bool found = false;

  if (needWildcardProof) {
    /* We now need to look for a NSEC3 covering the closest (provable) encloser
       RFC 5155 section-7.2.1
       FRC 7129 section-5.5
    */
    LOG("Now looking for the closest encloser for "<<qname<<endl);

    while (found == false && closestEncloser.chopOff()) {
      for(const auto& v : validrrsets) {
        if(v.first.second==QType::NSEC3) {
          for(const auto& r : v.second.records) {
            LOG("\t"<<r->getZoneRepresentation()<<endl);
            auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(r);
            if(!nsec3)
              continue;

            const DNSName signer = getSigner(v.second.signatures);
            if (!v.first.first.isPartOf(signer)) {
              LOG("Owner "<<v.first.first<<" is not part of the signer "<<signer<<", ignoring"<<endl);
              continue;
            }

            string h = getHashFromNSEC3(closestEncloser, nsec3);
            if (h.empty()) {
              return INSECURE;
            }

            string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);

            LOG("Comparing "<<toBase32Hex(h)<<" ("<<closestEncloser<<") against "<<toBase32Hex(beginHash)<<endl);
            if(beginHash == h) {
              if (qtype != QType::DS && isNSEC3AncestorDelegation(signer, v.first.first, nsec3)) {
                LOG("An ancestor delegation NSEC3 RR can only deny the existence of a DS"<<endl);
                continue;
              }

              LOG("Closest encloser for "<<qname<<" is "<<closestEncloser<<endl);
              found = true;
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
       we can construct the next closer (FRC7129 section-5.5) name
       and look for a NSEC3 RR covering it */
    unsigned int labelIdx = qname.countLabels() - closestEncloser.countLabels();
    if (labelIdx >= 1) {
      DNSName nextCloser(closestEncloser);
      nextCloser.prependRawLabel(qname.getRawLabel(labelIdx - 1));
      LOG("Looking for a NSEC3 covering the next closer name "<<nextCloser<<endl);

      for(const auto& v : validrrsets) {
        if(v.first.second==QType::NSEC3) {
          for(const auto& r : v.second.records) {
            LOG("\t"<<r->getZoneRepresentation()<<endl);
            auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(r);
            if(!nsec3)
              continue;

            string h = getHashFromNSEC3(nextCloser, nsec3);
            if (h.empty()) {
              return INSECURE;
            }

            string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);

            LOG("Comparing "<<toBase32Hex(h)<<" against "<<toBase32Hex(beginHash)<<" -> "<<toBase32Hex(nsec3->d_nexthash)<<endl);
            if(isCoveredByNSEC3Hash(h, beginHash, nsec3->d_nexthash)) {
              LOG("Denies existence of name "<<qname<<"/"<<QType(qtype).getName());
              nextCloserFound = true;

              if (qtype == QType::DS && nsec3->d_flags & 1) {
                LOG(" but is opt-out!");
                isOptOut = true;
              }
              LOG(endl);
              break;
            }
            LOG("Did not cover us ("<<qname<<"), start="<<v.first.first<<", us="<<toBase32Hex(h)<<", end="<<toBase32Hex(nsec3->d_nexthash)<<endl);
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
    if (needWildcardProof && !provesNSEC3NoWildCard(closestEncloser, qtype, validrrsets, &wildcardExists)) {
      if (!isOptOut) {
        LOG("But the existence of a wildcard is not denied for "<<qname<<"/"<<QType(qtype).getName()<<endl);
        return NODATA;
      }
    }

    if (isOptOut) {
      return OPTOUT;
    }
    else {
      if (wildcardExists) {
        return NXQTYPE;
      }
      return NXDOMAIN;
    }
  }

  // There were no valid NSEC(3) records
  // XXX maybe this should be INSECURE... it depends on the semantics of this function
  return NODATA;
}

/*
 * Finds all the zone-cuts between begin (longest name) and end (shortest name),
 * returns them all zone cuts, including end, but (possibly) not begin
 */
static const vector<DNSName> getZoneCuts(const DNSName& begin, const DNSName& end, DNSRecordOracle& dro)
{
  vector<DNSName> ret;
  if(!begin.isPartOf(end))
    throw PDNSException(end.toLogString() + "is not part of " + begin.toLogString());

  DNSName qname(end);
  vector<string> labelsToAdd = begin.makeRelative(end).getRawLabels();

  // The shortest name is assumed to a zone cut
  ret.push_back(qname);
  while(qname != begin) {
    bool foundCut = false;
    if (labelsToAdd.empty())
      break;

    qname.prependRawLabel(labelsToAdd.back());
    labelsToAdd.pop_back();
    auto records = dro.get(qname, (uint16_t)QType::NS);
    for (const auto record : records) {
      if(record.d_type != QType::NS || record.d_name != qname)
        continue;
      foundCut = true;
      break;
    }
    if (foundCut)
      ret.push_back(qname);
  }
  return ret;
}

bool isRRSIGNotExpired(const time_t now, const shared_ptr<RRSIGRecordContent> sig)
{
  return sig->d_siginception - g_signatureInceptionSkew <= now && sig->d_sigexpire >= now;
}

static bool checkSignatureWithKey(time_t now, const shared_ptr<RRSIGRecordContent> sig, const shared_ptr<DNSKEYRecordContent> key, const std::string& msg)
{
  bool result = false;
  try {
    /* rfc4035:
       - The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
       - The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
    */
    if(isRRSIGNotExpired(now, sig)) {
      std::shared_ptr<DNSCryptoKeyEngine> dke = shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromPublicKeyString(key->d_algorithm, key->d_key));
      result = dke->verify(msg, sig->d_signature);
      LOG("signature by key with tag "<<sig->d_tag<<" and algorithm "<<DNSSECKeeper::algorithm2name(sig->d_algorithm)<<" was " << (result ? "" : "NOT ")<<"valid"<<endl);
    }
    else {
      LOG("Signature is "<<((sig->d_siginception - g_signatureInceptionSkew > now) ? "not yet valid" : "expired")<<" (inception: "<<sig->d_siginception<<", inception skew: "<<g_signatureInceptionSkew<<", expiration: "<<sig->d_sigexpire<<", now: "<<now<<")"<<endl);
    }
  }
  catch(const std::exception& e) {
    LOG("Could not make a validator for signature: "<<e.what()<<endl);
  }
  return result;
}

bool validateWithKeySet(time_t now, const DNSName& name, const vector<shared_ptr<DNSRecordContent> >& records, const vector<shared_ptr<RRSIGRecordContent> >& signatures, const skeyset_t& keys, bool validateAllSigs)
{
  bool isValid = false;

  for(const auto& signature : signatures) {
    unsigned int labelCount = name.countLabels();
    if (signature->d_labels > labelCount) {
      LOG(name<<": Discarding invalid RRSIG whose label count is "<<signature->d_labels<<" while the RRset owner name has only "<<labelCount<<endl);
    }

    vector<shared_ptr<DNSRecordContent> > toSign = records;

    auto r = getByTag(keys, signature->d_tag, signature->d_algorithm);

    if(r.empty()) {
      LOG("No key provided for "<<signature->d_tag<<" and algorithm "<<std::to_string(signature->d_algorithm)<<endl;);
      continue;
    }

    string msg=getMessageForRRSET(name, *signature, toSign, true);
    for(const auto& l : r) {
      bool signIsValid = checkSignatureWithKey(now, signature, l, msg);
      if(signIsValid) {
        isValid = true;
        LOG("Validated "<<name<<"/"<<DNSRecordContent::NumberToType(signature->d_type)<<endl);
        //	  cerr<<"valid"<<endl;
        //	  cerr<<"! validated "<<i->first.first<<"/"<<)<<endl;
      }
      else {
        LOG("signature invalid"<<endl);
      }
      if (signIsValid && !validateAllSigs) {
        return true;
      }
    }
  }

  return isValid;
}

void validateWithKeySet(const cspmap_t& rrsets, cspmap_t& validated, const skeyset_t& keys)
{
  validated.clear();
  /*  cerr<<"Validating an rrset with following keys: "<<endl;
  for(auto& key : keys) {
    cerr<<"\tTag: "<<key->getTag()<<" -> "<<key->getZoneRepresentation()<<endl;
  }
  */
  time_t now = time(nullptr);
  for(auto i=rrsets.cbegin(); i!=rrsets.cend(); i++) {
    LOG("validating "<<(i->first.first)<<"/"<<DNSRecordContent::NumberToType(i->first.second)<<" with "<<i->second.signatures.size()<<" sigs"<<endl);
    if (validateWithKeySet(now, i->first.first, i->second.records, i->second.signatures, keys, true)) {
      validated[i->first] = i->second;
    }
  }
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
      cspmap[{rec.d_name, rec.d_type}].records.push_back(rec.d_content);
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

void validateDNSKeysAgainstDS(time_t now, const DNSName& zone, const dsmap_t& dsmap, const skeyset_t& tkeys, vector<shared_ptr<DNSRecordContent> >& toSign, const vector<shared_ptr<RRSIGRecordContent> >& sigs, skeyset_t& validkeys)
{
  /*
   * Check all DNSKEY records against all DS records and place all DNSKEY records
   * that have DS records (that we support the algo for) in the tentative key storage
   */
  for(auto const& dsrc : dsmap)
  {
    auto r = getByTag(tkeys, dsrc.d_tag, dsrc.d_algorithm);
    // cerr<<"looking at DS with tag "<<dsrc.d_tag<<", algo "<<DNSSECKeeper::algorithm2name(dsrc.d_algorithm)<<", digest "<<std::to_string(dsrc.d_digesttype)<<" for "<<zone<<", got "<<r.size()<<" DNSKEYs for tag"<<endl;

    for(const auto& drc : r)
    {
      bool isValid = false;
      bool dsCreated = false;
      DSRecordContent dsrc2;
      try {
        dsrc2 = makeDSFromDNSKey(zone, *drc, dsrc.d_digesttype);
        dsCreated = true;
        isValid = dsrc == dsrc2;
      }
      catch(const std::exception &e) {
        LOG("Unable to make DS from DNSKey: "<<e.what()<<endl);
      }

      if(isValid) {
        LOG("got valid DNSKEY (it matches the DS) with tag "<<dsrc.d_tag<<" and algorithm "<<std::to_string(dsrc.d_algorithm)<<" for "<<zone<<endl);

        validkeys.insert(drc);
      }
      else {
        if (dsCreated) {
          LOG("DNSKEY did not match the DS, parent DS: "<<dsrc.getZoneRepresentation() << " ! = "<<dsrc2.getZoneRepresentation()<<endl);
        }
      }
    }
  }

  vector<uint16_t> toSignTags;
  for (const auto& key : tkeys) {
    toSignTags.push_back(key->getTag());
  }

  //    cerr<<"got "<<validkeys.size()<<"/"<<tkeys.size()<<" valid/tentative keys"<<endl;
  // these counts could be off if we somehow ended up with
  // duplicate keys. Should switch to a type that prevents that.
  if(validkeys.size() < tkeys.size())
  {
    // this should mean that we have one or more DS-validated DNSKEYs
    // but not a fully validated DNSKEY set, yet
    // one of these valid DNSKEYs should be able to validate the
    // whole set
    for(const auto& sig : sigs)
    {
      //        cerr<<"got sig for keytag "<<i->d_tag<<" matching "<<getByTag(tkeys, i->d_tag).size()<<" keys of which "<<getByTag(validkeys, i->d_tag).size()<<" valid"<<endl;
      auto bytag = getByTag(validkeys, sig->d_tag, sig->d_algorithm);

      if (bytag.empty()) {
        continue;
      }

      string msg = getMessageForRRSET(zone, *sig, toSign);
      for(const auto& key : bytag) {
        //          cerr<<"validating : ";
        bool signIsValid = checkSignatureWithKey(now, sig, key, msg);

        if(signIsValid)
        {
          LOG("validation succeeded - whole DNSKEY set is valid"<<endl);
          validkeys = tkeys;
          break;
        }
        else {
          LOG("Validation did not succeed!"<<endl);
        }
      }
      //        if(validkeys.empty()) cerr<<"did not manage to validate DNSKEY set based on DS-validated KSK, only passing KSK on"<<endl;
    }
  }
}

vState getKeysFor(DNSRecordOracle& dro, const DNSName& zone, skeyset_t& keyset)
{
  auto luaLocal = g_luaconfs.getLocal();
  const auto anchors = luaLocal->dsAnchors;
  if (anchors.empty()) // Nothing to do here
    return Insecure;

  // Determine the lowest (i.e. with the most labels) Trust Anchor for zone
  DNSName lowestTA(".");
  for (auto const &anchor : anchors)
    if (zone.isPartOf(anchor.first) && lowestTA.countLabels() < anchor.first.countLabels())
      lowestTA = anchor.first;

  // Before searching for the keys, see if we have a Negative Trust Anchor. If
  // so, test if the NTA is valid and return an NTA state
  const auto negAnchors = luaLocal->negAnchors;

  if (!negAnchors.empty()) {
    DNSName lowestNTA;

    for (auto const &negAnchor : negAnchors)
      if (zone.isPartOf(negAnchor.first) && lowestNTA.countLabels() <= negAnchor.first.countLabels())
        lowestNTA = negAnchor.first;

    if(!lowestNTA.empty()) {
      LOG("Found a Negative Trust Anchor for "<<lowestNTA<<", which was added with reason '"<<negAnchors.at(lowestNTA)<<"', ");

      /* RFC 7646 section 2.1 tells us that we SHOULD still validate if there
       * is a Trust Anchor below the Negative Trust Anchor for the name we
       * attempt validation for. However, section 3 tells us this positive
       * Trust Anchor MUST be *below* the name and not the name itself
       */
      if(lowestTA.countLabels() <= lowestNTA.countLabels()) {
        LOG("marking answer Insecure"<<endl);
        return NTA; // Not Insecure, this way validateRecords() can shortcut
      }
      LOG("but a Trust Anchor for "<<lowestTA<<" is configured, continuing validation."<<endl);
    }
  }

  skeyset_t validkeys;
  dsmap_t dsmap;

  dsmap_t* tmp = (dsmap_t*) rplookup(anchors, lowestTA);
  if (tmp)
    dsmap = *tmp;

  auto zoneCuts = getZoneCuts(zone, lowestTA, dro);

  LOG("Found the following zonecuts:")
  for(const auto& zonecut : zoneCuts)
    LOG(" => "<<zonecut);
  LOG(endl);

  for(auto zoneCutIter = zoneCuts.cbegin(); zoneCutIter != zoneCuts.cend(); ++zoneCutIter)
  {
    vector<shared_ptr<RRSIGRecordContent> > sigs;
    vector<shared_ptr<DNSRecordContent> > toSign;

    skeyset_t tkeys; // tentative keys
    validkeys.clear();

    //    cerr<<"got DS for ["<<qname<<"], grabbing DNSKEYs"<<endl;
    auto records=dro.get(*zoneCutIter, (uint16_t)QType::DNSKEY);
    // this should use harvest perhaps
    for(const auto& rec : records) {
      if(rec.d_name != *zoneCutIter)
        continue;

      if(rec.d_type == QType::RRSIG)
      {
        auto rrc=getRR<RRSIGRecordContent> (rec);
        if(rrc) {
          LOG("Got signature: "<<rrc->getZoneRepresentation()<<" with tag "<<rrc->d_tag<<", for type "<<DNSRecordContent::NumberToType(rrc->d_type)<<endl);
          if(rrc->d_type != QType::DNSKEY)
            continue;
          sigs.push_back(rrc);
        }
      }
      else if(rec.d_type == QType::DNSKEY)
      {
        auto drc=getRR<DNSKEYRecordContent> (rec);
        if(drc) {
          tkeys.insert(drc);
          LOG("Inserting key with tag "<<drc->getTag()<<" and algorithm "<<DNSSECKeeper::algorithm2name(drc->d_algorithm)<<": "<<drc->getZoneRepresentation()<<endl);

          toSign.push_back(rec.d_content);
        }
      }
    }
    LOG("got "<<tkeys.size()<<" keys and "<<sigs.size()<<" sigs from server"<<endl);

    /*
     * Check all DNSKEY records against all DS records and place all DNSKEY records
     * that have DS records (that we support the algo for) in the tentative key storage
     */
    validateDNSKeysAgainstDS(time(nullptr), *zoneCutIter, dsmap, tkeys, toSign, sigs, validkeys);

    if(validkeys.empty())
    {
      LOG("ended up with zero valid DNSKEYs, going Bogus"<<endl);
      return Bogus;
    }
    LOG("situation: we have one or more valid DNSKEYs for ["<<*zoneCutIter<<"] (want ["<<zone<<"])"<<endl);

    if(zoneCutIter == zoneCuts.cend()-1) {
      LOG("requested keyset found! returning Secure for the keyset"<<endl);
      keyset.insert(validkeys.cbegin(), validkeys.cend());
      return Secure;
    }

    // We now have the DNSKEYs, use them to validate the DS records at the next zonecut
    LOG("next name ["<<*(zoneCutIter+1)<<"], trying to get DS"<<endl);

    dsmap_t tdsmap; // tentative DSes
    dsmap.clear();
    toSign.clear();

    auto recs=dro.get(*(zoneCutIter+1), QType::DS);

    cspmap_t cspmap=harvestCSPFromRecs(recs);

    cspmap_t validrrsets;
    validateWithKeySet(cspmap, validrrsets, validkeys);

    LOG("got "<<cspmap.count(make_pair(*(zoneCutIter+1),QType::DS))<<" records for DS query of which "<<validrrsets.count(make_pair(*(zoneCutIter+1),QType::DS))<<" valid "<<endl);

    auto r = validrrsets.equal_range(make_pair(*(zoneCutIter+1), QType::DS));
    if(r.first == r.second) {
      LOG("No DS for "<<*(zoneCutIter+1)<<", now look for a secure denial"<<endl);
      dState res = getDenial(validrrsets, *(zoneCutIter+1), QType::DS, true, true);
      if (res == INSECURE || res == NXDOMAIN)
        return Bogus;
      if (res == NXQTYPE || res == OPTOUT)
        return Insecure;
    }

    /*
     * Collect all DS records and add them to the dsmap for the next iteration
     */
    for(auto cspiter =r.first;  cspiter!=r.second; cspiter++) {
      for(auto j=cspiter->second.records.cbegin(); j!=cspiter->second.records.cend(); j++)
      {
        const auto dsrc=std::dynamic_pointer_cast<DSRecordContent>(*j);
        if(dsrc) {
          dsmap.insert(*dsrc);
        }
      }
    }
  }
  // There were no zone cuts (aka, we should never get here)
  return Bogus;
}

bool isSupportedDS(const DSRecordContent& ds)
{
  if (!DNSCryptoKeyEngine::isAlgorithmSupported(ds.d_algorithm)) {
    LOG("Discarding DS "<<ds.d_tag<<" because we don't support algorithm number "<<std::to_string(ds.d_algorithm)<<endl);
    return false;
  }

  if (!DNSCryptoKeyEngine::isDigestSupported(ds.d_digesttype)) {
    LOG("Discarding DS "<<ds.d_tag<<" because we don't support digest number "<<std::to_string(ds.d_digesttype)<<endl);
    return false;
  }

  return true;
}

DNSName getSigner(const std::vector<std::shared_ptr<RRSIGRecordContent> >& signatures)
{
  for (const auto sig : signatures) {
    if (sig) {
      return sig->d_signer;
    }
  }

  return DNSName();
}
