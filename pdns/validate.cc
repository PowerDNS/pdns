#include "validate.hh"
#include "misc.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "rec-lua-conf.hh"
#include "base32.hh"
#include "logger.hh"
bool g_dnssecLOG{false};
uint16_t g_maxNSEC3Iterations{0};

#define LOG(x) if(g_dnssecLOG) { L <<Logger::Warning << x; }
void dotEdge(DNSName zone, string type1, DNSName name1, string tag1, string type2, DNSName name2, string tag2, string color="");
void dotNode(string type, DNSName name, string tag, string content);
string dotName(string type, DNSName name, string tag);
string dotEscape(string name);

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
          beginHash == nextHash);                     // "we have only 1 NSEC3 record, LOL!"
}

// FIXME: needs a zone argument, to avoid things like 6840 4.1
// FIXME: Add ENT support
// FIXME: Make usable for non-DS records and hook up to validateRecords (or another place)
dState getDenial(const cspmap_t &validrrsets, const DNSName& qname, const uint16_t qtype)
{
  for(const auto& v : validrrsets) {
    LOG("Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);

    if(v.first.second==QType::NSEC) {
      for(const auto& r : v.second.records) {
        LOG("\t"<<r->getZoneRepresentation()<<endl);
        auto nsec = std::dynamic_pointer_cast<NSECRecordContent>(r);
        if(!nsec)
          continue;

        /* check if the type is denied */
        if(qname == v.first.first && !nsec->d_set.count(qtype)) {
          LOG("Denies existence of type "<<QType(qtype).getName()<<endl);
          return NXQTYPE;
        }

        /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
           Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
           nonexistence of any RRs below that zone cut, which include all RRs at
           that (original) owner name other than DS RRs, and all RRs below that
           owner name regardless of type.
        */
        LOG("type is "<<QType(qtype).getName()<<", NS is "<<std::to_string(nsec->d_set.count(QType::NS))<<", SOA is "<<std::to_string(nsec->d_set.count(QType::SOA))<<", signer is "<<getSigner(v.second.signatures).toString()<<", owner name is "<<v.first.first.toString()<<endl);
        if (qtype != QType::DS && nsec->d_set.count(QType::NS) && !nsec->d_set.count(QType::SOA) &&
            getSigner(v.second.signatures).countLabels() < v.first.first.countLabels()) {
          /* this is an "ancestor delegation" NSEC RR */
          LOG("An ancestor delegation NSEC RR can only deny the existence of a DS");
          continue;
        }

        /* check if the whole NAME is denied existing */
        if(v.first.first.canonCompare(qname) && qname.canonCompare(nsec->d_next)) {
          LOG("Denies existence of name "<<qname<<"/"<<QType(qtype).getName()<<endl);
          return NXDOMAIN;
        }

        LOG("Did not deny existence of "<<QType(qtype).getName()<<", "<<v.first.first<<"?="<<qname<<", "<<nsec->d_set.count(qtype)<<", next: "<<nsec->d_next<<endl);
      }
    } else if(v.first.second==QType::NSEC3) {
      for(const auto& r : v.second.records) {
        LOG("\t"<<r->getZoneRepresentation()<<endl);
        auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(r);
        if(!nsec3)
          continue;

        if (g_maxNSEC3Iterations && nsec3->d_iterations > g_maxNSEC3Iterations) {
          return INSECURE;
        }

        string h = hashQNameWithSalt(nsec3->d_salt, nsec3->d_iterations, qname);
        //              cerr<<"Salt length: "<<nsec3->d_salt.length()<<", iterations: "<<nsec3->d_iterations<<", hashed: "<<qname<<endl;
        LOG("\tquery hash: "<<toBase32Hex(h)<<endl);
        string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);

        // If the name exists, check if the qtype is denied
        if(beginHash == h && !nsec3->d_set.count(qtype)) {
          LOG("Denies existence of type "<<QType(qtype).getName()<<" for name "<<qname<<"  (not opt-out).");
          /*
           * RFC 5155 section 8.9:
           * If there is an NSEC3 RR present in the response that matches the
           * delegation name, then the validator MUST ensure that the NS bit is
           * set and that the DS bit is not set in the Type Bit Maps field of the
           * NSEC3 RR.
           */
          if (qtype == QType::DS && !nsec3->d_set.count(QType::NS)) {
            LOG("However, no NS record exists at this level!"<<endl);
            return INSECURE;
          }
          LOG(endl);
          return NXQTYPE;
        }

        /* check if the whole NAME does not exist */
        if(isCoveredByNSEC3Hash(h, beginHash, nsec3->d_nexthash)) {
          LOG("Denies existence of name "<<qname<<"/"<<QType(qtype).getName());
          if (qtype == QType::DS && nsec3->d_flags & 1) {
            LOG(" but is opt-out!"<<endl);
            return OPTOUT;
          }
          LOG(endl);
          return NXDOMAIN;
        }

        LOG("Did not cover us ("<<qname<<"), start="<<v.first.first<<", us="<<toBase32Hex(h)<<", end="<<toBase32Hex(nsec3->d_nexthash)<<endl);
      }
    }
  }

  /* check closest encloser */
  LOG("Now looking for the closest encloser for "<<qname<<endl);
  DNSName sname(qname);
  bool found = false;

  while (found == false && sname.chopOff()) {
    for(const auto& v : validrrsets) {
      if(v.first.second==QType::NSEC3) {
        for(const auto& r : v.second.records) {
          LOG("\t"<<r->getZoneRepresentation()<<endl);
          auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(r);
          if(!nsec3)
            continue;

          if (g_maxNSEC3Iterations && nsec3->d_iterations > g_maxNSEC3Iterations) {
            return INSECURE;
          }

          string h = hashQNameWithSalt(nsec3->d_salt, nsec3->d_iterations, sname);
          string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);

          LOG("Comparing "<<toBase32Hex(h)<<" against "<<toBase32Hex(beginHash)<<endl);
          if(beginHash == h) {
            LOG("Closest encloser for "<<qname<<" is "<<sname<<endl);
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

  if (found == true) {
    /* we now need a NSEC3 RR covering the next closer name */
    unsigned int labelIdx = qname.countLabels() - sname.countLabels();
    if (labelIdx >= 1) {
      DNSName nextCloser(sname);
      nextCloser.prependRawLabel(qname.getRawLabel(labelIdx - 1));
      LOG("Looking for a NSEC3 covering the next closer name "<<nextCloser<<endl);

      for(const auto& v : validrrsets) {
        if(v.first.second==QType::NSEC3) {
          for(const auto& r : v.second.records) {
            LOG("\t"<<r->getZoneRepresentation()<<endl);
            auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(r);
            if(!nsec3)
              continue;
            if (g_maxNSEC3Iterations && nsec3->d_iterations > g_maxNSEC3Iterations) {
              return INSECURE;
            }

            string h = hashQNameWithSalt(nsec3->d_salt, nsec3->d_iterations, nextCloser);
            string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);

            LOG("Comparing "<<toBase32Hex(h)<<" against "<<toBase32Hex(beginHash)<<endl);
            if(isCoveredByNSEC3Hash(h, beginHash, nsec3->d_nexthash)) {
              LOG("Denies existence of name "<<qname<<"/"<<QType(qtype).getName());
              if (qtype == QType::DS && nsec3->d_flags & 1) {
                LOG(" but is opt-out!"<<endl);
                return OPTOUT;
              }
              LOG(endl);
              return NXDOMAIN;
            }
          }
        }
      }
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
    throw PDNSException(end.toLogString() + "is not part of " + begin.toString());

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

static bool checkSignatureWithKey(time_t now, const shared_ptr<RRSIGRecordContent> sig, const shared_ptr<DNSKEYRecordContent> key, const std::string& msg)
{
  bool result = false;
  try {
    /* rfc4035:
       - The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
       - The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
    */
    if(sig->d_siginception <= now && sig->d_sigexpire >= now) {
      std::shared_ptr<DNSCryptoKeyEngine> dke = shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromPublicKeyString(key->d_algorithm, key->d_key));
      result = dke->verify(msg, sig->d_signature);
      LOG("signature by key with tag "<<sig->d_tag<<" and algorithm "<<DNSSECKeeper::algorithm2name(sig->d_algorithm)<<" was " << (result ? "" : "NOT ")<<"valid"<<endl);
    }
    else {
      LOG("Signature is "<<((sig->d_siginception > now) ? "not yet valid" : "expired")<<" (inception: "<<sig->d_siginception<<", expiration: "<<sig->d_sigexpire<<", now: "<<now<<")"<<endl);
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
      if(signature->d_type != QType::DNSKEY) {
        dotEdge(signature->d_signer,
                "DNSKEY", signature->d_signer, std::to_string(signature->d_tag),
                DNSRecordContent::NumberToType(signature->d_type), name, "", signIsValid ? "green" : "red");
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
        dotNode("DS", zone, "" /*std::to_string(dsrc.d_tag)*/, (boost::format("tag=%d, digest algo=%d, algo=%d") % dsrc.d_tag % static_cast<int>(dsrc.d_digesttype) % static_cast<int>(dsrc.d_algorithm)).str());
      }
      else {
        if (dsCreated) {
          LOG("DNSKEY did not match the DS, parent DS: "<<dsrc.getZoneRepresentation() << " ! = "<<dsrc2.getZoneRepresentation()<<endl);
        }
      }
      // cout<<"    subgraph "<<dotEscape("cluster "+zone)<<" { "<<dotEscape("DS "+zone)<<" -> "<<dotEscape("DNSKEY "+zone)<<" [ label = \""<<dsrc.d_tag<<"/"<<static_cast<int>(dsrc.d_digesttype)<<"\" ]; label = \"zone: "<<zone<<"\"; }"<<endl;
      dotEdge(g_rootdnsname, "DS", zone, "" /*std::to_string(dsrc.d_tag)*/, "DNSKEY", zone, std::to_string(drc->getTag()), isValid ? "green" : "red");
      // dotNode("DNSKEY", zone, (boost::format("tag=%d, algo=%d") % drc->getTag() % static_cast<int>(drc->d_algorithm)).str());
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

        for(uint16_t tag : toSignTags) {
          dotEdge(zone,
                  "DNSKEY", zone, std::to_string(sig->d_tag),
                  "DNSKEY", zone, std::to_string(tag), signIsValid ? "green" : "red");
        }

        if(signIsValid)
        {
          LOG("validation succeeded - whole DNSKEY set is valid"<<endl);
          // cout<<"    "<<dotEscape("DNSKEY "+stripDot(i->d_signer))<<" -> "<<dotEscape("DNSKEY "+zone)<<";"<<endl;
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
      LOG("Found a Negative Trust Anchor for "<<lowestNTA.toStringRootDot()<<", which was added with reason '"<<negAnchors.at(lowestNTA)<<"', ");

      /* RFC 7646 section 2.1 tells us that we SHOULD still validate if there
       * is a Trust Anchor below the Negative Trust Anchor for the name we
       * attempt validation for. However, section 3 tells us this positive
       * Trust Anchor MUST be *below* the name and not the name itself
       */
      if(lowestTA.countLabels() <= lowestNTA.countLabels()) {
        LOG("marking answer Insecure"<<endl);
        return NTA; // Not Insecure, this way validateRecords() can shortcut
      }
      LOG("but a Trust Anchor for "<<lowestTA.toStringRootDot()<<" is configured, continuing validation."<<endl);
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
          //          dotNode("DNSKEY", *zoneCutIter, std::to_string(drc->getTag()), (boost::format("tag=%d, algo=%d") % drc->getTag() % static_cast<int>(drc->d_algorithm)).str());

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
      dState res = getDenial(validrrsets, *(zoneCutIter+1), QType::DS);
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
          // dotEdge(key*(zoneCutIter+1),
          //         "DNSKEY", key*(zoneCutIter+1), ,
          //         "DS", *(zoneCutIter+1), std::to_string(dsrc.d_tag));
          // cout<<"    "<<dotEscape("DNSKEY "+key*(zoneCutIter+1))<<" -> "<<dotEscape("DS "+*(zoneCutIter+1))<<";"<<endl;
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
    return sig->d_signer;
  }

  return DNSName();
}

string dotEscape(string name)
{
  return "\"" + boost::replace_all_copy(name, "\"", "\\\"") + "\"";
}

string dotName(string type, DNSName name, string tag)
{
  if(tag == "")
    return type+" "+name.toString();
  else
    return type+" "+name.toString()+"/"+tag;
}
void dotNode(string type, DNSName name, string tag, string content)
{
#ifdef GRAPHVIZ
  cout<<"    "
      <<dotEscape(dotName(type, name, tag))
      <<" [ label="<<dotEscape(dotName(type, name, tag)+"\\n"+content)<<" ];"<<endl;
#endif
}

void dotEdge(DNSName zone, string type1, DNSName name1, string tag1, string type2, DNSName name2, string tag2, string color)
{
#ifdef GRAPHVIZ
  cout<<"    ";
  if(zone != g_rootdnsname) cout<<"subgraph "<<dotEscape("cluster "+zone.toString())<<" { ";
  cout<<dotEscape(dotName(type1, name1, tag1))
      <<" -> "
      <<dotEscape(dotName(type2, name2, tag2));
  if(color != "") cout<<" [ color=\""<<color<<"\" ]; ";
  else cout<<"; ";
  if(zone != g_rootdnsname) cout<<"label = "<<dotEscape("zone: "+zone.toString())<<";"<<"}";
  cout<<endl;
#endif
}

