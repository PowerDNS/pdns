#include "validate.hh"
#include "misc.hh"
#include "dnssecinfra.hh"
#include "rec-lua-conf.hh"
#include "base32.hh"
#include "logger.hh"
bool g_dnssecLOG{false};

#define LOG(x) if(g_dnssecLOG) { L <<Logger::Warning << x; }
void dotEdge(DNSName zone, string type1, DNSName name1, string tag1, string type2, DNSName name2, string tag2, string color="");
void dotNode(string type, DNSName name, string tag, string content);
string dotName(string type, DNSName name, string tag);
string dotEscape(string name);

const char *dStates[]={"nodata", "nxdomain", "empty non-terminal", "insecure (no-DS proof)"};
const char *vStates[]={"Indeterminate", "Bogus", "Insecure", "Secure", "NTA"};

typedef set<DNSKEYRecordContent> keyset_t;
vector<DNSKEYRecordContent> getByTag(const keyset_t& keys, uint16_t tag)
{
  vector<DNSKEYRecordContent> ret;
  for(const auto& key : keys)
    if(key.getTag() == tag)
      ret.push_back(key);
  return ret;
}


static string nsec3Hash(const DNSName &qname, const NSEC3RecordContent& nrc)
{
  NSEC3PARAMRecordContent ns3pr;
  ns3pr.d_iterations = nrc.d_iterations;
  ns3pr.d_salt = nrc.d_salt;
  return toBase32Hex(hashQNameWithSalt(ns3pr, qname));
}


// FIXME: needs a zone argument, to avoid things like 6840 4.1
static dState getDenial(cspmap_t &validrrsets, DNSName qname, uint16_t qtype)
{
  std::multimap<DNSName, NSEC3RecordContent> nsec3s;

  for(auto i=validrrsets.begin(); i!=validrrsets.end(); ++i)
  {
    // FIXME also support NSEC
    if(i->first.second != QType::NSEC3) continue;
    
    for(auto j=i->second.records.begin(); j!=i->second.records.end(); ++j) {
      NSEC3RecordContent ns3r = dynamic_cast<NSEC3RecordContent&> (**j);
      // nsec3.insert(new nsec3()
      // cerr<<toBase32Hex(r.d_nexthash)<<endl;
      nsec3s.insert(make_pair(i->first.first, ns3r));
    }
  }
  //  cerr<<"got "<<nsec3s.size()<<" NSEC3s"<<endl;
  for(auto i=nsec3s.begin(); i != nsec3s.end(); ++i) {
    vector<string> parts = i->first.getRawLabels();

      string base=toLower(parts[0]);
      string next=toLower(toBase32Hex(i->second.d_nexthash));
      string hashed = nsec3Hash(qname, i->second);
      //      cerr<<base<<" .. ? "<<hashed<<" ("<<qname<<") ? .. "<<next<<endl;
      if(base==hashed) {
        // positive name proof, need to check type
	//        cerr<<"positive name proof, checking type bitmap"<<endl;
	//        cerr<<"d_set.count("<<qtype<<"): "<<i->second.d_set.count(qtype)<<endl;
        if(qtype == QType::DS && i->second.d_set.count(qtype) == 0) return INSECURE; // FIXME need to require 'NS in bitmap' here, otherwise no delegation! (but first, make sure this is reliable - does not work that way for direct auth queries)
      } else if ((hashed > base && hashed < next) ||
                (next < base && (hashed < next || hashed > base))) {
        bool optout=(1 & i->second.d_flags);
	//        cerr<<"negative name proof, optout = "<<optout<<endl;
        if(qtype == QType::DS && optout) return INSECURE;
      }
  }
  /* NODATA is not really appropriate here, but we
     just need to return something else than INSECURE.
  */
  dState ret = NODATA;
  return ret;
}

void validateWithKeySet(const cspmap_t& rrsets, cspmap_t& validated, const keyset_t& keys)
{
  validated.clear();
  /*  cerr<<"Validating an rrset with following keys: "<<endl;
  for(auto& key : keys) {
    cerr<<"\tTag: "<<key.getTag()<<" -> "<<key.getZoneRepresentation()<<endl;
  }
  */
  for(auto i=rrsets.begin(); i!=rrsets.end(); i++) {
    LOG("validating "<<(i->first.first)<<"/"<<DNSRecordContent::NumberToType(i->first.second)<<" with "<<i->second.signatures.size()<<" sigs"<<endl);
    for(const auto& signature : i->second.signatures) {
      vector<shared_ptr<DNSRecordContent> > toSign = i->second.records;
      
      if(getByTag(keys,signature->d_tag).empty()) {
	LOG("No key provided for "<<signature->d_tag<<endl;);
	continue;
      }
      
      string msg=getMessageForRRSET(i->first.first, *signature, toSign, true);
      auto r = getByTag(keys,signature->d_tag); // FIXME: also take algorithm into account? right now we wrongly validate unknownalgorithm.bad-dnssec.wb.sidnlabs.nl
      for(const auto& l : r) {
	bool isValid = false;
	try {
	  unsigned int now=time(0);
	  if(signature->d_siginception < now && signature->d_sigexpire > now) {
	    std::shared_ptr<DNSCryptoKeyEngine> dke = shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromPublicKeyString(l.d_algorithm, l.d_key));
	    isValid = dke->verify(msg, signature->d_signature);
            LOG("signature by key with tag "<<signature->d_tag<<" was " << (isValid ? "" : "NOT ")<<"valid"<<endl);
	  }
	  else {
	    LOG("signature is expired/not yet valid"<<endl);
          }
	}
	catch(std::exception& e) {
	  LOG("Error validating with engine: "<<e.what()<<endl);
	}
	if(isValid) {
	  validated[i->first] = i->second;
          LOG("Validated "<<i->first.first<<"/"<<DNSRecordContent::NumberToType(signature->d_type)<<endl);
	  //	  cerr<<"valid"<<endl;
	  //	  cerr<<"! validated "<<i->first.first<<"/"<<)<<endl;
	}
	else {
          LOG("signature invalid"<<endl);
        }
	if(signature->d_type != QType::DNSKEY) {
	  dotEdge(signature->d_signer,
		  "DNSKEY", signature->d_signer, std::to_string(signature->d_tag),
		  DNSRecordContent::NumberToType(signature->d_type), i->first.first, "", isValid ? "green" : "red");
	  
	}
	// FIXME: break out enough levels
      }
    }
  }
}


// returns vState
// should return vState, zone cut and validated keyset
// i.e. www.7bits.nl -> insecure/7bits.nl/[]
//      www.powerdnssec.org -> secure/powerdnssec.org/[keys]
//      www.dnssec-failed.org -> bogus/dnssec-failed.org/[]

const char *g_rootDS;

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

vState getKeysFor(DNSRecordOracle& dro, const DNSName& zone, keyset_t &keyset)
{
  auto luaLocal = g_luaconfs.getLocal();
  auto anchors = luaLocal->dsAnchors;
  // Determine the lowest (i.e. with the most labels) Trust Anchor for zone
  DNSName lowestTA(".");
  for (auto const &anchor : anchors)
    if (zone.isPartOf(anchor.first) && lowestTA.countLabels() < anchor.first.countLabels())
      lowestTA = anchor.first;

  // Before searching for the keys, see if we have a Negative Trust Anchor. If
  // so, test if the NTA is valid and return an NTA state
  auto negAnchors = luaLocal->negAnchors;

  if (!negAnchors.empty()) {
    DNSName lowestNTA;

    for (auto const &negAnchor : negAnchors)
      if (zone.isPartOf(negAnchor.first) && lowestNTA.countLabels() < negAnchor.first.countLabels())
        lowestNTA = negAnchor.first;

    if(!lowestNTA.empty()) {
      LOG("Found a Negative Trust Anchor for "<<lowestNTA.toStringRootDot()<<", which was added with reason '"<<negAnchors[lowestNTA]<<"', ");

      /* RFC 7646 section 2.1 tells us that we SHOULD still validate if there
       * is a Trust Anchor below the Negative Trust Anchor for the name we
       * attempt validation for. However, section 3 tells us this positive
       * Trust Anchor MUST be *below* the name and not the name itself
       */
      if(lowestTA.countLabels() < lowestNTA.countLabels()) {
        LOG("marking answer Insecure"<<endl);
        return NTA; // Not Insecure, this way validateRecords() can shortcut
      }
      LOG("but a Trust Anchor for "<<lowestTA.toStringRootDot()<<" is configured, continuing validation."<<endl);
    }
  }

  vector<string> labels = zone.getRawLabels();

  dsmap_t dsmap;
  keyset_t validkeys;

  DNSName qname = lowestTA;
  vState state = Secure; // the lowest Trust Anchor is secure

  while(zone.isPartOf(qname))
  {
    dsmap_t* tmp = (dsmap_t*) rplookup(luaLocal->dsAnchors, qname);
    if (tmp)
      dsmap = *tmp;

    vector<RRSIGRecordContent> sigs;
    vector<shared_ptr<DNSRecordContent> > toSign;
    vector<uint16_t> toSignTags;

    keyset_t tkeys; // tentative keys
    validkeys.clear();

    // start of this iteration
    // we can trust that dsmap has valid DS records for qname

    //    cerr<<"got DS for ["<<qname<<"], grabbing DNSKEYs"<<endl;
    auto recs=dro.get(qname, (uint16_t)QType::DNSKEY);
    // this should use harvest perhaps
    for(const auto& rec : recs) {
      if(rec.d_name != qname)
        continue;

      if(rec.d_type == QType::RRSIG)
      {
        auto rrc=getRR<RRSIGRecordContent> (rec);
        LOG("Got signature: "<<rrc->getZoneRepresentation()<<" with tag "<<rrc->d_tag<<", for type "<<DNSRecordContent::NumberToType(rrc->d_type)<<endl);
        if(rrc && rrc->d_type != QType::DNSKEY)
          continue;
        sigs.push_back(*rrc);
      }
      else if(rec.d_type == QType::DNSKEY)
      {
        auto drc=getRR<DNSKEYRecordContent> (rec);
        if(drc) {
          tkeys.insert(*drc);
          LOG("Inserting key with tag "<<drc->getTag()<<": "<<drc->getZoneRepresentation()<<endl);
          //          dotNode("DNSKEY", qname, std::to_string(drc->getTag()), (boost::format("tag=%d, algo=%d") % drc->getTag() % static_cast<int>(drc->d_algorithm)).str());

          toSign.push_back(rec.d_content);
          toSignTags.push_back(drc->getTag());
        }
      }
    }
    LOG("got "<<tkeys.size()<<" keys and "<<sigs.size()<<" sigs from server"<<endl);

    for(auto const& dsrc : dsmap)
    {
      auto r = getByTag(tkeys, dsrc.d_tag);
      //      cerr<<"looking at DS with tag "<<dsrc.d_tag<<"/"<<i->first<<", got "<<r.size()<<" DNSKEYs for tag"<<endl;

      for(const auto& drc : r)
      {
	bool isValid = false;
	DSRecordContent dsrc2;
	try {
	  dsrc2=makeDSFromDNSKey(qname, drc, dsrc.d_digesttype);
	  isValid = dsrc == dsrc2;
	} 
	catch(std::exception &e) {
	  LOG("Unable to make DS from DNSKey: "<<e.what()<<endl);
	}

        if(isValid) {
	  LOG("got valid DNSKEY (it matches the DS) with tag "<<dsrc.d_tag<<" for "<<qname<<endl);
	  
          validkeys.insert(drc);
	  dotNode("DS", qname, "" /*std::to_string(dsrc.d_tag)*/, (boost::format("tag=%d, digest algo=%d, algo=%d") % dsrc.d_tag % static_cast<int>(dsrc.d_digesttype) % static_cast<int>(dsrc.d_algorithm)).str());
        }
	else {
	  LOG("DNSKEY did not match the DS, parent DS: "<<drc.getZoneRepresentation() << " ! = "<<dsrc2.getZoneRepresentation()<<endl);
	}
        // cout<<"    subgraph "<<dotEscape("cluster "+qname)<<" { "<<dotEscape("DS "+qname)<<" -> "<<dotEscape("DNSKEY "+qname)<<" [ label = \""<<dsrc.d_tag<<"/"<<static_cast<int>(dsrc.d_digesttype)<<"\" ]; label = \"zone: "<<qname<<"\"; }"<<endl;
	dotEdge(DNSName("."), "DS", qname, "" /*std::to_string(dsrc.d_tag)*/, "DNSKEY", qname, std::to_string(drc.getTag()), isValid ? "green" : "red");
        // dotNode("DNSKEY", qname, (boost::format("tag=%d, algo=%d") % drc.getTag() % static_cast<int>(drc.d_algorithm)).str());
      }
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
      for(auto i=sigs.begin(); i!=sigs.end(); i++)
      {
	//        cerr<<"got sig for keytag "<<i->d_tag<<" matching "<<getByTag(tkeys, i->d_tag).size()<<" keys of which "<<getByTag(validkeys, i->d_tag).size()<<" valid"<<endl;
        string msg=getMessageForRRSET(qname, *i, toSign);
        auto bytag = getByTag(validkeys, i->d_tag);
        for(const auto& j : bytag) {
	  //          cerr<<"validating : ";
          bool isValid = false;
	  try {
	    unsigned int now = time(0);
	    if(i->d_siginception < now && i->d_sigexpire > now) {
	      std::shared_ptr<DNSCryptoKeyEngine> dke = shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromPublicKeyString(j.d_algorithm, j.d_key));
	      isValid = dke->verify(msg, i->d_signature);
	    }
	  }
	  catch(std::exception& e) {
	    LOG("Could not make a validator for signature: "<<e.what()<<endl);
	  }
	  for(uint16_t tag : toSignTags) {
	    dotEdge(qname,
		    "DNSKEY", qname, std::to_string(i->d_tag),
		    "DNSKEY", qname, std::to_string(tag), isValid ? "green" : "red");
	  }
	  
          if(isValid)
          {
	    LOG("validation succeeded - whole DNSKEY set is valid"<<endl);
            // cout<<"    "<<dotEscape("DNSKEY "+stripDot(i->d_signer))<<" -> "<<dotEscape("DNSKEY "+qname)<<";"<<endl;
            validkeys=tkeys;
            break;
          }
	  else {
	    LOG("Validation did not succeed!"<<endl);
          }
        }
	//        if(validkeys.empty()) cerr<<"did not manage to validate DNSKEY set based on DS-validated KSK, only passing KSK on"<<endl;
      }
    }

    if(validkeys.empty())
    {
      LOG("ended up with zero valid DNSKEYs, going Bogus"<<endl);
      state=Bogus;
      break;
    }
    LOG("situation: we have one or more valid DNSKEYs for ["<<qname<<"] (want ["<<zone<<"])"<<endl);
    if(qname == zone) {
      LOG("requested keyset found! returning Secure for the keyset"<<endl);
      keyset.insert(validkeys.begin(), validkeys.end());
      return Secure;
    }
    //    cerr<<"walking downwards to find DS"<<endl;
    DNSName keyqname=qname;
    do {
      qname=DNSName(labels.back())+qname;
      labels.pop_back();
      LOG("next name ["<<qname<<"], trying to get DS"<<endl);

      dsmap_t tdsmap; // tentative DSes
      dsmap.clear();
      toSign.clear();
      toSignTags.clear();

      auto recs=dro.get(qname, QType::DS);

      cspmap_t cspmap=harvestCSPFromRecs(recs);

      cspmap_t validrrsets;
      validateWithKeySet(cspmap, validrrsets, validkeys);

      LOG("got "<<cspmap.count(make_pair(qname,QType::DS))<<" records for DS query of which "<<validrrsets.count(make_pair(qname,QType::DS))<<" valid "<<endl);

      auto r = validrrsets.equal_range(make_pair(qname, QType::DS));
      if(r.first == r.second) {
        LOG("No DS for "<<qname<<", now look for a secure denial"<<endl);

        for(const auto& v : validrrsets) {
          LOG("Do have: "<<v.first.first<<"/"<<DNSRecordContent::NumberToType(v.first.second)<<endl);
          if(v.first.second==QType::CNAME) {
            LOG("Found CNAME for "<< v.first.first << ", ignoring records at this level."<<endl);
            goto skipLevel;
          }
          else if(v.first.second==QType::NSEC) { // check that it covers us!
            for(const auto& r : v.second.records) {
              LOG("\t"<<r->getZoneRepresentation()<<endl);
              auto nsec = std::dynamic_pointer_cast<NSECRecordContent>(r);
              if(nsec) {
                if(v.first.first == qname && !nsec->d_set.count(QType::DS)) {
                  LOG("Denies existence of DS!"<<endl);
                  return Insecure;
                }
                else if(v.first.first.canonCompare(qname) && qname.canonCompare(nsec->d_next) ) {
                  LOG("Did not find DS for this level, trying one lower"<<endl);
                  goto skipLevel;
                }
                else {
                  LOG("Did not deny existence of DS, "<<v.first.first<<"?="<<qname<<", "<<nsec->d_set.count(QType::DS)<<", next: "<<nsec->d_next<<endl);
                }
              }
            }

          }
          else if(v.first.second==QType::NSEC3) {
            for(const auto& r : v.second.records) {
              LOG("\t"<<r->getZoneRepresentation()<<endl);

              auto nsec3 = std::dynamic_pointer_cast<NSEC3RecordContent>(r);
              string h = hashQNameWithSalt(nsec3->d_salt, nsec3->d_iterations, qname);
              //              cerr<<"Salt length: "<<nsec3->d_salt.length()<<", iterations: "<<nsec3->d_iterations<<", hashed: "<<qname<<endl;
              LOG("\tquery hash: "<<toBase32Hex(h)<<endl);
              string beginHash=fromBase32Hex(v.first.first.getRawLabels()[0]);
              if( (beginHash < h && h < nsec3->d_nexthash) ||
                  (nsec3->d_nexthash > h  && beginHash > nsec3->d_nexthash) ||  // wrap // HASH --- END --- BEGINNING
                  (nsec3->d_nexthash < beginHash  && beginHash < h) ||  // wrap other case // END -- BEGINNING -- HASH
                  beginHash == nsec3->d_nexthash)  // "we have only 1 NSEC3 record, LOL!"  
              {
                LOG("Denies existence of DS!"<<endl);
                return Insecure;
              }
              else if(beginHash == h && !nsec3->d_set.count(QType::DS)) {
                LOG("Denies existence of DS (not opt-out)"<<endl);
                return Insecure;
              }
              else {
                LOG("Did not cover us, start="<<v.first.first<<", us="<<toBase32Hex(h)<<", end="<<toBase32Hex(nsec3->d_nexthash)<<endl);
              }
            }
          }
        }
        return Bogus;
      }
      for(auto cspiter =r.first;  cspiter!=r.second; cspiter++) {
        for(auto j=cspiter->second.records.cbegin(); j!=cspiter->second.records.cend(); j++)
        {
          const auto dsrc=std::dynamic_pointer_cast<DSRecordContent>(*j);
          if(dsrc) {
            dsmap.insert(*dsrc);
            // dotEdge(keyqname,
            //         "DNSKEY", keyqname, ,
            //         "DS", qname, std::to_string(dsrc.d_tag));
            // cout<<"    "<<dotEscape("DNSKEY "+keyqname)<<" -> "<<dotEscape("DS "+qname)<<";"<<endl;
          }
        }
      }
      if(!dsmap.size()) {
	//        cerr<<"no DS at this level, checking for denials"<<endl;
        dState dres = getDenial(validrrsets, qname, QType::DS);
        if(dres == INSECURE) return Insecure;
      }
    skipLevel:;
    } while(!dsmap.size() && labels.size());

    // break;
  }

  return state;
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
  if(zone != DNSName(".")) cout<<"subgraph "<<dotEscape("cluster "+zone.toString())<<" { ";
  cout<<dotEscape(dotName(type1, name1, tag1))
      <<" -> "
      <<dotEscape(dotName(type2, name2, tag2));
  if(color != "") cout<<" [ color=\""<<color<<"\" ]; ";
  else cout<<"; ";
  if(zone != DNSName(".")) cout<<"label = "<<dotEscape("zone: "+zone.toString())<<";"<<"}";
  cout<<endl;
#endif
}

