#include "validate.hh"
#include "validate-recursor.hh"
#include "syncres.hh"
#include "logger.hh"

DNSSECMode g_dnssecmode{DNSSECMode::ProcessNoValidate};

#define LOG(x) if(g_dnssecLOG) { L <<Logger::Warning << x; }

class SRRecordOracle : public DNSRecordOracle
{
public:
  vector<DNSRecord> get(const DNSName& qname, uint16_t qtype) override
  {
    struct timeval tv;
    gettimeofday(&tv, 0);
    SyncRes sr(tv);

    vector<DNSRecord> ret;
    sr.d_doDNSSEC=true;
    sr.beginResolve(qname, QType(qtype), 1, ret);
    d_queries += sr.d_outqueries;
    return ret;
  }
  int d_queries{0};
};


vState validateRecords(const vector<DNSRecord>& recs)
{
  if(recs.empty())
    return Insecure; // can't secure nothing 

  cspmap_t cspmap=harvestCSPFromRecs(recs);
  LOG("Got "<<cspmap.size()<<" RRSETs: "<<endl);
  int numsigs=0;
  for(const auto& csp : cspmap) {
    LOG("Going to validate: "<<csp.first.first<<"/"<<DNSRecordContent::NumberToType(csp.first.second)<<": "<<csp.second.signatures.size()<<" sigs for "<<csp.second.records.size()<<" records"<<endl);
    numsigs+= csp.second.signatures.size();
  }
   
  set<DNSKEYRecordContent> keys;
  cspmap_t validrrsets;

  SRRecordOracle sro;

  vState state=Insecure;
  if(numsigs) {
    for(const auto& csp : cspmap) {
      for(const auto& sig : csp.second.signatures) {
        state = getKeysFor(sro, sig->d_signer, keys); // XXX check validity here
        if(state == NTA)
          return Insecure;
        LOG("! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys"<<endl);
        for(const auto& k : keys) {
          LOG("Key: "<<k.getZoneRepresentation()<< " {tag="<<k.getTag()<<"}"<<endl);
        }
        // this sort of charges on and 'state' ends up as the last thing to have been checked
        // maybe not the right idea
      }
    }
    if(state == Bogus) {
      return state;
    }
    validateWithKeySet(cspmap, validrrsets, keys);
  }
  else {
    LOG("! no sigs, hoping for Insecure status of "<<recs.begin()->d_name<<endl);
    state = getKeysFor(sro, recs.begin()->d_name, keys); // um WHAT DOES THIS MEAN - try first qname??
   
    LOG("! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys "<<endl);
    return state;
  }
  
  LOG("Took "<<sro.d_queries<<" queries"<<endl);
  if(validrrsets.size() == cspmap.size()) // shortcut - everything was ok
    return Secure;

  if(keys.empty()) {
    return Insecure;
  }

#if 0
  cerr<<"! validated "<<validrrsets.size()<<" RRsets out of "<<cspmap.size()<<endl;

  cerr<<"% validated RRs:"<<endl;
  for(auto i=validrrsets.begin(); i!=validrrsets.end(); i++) {
        cerr<<"% "<<i->first.first<<"/"<<DNSRecordContent::NumberToType(i->first.second)<<endl;
    for(auto j=i->second.records.begin(); j!=i->second.records.end(); j++) {
            cerr<<"\t% > "<<(*j)->getZoneRepresentation()<<endl;
    }
  }
#endif
  //  cerr<<"Input to validate: "<<endl;
  for(const auto& csp : cspmap) {
    LOG(csp.first.first<<"|"<<DNSRecordContent::NumberToType(csp.first.second)<<" with "<<csp.second.signatures.size()<<" signatures"<<endl);
    if(!csp.second.signatures.empty() && !validrrsets.count(csp.first)) {
      LOG("Lacks signature, must have one, signatures: "<<csp.second.signatures.size()<<", valid rrsets: "<<validrrsets.count(csp.first)<<endl);
      return Bogus;
    }
  }
  
  return Insecure;
}
