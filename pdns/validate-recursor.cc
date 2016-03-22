#include "validate.hh"
#include "validate-recursor.hh"
#include "syncres.hh"

DNSSECMode g_dnssecmode{DNSSECMode::Process};

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
  //  cerr<<"Got "<<cspmap.size()<<" RRSETs: ";
  int numsigs=0;
  for(const auto& csp : cspmap) {
    //    cerr<<"Going to validate: "<<csp.first.first<<'/'<<DNSRecordContent::NumberToType(csp.first.second)<<": "<<csp.second.signatures.size()<<" sigs for "<<csp.second.records.size()<<" records"<<endl;
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
        //	cerr<<"! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys"<<endl;
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
    //    cerr<<"no sigs, hoping for Insecure"<<endl;
    state = getKeysFor(sro, recs.begin()->d_name, keys); // um WHAT DOES THIS MEAN - try first qname??
   
    //    cerr<<"! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys "<<endl;
    return state;
  }
  
  //  cerr<<"Took "<<sro.d_queries<<" queries"<<endl;
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
    cerr<<csp.first.first<<"|"<<csp.first.second<<" with "<<csp.second.signatures.size()<<" signatures"<<endl;
    if(!csp.second.signatures.empty() && !validrrsets.count(csp.first)) {
      //      cerr<<"Lacks signature, must have one"<<endl;
      return Bogus;
    }
  }
  
  return Insecure;
}
