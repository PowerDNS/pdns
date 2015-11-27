#include "validate.hh"
#include "validate-recursor.hh"
#include "syncres.hh"

class SRRecordOracle : public DNSRecordOracle
{
public:
  vector<DNSRecord> get(const DNSName& qname, uint16_t qtype) override
  {
    struct timeval tv;
    gettimeofday(&tv, 0);
    SyncRes sr(tv);

    vector<DNSRecord> ret;
    int res;
    sr.d_doDNSSEC=true;
    res=sr.beginResolve(qname, QType(qtype), 1, ret);
    d_queries += sr.d_outqueries;
    return ret;
  }
  int d_queries{0};
};


bool validateRecords(const vector<DNSRecord>& recs)
{
  g_rootDS =  "19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5";
  cspmap_t cspmap=harvestCSPFromRecs(recs);
  //  cerr<<"Got "<<cspmap.size()<<" RRSETs: ";
  int numsigs=0;
  for(const auto& csp : cspmap) {
    //    cerr<<" "<<csp.first.first<<'/'<<DNSRecordContent::NumberToType(csp.first.second)<<": "<<csp.second.signatures.size()<<" sigs for "<<csp.second.records.size()<<" records"<<endl;
    numsigs+= csp.second.signatures.size();
  }
   
  set<DNSKEYRecordContent> keys;
  cspmap_t validrrsets;

  SRRecordOracle sro;

  if(numsigs) {
    for(const auto& csp : cspmap) {
      for(const auto& sig : csp.second.signatures) {
	//	cerr<<"got rrsig "<<sig->d_signer<<"/"<<sig->d_tag<<endl;
	vState state = getKeysFor(sro, sig->d_signer, keys);
	//	cerr<<"! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys"<<endl;
        // dsmap.insert(make_pair(dsrc.d_tag, dsrc));
      }
    }

    validateWithKeySet(cspmap, validrrsets, keys);
  }
  else {
    //    cerr<<"no sigs, hoping for Insecure"<<endl;
    vState state = getKeysFor(sro, recs.begin()->d_name, keys); // um WHAT DOES THIS MEAN - try first qname??
    //    cerr<<"! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys "<<endl;
  }
  //  cerr<<"! validated "<<validrrsets.size()<<" RRsets out of "<<cspmap.size()<<endl;

  //  cerr<<"% validated RRs:"<<endl;
  for(auto i=validrrsets.begin(); i!=validrrsets.end(); i++) {
    //    cerr<<"% "<<i->first.first<<"/"<<DNSRecordContent::NumberToType(i->first.second)<<endl;
    for(auto j=i->second.records.begin(); j!=i->second.records.end(); j++) {
      //      cerr<<"\t% > "<<(*j)->getZoneRepresentation()<<endl;
    }
  }
  //  cerr<<"Took "<<sro.d_queries<<" queries"<<endl;
  return validrrsets.size() == cspmap.size();
}
