#include "validate.hh"
#include "validate-recursor.hh"
#include "syncres.hh"
#include "logger.hh"

DNSSECMode g_dnssecmode{DNSSECMode::ProcessNoValidate};
bool g_dnssecLogBogus;

extern int getMTaskerTID();

#define LOG(x) if(g_dnssecLOG) { L <<Logger::Warning << x; }

class SRRecordOracle : public DNSRecordOracle
{
public:
  SRRecordOracle(const ResolveContext& ctx): d_ctx(ctx)
  {
  }
  vector<DNSRecord> get(const DNSName& qname, uint16_t qtype) override
  {
    struct timeval tv;
    gettimeofday(&tv, 0);
    SyncRes sr(tv);
    sr.setId(getMTaskerTID());
#ifdef HAVE_PROTOBUF
    sr.setInitialRequestId(d_ctx.d_initialRequestId);
#endif

    vector<DNSRecord> ret;
    sr.setDoDNSSEC(true);
    if (qtype == QType::DS || qtype == QType::DNSKEY || qtype == QType::NS)
      sr.setSkipCNAMECheck(true);
    sr.beginResolve(qname, QType(qtype), 1, ret);
    d_queries += sr.d_outqueries;
    return ret;
  }
  const ResolveContext& d_ctx;
  unsigned int d_queries{0};
};

bool checkDNSSECDisabled() {
  return warnIfDNSSECDisabled("");
}

bool warnIfDNSSECDisabled(const string& msg) {
  if(g_dnssecmode == DNSSECMode::Off) {
    if (!msg.empty())
      L<<Logger::Warning<<msg<<endl;
    return true;
  }
  return false;
}

static vState increaseDNSSECStateCounter(const vState& state)
{
  g_stats.dnssecResults[state]++;
  return state;
}

/*
 * This inline possibly sets currentState based on the new state. It will only
 * set it to Secure iff the newState is Secure and mayUpgradeToSecure == true.
 * This should be set by the calling function when checking more than one record
 * and this is not the first record, this way, we can never go *back* to Secure
 * from an Insecure vState
 */
static void processNewState(vState& currentState, const vState& newState, bool& hadNTA, const bool& mayUpgradeToSecure)
{
  if (mayUpgradeToSecure && newState == Secure)
    currentState = Secure;

  if (newState == Insecure || newState == NTA) // We can never go back to Secure
    currentState = Insecure;

  if (newState == NTA)
    hadNTA = true;
}

vState validateRecords(const ResolveContext& ctx, const vector<DNSRecord>& recs)
{
  if(recs.empty())
    return Insecure; // can't secure nothing 

  g_stats.dnssecValidations++;

  cspmap_t cspmap=harvestCSPFromRecs(recs);
  LOG("Got "<<cspmap.size()<<" RRSETs: "<<endl);
  size_t numsigs=0;
  for(const auto& csp : cspmap) {
    LOG("Going to validate: "<<csp.first.first<<"/"<<DNSRecordContent::NumberToType(csp.first.second)<<": "<<csp.second.signatures.size()<<" sigs for "<<csp.second.records.size()<<" records"<<endl);
    numsigs+= csp.second.signatures.size();
  }
   
  skeyset_t keys;
  cspmap_t validrrsets;

  SRRecordOracle sro(ctx);

  vState state=Insecure;
  bool hadNTA = false;
  if(numsigs) {
    bool first = true;
    for(const auto& csp : cspmap) {
      for(const auto& sig : csp.second.signatures) {
        vState newState = getKeysFor(sro, sig->d_signer, keys); // XXX check validity here

        if (newState == Bogus) // No hope
          return increaseDNSSECStateCounter(Bogus);

        processNewState(state, newState, hadNTA, first);

        first = false;

        LOG("! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys"<<endl);
        for(const auto& k : keys) {
          LOG("Key: "<<k->getZoneRepresentation()<< " {tag="<<k->getTag()<<"}"<<endl);
        }
      }
    }
    validateWithKeySet(cspmap, validrrsets, keys);
  }
  else {
    LOG("! no sigs, hoping for Insecure status of "<<recs.begin()->d_name<<endl);

    bool first = true;
    for(const auto& rec : recs) {
      vState newState = getKeysFor(sro, rec.d_name, keys);

      if (newState == Bogus) // We're done
        return increaseDNSSECStateCounter(Bogus);

      processNewState(state, newState, hadNTA, first);
      first = false;

      LOG("! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys "<<endl);

      if (state != Insecure && state != NTA) {
        /* we had no sigs, remember? */
        return increaseDNSSECStateCounter(Bogus);
      }
    }
    return increaseDNSSECStateCounter(state);
  }

  LOG("Took "<<sro.d_queries<<" queries"<<endl);
  if(validrrsets.size() == cspmap.size())// shortcut - everything was ok
    return increaseDNSSECStateCounter(Secure);

  if(state == Insecure || keys.empty()) {
    if (hadNTA) {
      increaseDNSSECStateCounter(NTA);
      return Insecure;
    }
    return increaseDNSSECStateCounter(Insecure);
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
      return increaseDNSSECStateCounter(Bogus);
    }
  }
  return increaseDNSSECStateCounter(Insecure);
}
