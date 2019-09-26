#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "rec-lua-conf.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "ednssubnet.hh"
#include "dnssecinfra.hh"
#include "recursor_cache.hh"
#include "base32.hh"
#include "root-dnssec.hh"

#include "validate.hh"
StatBag S;

class TCPResolver : public boost::noncopyable
{
public:
  TCPResolver(ComboAddress addr) : d_rsock(AF_INET, SOCK_STREAM)
  {
    d_rsock.connect(addr);
  }

  string query(const DNSName& qname, uint16_t qtype)
  {
    cerr<<"Q "<<qname<<"/"<<DNSRecordContent::NumberToType(qtype)<<endl;
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, qname, qtype);

    // recurse
    pw.getHeader()->rd=true;

    // we'll do the validation
    pw.getHeader()->cd=true;
    pw.getHeader()->ad=true;

    // we do require DNSSEC records to do that!
    pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
    pw.commit();

    uint16_t len;
    len = htons(packet.size());
    if(d_rsock.write((char *) &len, 2) != 2)
      throw PDNSException("tcp write failed");

    d_rsock.writen(string(packet.begin(), packet.end()));
    
    int bread=d_rsock.read((char *) &len, 2);
    if( bread <0)
      throw PDNSException("tcp read failed: "+stringerror());
    if(bread != 2) 
      throw PDNSException("EOF on TCP read");

    len=ntohs(len);
    std::unique_ptr<char[]> creply(new char[len]);
    int n=0;
    int numread;
    while(n<len) {
      numread=d_rsock.read(creply.get()+n, len-n);
      if(numread<0) {
        throw PDNSException("tcp read failed: "+stringerror());
      }
      n+=numread;
    }

    string reply(creply.get(), len);

    return reply;
  }

  Socket d_rsock;
};


class TCPRecordOracle : public DNSRecordOracle
{
public:
  TCPRecordOracle(const ComboAddress& dest) : d_dest(dest) {}
  vector<DNSRecord> get(const DNSName& qname, uint16_t qtype) override
  {
    TCPResolver tr(d_dest);
    string resp=tr.query(qname, qtype);
    MOADNSParser mdp(false, resp);
    vector<DNSRecord> ret;
    ret.reserve(mdp.d_answers.size());
    for(const auto& a : mdp.d_answers) {
      ret.push_back(a.first);
    }
    return ret;
  }
private:
  ComboAddress d_dest;
};

GlobalStateHolder<LuaConfigItems> g_luaconfs;
LuaConfigItems::LuaConfigItems()
{
  for (const auto &dsRecord : rootDSs) {
    auto ds=std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(dsRecord));
    dsAnchors[g_rootdnsname].insert(*ds);
  }
}

DNSFilterEngine::DNSFilterEngine() {}

int main(int argc, char** argv)
try
{
  reportAllTypes();
//  g_rootDS =  "19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5";

//  if(argv[5])
//    g_rootDS = argv[5];
  
  //  g_anchors.insert(DSRecordContent("19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5"));
  if(argc < 4) {
    cerr<<"Syntax: toysdig IP-address port question question-type [rootDS]\n";
    exit(EXIT_FAILURE);
  }
  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  TCPRecordOracle tro(dest);
  DNSName qname(argv[3]);
  uint16_t qtype=DNSRecordContent::TypeToNumber(argv[4]);
  cout<<"digraph oneshot {"<<endl;

  auto recs=tro.get(qname, qtype);

  cspmap_t cspmap=harvestCSPFromRecs(recs);
  cerr<<"Got "<<cspmap.size()<<" RRSETs: ";
  int numsigs=0;
  for(const auto& csp : cspmap) {
    cerr<<" "<<csp.first.first<<'/'<<DNSRecordContent::NumberToType(csp.first.second)<<": "<<csp.second.signatures.size()<<" sigs for "<<csp.second.records.size()<<" records"<<endl;
    numsigs+= csp.second.signatures.size();
  }
   
  skeyset_t keys;
  cspmap_t validrrsets;

  if(numsigs) {
    for(const auto& csp : cspmap) {
      for(const auto& sig : csp.second.signatures) {
	cerr<<"got rrsig "<<sig->d_signer<<"/"<<sig->d_tag<<endl;
	vState state = getKeysFor(tro, sig->d_signer, keys);
	cerr<<"! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys at "<<qname<<endl;
        // dsmap.insert(make_pair(dsrc.d_tag, dsrc));
      }
    }

    validateWithKeySet(cspmap, validrrsets, keys);
  }
  else {
    cerr<<"no sigs, hoping for Insecure"<<endl;
    vState state = getKeysFor(tro, qname, keys);
    cerr<<"! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys at "<<qname<<endl;
  }
  cerr<<"! validated "<<validrrsets.size()<<" RRsets out of "<<cspmap.size()<<endl;

  cerr<<"% validated RRs:"<<endl;
  for(auto i=validrrsets.begin(); i!=validrrsets.end(); i++) {
    cerr<<"% "<<i->first.first<<"/"<<DNSRecordContent::NumberToType(i->first.second)<<endl;
    for(auto j=i->second.records.begin(); j!=i->second.records.end(); j++) {
      cerr<<"\t% > "<<(*j)->getZoneRepresentation()<<endl;
    }
  }

  cout<<"}"<<endl;
  exit(0);
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
catch(PDNSException &pe)
{
  cerr<<"Fatal: "<<pe.reason<<endl;
}

