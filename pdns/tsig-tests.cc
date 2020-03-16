#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "digests.hh"
#include "base64.hh"
#include "dnssecinfra.hh"
#include "axfr-retriever.hh"
#include "arguments.hh"
#include "dns_random.hh"

StatBag S;

ArgvMap& arg()
{
  static ArgvMap theArg;
  return theArg;
}

int main(int argc, char** argv)
try
{
  ::arg().set("query-local-address","Source IP address for sending queries")="0.0.0.0";
  ::arg().set("query-local-address6","Source IPv6 address for sending queries")="::";

  reportAllTypes();

  if(argc < 4) {
    cerr<<"tsig-tests: ask a TSIG signed question, verify the TSIG signed answer"<<endl;
    cerr<<"Syntax: tsig IP-address port question question-type\n";
    exit(EXIT_FAILURE);
  }

  vector<uint8_t> packet;
  
  DNSPacketWriter pw(packet, DNSName(argv[3]), DNSRecordContent::TypeToNumber(argv[4]));

  pw.getHeader()->id=htons(0x4831);
  
  string key;
  B64Decode("Syq9L9WrBWdxBC+HxKok2g==", key);

  DNSName keyname("pdns-b-aa");

  TSIGRecordContent trc;
  trc.d_algoName=DNSName("hmac-md5.sig-alg.reg.int");
  trc.d_time=time(0);
  trc.d_fudge=300;
  trc.d_origID=ntohs(pw.getHeader()->id);
  trc.d_eRcode=0;

  addTSIG(pw, trc, keyname, key, "", false);

  Socket sock(AF_INET, SOCK_DGRAM);
  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  cerr<<"Keyname: '"<<keyname<<"', algo: '"<<trc.d_algoName<<"', key: '"<<Base64Encode(key)<<"'\n";
  TSIGTriplet tt;
  tt.name=keyname;
  tt.algo=DNSName("hmac-md5");
  tt.secret=key;
  AXFRRetriever axfr(dest, DNSName("b.aa"), tt);
  vector<DNSResourceRecord> res;
  while(axfr.getChunk(res)) {
  }
  return 0;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
  return 1;
}
catch(PDNSException& ae)
{
  cerr<<"Fatal 2: "<<ae.reason<<endl;
  return 1;
}
