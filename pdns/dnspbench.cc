#include "logger.hh"
Logger L("dnspbench");

#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"

#include "statbag.hh"
#include <stdint.h>
#include <set>

using namespace boost;


StatBag S;

#include <bits/atomicity.h>
// This code is ugly but does speedup the recursor tremendously on multi-processor systems, and even has a large effect (20, 30%) on uniprocessor 
namespace __gnu_cxx
{
  _Atomic_word
  __attribute__ ((__unused__))
  __exchange_and_add(volatile _Atomic_word* __mem, int __val)
  {
    register _Atomic_word __result=*__mem;
    *__mem+=__val;
    return __result;
  }

  void
  __attribute__ ((__unused__))
  __atomic_add(volatile _Atomic_word* __mem, int __val)
  {
    *__mem+=__val;
  }
}

int xcount;

int main(int argc, char** argv)
try
{
  reportAllTypes();

  Socket s(InterNetwork, Datagram);
  
  IPEndpoint rem("10.0.1.6", atoi(argv[1])), loc("213.156.2.1", 53);
  //  s.bind(loc);

  vector<uint8_t> vpacket;
  string domain="ds9a.nl";
  uint16_t type=1;

  for(unsigned int n=0; n < 65536; ++n) {
    DNSPacketWriter pw(vpacket, domain, type);
    
    pw.getHeader()->rd=1;
    pw.getHeader()->qr=0;
    pw.getHeader()->id=n;
    //    ARecordContent arc("1.2.3.4");
    //    pw.startRecord("ds9a.nl", 1, 9999, 1, DNSPacketWriter::ANSWER);
    //    arc.toPacket(pw);
    //    pw.commit();

    string spacket((char*)(&*vpacket.begin()), vpacket.size());
    s.sendTo(spacket, rem);
  }

  return 0; 
#if 0

  vector<uint8_t> packet;

  uint16_t type=DNSRecordContent::TypeToNumber(argv[2]);

  DNSRecordContent* drc=DNSRecordContent::mastermake(type, 1, argv[3]);

  cerr<<"In: "<<argv[1]<<" IN " <<argv[2]<<" "<< argv[3] << "\n";

  string record=drc->serialize(argv[1]);

  cerr<<"sizeof: "<<record.length()<<"\n";
  cerr<<"hexdump: "<<makeHexDump(record)<<"\n";
  //  cerr<<"record: "<<record<<"\n";

  shared_ptr<DNSRecordContent> regen=DNSRecordContent::unserialize(argv[1], type, record);
  cerr<<"Out: "<<argv[1]<<" IN "<<argv[2]<<" "<<regen->getZoneRepresentation()<<endl;
#endif
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<"\n";
}

  
