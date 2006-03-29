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

  vector<uint8_t> vpacket;
  string domain="www.ds9a.nl";
  uint16_t type=1;

  for(unsigned int n=0; n < 1000000; ++n) {
    DNSPacketWriter pw(vpacket, domain, type);
    pw.startRecord(domain, 1, 3600, 1, DNSPacketWriter::ANSWER);
    shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(1, 1, "1.2.3.4"));      

    drc->toPacket(pw);
    pw.commit();
    pw.getHeader()->rd=0;
    //    IPEndpoint rem("127.0.0.1",5300);
    //    string spacket((char*)(&*vpacket.begin()), vpacket.size());
    //    s.sendTo(spacket, rem);
  }
  cout<<xcount<<endl;

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
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<"\n";
}

  
