#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "logger.hh"
#include "statbag.hh"
#include <set>
#define BOOST_NO_MT

#include <boost/pool/pool.hpp>
#include <boost/pool/object_pool.hpp>

#include <boost/pool/pool_alloc.hpp>
using namespace boost;

Logger L("dnspbench");
StatBag S;

int main(int argc, char** argv)
try
{
  set<int, std::less<int>, boost::pool_allocator<int> > blah;

  for(unsigned int n=0;n< 1000000;++n)
    blah.insert(random());
  cerr<<"Done inserting"<<endl;
  string line;
  getline(cin, line);
  cerr<<"Done!"<<endl;

  exit(0);

  dnsheader dnsheader;
  dnsheader.qdcount=htons(1);
  dnsheader.ancount=htons(1);
  Socket s(InterNetwork, Datagram);
  string spacket;
  char* p=(char*)&dnsheader;
  spacket.assign(p, p+sizeof(dnsheader));
  IPEndpoint rem("127.0.0.1",5300);
  s.sendTo(spacket, rem);
  
  return 0;

  reportAllTypes();

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
}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<"\n";
}

  
