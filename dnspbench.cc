#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"



int main(int argc, char** argv)
try
{
  reportAllTypes();

  cerr<<"sizeof(optString): "<<sizeof(struct optString)<<endl;

  optString os("hallo!");

  cerr<<"optString: '"<<(string)os<<"'\n";

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

  
