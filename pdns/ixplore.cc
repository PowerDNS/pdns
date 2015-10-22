#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "base64.hh"
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "base32.hh"
#include "dnssecinfra.hh"
#include <boost/foreach.hpp>
#include "dns_random.hh"
#include "gss_context.hh"

StatBag S;


uint32_t getSerial(const ComboAddress& master, const DNSName& zone, shared_ptr<SOARecordContent>& sr)
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, zone, QType::SOA);
  
  Socket s(master.sin4.sin_family, SOCK_DGRAM);
  s.connect(master);
  string msg((const char*)&packet[0], packet.size());
  s.writen(msg);

  string reply;
  s.read(reply);
  MOADNSParser mdp(reply);
  for(const auto& r: mdp.d_answers) {
    if(r.first.d_type == QType::SOA) {
      sr = std::dynamic_pointer_cast<SOARecordContent>(r.first.d_content);
      cout<<"Current serial number: "<<sr->d_st.serial<<endl;
      return sr->d_st.serial;
    }
  }
  return 0;
}

vector<vector<pair<vector<DNSRecord>, vector<DNSRecord> > > >  getIXFRDeltas(const ComboAddress& master, const DNSName& zone, shared_ptr<SOARecordContent> sr)
{
  vector<vector<pair<vector<DNSRecord>, vector<DNSRecord> > > > ret;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, zone, QType::IXFR);
  pw.getHeader()->qr=0;
  pw.getHeader()->rd=0;
  pw.startRecord(zone, QType::SOA, 3600, QClass::IN, DNSPacketWriter::AUTHORITY);
  sr->toPacket(pw);
  pw.commit();
  
  
  uint16_t len=htons(packet.size());
  string msg((const char*)&len, 2);
  msg.append((const char*)&packet[0], packet.size());

  Socket s(master.sin4.sin_family, SOCK_STREAM);
  s.connect(master);
  s.writen(msg);

  // CURRENT MASTER SOA
  // REPEAT:
  //   SOA WHERE THIS DELTA STARTS
  //   RECORDS TO REMOVE
  //   SOA WHERE THIS DELTA GOES
  //   RECORDS TO ADD
  // CURRENT MASTER SOA 
  shared_ptr<SOARecordContent> masterSOA;
  vector<DNSRecord> records;
  for(;;) {
    if(s.read((char*)&len, 2)!=2)
      break;
    len=ntohs(len);
    cout<<"Got chunk of "<<len<<" bytes"<<endl;
    if(!len)
      break;
    char reply[len]; 
    readn2(s.getHandle(), reply, len);
    MOADNSParser mdp(string(reply, len));
    cout<<"Got a response, rcode: "<<mdp.d_header.rcode<<", got "<<mdp.d_answers.size()<<" answers"<<endl;
    for(const auto& r: mdp.d_answers) {
      records.push_back(r.first);
      if(r.first.d_type == QType::SOA) {
	auto sr = std::dynamic_pointer_cast<SOARecordContent>(r.first.d_content);
	if(!masterSOA) {
	  masterSOA=sr;
	}
	else if(sr->d_st.serial == masterSOA->d_st.serial)
	  goto done;

      }
    }
  }
 done:;
  for(int pos = 1;pos < records.size();) {
    auto sr = std::dynamic_pointer_cast<SOARecordContent>(records[pos].d_content);
    if(sr->d_st.serial == masterSOA->d_st.serial)
      break;
    
    cout<<"Got delta going from "<<sr->d_st.serial<<endl;
    for(pos++; pos < records.size() && records[pos].d_type != QType::SOA; ++pos)
      cout<<"Should remove "<<records[pos].d_name<<" "<<DNSRecordContent::NumberToType(records[pos].d_type)<<" "<<records[pos].d_content->getZoneRepresentation()<<endl;
    sr = std::dynamic_pointer_cast<SOARecordContent>(records[pos].d_content);
    cout<<"This delta goes to "<<sr->d_st.serial<<endl;
    for(pos++; pos < records.size() && records[pos].d_type != QType::SOA; ++pos) 
      cout<<"Should ADD "<<records[pos].d_name<<" "<<DNSRecordContent::NumberToType(records[pos].d_type)<<" "<<records[pos].d_content->getZoneRepresentation()<<endl;
    cout<<"End of this delta"<<endl<<endl;
  }
  
  return ret;
  
}


int main(int argc, char** argv)
try
{
  if(argc < 4) {
    cerr<<"Syntax: saxfr IP-address port zone directory"<<endl;
    exit(EXIT_FAILURE);
  }

  reportAllTypes();

    /* goal in life:
     in directory/zone-name we leave files with their name the serial number
     at startup, retrieve current SOA SERIAL for domain from master server
     
     compare with what the best is we have in our directory, IXFR from that.
     Store result in memory, read that best zone in memory, apply deltas, write it out.

     Next up, loop this every REFRESH seconds */

  DNSName zone(argv[3]);
  
  ComboAddress master(argv[1], atoi(argv[2]));

  shared_ptr<SOARecordContent> sr;
  uint32_t serial = getSerial(master, zone, sr);
  sr->d_st.serial=1445514388;

  auto deltas = getIXFRDeltas(master, zone, sr);
  
  

}
catch(PDNSException &e2) {
  cerr<<"Fatal: "<<e2.reason<<endl;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
