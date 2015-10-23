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
#include "zoneparser-tng.hh"
#include <boost/multi_index_container.hpp>
#include <fstream>
using namespace boost::multi_index;
StatBag S;

struct CanonStruct : public std::binary_function<DNSName, DNSName, bool>
{
  bool operator()(const DNSName&a, const DNSName& b) const
  {
    return a.canonCompare(b);
  }
};

struct CIContentCompareStruct
{
  bool operator()(const shared_ptr<DNSRecordContent>&a, const shared_ptr<DNSRecordContent>& b) const
  {
    return toLower(a->getZoneRepresentation()) < toLower(b->getZoneRepresentation());
  }
};


typedef multi_index_container<
  DNSRecord,
    indexed_by<
      ordered_non_unique<
        composite_key<DNSRecord,
		      member<DNSRecord, DNSName, &DNSRecord::d_name>,
		      member<DNSRecord, uint16_t, &DNSRecord::d_type>,
		      member<DNSRecord, uint16_t, &DNSRecord::d_class>,
		      member<DNSRecord, shared_ptr<DNSRecordContent>, &DNSRecord::d_content> >,
		      composite_key_compare<CanonStruct, std::less<uint16_t>, std::less<uint16_t>, CIContentCompareStruct >
		      
      >
    >
  >records_t;

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

vector<pair<vector<DNSRecord>, vector<DNSRecord> > >   getIXFRDeltas(const ComboAddress& master, const DNSName& zone, shared_ptr<SOARecordContent> sr)
{
  vector<pair<vector<DNSRecord>, vector<DNSRecord> > >  ret;
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
    //    cout<<"Got chunk of "<<len<<" bytes"<<endl;
    if(!len)
      break;
    char reply[len]; 
    readn2(s.getHandle(), reply, len);
    MOADNSParser mdp(string(reply, len));
    //    cout<<"Got a response, rcode: "<<mdp.d_header.rcode<<", got "<<mdp.d_answers.size()<<" answers"<<endl;
    for(auto& r: mdp.d_answers) {
      r.first.d_name = r.first.d_name.makeRelative(zone);
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
  for(unsigned int pos = 1;pos < records.size();) {
    auto sr = std::dynamic_pointer_cast<SOARecordContent>(records[pos].d_content);
    if(sr->d_st.serial == masterSOA->d_st.serial)
      break;
    
    //    cout<<"Got delta going from "<<sr->d_st.serial<<endl;
    vector<DNSRecord> remove, add;
    remove.push_back(records[pos]); // this adds the SOA
    for(pos++; pos < records.size() && records[pos].d_type != QType::SOA; ++pos) {
      // cout<<"Should remove "<<records[pos].d_name<<" "<<DNSRecordContent::NumberToType(records[pos].d_type)<<" "<<records[pos].d_content->getZoneRepresentation()<<endl;
      remove.push_back(records[pos]);
    }
    sr = std::dynamic_pointer_cast<SOARecordContent>(records[pos].d_content);
    //    cout<<"This delta goes to "<<sr->d_st.serial<<endl;
    add.push_back(records[pos]); // this adds the new SOA
    for(pos++; pos < records.size() && records[pos].d_type != QType::SOA; ++pos)  {
      //      cout<<"Should ADD "<<records[pos].d_name<<" "<<DNSRecordContent::NumberToType(records[pos].d_type)<<" "<<records[pos].d_content->getZoneRepresentation()<<endl;
      add.push_back(records[pos]);
    }
    ret.push_back(make_pair(remove,add));
    //    cout<<"End of this delta"<<endl<<endl;
  }
  
  return ret;
  
}

uint32_t getHighestSerialFromDir(const std::string& dir)
{
  return 1445497587;
}

bool canonCompare(const DNSRecord& a, const DNSRecord& b)
{
  if(a.d_name.canonCompare(b.d_name))
    return true;
  if(a.d_name!=b.d_name) {
    return false;
  }
  string lzrp, rzrp;
  if(a.d_content)
    lzrp=toLower(a.d_content->getZoneRepresentation());
  if(b.d_content)
    rzrp=toLower(b.d_content->getZoneRepresentation());
  auto atype = a.d_type == QType::SOA ? 0 : a.d_type;
  auto btype = b.d_type == QType::SOA ? 0 : b.d_type;
  
  return tie(atype, a.d_class, lzrp) <
         tie(btype, b.d_class, rzrp);
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
  uint32_t ourSerial = getHighestSerialFromDir(argv[4]);

  cout<<"Our serial: "<<ourSerial<<", their serial: "<<serial<<endl;

  ZoneParserTNG zpt(argv[4]+string("/")+std::to_string(ourSerial), zone);
  DNSResourceRecord rr;
  unsigned int nrecords=0;
  records_t records;

  while(zpt.get(rr)) {
    ++nrecords;
    if(rr.qtype.getCode() == QType::CNAME && rr.content.empty())
      rr.content=".";
    rr.qname = rr.qname.makeRelative(zone);
    records.insert(DNSRecord(rr));
  }

  cout<<"Parsed "<<nrecords<<" records"<<endl;
  sr->d_st.serial= ourSerial;

  auto deltas = getIXFRDeltas(master, zone, sr);
  cout<<"Got "<<deltas.size()<<" deltas, applying.."<<endl;
  int oldserial;
  for(const auto& delta : deltas) {
    for(const auto& r : records) {
      if(r.d_type == QType::SOA) {
	oldserial=std::dynamic_pointer_cast<SOARecordContent>(r.d_content)->d_st.serial;
	cout<<"Serial before application: "<< oldserial  <<endl;
	break;
      }
    }

    const auto& remove = delta.first;
    const auto& add = delta.second;
    set<DNSRecord> toremove;
    ofstream report(string(argv[4]) +"/delta."+std::to_string(oldserial));
    for(const auto& rr : remove) {
      auto range = records.equal_range(tie(rr.d_name, rr.d_type, rr.d_class, rr.d_content));
      if(range.first == range.second) {
	cerr<<"Could not find record "<<rr.d_name<<" to remove!!"<<endl;
	exit(1);
      }
      if(rr.d_type == QType::SOA) {
	cout<<"Serial to remove:  "<< std::dynamic_pointer_cast<SOARecordContent>(rr.d_content)->d_st.serial <<endl;
      }
      records.erase(range.first, range.second);
      report<<'-'<< (rr.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(rr.d_type)<<" "<<rr.d_content->getZoneRepresentation()<<endl;
    }
    cout<<"Adding "<<add.size()<<" records now"<<endl;

    uint32_t newserial=0;
    for(const auto& rr : add) {
      if(rr.d_type == QType::SOA) {
	newserial=std::dynamic_pointer_cast<SOARecordContent>(rr.d_content)->d_st.serial;
	cout<<"Serial to ADD:  "<< newserial <<endl;
      }
      report<<'+'<< (rr.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(rr.d_type)<<" "<<rr.d_content->getZoneRepresentation()<<endl;
      records.insert(rr);
    }
    if(newserial == serial) {
      FILE* fp=fopen((string(argv[4]) +"/"+std::to_string(newserial)).c_str(), "w");
      for(const auto& r: records) {
	fprintf(fp, "%s\t%d\tIN\t%s\t%s\n", (r.d_name+zone).toString().c_str(),
		r.d_ttl,
		DNSRecordContent::NumberToType(r.d_type).c_str(),
		r.d_content->getZoneRepresentation().c_str());
      }
      fclose(fp);
      
    }
  }
}
catch(PDNSException &e2) {
  cerr<<"Fatal: "<<e2.reason<<endl;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
