#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "arguments.hh"
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
#include "resolver.hh"
#include <fstream>
using namespace boost::multi_index;
StatBag S;


ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}


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
	composite_key_compare<CanonDNSNameCompare, std::less<uint16_t>, std::less<uint16_t>, CIContentCompareStruct >
		      
      >
    >
  >records_t;

uint32_t getSerialFromMaster(const ComboAddress& master, const DNSName& zone, shared_ptr<SOARecordContent>& sr)
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
      return sr->d_st.serial;
    }
  }
  return 0;
}

vector<pair<vector<DNSRecord>, vector<DNSRecord> > >   getIXFRDeltas(const ComboAddress& master, const DNSName& zone, const DNSRecord& sr)
{
  vector<pair<vector<DNSRecord>, vector<DNSRecord> > >  ret;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, zone, QType::IXFR);
  pw.getHeader()->qr=0;
  pw.getHeader()->rd=0;
  pw.startRecord(zone, QType::SOA, 3600, QClass::IN, DNSPacketWriter::AUTHORITY);
  sr.d_content->toPacket(pw);
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

uint32_t getSerialsFromDir(const std::string& dir)
{
  uint32_t ret=0;
  DIR* dirhdl=opendir(dir.c_str());
  if(!dirhdl) 
    throw runtime_error("Could not open IXFR directory");
  struct dirent *entry;
  
  while((entry = readdir(dirhdl))) {
    uint32_t num = atoi(entry->d_name);
    if(std::to_string(num) == entry->d_name)
      ret = max(num, ret);
  }
  closedir(dirhdl);
  return ret;
}

uint32_t getSerialFromRecords(const records_t& records,	DNSRecord& soaret)
{ 
  DNSName root(".");
  uint16_t t=QType::SOA;

  auto found = records.equal_range(tie(root, t));

  for(auto iter = found.first; iter != found.second; ++iter) {
    auto soa = std::dynamic_pointer_cast<SOARecordContent>(iter->d_content);
    soaret = *iter;
    return soa->d_st.serial;
  }
  return 0;
}

void writeZoneToDisk(const records_t& records, const DNSName& zone, const std::string& directory)
{
  DNSRecord soa;
  int serial = getSerialFromRecords(records, soa);
  string fname=directory +"/"+std::to_string(serial);
  FILE* fp=fopen((fname+".partial").c_str(), "w");
  records_t soarecord;
  soarecord.insert(soa);

  for(const auto& outer : {soarecord, records, soarecord} ) {
    for(const auto& r: outer) {
      fprintf(fp, "%s\t%d\tIN\t%s\t%s\n", (r.d_name+zone).toString().c_str(),
	      r.d_ttl,
	      DNSRecordContent::NumberToType(r.d_type).c_str(),
	      r.d_content->getZoneRepresentation().c_str());
    }
  }
  fclose(fp);
  rename( (fname+".partial").c_str(), fname.c_str());
}

void loadZoneFromDisk(records_t& records, const string& fname, const DNSName& zone)
{
  ZoneParserTNG zpt(fname, zone);

  DNSResourceRecord rr;
  bool seenSOA=false;
  unsigned int nrecords=0;
  while(zpt.get(rr)) {
    ++nrecords;
    if(rr.qtype.getCode() == QType::CNAME && rr.content.empty())
      rr.content=".";
    rr.qname = rr.qname.makeRelative(zone);
    
    if(rr.qtype.getCode() != QType::SOA || seenSOA==false)
      records.insert(DNSRecord(rr));
    if(rr.qtype.getCode() == QType::SOA) {
      seenSOA=true;
    }
  }
  cout<<"Parsed "<<nrecords<<" records"<<endl;
  if(rr.qtype.getCode() == QType::SOA && seenSOA) {
    cout<<"Zone was complete (SOA at end)"<<endl;
  }
  else  {
    records.clear();
    throw runtime_error("Zone not complete!");
  }
}

int main(int argc, char** argv)
try
{
  reportAllTypes();
  if(argc==5 && string(argv[1])=="diff") {
    cerr<<"Syntax: ixplore diff zone file1 file2"<<endl;
    records_t before, after;
    DNSName zone(argv[2]);
    cout<<"Loading before from "<<argv[3]<<endl;
    loadZoneFromDisk(before, argv[3], zone);
    cout<<"Loading after from "<<argv[4]<<endl;
    loadZoneFromDisk(after, argv[4], zone);

    vector<DNSRecord> diff;

    set_difference(before.cbegin(), before.cend(), after.cbegin(), after.cend(), back_inserter(diff), before.value_comp());
    for(const auto& d : diff) {
      cout<<'-'<< (d.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(d.d_type)<<" "<<d.d_content->getZoneRepresentation()<<endl;
    }
    diff.clear();
    set_difference(after.cbegin(), after.cend(), before.cbegin(), before.cend(), back_inserter(diff), before.value_comp());
    for(const auto& d : diff) {
      cout<<'+'<< (d.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(d.d_type)<<" "<<d.d_content->getZoneRepresentation()<<endl;
    }
    exit(1);
  }
  if(argc < 4) {
    cerr<<"Syntax: ixplore IP-address port zone directory"<<endl;
    exit(EXIT_FAILURE);
  }



    /* goal in life:
     in directory/zone-name we leave files with their name the serial number
     at startup, retrieve current SOA SERIAL for domain from master server
     
     compare with what the best is we have in our directory, IXFR from that.
     Store result in memory, read that best zone in memory, apply deltas, write it out.

     Next up, loop this every REFRESH seconds */
  dns_random_init("0123456789abcdef");

  DNSName zone(argv[3]);
  ComboAddress master(argv[1], atoi(argv[2]));
  records_t records;

  uint32_t ourSerial = getSerialsFromDir(argv[4]);

  cout<<"Loading zone, our highest available serial is "<< ourSerial<<endl;

  try {
    if(!ourSerial)
      throw std::runtime_error("There is no local zone available");
    string fname=argv[4]+string("/")+std::to_string(ourSerial);
    cout<<"Loading serial number "<<ourSerial<<" from file "<<fname<<endl;
    loadZoneFromDisk(records, fname, zone);
  }
  catch(std::exception& e) {
    cout<<"Could not load zone from disk: "<<e.what()<<endl;
    cout<<"Retrieving latest from master "<<master.toStringWithPort()<<endl;
    ComboAddress local("0.0.0.0");
    AXFRRetriever axfr(master, zone, DNSName(), DNSName(), "", &local);
    unsigned int nrecords=0;
    Resolver::res_t nop;
    vector<DNSRecord> chunk;
    char wheel[]="|/-\\";
    int count=0;
    time_t last=0;
    while(axfr.getChunk(nop, &chunk)) {
      for(auto& dr : chunk) {
	dr.d_name.makeUsRelative(zone);
	records.insert(dr);
	nrecords++;
      } 
    
      if(last != time(0)) {
	cout << '\r' << wheel[count % (sizeof(wheel)-1)] << ' ' <<nrecords;
	count++;
	cout.flush();
	last=time(0);
      }
    }
    cout <<"\rDone, got "<<nrecords<<"                                            "<<endl;
    cout<<"Writing to disk.."<<endl;
    writeZoneToDisk(records, zone, argv[4]);
  }

  for(;;) {
    DNSRecord ourSoa;
    ourSerial = getSerialFromRecords(records, ourSoa);

    cout<<"Checking for update, our serial number is "<<ourSerial<<".. ";
    cout.flush();
    shared_ptr<SOARecordContent> sr;
    uint32_t serial = getSerialFromMaster(master, zone, sr);
    if(ourSerial == serial) {
      cout<<"still up to date, their serial is "<<serial<<", sleeping "<<sr->d_st.refresh<<" seconds"<<endl;
      sleep(sr->d_st.refresh);
      continue;
    }

    cout<<"got new serial: "<<serial<<", initiating IXFR!"<<endl;
    auto deltas = getIXFRDeltas(master, zone, ourSoa);
    cout<<"Got "<<deltas.size()<<" deltas, applying.."<<endl;

    for(const auto& delta : deltas) {
      const auto& remove = delta.first;
      const auto& add = delta.second;

      ourSerial=getSerialFromRecords(records, ourSoa);
      uint32_t newserial=0;
      for(const auto& rr : add) {
	if(rr.d_type == QType::SOA) {
	  newserial=std::dynamic_pointer_cast<SOARecordContent>(rr.d_content)->d_st.serial;
	}
      }
      cout<<"This delta ("<<ourSerial<<" - "<<newserial<<") has "<<remove.size()<<" removals, "<<add.size()<<" additions"<<endl;
      bool stop=false;
      ofstream report(string(argv[4]) +"/delta."+std::to_string(ourSerial)+"-"+std::to_string(newserial));
      for(const auto& rr : remove) {
	report<<'-'<< (rr.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(rr.d_type)<<" "<<rr.d_content->getZoneRepresentation()<<endl;
	auto range = records.equal_range(tie(rr.d_name, rr.d_type, rr.d_class, rr.d_content));
	if(range.first == range.second) {
	  cout<<endl<<" !! Could not find record "<<rr.d_name<<" to remove!!"<<endl;
	  //	  stop=true;
	  report.flush();
	}
	records.erase(range.first, range.second);

      }

      for(const auto& rr : add) {
	report<<'+'<< (rr.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(rr.d_type)<<" "<<rr.d_content->getZoneRepresentation()<<endl;
	records.insert(rr);
      }
      if(stop) {
	cerr<<"Had error condition, stopping.."<<endl;
	report.flush();
	exit(1);
      }
    }
    cout<<"Writing zone to disk.. "; cout.flush();
    writeZoneToDisk(records, zone, argv[4]);
    cout<<"Done"<<endl;
  }
}
catch(PDNSException &e2) {
  cerr<<"Fatal: "<<e2.reason<<endl;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
catch(...)
{
  cerr<<"Any other exception"<<endl;
}
