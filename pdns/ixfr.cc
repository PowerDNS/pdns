#include "ixfr.hh"
#include "sstuff.hh"
#include "dns_random.hh"
#include "dnsrecords.hh"


vector<pair<vector<DNSRecord>, vector<DNSRecord> > >   getIXFRDeltas(const ComboAddress& master, const DNSName& zone, const DNSRecord& oursr)
{
  vector<pair<vector<DNSRecord>, vector<DNSRecord> > >  ret;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, zone, QType::IXFR);
  pw.getHeader()->qr=0;
  pw.getHeader()->rd=0;
  pw.getHeader()->id=dns_random(0xffff);
  pw.startRecord(zone, QType::SOA, 3600, QClass::IN, DNSResourceRecord::AUTHORITY);
  oursr.d_content->toPacket(pw);
  pw.commit();
  
  uint16_t len=htons(packet.size());
  string msg((const char*)&len, 2);
  msg.append((const char*)&packet[0], packet.size());

  Socket s(master.sin4.sin_family, SOCK_STREAM);
  //  cout<<"going to connect"<<endl;
  s.connect(master);
  //  cout<<"Connected"<<endl;
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
      //      cout<<r.first.d_name<< " " <<r.first.d_content->getZoneRepresentation()<<endl;
      r.first.d_name = r.first.d_name.makeRelative(zone);
      records.push_back(r.first);
      if(r.first.d_type == QType::SOA) {
	auto sr = std::dynamic_pointer_cast<SOARecordContent>(r.first.d_content);
	if(!masterSOA) {
	  if(sr->d_st.serial == std::dynamic_pointer_cast<SOARecordContent>(oursr.d_content)->d_st.serial) // we are up to date
	    goto done;
	  masterSOA=sr;

	}
	else if(sr->d_st.serial == masterSOA->d_st.serial)
	  goto done;

      }
    }
  }
  //  cout<<"Got "<<records.size()<<" records"<<endl;
 done:;
  for(unsigned int pos = 1;pos < records.size();) {
    auto sr = std::dynamic_pointer_cast<SOARecordContent>(records[pos].d_content);
    if(sr->d_st.serial == masterSOA->d_st.serial)
      break;
    
    vector<DNSRecord> remove, add;
    remove.push_back(records[pos]); // this adds the SOA
    for(pos++; pos < records.size() && records[pos].d_type != QType::SOA; ++pos) {
      remove.push_back(records[pos]);
    }
    sr = std::dynamic_pointer_cast<SOARecordContent>(records[pos].d_content);

    add.push_back(records[pos]); // this adds the new SOA
    for(pos++; pos < records.size() && records[pos].d_type != QType::SOA; ++pos)  {
      add.push_back(records[pos]);
    }
    ret.push_back(make_pair(remove,add));
  }
  return ret;
}
