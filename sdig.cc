#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
StatBag S;

int main(int argc, char** argv)
try
{
  reportAllTypes();

  if(argc < 4) {
    cerr<<"Syntax: sdig IP-address port question question-type\n";
    exit(EXIT_FAILURE);
  }

  vector<uint8_t> packet;
  
  DNSPacketWriter pw(packet, argv[3], DNSRecordContent::TypeToNumber(argv[4]));

  //  pw.setRD(true);
 
  /*
  pw.startRecord("powerdns.com", DNSRecordContent::TypeToNumber("NS"));
  NSRecordContent nrc("ns1.powerdns.com");
  nrc.toPacket(pw);

  pw.startRecord("powerdns.com", DNSRecordContent::TypeToNumber("NS"));
  NSRecordContent nrc2("ns2.powerdns.com");
  nrc2.toPacket(pw);
  */

  DNSPacketWriter::optvect_t opts;
  string ping("hallo!");
  //  opts.push_back(make_pair(5, ping));
  pw.addOpt(5200, 0, 0x8000, opts);
  pw.commit();

  Socket sock(InterNetwork, Datagram);
  IPEndpoint dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));

  sock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
  
  string reply;
  sock.recvFrom(reply, dest);

  MOADNSParser mdp(reply);
  cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
  cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
  cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
    cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
  }

  EDNSOpts edo;
  if(getEDNSOpts(mdp, &edo)) {
    
    cerr<<"Have "<<edo.d_options.size()<<" options!"<<endl;
    for(vector<pair<uint16_t, string> >::const_iterator iter = edo.d_options.begin();
	iter != edo.d_options.end(); 
	++iter) {
      if(iter->first == 1) {// 'EDNS PING'
	cerr<<"Have ednsping: '"<<iter->second<<"'\n";
	if(iter->second == ping) 
	  cerr<<"It is correct!"<<endl;
      }
    }

  }
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
