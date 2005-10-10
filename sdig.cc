#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"


int main(int argc, char** argv)
try
{

  if(argc < 4) {
    cerr<<"Syntax: sdig IP-address port question question-type\n";
    exit(EXIT_FAILURE);
  }

  vector<uint8_t> packet;
  
  DNSPacketWriter pw(packet, argv[3], DNSRecordContent::TypeToNumber(argv[4]));
#if 0  
  static char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
		     "192.36.148.17","192.58.128.30", "193.0.14.129", "198.32.64.12", "202.12.27.33"};
  static char templ[40];
  strncpy(templ,"a.root-servers.net", sizeof(templ) - 1);
  for(char c='a';c<='m';++c) {
    *templ=c;
    
    pw.startRecord("", DNSRecordContent::TypeToNumber("NS"));
    NSRecordContent nrc(templ);
    nrc.toPacket(pw);
  }
  
  for(char c='a';c<='m';++c) {
    *templ=c;
    
    pw.startRecord(templ, DNSRecordContent::TypeToNumber("A"), 3600, 1, DNSPacketWriter::ADDITIONAL);
    ARecordContent arc(ips[c-'a']);
    arc.toPacket(pw);
  }
#endif
  pw.commit();

  //  pw.setRD(true);
 
  /*
  pw.startRecord("powerdns.com", DNSRecordContent::TypeToNumber("NS"));
  NSRecordContent nrc("ns1.powerdns.com");
  nrc.toPacket(pw);

  pw.startRecord("powerdns.com", DNSRecordContent::TypeToNumber("NS"));
  NSRecordContent nrc2("ns2.powerdns.com");
  nrc2.toPacket(pw);

  //  pw.addOpt(2800, 0, 0x8000);
  */

  pw.commit();

  Socket sock(InterNetwork, Datagram);
  IPEndpoint dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));

  sock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
  
  string reply;
  sock.recvFrom(reply, dest);

  MOADNSParser mdp(reply);
  cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
  cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd;
  cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
    cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<endl;
  }

}
catch(exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
