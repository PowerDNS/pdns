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

  pw.startRecord("enum.powerdns.com", DNSRecordContent::TypeToNumber("NSEC"));

  NSECRecordContent nrc("jnum.powerdns.com SRV A AAAA RRSIG");
  nrc.toPacket(pw);

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
    cout<<i->first.d_place<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
    cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<endl;
  }

}
catch(exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

