#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include <boost/array.hpp>
StatBag S;

int main(int argc, char** argv)
try
{
  bool dnssec=false;
  bool recurse=false;
  bool tcp=false;

  reportAllTypes();

  if(argc < 5) {
    cerr<<"Syntax: sdig IP-address port question question-type [dnssec|recurse]\n";
    exit(EXIT_FAILURE);
  }

  // FIXME: turn recurse and dnssec into proper flags or something
  if(argc > 5 && strcmp(argv[5], "dnssec")==0)
  {
    dnssec=true;
  }
  
  if(argc > 5 && strcmp(argv[5], "dnssec-tcp")==0)
  {
    dnssec=true;
    tcp=true;
  }

  if(argc > 5 && strcmp(argv[5], "recurse")==0)
  {
    recurse=true;
  }

  vector<uint8_t> packet;
  
  DNSPacketWriter pw(packet, argv[3], DNSRecordContent::TypeToNumber(argv[4]));

  if(dnssec || getenv("SDIGBUFSIZE"))
  {
    char *sbuf=getenv("SDIGBUFSIZE");
    int bufsize;
    if(sbuf)
      bufsize=atoi(sbuf);
    else
      bufsize=2800;

    pw.addOpt(bufsize, 0, dnssec ? EDNSOpts::DNSSECOK : 0);
    pw.commit();
  }

  if(recurse)
  {
    pw.getHeader()->rd=true;
  }
  //  pw.setRD(true);
 
  /*
  pw.startRecord("powerdns.com", DNSRecordContent::TypeToNumber("NS"));
  NSRecordContent nrc("ns1.powerdns.com");
  nrc.toPacket(pw);

  pw.startRecord("powerdns.com", DNSRecordContent::TypeToNumber("NS"));
  NSRecordContent nrc2("ns2.powerdns.com");
  nrc2.toPacket(pw);
  */

/*  DNSPacketWriter::optvect_t opts;

  opts.push_back(make_pair(5, ping));
  
  pw.commit();
*/
  // pw.addOpt(5200, 0, 0);
  // pw.commit();
  
  string reply;

  if(tcp) {
    Socket sock(InterNetwork, Stream);
    ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
    sock.connect(dest);
    uint16_t len;
    len = htons(packet.size());
    if(sock.write((char *) &len, 2) != 2)
      throw AhuException("tcp write failed");

    sock.writen(string((char*)&*packet.begin(), (char*)&*packet.end()));
    
    if(sock.read((char *) &len, 2) != 2)
      throw AhuException("tcp read failed");

    len=ntohs(len);
    char *creply = new char[len];
    int n=0;
    int numread;
    while(n<len) {
      numread=sock.read(creply+n, len-n);
      if(numread<0)
        throw AhuException("tcp read failed");
      n+=numread;
    }

    reply=string(creply, len);
    delete[] creply;
  }
  else //udp
  {
    Socket sock(InterNetwork, Datagram);
    ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
    sock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
    
    sock.recvFrom(reply, dest);
  }
  MOADNSParser mdp(reply);
  cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
  cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
  cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
    if(i->first.d_type == QType::RRSIG) 
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<i->first.d_ttl<<"\t"<< parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" "<<parts[3]<<" [expiry] [inception] [keytag] "<<parts[7]<<" ...\n";
    }
    else if(i->first.d_type == QType::DNSKEY)
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<i->first.d_ttl<<"\t"<< parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" ...\n";
    }
    else
    {
      cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
    }

  }

  EDNSOpts edo;
  if(getEDNSOpts(mdp, &edo)) {
//    cerr<<"Have "<<edo.d_options.size()<<" options!"<<endl;
    for(vector<pair<uint16_t, string> >::const_iterator iter = edo.d_options.begin();
        iter != edo.d_options.end(); 
        ++iter) {
      if(iter->first == 5) {// 'EDNS PING'
        cerr<<"Have ednsping: '"<<iter->second<<"'\n";
        //if(iter->second == ping) 
         // cerr<<"It is correct!"<<endl;
      }
      else {
        cerr<<"Have unknown option "<<(int)iter->first<<endl;
      }
    }

  }

}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
