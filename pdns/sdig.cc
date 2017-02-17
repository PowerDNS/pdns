#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include <boost/array.hpp>
#include "ednssubnet.hh"
StatBag S;

bool hidettl=false;

string ttl(uint32_t ttl)
{
  if(hidettl)
    return "[ttl]";
  else
    return std::to_string(ttl);
}

void usage() {
  cerr<<"sdig"<<endl;
  cerr<<"Syntax: sdig IP-ADDRESS PORT QUESTION QUESTION-TYPE [dnssec] [recurse] [showflags] [hidesoadetails] [hidettl] [tcp] [ednssubnet SUBNET]"<<endl;
}

int main(int argc, char** argv)
try
{
  bool dnssec=false;
  bool recurse=false;
  bool tcp=false;
  bool showflags=false;
  bool hidesoadetails=false;
  boost::optional<Netmask> ednsnm;


  for(int i=1; i<argc; i++) {
    if ((string) argv[i] == "--help") {
      usage();
      exit(EXIT_SUCCESS);
    }

    if ((string) argv[i] == "--version") {
      cerr<<"sdig "<<VERSION<<endl;
      exit(EXIT_SUCCESS);
    }
  }

  if(argc < 5) {
    usage();
    exit(EXIT_FAILURE);
  }

  reportAllTypes();

  if (argc > 5) {
    for(int i=5; i<argc; i++) {
      if (strcmp(argv[i], "dnssec") == 0)
        dnssec=true;
      if (strcmp(argv[i], "recurse") == 0)
        recurse=true;
      if (strcmp(argv[i], "showflags") == 0)
        showflags=true;
      if (strcmp(argv[i], "hidesoadetails") == 0)
        hidesoadetails=true;
      if (strcmp(argv[i], "hidettl") == 0)
        hidettl=true;
      if (strcmp(argv[i], "tcp") == 0)
        tcp=true;
      if (strcmp(argv[i], "ednssubnet") == 0) {
        ednsnm=Netmask(argv[++i]);
      }
    }
  }

  vector<uint8_t> packet;
  
  DNSPacketWriter pw(packet, DNSName(argv[3]), DNSRecordContent::TypeToNumber(argv[4]));

  if(dnssec || ednsnm || getenv("SDIGBUFSIZE"))
  {
    char *sbuf=getenv("SDIGBUFSIZE");
    int bufsize;
    if(sbuf)
      bufsize=atoi(sbuf);
    else
      bufsize=2800;
    DNSPacketWriter::optvect_t opts;
    if(ednsnm) {
      EDNSSubnetOpts eo;
      eo.source = *ednsnm;
      opts.push_back(make_pair(8, makeEDNSSubnetOptsString(eo)));
    }

    pw.addOpt(bufsize, 0, dnssec ? EDNSOpts::DNSSECOK : 0, opts);
    pw.commit();
  }

  if(recurse)
  {
    pw.getHeader()->rd=true;
  }

  string reply;
  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));

  if(tcp) {
    Socket sock(dest.sin4.sin_family, SOCK_STREAM);
    sock.connect(dest);
    uint16_t len;
    len = htons(packet.size());
    if(sock.write((char *) &len, 2) != 2)
      throw PDNSException("tcp write failed");

    sock.writen(string((char*)&*packet.begin(), (char*)&*packet.end()));
    
    if(sock.read((char *) &len, 2) != 2)
      throw PDNSException("tcp read failed");

    len=ntohs(len);
    char *creply = new char[len];
    int n=0;
    int numread;
    while(n<len) {
      numread=sock.read(creply+n, len-n);
      if(numread<0)
        throw PDNSException("tcp read failed");
      n+=numread;
    }

    reply=string(creply, len);
    delete[] creply;
  }
  else //udp
  {
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    sock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
    int result=waitForData(sock.getHandle(), 10);
    if(result < 0) 
      throw std::runtime_error("Error waiting for data: "+string(strerror(errno)));
    if(!result)
      throw std::runtime_error("Timeout waiting for data");
    sock.recvFrom(reply, dest);
  }
  MOADNSParser mdp(false, reply);
  cout<<"Reply to question for qname='"<<mdp.d_qname.toString()<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
  cout<<"Rcode: "<<mdp.d_header.rcode<<" ("<<RCode::to_s(mdp.d_header.rcode)<<"), RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
  cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    cout<<i->first.d_place-1<<"\t"<<i->first.d_name.toString()<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
    if(i->first.d_type == QType::RRSIG) 
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<ttl(i->first.d_ttl)<<"\t"<< parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" "<<parts[3]<<" [expiry] [inception] [keytag] "<<parts[7]<<" ...\n";
    }
    else if(!showflags && i->first.d_type == QType::NSEC3)
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<ttl(i->first.d_ttl)<<"\t"<< parts[0]<<" [flags] "<<parts[2]<<" "<<parts[3]<<" "<<parts[4];
      for(vector<string>::iterator iter = parts.begin()+5; iter != parts.end(); ++iter)
        cout<<" "<<*iter;
      cout<<"\n";
    }
    else if(i->first.d_type == QType::DNSKEY)
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<ttl(i->first.d_ttl)<<"\t"<< parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" ...\n";
    }
    else if (i->first.d_type == QType::SOA && hidesoadetails)
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<ttl(i->first.d_ttl)<<"\t"<<parts[0]<<" "<<parts[1]<<" [serial] "<<parts[3]<<" "<<parts[4]<<" "<<parts[5]<<" "<<parts[6]<<"\n";
    }
    else
    {
      cout<<"\t"<<ttl(i->first.d_ttl)<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
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
      if(iter->first == 8) {// 'EDNS subnet'
	EDNSSubnetOpts reso;
        if(getEDNSSubnetOptsFromString(iter->second, &reso)) {
          cerr<<"EDNS Subnet response: "<<reso.source.toString()<<", scope: "<<reso.scope.toString()<<", family = "<<reso.scope.getNetwork().sin4.sin_family<<endl;
	}
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
catch(PDNSException &e)
{
  cerr<<"Fatal: "<<e.reason<<endl;
}
