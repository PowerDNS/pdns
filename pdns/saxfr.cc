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
  if(argc < 4) {
    cerr<<"Syntax: saxfr IP-address port zone [showflags] [hidesoadetails]\n";
    exit(EXIT_FAILURE);
  }

  bool showflags=false;
  bool hidesoadetails=false;

  if (argc > 4) {
    for(int i=4; i<argc; i++) {
      if (strcmp(argv[i], "showflags") == 0)
        showflags=true;
      if (strcmp(argv[i], "hidesoadetails") == 0)
        hidesoadetails=true;
    }
  }

  reportAllTypes();

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, argv[3], 252);

  Socket sock(InterNetwork, Stream);
  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  sock.connect(dest);
  uint16_t len;
  len = htons(packet.size());
  if(sock.write((char *) &len, 2) != 2)
    throw PDNSException("tcp write failed");

  sock.writen(string((char*)&*packet.begin(), (char*)&*packet.end()));

  int soacount=0;
  while(soacount<2) {
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

    MOADNSParser mdp(string(creply, len));
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
      if(i->first.d_type == QType::SOA)
      {
        ++soacount;
      }

      cout<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
      if(i->first.d_type == QType::RRSIG)
      {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout<<"\t"<<i->first.d_ttl<<"\t"<< parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" "<<parts[3]<<" [expiry] [inception] [keytag] "<<parts[7]<<" ...\n";
      }
      else if(!showflags && i->first.d_type == QType::NSEC3)
      {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout<<"\t"<<i->first.d_ttl<<"\t"<< parts[0]<<" [flags] "<<parts[2]<<" "<<parts[3]<<" "<<parts[4];
        for(vector<string>::iterator iter = parts.begin()+5; iter != parts.end(); ++iter)
          cout<<" "<<*iter;
        cout<<"\n";
      }
      else if(i->first.d_type == QType::DNSKEY)
      {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout<<"\t"<<i->first.d_ttl<<"\t"<< parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" ...\n";
      }
      else if (i->first.d_type == QType::SOA && hidesoadetails)
      {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout<<"\t"<<i->first.d_ttl<<"\t"<<parts[0]<<" "<<parts[1]<<" [serial] "<<parts[3]<<" "<<parts[4]<<" "<<parts[5]<<" "<<parts[6]<<"\n";
      }
      else
      {
        cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
      }
    }
    delete[] creply;
  }
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
