#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "ednssubnet.hh"
StatBag S;

int main(int argc, char** argv)
try
{
  reportAllTypes();

  if(argc < 4) {
    cerr<<"Syntax: sdig IP-address port question question-type\n";
    exit(EXIT_FAILURE);
  }


  Socket sock(AF_INET, SOCK_DGRAM);
  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  for(unsigned int n=0; n < 20000; ++n) {
    vector<uint8_t> packet;
    string qname;

    if(!(n%20))
      qname=boost::lexical_cast<string>(n)+".ds9a.nl";
    else
      qname=boost::lexical_cast<string>(n)+"."+argv[3];
    
    DNSPacketWriter pw(packet, qname, DNSRecordContent::TypeToNumber(argv[4]));

    pw.getHeader()->rd=1;

    pw.getHeader()->id=n;
    pw.addOpt(1800, 0, EDNSOpts::DNSSECOK);
    pw.commit();

    sock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
    usleep(100);
  }
  

 

}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
