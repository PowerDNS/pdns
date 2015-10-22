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

StatBag S;


int main(int argc, char** argv)
try
{
  if(argc < 4) {
    cerr<<"Syntax: saxfr IP-address port zone directory"<<endl;
    exit(EXIT_FAILURE);
  }

  reportAllTypes();
  dns_random_init("0123456789abcdef");

  /* goal in life:
     in directory/zone-name we leave files with their name the serial number
     at startup, retrieve current SOA SERIAL for domain from master server
     
     compare with what the best is we have in our directory, IXFR from that.
     Store result in memory, read that best zone in memory, apply deltas, write it out.

     Next up, loop this every REFRESH seconds */

  DNSName zone(argv[3]);
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, zone, QType::SOA);
  ComboAddress master(argv[1], atoi(argv[2]));

  Socket s(master.sin4.sin_family, SOCK_DGRAM);
  s.connect(master);
  string msg((const char*)&packet[0], packet.size());
  s.writen(msg);

  string reply;
  s.read(reply);
  MOADNSParser mdp(reply);
  for(const auto& r: mdp.d_answers) {
    if(r.first.d_type == QType::SOA) {
      auto sr = std::dynamic_pointer_cast<SOARecordContent>(r.first.d_content);
      cout<<"Current serial number: "<<sr->d_st.serial<<endl;
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
