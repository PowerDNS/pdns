/** two modes:

anonymizing and stripping tcpdumps of irrelevant traffic, so operators can send non-privacy violating dumps
for analysis.

algorithm:

read a packet, check if it has the recursion desired bit set. 

If the question has the response bit set, obfuscate the destination IP address
otherwise, obfuscate the response IP address

*/

#include <pcap.h>
#include "misc.hh"
#include <iostream>
#include <boost/format.hpp>
#include "statbag.hh"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <vector>
#include "dnspcap.hh"

using namespace boost;
using namespace std;

StatBag S;


class IPObfuscator
{
public:
  IPObfuscator() : d_romap(d_ipmap), d_counter(0)
  {
  }

  uint32_t obf(uint32_t orig)
  {
    if(d_romap.count(orig))
      return d_ipmap[orig];
    else {
      return d_ipmap[orig]=d_counter++;
    }
  }

private:
  map<uint32_t, uint32_t> d_ipmap;
  const map<uint32_t, uint32_t>& d_romap;
  uint32_t d_counter;
};

int main(int argc, char** argv)
try
{
  PcapPacketReader pr(argv[1]);
  PcapPacketWriter pw(argv[2], pr);
  IPObfuscator ipo;

  while(pr.getUDPPacket()) {
    if(ntohs(pr.d_udp->dest)==53 || ntohs(pr.d_udp->source)==53) {
      /*
      MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
      string name=mdp.d_qname+"|"+DNSRecordContent::NumberToType(mdp.d_qtype);
      
      if(mdp.d_header.qr) {
	pr.d_ip->daddr=ipo.obf(pr.d_ip->daddr);
	cout<<"Answer to '"<< name <<"': RCODE="<<(int)mdp.d_rcode<<", "<<mdp.d_answers.size()<<" answers\n";
      }
      else {
	pr.d_ip->saddr=ipo.obf(pr.d_ip->saddr);
	cout<<"Question for '"<< name <<"'\n";
      }
      */
      pw.write();
    }
    
  }
  cerr<<"Saw "<<pr.d_packets<<" packets"<<endl;
}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
