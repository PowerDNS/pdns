/** two modes:

anonymizing and stripping tcpdumps of irrelevant traffic, so operators can send non-privacy violating dumps
for analysis.

algorithm:

read a packet, check if it has the recursion desired bit set. 

If the question has the response bit set, obfuscate the destination IP address
otherwise, obfuscate the response IP address
*/

#include <pcap.h>

#include "statbag.hh"
#include "dnspcap.hh"
#include <arpa/nameser.h>

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
    if(ntohs(pr.d_udp->dest)==53 || ntohs(pr.d_udp->source)==53 && pr.d_len > sizeof(HEADER)) {
      HEADER* dh=(HEADER*)pr.d_payload;

      if(dh->rd) {
	if(dh->qr)
	  pr.d_ip->daddr=htonl(ipo.obf(pr.d_ip->daddr));
	else
	  pr.d_ip->saddr=htonl(ipo.obf(pr.d_ip->saddr));
	
	pw.write();
      }
    }
    
  }
  cerr<<"Saw "<<pr.d_correctpackets<<" correct packets, "<<pr.d_runts<<" runts, "<< pr.d_oversized<<" oversize, "<<
    pr.d_nonetheripudp<<" unknown encaps"<<endl;
}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
