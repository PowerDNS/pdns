/** two modes:

anonymizing and stripping tcpdumps of irrelevant traffic, so operators can send non-privacy violating dumps
for analysis.

algorithm:

read a packet, check if it has the recursion desired bit set. 

If the question has the response bit set, obfuscate the destination IP address
otherwise, obfuscate the response IP address
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "dnspcap.hh"

#include "namespaces.hh"
#include "namespaces.hh"

StatBag S;


class IPObfuscator
{
public:
  IPObfuscator() : d_romap(d_ipmap), d_ro6map(d_ip6map), d_counter(0)
  {
  }

  uint32_t obf4(uint32_t orig)
  {
    if(d_romap.count(orig))
      return d_ipmap[orig];
    else {
      return d_ipmap[orig]=d_counter++;
    }
  }

  uint64_t obf6(uint64_t orig)
  {
    cout<<d_counter<<endl;
    if(d_ro6map.count(orig))
      return d_ip6map[orig];
    else {
      return d_ip6map[orig]=d_counter++;
    }
  }

private:
  map<uint32_t, uint32_t> d_ipmap;
  const map<uint32_t, uint32_t>& d_romap;
  // For IPv6 addresses
  map<uint64_t, uint32_t> d_ip6map;
  const map<uint64_t, uint32_t>& d_ro6map;
  // The counter that we'll convert to an IP address
  uint32_t d_counter;
};

int main(int argc, char** argv)
try
{
  if(argc!=3) {
    cerr<<"Syntax: dnswasher infile outfile\n";
    exit(1);
  }
  PcapPacketReader pr(argv[1]);
  PcapPacketWriter pw(argv[2], pr);
  IPObfuscator ipo;

  while(pr.getUDPPacket()) {
    if(ntohs(pr.d_udp->uh_dport)==53 || (ntohs(pr.d_udp->uh_sport)==53 && pr.d_len > sizeof(dnsheader))) {
      dnsheader* dh=(dnsheader*)pr.d_payload;

      if (pr.d_ip->ip_v == 4){
        uint32_t *src=(uint32_t*)&pr.d_ip->ip_src;
        uint32_t *dst=(uint32_t*)&pr.d_ip->ip_dst;

        if(dh->qr)
          *dst=htonl(ipo.obf4(*dst));
        else
          *src=htonl(ipo.obf4(*src));
      } else if (pr.d_ip->ip_v == 6) {
        uint64_t *src=1+(uint64_t*)&pr.d_ip6->ip6_src;
        uint64_t *dst=1+(uint64_t*)&pr.d_ip6->ip6_dst;

        if(dh->qr)
          *dst=ipo.obf6(*dst);
        else
          *src=ipo.obf6(*src);
      }
      pr.d_ip->ip_sum=0;
      pw.write();
    }
  }
  cerr<<"Saw "<<pr.d_correctpackets<<" correct packets, "<<pr.d_runts<<" runts, "<< pr.d_oversized<<" oversize, "<<
    pr.d_nonetheripudp<<" unknown encaps"<<endl;
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
