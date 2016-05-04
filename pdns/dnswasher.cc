/** two modes:

anonymizing and stripping tcpdumps of irrelevant traffic, so operators can send non-privacy violating dumps
for analysis.

algorithm:

read a packet, check if it has the QR bit set.

If the question has the response bit set, obfuscate the destination IP address
otherwise, obfuscate the response IP address
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "dnspcap.hh"
#include "iputils.hh"

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

void usage() {
  cerr<<"Syntax: dnswasher INFILE1 [INFILE2..] OUTFILE"<<endl;
}

int main(int argc, char** argv)
try
{
  for (int i = 1; i < argc; i++) {
    if ((string) argv[i] == "--help") {
      usage();
      exit(EXIT_SUCCESS);
    }

    if ((string) argv[i] == "--version") {
      cerr<<"dnswasher "<<VERSION<<endl;
      exit(EXIT_SUCCESS);
    }
  }

  if(argc < 3) {
    usage();
    exit(1);
  }

  PcapPacketWriter pw(argv[argc-1]);
  IPObfuscator ipo;
  // 0          1   2   3    - argc == 4
  // dnswasher in1 in2 out
  for(int n=1; n < argc -1; ++n) {
    PcapPacketReader pr(argv[n]);
    pw.setPPR(pr);

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
          
          pr.d_ip->ip_sum=0;
        } else if (pr.d_ip->ip_v == 6) {
          uint64_t *src=(uint64_t*)&pr.d_ip6->ip6_src;
          uint64_t *dst=(uint64_t*)&pr.d_ip6->ip6_dst;
          
          if(dh->qr)
            *dst=htobe64(ipo.obf6(*dst));
          else
            *src=htobe64(ipo.obf6(*src));
        }
        pw.write();
      }
    }
    cerr<<"Saw "<<pr.d_correctpackets<<" correct packets, "<<pr.d_runts<<" runts, "<< pr.d_oversized<<" oversize, "<<
      pr.d_nonetheripudp<<" unknown encaps"<<endl;
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
