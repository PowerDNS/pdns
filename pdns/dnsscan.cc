#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <bitset>
#include "statbag.hh"
#include "dnspcap.hh"
#include "sstuff.hh"
#include "anadns.hh"

// this is needed because boost multi_index also uses 'L', as do we (which is sad enough)
#undef L

#include <set>
#include <deque>

#include <boost/format.hpp>
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <cctype>

#include "namespaces.hh"
using namespace ::boost::multi_index;
#include "namespaces.hh"
StatBag S;

int main(int argc, char** argv)
try
{
  Socket sock(AF_INET, SOCK_DGRAM);

  /*
  IPEndpoint remote(argc > 2 ? argv[2] : "127.0.0.1", 
                    argc > 3 ? atoi(argv[3]) : 5300);

  */

  if(argc<2) {
    cerr<<"Syntax: dnsscan file1 [file2 ..] "<<endl;
    exit(1);
  }

  unsigned int counts[256];
  for(unsigned int n=0 ; n < 256; ++n) 
    counts[n]=0;
    
  for(int n=1; n < argc; ++n) {
    PcapPacketReader pr(argv[n]);
    
    while(pr.getUDPPacket()) {
      try {
        MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
        if(mdp.d_qtype < 256)
          counts[mdp.d_qtype]++;

      }
      catch(MOADNSException &e) {
        cout<<"Error from remote "<<pr.getSource().toString()<<": "<<e.what()<<"\n";
        //        sock.sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
      }
    }
  }
  for(unsigned int n=0 ; n < 256; ++n) {
    if(counts[n])
      cout << n << "\t" << counts[n] << "\n";
  }

}
catch(std::exception& e)
{
  cout<<"Fatal: "<<e.what()<<endl;
}

