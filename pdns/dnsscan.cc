/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <bitset>
#include "statbag.hh"
#include "dnspcap.hh"
#include "sstuff.hh"
#include "anadns.hh"


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

static void usage() {
  cerr<<"syntax: dnsscan INFILE ..."<<endl;
}

int main(int argc, char** argv)
try
{
  Socket sock(AF_INET, SOCK_DGRAM);

  /*
  IPEndpoint remote(argc > 2 ? argv[2] : "127.0.0.1", 
                    argc > 3 ? atoi(argv[3]) : 5300);

  */

  if(argc<2) {
    usage();
    exit(EXIT_SUCCESS);
  }

  for(int n=1; n < argc; ++n) {
    if ((string) argv[n] == "--help") {
      usage();
      return EXIT_SUCCESS;
    }

    if ((string) argv[n] == "--version") {
      cerr<<"dnsscan "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  }

  unsigned int counts[256];
  for(unsigned int n=0 ; n < 256; ++n) 
    counts[n]=0;
    
  for(int n=1; n < argc; ++n) {
    PcapPacketReader pr(argv[n]);
    
    while(pr.getUDPPacket()) {
      try {
        MOADNSParser mdp(false, (const char*)pr.d_payload, pr.d_len);
        if(mdp.d_qtype < 256)
          counts[mdp.d_qtype]++;

      }
      catch(const MOADNSException &mde) {
        cout<<"Error from remote "<<pr.getSource().toString()<<": "<<mde.what()<<"\n";
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

