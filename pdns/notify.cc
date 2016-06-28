#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <bitset>
#include "dnsparser.hh"
#include "iputils.hh"
#undef L
#include <boost/program_options.hpp>

#include <boost/format.hpp>
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include "mplexer.hh"
#include "statbag.hh"
#include "arguments.hh"

#include "namespaces.hh"
using namespace ::boost::multi_index;
#include "namespaces.hh"

namespace po = boost::program_options;
po::variables_map g_vm;

StatBag S;
ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
}

void usage() {
  cerr<<"Syntax: pdns_notify IP_ADDRESS[:PORT] DOMAIN"<<endl;
}

int main(int argc, char** argv)
try
{

  for(int n=1 ; n < argc; ++n) {
    if ((string) argv[n] == "--help") {
      usage();
      return EXIT_SUCCESS;
    }

    if ((string) argv[n] == "--version") {
      cerr<<"notify "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  }

  if(argc!=3) {
    usage();
    exit(1);
  }

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock < 0)
    throw runtime_error("Creating socket for incoming packets: "+stringerror());


 // ComboAddress local("127.0.0.1", (int)0);
//  if(::bind(sock, (struct sockaddr*) &local, local.getSocklen()) < 0) 
//    throw runtime_error("Failed to bind local socket to address "+local.toString()+": "+stringerror());

  ComboAddress pdns(argv[1], 53);
  if(connect(sock, (struct sockaddr*) &pdns, pdns.getSocklen()) < 0) 
    throw runtime_error("Failed to connect PowerDNS socket to address "+pdns.toString()+": "+stringerror());
  
  vector<uint8_t> outpacket;
  DNSPacketWriter pw(outpacket, DNSName(argv[2]), QType::SOA, 1, Opcode::Notify);
  pw.getHeader()->id = random();


  if(send(sock, &outpacket[0], outpacket.size(), 0) < 0) {
    throw runtime_error("Unable to send notify to PowerDNS: "+stringerror());
  }
  
  char buffer[1500];

  int len=recv(sock, buffer, sizeof(buffer),0);
  if(len < 0)
    throw runtime_error("Unable to receive notification response from PowerDNS: "+stringerror());

  string packet(buffer, len);
  MOADNSParser mdp(packet);

  cerr<<"Received notification response with error: "<<RCode::to_s(mdp.d_header.rcode)<<endl;
  cerr<<"For: '"<<mdp.d_qname<<"'"<<endl;
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

