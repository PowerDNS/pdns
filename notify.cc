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

using namespace boost;
using namespace ::boost::multi_index;
using namespace std;

namespace po = boost::program_options;
po::variables_map g_vm;


int main(int argc, char** argv)
try
{
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock < 0)
    throw runtime_error("Creating socket for incoming packets: "+stringerror());

  ComboAddress local("127.0.0.1", (int)0);
  if(::bind(sock, (struct sockaddr*) &local, local.getSocklen()) < 0) 
    throw runtime_error("Failed to bind local socket to address "+local.toString()+": "+stringerror());

  ComboAddress pdns(argv[1], 53);
  if(connect(sock, (struct sockaddr*) &pdns, pdns.getSocklen()) < 0) 
    throw runtime_error("Failed to connect PowerDNS socket to address "+pdns.toString()+": "+stringerror());
  
  vector<uint8_t> outpacket;
  DNSPacketWriter pw(outpacket, argv[2], QType::SOA, 1, Opcode::Notify);
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

  cerr<<"Received notification response with code: "<<mdp.d_header.rcode<<endl;
  cerr<<"For: '"<<mdp.d_qname<<"'"<<endl;
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

/* added so we don't have to link in most of powerdns */

const char *Utility::inet_ntop(int af, const char *src, char *dst, size_t size)
{
  return ::inet_ntop(af,src,dst,size);
}

// Converts an address from presentation format to network format.
int Utility::inet_pton( int af, const char *src, void *dst )
{
  return ::inet_pton(af, src, dst);
}

// Compares two string, ignoring the case.
int Utility::strcasecmp( const char *s1, const char *s2 )
{
  return ::strcasecmp( s1, s2 );
}

// Returns the current time.
int Utility::gettimeofday( struct timeval *tv, void *tz )
{
  return ::gettimeofday(tv,0);
}

string stringerror()
{
  return strerror(errno);
}

bool IpToU32(const string &str, uint32_t *ip)
{
  if(str.empty()) {
    *ip=0;
    return true;
  }
  
  struct in_addr inp;
  if(inet_aton(str.c_str(), &inp)) {
    *ip=inp.s_addr;
    return true;
  }
  return false;
}
