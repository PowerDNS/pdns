#define __FAVOR_BSD
#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"

#include "namespaces.hh"
using namespace std;

StatBag S;

struct Entry
{
  uint32_t ip;
  uint16_t port;
  uint16_t id;

  bool operator<(const struct Entry& rhs) const 
  {
    return tie(ip, port, id) < tie(rhs.ip, rhs.port, rhs.id);
  }
};


typedef map<Entry, uint32_t> emap_t;
emap_t ecount;

int main(int argc, char** argv)
try
{
  cout << "begin;";
  for(int n=1 ; n < argc; ++n) {
    PcapPacketReader pr(argv[n]);
    
    Entry entry;
    while(pr.getUDPPacket()) {
      if(ntohs(pr.d_udp->uh_dport)==53 &&  pr.d_len > 12) {
	try {
	  dnsheader* dh= (dnsheader*) pr.d_payload;

	  if(dh->rd || dh->qr)
	    continue;

	  MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);

	  memcpy(&entry.ip, &pr.d_ip->ip_src, 4);
	  entry.port = pr.d_udp->uh_sport;
	  entry.id=dh->id;

	  //	  ecount[entry]++;
	  string::size_type pos = 0;
	  for(pos = 0; pos < mdp.d_qname.size() ; ++pos ) {
	    char c=mdp.d_qname[pos] ;
	    if(!isalnum(c) && c!='-' && c!='.')
	      break;
	  }
	  if(pos ==mdp.d_qname.size()) {
	    cout << "insert into dnsstats (source, port, id, query, qtype, tstampSec, tstampUsec, arcount) values ('" << U32ToIP(ntohl(entry.ip)) <<"', "<< ntohs(entry.port) <<", "<< ntohs(dh->id);
	    cout <<", '"<<mdp.d_qname<<"', "<<mdp.d_qtype<<", " << pr.d_pheader.ts.tv_sec <<", " << pr.d_pheader.ts.tv_usec;
	    cout <<", "<< ntohs(dh->arcount) <<");\n";
	  }

	}
	catch(MOADNSException& mde) {
	  //	cerr<<"error parsing packet: "<<mde.what()<<endl;
	  continue;
	}
	catch(std::exception& e) {
	  cerr << e.what() << endl;
	  continue;
	}
      }
    }
  }
  cout <<"commit;";
  /*
  for(emap_t::const_iterator i = ecount.begin(); i != ecount.end(); ++i) {
    if(i->second > 1)
      cout << U32ToIP(ntohl(i->first.ip)) <<":"<<ntohs(i->first.port)<<" -> "<<i->second <<endl;
  }
  */

}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
