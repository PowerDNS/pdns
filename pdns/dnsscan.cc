#include <bitset>
#include "statbag.hh"
#include "dnspcap.hh"
#include "sstuff.hh"
#include "anadns.hh"

// this is needed because boost multi_index also uses 'L', as do we (which is sad enough)
#undef L

#include <arpa/nameser.h>
#include <set>
#include <deque>

#include <boost/format.hpp>
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <cctype>

using namespace boost;
using namespace ::boost::multi_index;
using namespace std;
StatBag S;

int main(int argc, char** argv)
try
{
  Socket sock(InterNetwork, Datagram);

  /*
  IPEndpoint remote(argc > 2 ? argv[2] : "127.0.0.1", 
		    argc > 3 ? atoi(argv[3]) : 5300);

  */

  if(argc<2) {
    cerr<<"Syntax: dnsscan file1 [file2 ..] "<<endl;
    exit(1);
  }
    
  for(int n=1; n < argc; ++n) {
    PcapPacketReader pr(argv[n]);
    
    while(pr.getUDPPacket()) {
      try {
	MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
	for(int i=0; i < mdp.d_qname.length(); ++i)
	  if(!isalnum(mdp.d_qname[i]) && mdp.d_qname[i]!='.' && mdp.d_qname[i]!='-' && mdp.d_qname[i]!='_') {
	    //	  cout<<mdp.d_qname<<"|"<<mdp.d_qtype<<"|"<<mdp.d_qclass<<"\n";
	    // sock.sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
	    break;
	  }
	if(mdp.d_qtype > 256 || mdp.d_qclass!=1 ) {
	  //	sock.sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
	  
	}
	for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
	  
	}
	
      }
      catch(MOADNSException &e) {
	cout<<"Error from remote "<<U32ToIP(ntohl(*((uint32_t*)&pr.d_ip->ip_src)))<<": "<<e.what()<<"\n";
	//	sock.sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
      }
    }
  }
}
catch(exception& e)
{
  cout<<"Fatal: "<<e.what()<<endl;
}

