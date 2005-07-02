/** two modes:

Replay all recursion-desired DNS questions to a specified IP address

*/

#include <pcap.h>

#include "statbag.hh"
#include "dnspcap.hh"
#include "sstuff.hh"

#include <arpa/nameser.h>

using namespace boost;
using namespace std;

StatBag S;


int main(int argc, char** argv)
try
{
  struct sched_param p;
  p.sched_priority=50;
  cout<<"Sched returned: "<<sched_setscheduler(0, SCHED_RR, &p)<<endl;

  PcapPacketReader pr(argv[1]);
  Socket s(InterNetwork, Datagram);

  IPEndpoint remote("127.0.0.1", 5300);

  struct timespec tosleep;

  struct timeval lastsent={0,0};
  double seconds, useconds;
  double factor=20;
  while(pr.getUDPPacket()) {
    if(ntohs(pr.d_udp->dest)==53 || ntohs(pr.d_udp->source)==53 && pr.d_len > sizeof(HEADER)) {
      HEADER* dh=(HEADER*)pr.d_payload;

      if(dh->rd && !dh->qr) {
	if(lastsent.tv_sec) {
	  seconds=pr.d_pheader.ts.tv_sec - lastsent.tv_sec;
	  useconds=(pr.d_pheader.ts.tv_usec - lastsent.tv_usec);
	  
	  seconds/=factor;
	  useconds/=factor;
	  
	  long long nanoseconds=1000000000ULL*seconds + useconds * 1000;
	  
	  tosleep.tv_sec=nanoseconds/1000000000UL;
	  tosleep.tv_nsec=nanoseconds%1000000000UL;
	  
	  nanosleep(&tosleep, 0);
	}
	lastsent=pr.d_pheader.ts;
	s.sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
      }
    }
    
  }

}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
