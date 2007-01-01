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

using namespace boost;
using namespace std;

StatBag S;


int32_t g_clientQuestions, g_clientResponses, g_serverQuestions, g_serverResponses;
struct timeval g_lastanswerTime, g_lastquestionTime;
void makeReport(const struct timeval& tv)
{
  int64_t clientdiff = g_clientQuestions - g_clientResponses;
  if(clientdiff > 0.05*g_clientQuestions) {
    char tmp[80];
    struct tm tm=*localtime_r(&tv.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);

    cout << tmp << ": Resolver dropped too many questions (" 
	 << g_clientQuestions <<" vs " << g_clientResponses << "), diff: " <<clientdiff<<endl;

    tm=*localtime_r(&g_lastanswerTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last answer: "<<tmp<<"."<<g_lastanswerTime.tv_usec/1000000.0<<endl;

    tm=*localtime_r(&g_lastquestionTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last question: "<<tmp<<"."<<g_lastquestionTime.tv_usec/1000000.0<<endl;


  }
  g_clientQuestions=g_clientResponses=g_serverQuestions=g_serverResponses=0;
}


int main(int argc, char** argv)
try
{
  for(int n=1 ; n < argc; ++n) {
    cout<<argv[n]<<endl;
    PcapPacketReader pr(argv[n]);
    
    /* four sorts of packets: 
       "rd": question from a client pc
       "rd qr": answer to a client pc
       "": question from the resolver
       "qr": answer to the resolver */
    
    /* what are interesting events to note? */
    /* we measure every 60 seconds, each interval with 10% less answers than questions is interesting */
    /* report chunked */
    
    struct timeval lastreport={0, 0};
    
    while(pr.getUDPPacket()) {
      if((ntohs(pr.d_udp->uh_dport)==5300 || ntohs(pr.d_udp->uh_sport)==5300 ||
	  ntohs(pr.d_udp->uh_dport)==53   || ntohs(pr.d_udp->uh_sport)==53) &&
	 pr.d_len > 12) {
	try {
	  MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
	  
	  if(lastreport.tv_sec == 0) {
	    lastreport = pr.d_pheader.ts;
	  }
	  
	  if(mdp.d_header.rd && !mdp.d_header.qr)
	    g_clientQuestions++;
	  else if(mdp.d_header.rd && mdp.d_header.qr) {
	    g_lastanswerTime=pr.d_pheader.ts;
	    g_clientResponses++;
	  }
	  else if(!mdp.d_header.rd && !mdp.d_header.qr) {
	    g_lastquestionTime=pr.d_pheader.ts;
	    g_serverQuestions++;
	  }
	  else if(!mdp.d_header.rd && mdp.d_header.qr)
	    g_serverResponses++;
	  
	  if(pr.d_pheader.ts.tv_sec - lastreport.tv_sec > 10) {
	    makeReport(pr.d_pheader.ts);
	    lastreport = pr.d_pheader.ts;
	  }
	  
	}
	catch(MOADNSException& mde) {
	  //	cerr<<"error parsing packet: "<<mde.what()<<endl;
	  continue;
	}
	catch(exception& e) {
	  cerr << e.what() << endl;
	  continue;
	}
      }
    }
  }
}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
