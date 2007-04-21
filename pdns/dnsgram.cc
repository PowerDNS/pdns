#define __FAVOR_BSD
#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/algorithm/string.hpp>
#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"

using namespace boost;
using namespace std;

StatBag S;

int32_t g_clientQuestions, g_clientResponses, g_serverQuestions, g_serverResponses, g_skipped;
struct timeval g_lastanswerTime, g_lastquestionTime;
void makeReport(const struct timeval& tv)
{
  int64_t clientdiff = g_clientQuestions - g_clientResponses;
  int64_t serverdiff = g_serverQuestions - g_serverResponses;

  if(clientdiff > 0.01*g_clientQuestions) {
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

  if(serverdiff > 0.01*g_serverQuestions) {
    char tmp[80];
    struct tm tm=*localtime_r(&tv.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);

    cout << tmp << ": Auth server dropped too many questions (" 
	 << g_serverQuestions <<" vs " << g_serverResponses << "), diff: " <<serverdiff<<endl;

    cout << tv.tv_sec<<endl;

    tm=*localtime_r(&g_lastanswerTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last answer: "<<tmp<<"."<<g_lastanswerTime.tv_usec/1000000.0<<endl;

    tm=*localtime_r(&g_lastquestionTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last question: "<<tmp<<"."<<g_lastquestionTime.tv_usec/1000000.0<<endl;
  }
//  cout <<"Recursive questions: "<<g_clientQuestions<<", recursive responses: " << g_clientResponses<< 
//    ", server questions: "<<g_serverQuestions<<", server responses: "<<g_serverResponses<<endl;


  cerr << tv.tv_sec << " " <<g_clientQuestions<<" " << g_clientResponses<< " "<<g_serverQuestions<<" "<<g_serverResponses<<" "<<g_skipped<<endl;
  g_clientQuestions=g_clientResponses=g_serverQuestions=g_serverResponses=0;
  g_skipped=0;
}


int main(int argc, char** argv)
try
{
  for(int n=1 ; n < argc; ++n) {
    cout<<argv[n]<<endl;
    unsigned int parseErrors=0, totalQueries=0, skipped=0;
    PcapPacketReader pr(argv[n]);
    PcapPacketWriter pw(argv[n]+string(".out"), pr);
    /* four sorts of packets: 
       "rd": question from a client pc
       "rd qr": answer to a client pc
       "": question from the resolver
       "qr": answer to the resolver */
    
    /* what are interesting events to note? */
    /* we measure every 60 seconds, each interval with 10% less answers than questions is interesting */
    /* report chunked */
    
    struct timeval lastreport={0, 0};
    
    typedef set<pair<string, uint16_t> > queries_t;
    queries_t questions, answers;

    unsigned int count = 10000;

    while(pr.getUDPPacket()) {
      if((ntohs(pr.d_udp->uh_dport)==5300 || ntohs(pr.d_udp->uh_sport)==5300 ||
	  ntohs(pr.d_udp->uh_dport)==53   || ntohs(pr.d_udp->uh_sport)==53) &&
	 pr.d_len > 12) {
	try {
	  MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
	  if(mdp.d_header.id==htons(4575)) {
//	    cerr << ntohl(*(uint32_t*)&pr.d_ip->ip_src)<<endl;
	    g_skipped++;
	    continue;
	  }
	  if(iequals(mdp.d_qname,"ycjnakisys1m.post.yamaha.co.jp."))
	    cerr<<"hit: "<<mdp.d_qtype<<", rd="<<mdp.d_header.rd<< ", id="<<mdp.d_header.id<<", qr="<<mdp.d_header.qr<<"\n";

	  if(lastreport.tv_sec == 0) {
	    lastreport = pr.d_pheader.ts;
	  }
	  
	  if(pr.d_pheader.ts.tv_sec > 1176897290 && pr.d_pheader.ts.tv_sec < 1176897310 ) 
	    pw.write();

	  if(mdp.d_header.rd && !mdp.d_header.qr) {
	    g_lastquestionTime=pr.d_pheader.ts;
	    g_clientQuestions++;
	    totalQueries++;
	    questions.insert(make_pair(mdp.d_qname, mdp.d_qtype));
	  }
	  else if(mdp.d_header.rd && mdp.d_header.qr) {
	    g_lastanswerTime=pr.d_pheader.ts;
	    g_clientResponses++;
	    answers.insert(make_pair(mdp.d_qname, mdp.d_qtype));
	  }
	  else if(!mdp.d_header.rd && !mdp.d_header.qr) {
	    g_lastquestionTime=pr.d_pheader.ts;
	    g_serverQuestions++;
	    totalQueries++;
	  }
	  else if(!mdp.d_header.rd && mdp.d_header.qr)
	    g_serverResponses++;
	  
	  if(pr.d_pheader.ts.tv_sec - lastreport.tv_sec > 2) {
	    makeReport(pr.d_pheader.ts);
	    lastreport = pr.d_pheader.ts;
	  }
	  
	}
	catch(MOADNSException& mde) {
	  //	cerr<<"error parsing packet: "<<mde.what()<<endl;
	  parseErrors++;
	  continue;
	}
	catch(exception& e) {
	  cerr << e.what() << endl;
	  continue;
	}
      }

    }
    cerr<<"Parse errors: "<<parseErrors<<", total queries: "<<totalQueries<<endl;
    typedef vector<queries_t::value_type> diff_t;
    diff_t diff;
    set_difference(questions.begin(), questions.end(), answers.begin(), answers.end(), back_inserter(diff));
    cerr<<questions.size()<<" different rd questions, "<< answers.size()<<" different rd answers, diff: "<<diff.size()<<endl;
    cerr<<skipped<<" skipped\n";
    ofstream failed("failed");
    for(diff_t::const_iterator i = diff.begin(); i != diff.end() ; ++i) {
      failed << i->first << "\t" << i->second << "\n";
    }

    diff.clear();
    
    set_difference(answers.begin(), answers.end(), questions.begin(), questions.end(), back_inserter(diff));
    cerr<<diff.size()<<" answers w/o questions\n";

    ofstream succeeded("succeeded");
    for(queries_t::const_iterator i = answers.begin(); i != answers.end() ; ++i) {
      succeeded << i->first << "\t" << i->second << "\n";
    }
  }
}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
