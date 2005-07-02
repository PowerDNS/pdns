#include <pcap.h>

#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <map>
#include <set>
#include <fstream>

using namespace boost;
using namespace std;

StatBag S;

struct QuestionIdentifyer
{
  QuestionIdentifyer() 
  {}

  bool operator<(const QuestionIdentifyer& rhs) const
  {
    return 
      tie(d_sourceip, d_destip, d_sourceport, d_destport, d_qname, d_qtype, d_id) < 
      tie(rhs.d_sourceip, rhs.d_destip, rhs.d_sourceport, rhs.d_destport, rhs.d_qname, rhs.d_qtype, rhs.d_id);
  }

  // the canonical direction is that of the question
  static QuestionIdentifyer create(const struct iphdr* d_ip, const struct udphdr* d_udp, const MOADNSParser& mdp)
  {
    QuestionIdentifyer ret;
    if(mdp.d_header.qr) {
      ret.d_sourceip=htonl(d_ip->daddr);
      ret.d_destip=htonl(d_ip->saddr);
      ret.d_sourceport=htons(d_udp->dest);
      ret.d_destport=htons(d_udp->source);
    }
    else {
      ret.d_sourceip=htonl(d_ip->saddr);
      ret.d_destip=htonl(d_ip->daddr);
      ret.d_sourceport=htons(d_udp->source);
      ret.d_destport=htons(d_udp->dest);
    }
    ret.d_qname=mdp.d_qname;
    ret.d_qtype=mdp.d_qtype;
    ret.d_id=mdp.d_header.id;
    return ret;
  }

  uint32_t d_sourceip;
  uint32_t d_destip;
  uint16_t d_sourceport;
  uint16_t d_destport;

  string d_qname;
  uint16_t d_qtype;
  uint16_t d_id;
};

struct QuestionData
{
  QuestionData() : d_qcount(0), d_answercount(0)
  {
    d_firstquestiontime.tv_sec=0;
  }

  int d_qcount;
  int d_answercount;

  struct timeval d_firstquestiontime;
};

typedef map<QuestionIdentifyer, QuestionData> statmap_t;
statmap_t statmap;

int main(int argc, char** argv)
try
{
  PcapPacketReader pr(argv[1]);
  PcapPacketWriter* pw=0;

  if(argc==3)
    pw=new PcapPacketWriter(argv[2], pr);

  int dnserrors=0;
  typedef map<uint32_t,uint32_t> cumul_t;
  cumul_t cumul;
  unsigned int untracked=0, errorresult=0;

  typedef map<uint16_t,uint32_t> rcodes_t;
  rcodes_t rcodes;

  while(pr.getUDPPacket()) {
    if(ntohs(pr.d_udp->dest)==53 || ntohs(pr.d_udp->source)==53 && pr.d_len > sizeof(HEADER)) {
      try {
	MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);

	string name=mdp.d_qname+"|"+DNSRecordContent::NumberToType(mdp.d_qtype);
	
	QuestionIdentifyer qi=QuestionIdentifyer::create(pr.d_ip, pr.d_udp, mdp);

	if(!mdp.d_header.qr) {
	  //	  cout<<"Question for '"<< name <<"'\n";

	  QuestionData& qd=statmap[qi];
	  
	  if(!qd.d_firstquestiontime.tv_sec)
	    qd.d_firstquestiontime=pr.d_pheader.ts;
	  qd.d_qcount++;
	}
	else  {  // NO ERROR or NXDOMAIN
	  QuestionData& qd=statmap[qi];

	  if(!qd.d_qcount)
	    untracked++;

	  qd.d_answercount++;
	  //	  cout<<"Answer to '"<< name <<"': RCODE="<<(int)mdp.d_rcode<<", "<<mdp.d_answers.size()<<" answers\n";
	  if(qd.d_qcount) {
	    uint32_t usecs= (pr.d_pheader.ts.tv_sec - qd.d_firstquestiontime.tv_sec) * 1000000 +  
	                    (pr.d_pheader.ts.tv_usec - qd.d_firstquestiontime.tv_usec) ;
	    //	    cout<<"Took: "<<usecs<<"usec\n";
	    cumul[usecs]++;

	    
	    if(mdp.d_header.rcode != 0 && mdp.d_header.rcode!=3) 
	      errorresult++;
	  }

	  if(!qd.d_qcount || qd.d_qcount == qd.d_answercount)
	    statmap.erase(statmap.find(qi));
 	}

	rcodes[mdp.d_header.rcode]++;
      }
      catch(MOADNSException& mde) {
	//	cerr<<"error parsing packet: "<<mde.what()<<endl;
	if(pw)
	  pw->write();
	dnserrors++;
	continue;
      }
      catch(exception& e) {
	cerr<<"Bogus packet"<<endl;
	if(pw)
	  pw->write();
	continue;
      }
    }
  }
  cerr<<"Saw "<<pr.d_correctpackets<<" correct packets, "<<pr.d_runts<<" runts, "<< pr.d_oversized<<" oversize, "<<
    pr.d_nonetheripudp<<" unknown encaps, "<<dnserrors<<" dns decoding errors"<<endl;

  unsigned int unanswered=0;
  for(statmap_t::const_iterator i=statmap.begin(); i!=statmap.end(); ++i) {
    if(!i->second.d_answercount)
      unanswered++;
  }

  cerr<<statmap.size()<<" packets went unanswered, of which "<< statmap.size()-unanswered<<" were answered on exact retransmit"<<endl;
  cerr<<untracked<<" answers could not be matched to questions"<<endl;
  cerr<<dnserrors<<" answers were unsatisfactory (indefinite, or SERVFAIL)"<<endl;

#if 0
        ns_r_noerror = 0,       /* No error occurred. */
        ns_r_formerr = 1,       /* Format error. */
        ns_r_servfail = 2,      /* Server failure. */
        ns_r_nxdomain = 3,      /* Name error. */
        ns_r_notimpl = 4,       /* Unimplemented. */
        ns_r_refused = 5,       /* Operation refused. */
#endif

  cerr<<"Rcode\tCount\n";
  for(rcodes_t::const_iterator i=rcodes.begin(); i!=rcodes.end(); ++i)
    cerr<<i->first<<"\t"<<i->second<<endl;

  uint32_t sum=0;
  ofstream stats("stats");
  uint32_t totpackets=0;
  double tottime=0;
  for(cumul_t::const_iterator i=cumul.begin(); i!=cumul.end(); ++i) {
    stats<<i->first<<"\t"<<(sum+=i->second)<<"\n";
    totpackets+=i->second;
    tottime+=i->first*i->second;
  }


  typedef map<uint32_t, bool> done_t;
  done_t done;
  done[50];
  done[100];
  done[200];
  done[250];
  done[300];
  done[350];
  done[400];
  done[800];
  done[1000];
  done[2000];
  done[4000];
  done[8000];
  done[16000];
  done[32000];
  done[64000];
  done[128000];
  done[256000];
  done[512000];
  done[1024000];
  done[2048000];

  cout.setf(ios::fixed);
  cout.precision(2);
  sum=0;
  
  double lastperc=0, perc=0;
  for(cumul_t::const_iterator i=cumul.begin(); i!=cumul.end(); ++i) {
    sum+=i->second;

    for(done_t::iterator j=done.begin(); j!=done.end(); ++j)
    if(!j->second && i->first > j->first) {
      j->second=true;

      perc=sum*100.0/totpackets;
      if(j->first < 1024)
	cout<< perc <<"% of questions answered within " << j->first << " usec (";
      else
	cout<< perc <<"% of questions answered within " << j->first/1000.0 << " msec (";

      cout<<perc-lastperc<<"%)\n";
      lastperc=sum*100.0/totpackets;
    }
  }

  
  if(totpackets)
    cerr<<"Average response time: "<<tottime/totpackets<<" usec"<<endl;
}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
