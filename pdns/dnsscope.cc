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
#include "namespaces.hh"

StatBag S;


struct QuestionData
{
  QuestionData() : d_qcount(0), d_answercount(0)
  {
    d_firstquestiontime.tv_sec=0;
  }

  int d_qcount;
  int d_answercount;

  struct pdns_timeval d_firstquestiontime;
};

typedef map<QuestionIdentifier, QuestionData> statmap_t;
statmap_t statmap;

int main(int argc, char** argv)
try
{
  if(argc!=2) {
    cerr<<"Syntax: dnsscope filename.pcap"<<endl;
    exit(1);
  }
  PcapPacketReader pr(argv[1]);
  PcapPacketWriter* pw=0;

  if(argc==3)
    pw=new PcapPacketWriter(argv[2], pr);

  int dnserrors=0, bogus=0;
  typedef map<uint32_t,uint32_t> cumul_t;
  cumul_t cumul;
  unsigned int untracked=0, errorresult=0, reallylate=0, nonRDQueries=0, queries=0;
  unsigned int ipv4Packets=0, ipv6Packets=0;

  typedef map<uint16_t,uint32_t> rcodes_t;
  rcodes_t rcodes;

  time_t lowestTime=2000000000, highestTime=0;

  while(pr.getUDPPacket()) {
    if((ntohs(pr.d_udp->uh_dport)==5300 || ntohs(pr.d_udp->uh_sport)==5300 ||
        ntohs(pr.d_udp->uh_dport)==53   || ntohs(pr.d_udp->uh_sport)==53) &&
        pr.d_len > 12) {
      try {
        MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
	if(pr.d_ip->ip_v == 4) 
	  ++ipv4Packets;
	else
	  ++ipv6Packets;
	
	if(!mdp.d_header.qr) {
	  if(!mdp.d_header.rd)
	    nonRDQueries++;
	  queries++;
	}

        lowestTime=min((time_t)lowestTime,  (time_t)pr.d_pheader.ts.tv_sec);
        highestTime=max((time_t)highestTime, (time_t)pr.d_pheader.ts.tv_sec);

        string name=mdp.d_qname+"|"+DNSRecordContent::NumberToType(mdp.d_qtype);
        
        QuestionIdentifier qi=QuestionIdentifier::create(pr.getSource(), pr.getDest(), mdp);

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
            if(usecs<2049000)
              cumul[usecs]++;
            else
              reallylate++;

            
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
      catch(std::exception& e) {
        if(pw)
          pw->write();
        bogus++;
        continue;
      }
    }
  }
  cout<<"Timespan: "<<(highestTime-lowestTime)/3600.0<<" hours"<<endl;

  cout<<"Saw "<<pr.d_correctpackets<<" correct packets, "<<pr.d_runts<<" runts, "<< pr.d_oversized<<" oversize, "<<
    pr.d_nonetheripudp<<" unknown encaps, "<<dnserrors<<" dns decoding errors, "<<bogus<<" bogus packets"<<endl;
  cout<<"IPv4: "<<ipv4Packets<<" packets, IPv6: "<<ipv6Packets<<" packets"<<endl;
  unsigned int unanswered=0;
  for(statmap_t::const_iterator i=statmap.begin(); i!=statmap.end(); ++i) {
    if(!i->second.d_answercount) {
      unanswered++;
      // cout << i->first.d_qname <<" " <<i->first.d_qtype<<endl;
    }
  }

  cout<< boost::format("%d (%.02f%% of all) queries did not request recursion") % nonRDQueries % ((nonRDQueries*100.0)/queries) << endl;
  cout<<statmap.size()<<" queries went unanswered, of which "<< statmap.size()-unanswered<<" were answered on exact retransmit"<<endl;
  cout<<untracked<<" responses could not be matched to questions"<<endl;
  cout<<dnserrors<<" responses were unsatisfactory (indefinite, or SERVFAIL)"<<endl;
  cout<<reallylate<<" responses (would be) discarded because older than 2 seconds"<<endl;
#if 0
        ns_r_noerror = 0,       /* No error occurred. */
        ns_r_formerr = 1,       /* Format error. */
        ns_r_servfail = 2,      /* Server failure. */
        ns_r_nxdomain = 3,      /* Name error. */
        ns_r_notimpl = 4,       /* Unimplemented. */
        ns_r_refused = 5,       /* Operation refused. */
#endif

  cout<<"Rcode\tCount\n";
  for(rcodes_t::const_iterator i=rcodes.begin(); i!=rcodes.end(); ++i)
    cout<<i->first<<"\t"<<i->second<<endl;

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

  cout.setf(std::ios::fixed);
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
    cout<<"Average response time: "<<tottime/totpackets<<" usec"<<endl;
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
