/** two modes:

Replay all recursion-desired DNS questions to a specified IP address.

Track all outgoing questions, remap id to one of ours.
Also track all recorded answers, and map them to that same id, the 'expectation'.

When we see a question, parse it, give it a QuestionIdentifyer, and and an id from the free-id list.

When we see an answer in the tcpdump, parse it, make QI, and add it to the original QI
   and check

When we see an answer from the socket, use the id to match it up to the original QI
   and check


There is one central object, which has (when complete)

   our assigned id
   QI
   Original answer
   Socket answer
*/

#include <pcap.h>
#include <bitset>
#include "statbag.hh"
#include "dnspcap.hh"
#include "sstuff.hh"
#include "anadns.hh"
#include <arpa/nameser.h>
#include <set>

using namespace boost;
using namespace std;

StatBag S;

class DNSIDManager
{
public:
  
  int getID()
  {

    for(unsigned int n=0; n < d_freeids.size() ; ++n)
      if(!d_freeids[n]) {
	d_freeids[n]=1;
	return n;
      }

    throw runtime_error("Out of free IDs");
  }

  void releaseID(int id)
  {
    if(!d_freeids[id])
      throw runtime_error("Trying to release unused id: "+lexical_cast<string>(id));
    d_freeids[id]=0;
  }

private:
  bitset<65536> d_freeids;
} s_idmanager;

struct QuestionData
{
  QuestionData() : d_assignedID(-1), d_origRcode(-1), d_newRcode(-1) 
  {}
  int d_assignedID;
  MOADNSParser::answers_t d_origAnswers, d_newAnswers;
  int d_origRcode, d_newRcode;
};

typedef map<QuestionIdentifier, QuestionData> qids_t;
qids_t qids;

void compactAnswerSet(MOADNSParser::answers_t orig, set<DNSRecord>& compacted)
{
  for(MOADNSParser::answers_t::const_iterator i=orig.begin(); i != orig.end(); ++i)
    if(i->first.d_place==DNSRecord::Answer)
      compacted.insert(i->first);
}

void measureResultAndClean(const QuestionIdentifier& qi)
{
  QuestionData qd=qids[qi];
  cerr<<"Orig rcode: "<<qd.d_origRcode<<", ours: "<<qd.d_newRcode;

  set<DNSRecord> canonicOrig, canonicNew;
  compactAnswerSet(qd.d_origAnswers, canonicOrig);
  compactAnswerSet(qd.d_newAnswers, canonicNew);
  
  cerr<<", "<<canonicOrig.size()<< " vs " << canonicNew.size()<<", perfect: ";

  if(canonicOrig==canonicNew)
    cerr<<"yes";
  else
    cerr<<"no";
  cerr<<endl;

  qids.erase(qi);
}


void processIncoming(Socket& s)
{
  string packet;
  IPEndpoint remote;
  while(s.recvFromAsync(packet, remote)) {
    MOADNSParser mdp(packet.c_str(), packet.length());
    if(!mdp.d_header.qr) {
      cerr<<"Received a question from our reference nameserver!"<<endl;
      continue;
    }

    qids_t::iterator i=qids.begin();
    for(; i!=qids.end(); ++i)
      if(i->second.d_assignedID == ntohs(mdp.d_header.id))
	break;
    
    if(i==qids.end()) {
      cerr<<"Received an answer from reference nameserver with id "<<mdp.d_header.id<<" which we can't match to a question!"<<endl;
      continue;
    }
    
    cerr<<"Matched answer from reference to a question we asked"<<endl;

    QuestionData& qd=i->second;
    
    qd.d_newAnswers=mdp.d_answers;
    qd.d_newRcode=mdp.d_header.rcode;
    if(qd.d_origRcode!=-1) {
      cerr<<"Removing entry "<<i->first<<", is done [in socket]"<<endl;
      measureResultAndClean(i->first);
    }
  }
    
}

int main(int argc, char** argv)
try
{
  struct sched_param p;
  p.sched_priority=50;
  cout<<"Sched returned: "<<sched_setscheduler(0, SCHED_RR, &p)<<endl;

  PcapPacketReader pr(argv[1]);
  Socket s(InterNetwork, Datagram);
  s.setNonBlocking();
  IPEndpoint remote("127.0.0.1", 5300);

  /*
  struct timespec tosleep;
  struct timeval lastsent={0,0};
  double seconds, useconds;
  double factor=20;
  */

  while(pr.getUDPPacket()) {
    processIncoming(s);


    HEADER* dh=(HEADER*)pr.d_payload;
    if(ntohs(pr.d_udp->dest)!=53 && ntohs(pr.d_udp->source)!=53 ||  !dh->rd || pr.d_len <= sizeof(HEADER)) 
      continue;
    
    try {
      MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
      QuestionIdentifier qi=QuestionIdentifier::create(pr.d_ip, pr.d_udp, mdp);
      
      if(!mdp.d_header.qr) {
	if(qids.count(qi)) {
	  cerr<<"Saw an exact duplicate question, "<<qi<< endl;
	  continue;
	}
	else 
	  cerr<<"New question "<<qi<<endl;
	QuestionData& qd=qids[qi];
	
	qd.d_assignedID = s_idmanager.getID();
	dh->id=htons(qd.d_assignedID);
	s.sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
      }
      else {
	if(qids.count(qi)) {
	  QuestionData& qd=qids[qi];
	  cerr<<"Matched answer "<<qi<<endl;
	  qd.d_origAnswers=mdp.d_answers;
	  qd.d_origRcode=mdp.d_header.rcode;
	  if(qd.d_newRcode!=-1) {
	    cerr<<"Removing entry "<<qi<<", is done [in main loop]"<<endl;
	    measureResultAndClean(qi);
	  }
	  continue;
	}
	else 
	  cerr<<"Unmatched answer "<<qi<<endl;
	//	QuestionData& qd=qids[qi];
	
      }
    }
    catch(MOADNSException &e)
    {
    }
    catch(out_of_range &e)
    {
    }
    
  }

}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}


#if 0
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
#endif
