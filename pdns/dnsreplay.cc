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
    cerr<<"Out of free IDs"<<endl;
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
  QuestionData() : d_assignedID(-1), d_origRcode(-1), d_newRcode(-1), d_norecursionavailable(false)
  {}
  int d_assignedID;
  MOADNSParser::answers_t d_origAnswers, d_newAnswers;
  int d_origRcode, d_newRcode;
  struct timeval d_sentTime;
  bool d_norecursionavailable;
};

typedef map<QuestionIdentifier, QuestionData> qids_t;
qids_t qids;

unsigned int s_questions, s_answers, s_timedout, s_perfect, s_mostly, s_nooriginalanswer;
unsigned int s_webetter, s_origbetter, s_norecursionavailable;
unsigned int s_weunmatched, s_origunmatched;
unsigned int s_wednserrors, s_origdnserrors;
// XXX FIXME wasteful
void pruneQids()
{
  qids_t nqids;
  struct timeval now;
  gettimeofday(&now, 0);
  for(qids_t::iterator i=qids.begin(); i!=qids.end(); ++i)
    if(now.tv_sec < i->second.d_sentTime.tv_sec + 4 || (now.tv_sec == i->second.d_sentTime.tv_sec &&  now.tv_usec < i->second.d_sentTime.tv_usec)) 
      nqids[i->first]=i->second;
    else {
      s_idmanager.releaseID(i->second.d_assignedID);
      if(i->second.d_newRcode==-1)
	s_timedout++;
      else if(i->second.d_origRcode==-1)
	s_nooriginalanswer++;
      else
	cerr<<"Impossible - finished QI in the pool"<<endl;
    }

  nqids.swap(qids);
}

void compactAnswerSet(MOADNSParser::answers_t orig, set<DNSRecord>& compacted)
{
  for(MOADNSParser::answers_t::const_iterator i=orig.begin(); i != orig.end(); ++i)
    if(i->first.d_place==DNSRecord::Answer)
      compacted.insert(i->first);
}

bool isRcodeOk(int rcode)
{
  return rcode==0 || rcode==3;
}

set<pair<string,uint16_t> > s_origbetterset;

void measureResultAndClean(const QuestionIdentifier& qi)
{
  QuestionData qd=qids[qi];
  cout<<qi<<", orig rcode: "<<qd.d_origRcode<<", ours: "<<qd.d_newRcode;

  set<DNSRecord> canonicOrig, canonicNew;
  compactAnswerSet(qd.d_origAnswers, canonicOrig);
  compactAnswerSet(qd.d_newAnswers, canonicNew);
  
  cout<<", "<<canonicOrig.size()<< " vs " << canonicNew.size()<<", perfect: ";

  if(canonicOrig==canonicNew) {
    s_perfect++;
    cout<<"yes\n";
  }
  else {
    cout<<"no\n";
    
    if(qd.d_norecursionavailable)
      cout<<"\t* original nameserver did not provide recursion for this question *"<<endl;
    if(qd.d_origRcode == qd.d_newRcode ) {
      cout<<"\t* mostly correct *"<<endl;
      s_mostly++;
    }

    if(!isRcodeOk(qd.d_origRcode) && isRcodeOk(qd.d_newRcode)) {
      cout<<"\t* we better *"<<endl;
      s_webetter++;
    }
    if(isRcodeOk(qd.d_origRcode) && !isRcodeOk(qd.d_newRcode)) {
      cout<<"\t* orig better *"<<endl;
      s_origbetter++;
      s_origbetterset.insert(make_pair(qi.d_qname, qi.d_qtype));
    }

    cout<<"orig:\n";
    for(set<DNSRecord>::const_iterator i=canonicOrig.begin(); i!=canonicOrig.end(); ++i)
      cout<<"\t"<<i->d_label<<"\t"<<DNSRecordContent::NumberToType(i->d_type)<<"\t'"  << (i->d_content ? i->d_content->getZoneRepresentation() : "") <<"'\n";
    cout<<"new:\n";
    for(set<DNSRecord>::const_iterator i=canonicNew.begin(); i!=canonicNew.end(); ++i)
      cout<<"\t"<<i->d_label<<"\t"<<DNSRecordContent::NumberToType(i->d_type)<<"\t'"  << (i->d_content ? i->d_content->getZoneRepresentation() : "") <<"'\n";
    cout<<"\n";
  }

  qids.erase(qi);
  s_idmanager.releaseID(qd.d_assignedID);
}


Socket *s_socket;

static pthread_mutex_t s_lock=PTHREAD_MUTEX_INITIALIZER;

void* incomingThread(void*)
try
{
  string packet;
  IPEndpoint remote;

  for(;;) {
    s_socket->recvFrom(packet, remote);
    try {
      MOADNSParser mdp(packet.c_str(), packet.length());
      if(!mdp.d_header.qr) {
	cout<<"Received a question from our reference nameserver!"<<endl;
	continue;
      }
      
      Lock l(&s_lock);
      
      qids_t::iterator i=qids.begin();
      for(; i!=qids.end(); ++i)
	if(i->second.d_assignedID == ntohs(mdp.d_header.id))
	  break;
      
      if(i==qids.end()) {
	cout<<"Received an answer from reference nameserver with id "<<mdp.d_header.id<<" which we can't match to a question!"<<endl;
	s_weunmatched++;
	continue;
      }
      
      //    cout<<"Matched answer from reference to a question we asked"<<endl;
      
      QuestionData& qd=i->second;
      
      qd.d_newAnswers=mdp.d_answers;
      qd.d_newRcode=mdp.d_header.rcode;
      if(qd.d_origRcode!=-1) {
	//      cout<<"Removing entry "<<i->first<<", is done [in socket]"<<endl;
	measureResultAndClean(i->first);
      }
    }
    catch(MOADNSException &e)
    {
      s_wednserrors++;
    }
    catch(out_of_range &e)
    {
      s_wednserrors++;
    }
  }
}
catch(exception& e)
{
  cerr<<"Receiver thread died: "<<e.what()<<endl;
  exit(1);
}
catch(...)
{
  cerr<<"Receiver thread died with unknown exception"<<endl;
  exit(1);
}

int main(int argc, char** argv)
try
{
  PcapPacketReader pr(argv[1]);
  s_socket= new Socket(InterNetwork, Datagram);
  
  pthread_t tid;
  pthread_create(&tid, 0, incomingThread, 0);

  IPEndpoint remote(argc > 2 ? argv[2] : "127.0.0.1", 
		    argc > 3 ? atoi(argv[3]) : 5300);
  struct timeval lastsent={0,0};

  unsigned int once=0;
  for(;;) {
    if(!pr.getUDPPacket())
      break;

    if(!((once++)%2000)) {
      Lock l(&s_lock);
      pruneQids();
      cerr<<"we drop: "<<s_timedout<<", orig drop: "<<s_nooriginalanswer<<", "<<s_questions<<" questions sent, "<<s_answers
	  <<" original answers, "<<s_perfect<<" perfect, "<<s_mostly<<" mostly correct"<<", "<<s_webetter<<" we better, "<<s_origbetter<<" orig better ("<<s_origbetterset.size()<<" diff)"<<endl;
      cerr<<"original questions from IP addresses for which recursion was not available: "<<s_norecursionavailable<<endl;
      cerr<<"Unmatched from us: "<<s_weunmatched<<", unmatched from original: "<<s_origunmatched<<endl;
      cerr<<"DNS decoding errors from us: "<<s_wednserrors<<", from original: "<<s_origdnserrors<<endl<<endl;
    }

    HEADER* dh=(HEADER*)pr.d_payload;
    //                                                             non-recursive  
    if((ntohs(pr.d_udp->dest)!=53 && ntohs(pr.d_udp->source)!=53) || !dh->rd || pr.d_len <= sizeof(HEADER)) 
      continue;
    
    

    try {
      MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
      QuestionIdentifier qi=QuestionIdentifier::create(pr.d_ip, pr.d_udp, mdp);

      int inflight;
      
      if(!mdp.d_header.qr) {
	s_questions++;
	{ 
	  Lock l(&s_lock);
	  if(qids.count(qi)) {
	    cout<<"Saw an exact duplicate question, "<<qi<< endl;
	    continue;
	  }
	  //	  else 
	  //	    cout<<"New question "<<qi<<endl;

	  QuestionData& qd=qids[qi];
	  gettimeofday(&qd.d_sentTime,0);
	  
	  qd.d_assignedID = s_idmanager.getID();


	  dh->id=htons(qd.d_assignedID);
	}

	if(lastsent.tv_sec) {
	  double seconds=pr.d_pheader.ts.tv_sec - lastsent.tv_sec;
	  double useconds=(pr.d_pheader.ts.tv_usec - lastsent.tv_usec);
	  double factor=10;
	  
	  seconds/=factor;
	  useconds/=factor;
	  
	  long long nanoseconds=1000000000ULL*seconds + useconds * 1000;
	  
	  struct timespec tosleep;
	  tosleep.tv_sec=nanoseconds/1000000000UL;
	  tosleep.tv_nsec=nanoseconds%1000000000UL;
	  
	  nanosleep(&tosleep, 0);
	}
	lastsent=pr.d_pheader.ts;
	//	cout<<"sending!"<<endl;
	s_socket->sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
      }
      else {
	s_answers++;
	Lock l(&s_lock);
	if(qids.count(qi)) {
	  QuestionData& qd=qids[qi];
	  //	  cout<<"Matched answer "<<qi<<endl;
	  qd.d_origAnswers=mdp.d_answers;
	  qd.d_origRcode=mdp.d_header.rcode;

	  if(!dh->ra) {
	    s_norecursionavailable++;
	    qd.d_norecursionavailable=true;
	  }

	  if(qd.d_newRcode!=-1) {
	    //	    cout<<"Removing entry "<<qi<<", is done [in main loop]"<<endl;
	    measureResultAndClean(qi);
	  }

	  
	  continue;
	}
	else {
	  s_origunmatched++;
	  cout<<"Unmatched original answer "<<qi<<endl;
	}
      }
    }
    catch(MOADNSException &e)
    {
      s_origdnserrors++;
    }
    catch(out_of_range &e)
    {
      s_origdnserrors++;
    }
  }

}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}


#if 0

  /*
  struct timespec tosleep;
  struct timeval lastsent={0,0};
  double seconds, useconds;
  double factor=20;
  */

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
