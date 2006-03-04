/**
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

What to do with timeouts. We keep around at most 65536 outstanding answers. 
*/


/* 
   mental_clock=0;
   for(;;) {

   do {
      read a packet
      send a packet
    } while(time_of_last_packet_sent < mental_clock) 
    mental_clock=time_of_last_packet_sent;

    wait for a response packet for 0.1 seconds
    note how much time has passed
    mental_clock+=time_passed;
   }

 */

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

using namespace boost;
using namespace ::boost::multi_index;
using namespace std;

StatBag S;
bool s_quiet=true;


void normalizeTV(struct timeval& tv)
{
  if(tv.tv_usec > 1000000) {
    ++tv.tv_sec;
    tv.tv_usec-=1000000;
  }
  else if(tv.tv_usec < 0) {
    --tv.tv_sec;
    tv.tv_usec+=1000000;
  }
}

const struct timeval operator+(const struct timeval& lhs, const struct timeval& rhs)
{
  struct timeval ret;
  ret.tv_sec=lhs.tv_sec + rhs.tv_sec;
  ret.tv_usec=lhs.tv_usec + rhs.tv_usec;
  normalizeTV(ret);
  return ret;
}

const struct timeval operator-(const struct timeval& lhs, const struct timeval& rhs)
{
  struct timeval ret;
  ret.tv_sec=lhs.tv_sec - rhs.tv_sec;
  ret.tv_usec=lhs.tv_usec - rhs.tv_usec;
  normalizeTV(ret);
  return ret;
}

const struct timeval operator*(int fact, const struct timeval& rhs)
{
  //  cout<<"In: "<<rhs.tv_sec<<" + "<<rhs.tv_usec<<"\n";
  struct timeval ret;
  if( (2000000000 / fact) < rhs.tv_usec) {
    double d=1.0 * rhs.tv_usec * fact;
    ret.tv_sec=fact * rhs.tv_sec;
    ret.tv_sec+=(int) (d/1000000);
    d/=1000000;
    d-=(int)d;

    ret.tv_usec=1000000*d;
    normalizeTV(ret);
    
    cout<<"out complex: "<<ret.tv_sec<<" + "<<ret.tv_usec<<"\n";
    
    return ret;
  }

  ret.tv_sec=rhs.tv_sec * fact;
  ret.tv_usec=rhs.tv_usec * fact;

  normalizeTV(ret);
  //  cout<<"out simple: "<<ret.tv_sec<<" + "<<ret.tv_usec<<"\n";
  return ret;
}


bool operator<(const struct timeval& lhs, const struct timeval& rhs) 
{
  return make_pair(lhs.tv_sec, lhs.tv_usec) < make_pair(rhs.tv_sec, rhs.tv_usec);
}




class DNSIDManager : public boost::noncopyable
{
public:
  DNSIDManager()
  {
    for(unsigned int i=0; i < 65536; ++i)
      d_available.push_back(i);

  }

  uint16_t getID()
  {
    uint16_t ret;
    if(!d_available.empty()) {
      ret=d_available.front();
      d_available.pop_front();
      return ret;
    }
    else
      throw runtime_error("out of ids!"); // XXX FIXME
  }

  void releaseID(uint16_t id)
  {
    d_available.push_back(id);
  }

private:
  deque<uint16_t> d_available;
  
} s_idmanager;


struct AssignedIDTag{};
struct QuestionTag{};

struct QuestionData
{
  QuestionData() : d_assignedID(-1), d_origRcode(-1), d_newRcode(-1), d_norecursionavailable(false), d_origlate(false), d_newlate(false)
  {
  }
  QuestionIdentifier d_qi;
  int d_assignedID;
  MOADNSParser::answers_t d_origAnswers, d_newAnswers;
  int d_origRcode, d_newRcode;
  struct timeval d_resentTime;
  bool d_norecursionavailable;
  bool d_origlate, d_newlate;
};

typedef multi_index_container<
  QuestionData, 
  indexed_by<
             ordered_unique<tag<QuestionTag>, BOOST_MULTI_INDEX_MEMBER(QuestionData, QuestionIdentifier, d_qi) > ,
	     ordered_unique<tag<AssignedIDTag>,  BOOST_MULTI_INDEX_MEMBER(QuestionData, int, d_assignedID) >
            >
> qids_t;
					 
qids_t qids;


bool g_throttled;

unsigned int s_questions, s_origanswers, s_weanswers, s_wetimedout, s_perfect, s_mostly, s_origtimedout;
unsigned int s_wenever, s_orignever;
unsigned int s_webetter, s_origbetter, s_norecursionavailable;
unsigned int s_weunmatched, s_origunmatched;
unsigned int s_wednserrors, s_origdnserrors;


double DiffTime(const struct timeval& first, const struct timeval& second)
{
  int seconds=second.tv_sec - first.tv_sec;
  int useconds=second.tv_usec - first.tv_usec;
  
  if(useconds < 0) {
    seconds-=1;
    useconds+=1000000;
  }
  return seconds + useconds/1000000.0;
}


void WeOrigSlowQueriesDelta(int& weOutstanding, int& origOutstanding, int& weSlow, int& origSlow)
{
  struct timeval now;
  gettimeofday(&now, 0);

  weOutstanding=origOutstanding=weSlow=origSlow=0;

  for(qids_t::iterator i=qids.begin(); i!=qids.end(); ++i) {
    double dt=DiffTime(i->d_resentTime, now);
    if(dt < 2.0) {
      if(i->d_newRcode == -1) 
	weOutstanding++;
      if(i->d_origRcode == -1)
	origOutstanding++;
    }
    else {
      if(i->d_newRcode == -1) {
	weSlow++;
	if(!i->d_newlate) {
	  QuestionData qd=*i;
	  qd.d_newlate=true;
	  qids.replace(i, qd);

	  s_wetimedout++;
	}
      }
      if(i->d_origRcode == -1) {
	origSlow++;
	if(!i->d_origlate) {
	  QuestionData qd=*i;
	  qd.d_origlate=true;
	  qids.replace(i, qd);

	  s_origtimedout++;
	}
      }
    }
  }
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
  QuestionData qd=*qids.find(qi);

  set<DNSRecord> canonicOrig, canonicNew;
  compactAnswerSet(qd.d_origAnswers, canonicOrig);
  compactAnswerSet(qd.d_newAnswers, canonicNew);
	
  if(!s_quiet) {
    cout<<qi<<", orig rcode: "<<qd.d_origRcode<<", ours: "<<qd.d_newRcode;  
    cout<<", "<<canonicOrig.size()<< " vs " << canonicNew.size()<<", perfect: ";
  }

  if(canonicOrig==canonicNew) {
    s_perfect++;
    if(!s_quiet)
      cout<<"yes\n";
  }
  else {
    if(!s_quiet)
      cout<<"no\n";
    
    if(qd.d_norecursionavailable)
      if(!s_quiet)
	cout<<"\t* original nameserver did not provide recursion for this question *"<<endl;
    if(qd.d_origRcode == qd.d_newRcode ) {
      if(!s_quiet)
	cout<<"\t* mostly correct *"<<endl;
      s_mostly++;
    }

    if(!isRcodeOk(qd.d_origRcode) && isRcodeOk(qd.d_newRcode)) {
      if(!s_quiet)
	cout<<"\t* we better *"<<endl;
      s_webetter++;
    }
    if(isRcodeOk(qd.d_origRcode) && !isRcodeOk(qd.d_newRcode)) {
      if(!s_quiet)
	cout<<"\t* orig better *"<<endl;
      s_origbetter++;
      s_origbetterset.insert(make_pair(qi.d_qname, qi.d_qtype));
    }

    if(!s_quiet) {
      cout<<"orig:\n";
      for(set<DNSRecord>::const_iterator i=canonicOrig.begin(); i!=canonicOrig.end(); ++i)
	cout<<"\t"<<i->d_label<<"\t"<<DNSRecordContent::NumberToType(i->d_type)<<"\t'"  << (i->d_content ? i->d_content->getZoneRepresentation() : "") <<"'\n";
      cout<<"new:\n";
      for(set<DNSRecord>::const_iterator i=canonicNew.begin(); i!=canonicNew.end(); ++i)
      cout<<"\t"<<i->d_label<<"\t"<<DNSRecordContent::NumberToType(i->d_type)<<"\t'"  << (i->d_content ? i->d_content->getZoneRepresentation() : "") <<"'\n";
      cout<<"\n";
    }
  }
  

  qids.erase(qi);
  s_idmanager.releaseID(qd.d_assignedID);
}


Socket *s_socket;

void receiveFromReference()
try
{
  string packet;
  IPEndpoint remote;

  int res=waitForData(s_socket->getHandle(), 0, 25000);
  if(res < 0 || res==0)
    return;

  while(s_socket->recvFromAsync(packet, remote)) {
    try {
      s_weanswers++;
      MOADNSParser mdp(packet.c_str(), packet.length());
      if(!mdp.d_header.qr) {
	cout<<"Received a question from our reference nameserver!"<<endl;
	continue;
      }

      typedef qids_t::index<AssignedIDTag>::type qids_by_id_index_t;
      qids_by_id_index_t& idindex=qids.get<AssignedIDTag>();
      qids_by_id_index_t::const_iterator found=idindex.find(ntohs(mdp.d_header.id));
      if(found == idindex.end()) {
	cout<<"Received an answer ("<<mdp.d_qname<<") from reference nameserver with id "<<mdp.d_header.id<<" which we can't match to a question!"<<endl;
	s_weunmatched++;
	continue;
      }
      QuestionIdentifier qi=found->d_qi;
      QuestionData qd=*found;
      
      qd.d_newAnswers=mdp.d_answers;
      qd.d_newRcode=mdp.d_header.rcode;
      idindex.replace(found, qd);
      if(qd.d_origRcode!=-1) {
	//      cout<<"Removing entry "<<i->first<<", is done [in socket]"<<endl;
	measureResultAndClean(qi);
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

void pruneQids()
{
  struct timeval now;
  gettimeofday(&now, 0);

  for(qids_t::iterator i=qids.begin(); i!=qids.end(); ) {
    if(DiffTime(i->d_resentTime, now) < 60)
      ++i;
    else {
      s_idmanager.releaseID(i->d_assignedID);
      if(i->d_newRcode==-1) {
       s_wenever++;
      }
      if(i->d_origRcode==-1) {
	s_orignever++;
      }

      qids.erase(i++);
    }
  }
}


void houseKeeping()
{
  static timeval last;

  struct timeval now;
  gettimeofday(&now, 0);

  if(DiffTime(last, now) < 0.3)
    return;

  int weWaitingFor, origWaitingFor, weSlow, origSlow;
  WeOrigSlowQueriesDelta(weWaitingFor, origWaitingFor, weSlow, origSlow);
    
  if(!g_throttled) {
    if( weWaitingFor > 1000) {
      cerr<<"Too many questions ("<<weWaitingFor<<") outstanding, throttling"<<endl;
      g_throttled=true;
    }
  }
  else if(weWaitingFor < 750) {
    cerr<<"Unthrottling ("<<weWaitingFor<<")"<<endl;
    g_throttled=false;
  }

  if(DiffTime(last, now) < 2)
    return;

  last=now;

  /*
        Questions - Pend. - Drop = Answers = (On time + Late) = (Err + Ok)
Orig    9           21      29     36         47        57       66    72


   */

  format headerfmt   ("%|9t|Questions - Pend. - Drop = Answers = (On time + Late) = (Err + Ok)\n");
  format datafmt("%s%|9t|%d %|21t|%d %|29t|%d %|36t|%d %|47t|%d %|57t|%d %|66t|%d %|72t|%d\n");

  
  cerr<<headerfmt;
  cerr<<(datafmt % "Orig"   % s_questions % origWaitingFor  % s_orignever  % s_origanswers % 0 % s_origtimedout  % 0 % 0);
  cerr<<(datafmt % "Refer." % s_questions % weWaitingFor    % s_wenever    % s_weanswers   % 0 % s_wetimedout    % 0 % 0);



  cerr<<weWaitingFor<<" queries that could still come in on time, "<<qids.size()<<" outstanding"<<endl;
  
  cerr<<"we late: "<<s_wetimedout<<", orig late: "<< s_origtimedout<<", "<<s_questions<<" questions sent, "<<s_origanswers
      <<" original answers, "<<s_perfect<<" perfect, "<<s_mostly<<" mostly correct"<<", "<<s_webetter<<" we better, "<<s_origbetter<<" orig better ("<<s_origbetterset.size()<<" diff)"<<endl;
  cerr<<"we never: "<<s_wenever<<", orig never: "<<s_orignever<<endl;
  cerr<<"original questions from IP addresses for which recursion was not available: "<<s_norecursionavailable<<endl;
  cerr<<"Unmatched from us: "<<s_weunmatched<<", unmatched from original: "<<s_origunmatched << " ( - decoding err: "<<s_origunmatched-s_origdnserrors<<")"<<endl;
  cerr<<"DNS decoding errors from us: "<<s_wednserrors<<", from original: "<<s_origdnserrors<<endl<<endl;

  pruneQids();

}

void sendPacketFromPR(PcapPacketReader& pr, const IPEndpoint& remote)
{
  static struct timeval lastsent;

  HEADER* dh=(HEADER*)pr.d_payload;
  //                                                             non-recursive  
  if((ntohs(pr.d_udp->uh_dport)!=53 && ntohs(pr.d_udp->uh_sport)!=53) || !dh->rd || (unsigned int)pr.d_len <= sizeof(HEADER))
    return;
  
  try {
    MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
    QuestionIdentifier qi=QuestionIdentifier::create(pr.d_ip, pr.d_udp, mdp);
    
    if(!mdp.d_header.qr) {
      s_questions++;
      if(qids.count(qi)) {
	if(!s_quiet)
	  cout<<"Saw an exact duplicate question, "<<qi<< endl;
	return;
      }
      
      // new question!

      QuestionData qd;
      qd.d_qi=qi;
      gettimeofday(&qd.d_resentTime,0);
      
      qd.d_assignedID = s_idmanager.getID();
      
      qids.insert(qd);

      dh->id=htons(qd.d_assignedID);

#if 0
      if(lastsent.tv_sec && (!(s_questions%25))) {
	double seconds=pr.d_pheader.ts.tv_sec - lastsent.tv_sec;
	double useconds=(pr.d_pheader.ts.tv_usec - lastsent.tv_usec);
	
	if(useconds < 0) {
	  seconds-=1;
	  useconds+=1000000;
	}
	
	double factor=10;
	
	seconds/=factor;
	useconds/=factor;
	
	long long nanoseconds=(long long)(1000000000ULL*seconds + useconds * 1000);
	
	struct timespec tosleep;
	tosleep.tv_sec=nanoseconds/1000000000UL;
	tosleep.tv_nsec=nanoseconds%1000000000UL;
	
	nanosleep(&tosleep, 0);
	lastsent=pr.d_pheader.ts;
      }
      if(!lastsent.tv_sec)
	lastsent=pr.d_pheader.ts;
      
      //	cout<<"sending!"<<endl;
#endif
      s_socket->sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
    }
    else {
      s_origanswers++;
      
      if(qids.count(qi)) {
	qids_t::const_iterator i=qids.find(qi);
	QuestionData qd=*i;

	//	  cout<<"Matched answer "<<qi<<endl;
	qd.d_origAnswers=mdp.d_answers;
	qd.d_origRcode=mdp.d_header.rcode;
	
	if(!dh->ra) {
	  s_norecursionavailable++;
	  qd.d_norecursionavailable=true;
	}
	qids.replace(i,qd);

	if(qd.d_newRcode!=-1) {
	  //	    cout<<"Removing entry "<<qi<<", is done [in main loop]"<<endl;

	  measureResultAndClean(qi);
	}
	
	return;
      }
      else {
	s_origunmatched++;
	if(!s_quiet)
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

int main(int argc, char** argv)
try
{
  if(argc < 2 || argc > 4) {
    cerr<<"dnsreplay - replay DNS traffic to a reference server to compare performance"<<endl;
    cerr<<"Syntax: dnsreplay pcapfile [target IP] [target port]\nDefaults to 127.0.0.1 and 5300"<<endl;
    return EXIT_FAILURE;
  }
  
  PcapPacketReader pr(argv[1]);
  s_socket= new Socket(InterNetwork, Datagram);

  s_socket->setNonBlocking();
  
  IPEndpoint remote(argc > 2 ? argv[2] : "127.0.0.1", 
		    argc > 3 ? atoi(argv[3]) : 5300);


  unsigned int once=0;
  struct timeval mental_time;
  mental_time.tv_sec=0; mental_time.tv_usec=0;

  if(!pr.getUDPPacket())
    return 0;

  for(;;) {

    if(!((once++)%100)) 
      houseKeeping();

    int count=0;
    while(pr.d_pheader.ts < mental_time) {
      if(!pr.getUDPPacket())
	goto out;
      
      sendPacketFromPR(pr, remote);
      count++;
    } 

    //    cout<<count<<"\n";

    mental_time=pr.d_pheader.ts;
    struct timeval then, now;
    gettimeofday(&then,0);

    receiveFromReference();

    gettimeofday(&now, 0);

    mental_time= mental_time + 1*(now-then);
  }
 out:;
}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
