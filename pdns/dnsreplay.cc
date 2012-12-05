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
#include <boost/program_options.hpp>
#include "dnsrecords.hh"

// this is needed because boost multi_index also uses 'L', as do we (which is sad enough)
#undef L

#include <set>
#include <deque>

#include <boost/format.hpp>
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include "namespaces.hh"
using namespace ::boost::multi_index;
#include "namespaces.hh"

StatBag S;
bool g_quiet=true;
int g_timeoutMsec=0; 

namespace po = boost::program_options;

po::variables_map g_vm;

const struct timeval operator*(float fact, const struct timeval& rhs)
{
  //  cout<<"In: "<<rhs.tv_sec<<" + "<<rhs.tv_usec<<"\n";
  struct timeval ret;
  if( (2000000000 / fact) < rhs.tv_usec) {
    double d=1.0 * rhs.tv_usec * fact;
    ret.tv_sec=fact * rhs.tv_sec;
    ret.tv_sec+=(int) (d/1000000);
    d/=1000000;
    d-=(int)d;

    ret.tv_usec=(unsigned int)(1000000*d);
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




class DNSIDManager : public boost::noncopyable
{
public:
  DNSIDManager()
  {
    for(unsigned int i=0; i < 65536; ++i)
      d_available.push_back(i);

  }

  uint16_t peakID()
  {
    uint16_t ret;
    if(!d_available.empty()) {
      ret=d_available.front();
      return ret;
    }
    else
      throw runtime_error("out of ids!"); // XXX FIXME
  }

  uint16_t getID()
  {
    uint16_t ret=peakID();
    d_available.pop_front();
    return ret;
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
unsigned int s_wednserrors, s_origdnserrors, s_duplicates;


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

bool isRootReferral(const MOADNSParser::answers_t& answers)
{
  if(answers.empty())
    return false;

  bool ok=true;
  for(MOADNSParser::answers_t::const_iterator iter = answers.begin(); iter != answers.end(); ++iter) {
    //    cerr<<(int)iter->first.d_place<<", "<<iter->first.d_label<<" "<<iter->first.d_type<<", # "<<answers.size()<<endl;
    if(iter->first.d_place!=2)
      ok=false;
    if(iter->first.d_label!="." || iter->first.d_type!=QType::NS)
      ok=false;
  }
  return ok;
}

void measureResultAndClean(const QuestionIdentifier& qi)
{
  QuestionData qd=*qids.find(qi);

  set<DNSRecord> canonicOrig, canonicNew;
  compactAnswerSet(qd.d_origAnswers, canonicOrig);
  compactAnswerSet(qd.d_newAnswers, canonicNew);
        
  if(!g_quiet) {
    cout<<qi<<", orig rcode: "<<qd.d_origRcode<<", ours: "<<qd.d_newRcode;  
    cout<<", "<<canonicOrig.size()<< " vs " << canonicNew.size()<<", perfect: ";
  }

  if(canonicOrig==canonicNew) {
    s_perfect++;
    if(!g_quiet)
      cout<<"yes\n";
  }
  else {
    if(!g_quiet)
      cout<<"no\n";
    
    if(qd.d_norecursionavailable)
      if(!g_quiet)
        cout<<"\t* original nameserver did not provide recursion for this question *"<<endl;
    if(qd.d_origRcode == qd.d_newRcode ) {
      if(!g_quiet)
        cout<<"\t* mostly correct *"<<endl;
      s_mostly++;
    }

    if(!isRcodeOk(qd.d_origRcode) && isRcodeOk(qd.d_newRcode)) {
      if(!g_quiet)
        cout<<"\t* we better *"<<endl;
      s_webetter++;
    }
    if(isRcodeOk(qd.d_origRcode) && !isRcodeOk(qd.d_newRcode) && !isRootReferral(qd.d_origAnswers)) {
      if(!g_quiet)
        cout<<"\t* orig better *"<<endl;
      s_origbetter++;
      if(!g_quiet) 
        if(s_origbetterset.insert(make_pair(qi.d_qname, qi.d_qtype)).second) {
          cout<<"orig better: " << qi.d_qname<<" "<< qi.d_qtype<<endl;
        }
    }

    if(!g_quiet) {
      cout<<"orig: rcode="<<qd.d_origRcode<<"\n";
      for(set<DNSRecord>::const_iterator i=canonicOrig.begin(); i!=canonicOrig.end(); ++i)
        cout<<"\t"<<i->d_label<<"\t"<<DNSRecordContent::NumberToType(i->d_type)<<"\t'"  << (i->d_content ? i->d_content->getZoneRepresentation() : "") <<"'\n";
      cout<<"new: rcode="<<qd.d_newRcode<<"\n";
      for(set<DNSRecord>::const_iterator i=canonicNew.begin(); i!=canonicNew.end(); ++i)
        cout<<"\t"<<i->d_label<<"\t"<<DNSRecordContent::NumberToType(i->d_type)<<"\t'"  << (i->d_content ? i->d_content->getZoneRepresentation() : "") <<"'\n";
      cout<<"\n";
      cout<<"-\n";

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
  ComboAddress remote;
  int res=waitForData(s_socket->getHandle(), g_timeoutMsec/1000, 1000*(g_timeoutMsec%1000));
  
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
//        cout<<"Received an answer ("<<mdp.d_qname<<") from reference nameserver with id "<<mdp.d_header.id<<" which we can't match to a question!"<<endl;
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
    catch(std::out_of_range &e)
    {
      s_wednserrors++;
    }
  }

}
catch(std::exception& e)
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
    if(DiffTime(i->d_resentTime, now) < 10)
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


void printStats(uint64_t origWaitingFor=0, uint64_t weWaitingFor=0)
{

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
  cerr<<"DNS decoding errors from us: "<<s_wednserrors<<", from original: "<<s_origdnserrors<<", exact duplicates from client: "<<s_duplicates<<endl<<endl;

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

  printStats(origWaitingFor, weWaitingFor);

  pruneQids();

}


bool g_rdSelector;

bool sendPacketFromPR(PcapPacketReader& pr, const ComboAddress& remote)
{
  dnsheader* dh=(dnsheader*)pr.d_payload;
  bool sent=false;
  if((ntohs(pr.d_udp->uh_dport)!=53 && ntohs(pr.d_udp->uh_sport)!=53) || dh->rd != g_rdSelector || (unsigned int)pr.d_len <= sizeof(dnsheader))
    return sent;

  QuestionData qd;
  try {
    if(!dh->qr) {
      qd.d_assignedID = s_idmanager.peakID();
      uint16_t tmp=dh->id;
      dh->id=htons(qd.d_assignedID);
      s_socket->sendTo(string(pr.d_payload, pr.d_payload + pr.d_len), remote);
      sent=true;
      dh->id=tmp;
    }
    MOADNSParser mdp((const char*)pr.d_payload, pr.d_len);
    QuestionIdentifier qi=QuestionIdentifier::create(pr.d_ip, pr.d_udp, mdp);
    
    if(!mdp.d_header.qr) {
      s_questions++;
      if(qids.count(qi)) {
        if(!g_quiet)
          cout<<"Saw an exact duplicate question, "<<qi<< endl;
        s_duplicates++;
        return sent;
      }
      // new question!
      qd.d_qi=qi;
      gettimeofday(&qd.d_resentTime,0);
      qd.d_assignedID = s_idmanager.getID();
      qids.insert(qd);
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
        qids.replace(i, qd);

        if(qd.d_newRcode!=-1) {
          //	    cout<<"Removing entry "<<qi<<", is done [in main loop]"<<endl;

          measureResultAndClean(qi);
        }
        
        return sent;
      }
      else {
        s_origunmatched++;
        if(!g_quiet)
          cout<<"Unmatched original answer "<<qi<<endl;
      }
    }
  }
  catch(MOADNSException &e)
  {
    s_origdnserrors++;
  }
  catch(std::out_of_range &e)
  {
    s_origdnserrors++;
  }
  return sent;
}

int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("packet-limit", po::value<uint32_t>()->default_value(0), "stop after this many packets")
    ("quiet", po::value<bool>()->default_value(true), "don't be too noisy")
    ("recursive", po::value<bool>()->default_value(true), "look at recursion desired packets, or not (defaults true)")
    ("speedup", po::value<float>()->default_value(1), "replay at this speedup")
    ("timeout-msec", po::value<uint32_t>()->default_value(500), "wait at least this many milliseconds for a reply");

  po::options_description alloptions;
  po::options_description hidden("hidden options");
  hidden.add_options()
    ("pcap-source", po::value<string>(), "PCAP source file")
    ("target-ip", po::value<string>()->default_value("127.0.0.1"), "target-ip")
    ("target-port", po::value<uint16_t>()->default_value(5300), "target port");

  alloptions.add(desc).add(hidden);
  po::positional_options_description p;
  p.add("pcap-source", 1);
  p.add("target-ip", 1);
  p.add("target-port", 1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);

  reportAllTypes();

  if (g_vm.count("help")) {
    cerr << "Usage: dnsreplay [--options] filename [ip-address] [port]"<<endl;
    cerr << desc << "\n";
    return EXIT_SUCCESS;
  }
  
  if(!g_vm.count("pcap-source")) {
    cerr<<"Fatal, need to specify at least a PCAP source file"<<endl;
    cerr << "Usage: dnsreplay [--options] filename [ip-address] [port]"<<endl;
    cerr << desc << "\n";
    return EXIT_FAILURE;
  }

  uint32_t packetLimit = g_vm["packet-limit"].as<uint32_t>();

  g_rdSelector = g_vm["recursive"].as<bool>();

  g_quiet = g_vm["quiet"].as<bool>();

  float speedup=g_vm["speedup"].as<float>();
  g_timeoutMsec=g_vm["timeout-msec"].as<uint32_t>();

  PcapPacketReader pr(g_vm["pcap-source"].as<string>());
  s_socket= new Socket(InterNetwork, Datagram);

  s_socket->setNonBlocking();
  
  ComboAddress remote(g_vm["target-ip"].as<string>(), 
        	    g_vm["target-port"].as<uint16_t>());

  cerr<<"Replaying packets to: '"<<g_vm["target-ip"].as<string>()<<"', port "<<g_vm["target-port"].as<uint16_t>()<<endl;

  unsigned int once=0;
  struct timeval mental_time;
  mental_time.tv_sec=0; mental_time.tv_usec=0;

  if(!pr.getUDPPacket()) // we do this here so we error out more cleanly on no packets
    return 0;
  unsigned int count=0;

  for(;;) {
    if(!((once++)%100)) 
      houseKeeping();
    
    struct timeval packet_ts;
    packet_ts.tv_sec = 0; 
    packet_ts.tv_usec = 0; 
    bool first = true;
    while(packet_ts < mental_time) {
      if(!first && !pr.getUDPPacket()) // otherwise we miss the first packet
        goto out;
      first=false;
      packet_ts.tv_sec = pr.d_pheader.ts.tv_sec;
      packet_ts.tv_usec = pr.d_pheader.ts.tv_usec;

      if(sendPacketFromPR(pr, remote))
        count++;
    } 
    if(packetLimit && count > packetLimit) 
      break;

    mental_time=packet_ts;
    struct timeval then, now;
    gettimeofday(&then,0);

    receiveFromReference();

    gettimeofday(&now, 0);

    mental_time= mental_time + speedup * (now-then);
  }
 out:;
  sleep(1);
  receiveFromReference();
  printStats();
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

