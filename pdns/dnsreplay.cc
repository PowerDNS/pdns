/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/**
Replay all recursion-desired DNS questions to a specified IP address.

Track all outgoing questions, remap id to one of ours.
Also track all recorded answers, and map them to that same id, the 'expectation'.

When we see a question, parse it, give it a QuestionIdentifier, and and an id from the free-id list.

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <bitset>
#include "statbag.hh"
#include "dnspcap.hh"
#include "sstuff.hh"
#include "anadns.hh"
#include <boost/program_options.hpp>
#include "dnsrecords.hh"
#include "ednssubnet.hh"
#include "ednsoptions.hh"

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

bool g_pleaseQuit;
void pleaseQuitHandler(int)
{
  g_pleaseQuit=true;
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


void setSocketBuffer(int fd, int optname, uint32_t size)
{
  uint32_t psize=0;
  socklen_t len=sizeof(psize);
  
  if(!getsockopt(fd, SOL_SOCKET, optname, (char*)&psize, &len) && psize > size) {
    cerr<<"Not decreasing socket buffer size from "<<psize<<" to "<<size<<endl;
    return; 
  }

  if (setsockopt(fd, SOL_SOCKET, optname, (char*)&size, sizeof(size)) < 0 )
    cerr<<"Warning: unable to raise socket buffer size to "<<size<<": "<<stringerror()<<endl;
}

static void setSocketReceiveBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_RCVBUF, size);
}

static void setSocketSendBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_SNDBUF, size);
}


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
    if(i->first.d_place==DNSResourceRecord::ANSWER)
      compacted.insert(i->first);
}

bool isRcodeOk(int rcode)
{
  return rcode==0 || rcode==3;
}

set<pair<DNSName,uint16_t> > s_origbetterset;

bool isRootReferral(const MOADNSParser::answers_t& answers)
{
  if(answers.empty())
    return false;

  bool ok=true;
  for(MOADNSParser::answers_t::const_iterator iter = answers.begin(); iter != answers.end(); ++iter) {
    //    cerr<<(int)iter->first.d_place<<", "<<iter->first.d_name<<" "<<iter->first.d_type<<", # "<<answers.size()<<endl;
    if(iter->first.d_place!=2)
      ok=false;
    if(!iter->first.d_name.isRoot() || iter->first.d_type!=QType::NS)
      ok=false;
  }
  return ok;
}

vector<uint32_t> flightTimes;
void accountFlightTime(qids_t::const_iterator iter)
{
  if(flightTimes.empty())
    flightTimes.resize(2050); 

  struct timeval now;
  gettimeofday(&now, 0);
  unsigned int mdiff = 1000*DiffTime(iter->d_resentTime, now);
  if(mdiff > flightTimes.size()-2)
    mdiff= flightTimes.size()-1;

  flightTimes[mdiff]++;
}

uint64_t countLessThan(unsigned int msec)
{
  uint64_t ret=0;
  for(unsigned int i = 0 ; i < msec && i < flightTimes.size() ; ++i) {
    ret += flightTimes[i];
  }
  return ret;
}

void emitFlightTimes()
{
  uint64_t totals = countLessThan(flightTimes.size());
  unsigned int limits[]={1, 2, 3, 4, 5, 10, 20, 30, 40, 50, 100, 200, 500, 1000, (unsigned int) flightTimes.size()};
  uint64_t sofar=0;
  cout.setf(std::ios::fixed);
  cout.precision(2);
  for(unsigned int i =0 ; i < sizeof(limits)/sizeof(limits[0]); ++i) {
    if(limits[i]!=flightTimes.size())
      cout<<"Within "<<limits[i]<<" msec: ";
    else 
      cout<<"Beyond "<<limits[i]-2<<" msec: ";
    uint64_t here = countLessThan(limits[i]);
    cout<<100.0*here/totals<<"% ("<<100.0*(here-sofar)/totals<<"%)"<<endl;
    sofar=here;
    
  }
}

void measureResultAndClean(qids_t::const_iterator iter)
{
  const QuestionData& qd=*iter;
  accountFlightTime(iter);

  set<DNSRecord> canonicOrig, canonicNew;
  compactAnswerSet(qd.d_origAnswers, canonicOrig);
  compactAnswerSet(qd.d_newAnswers, canonicNew);
        
  if(!g_quiet) {
    cout<<qd.d_qi<<", orig rcode: "<<qd.d_origRcode<<", ours: "<<qd.d_newRcode;  
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
        if(s_origbetterset.insert(make_pair(qd.d_qi.d_qname, qd.d_qi.d_qtype)).second) {
          cout<<"orig better: " << qd.d_qi.d_qname<<" "<< qd.d_qi.d_qtype<<endl;
        }
    }

    if(!g_quiet) {
      cout<<"orig: rcode="<<qd.d_origRcode<<"\n";
      for(set<DNSRecord>::const_iterator i=canonicOrig.begin(); i!=canonicOrig.end(); ++i)
        cout<<"\t"<<i->d_name<<"\t"<<DNSRecordContent::NumberToType(i->d_type)<<"\t'"  << (i->d_content ? i->d_content->getZoneRepresentation() : "") <<"'\n";
      cout<<"new: rcode="<<qd.d_newRcode<<"\n";
      for(set<DNSRecord>::const_iterator i=canonicNew.begin(); i!=canonicNew.end(); ++i)
        cout<<"\t"<<i->d_name<<"\t"<<DNSRecordContent::NumberToType(i->d_type)<<"\t'"  << (i->d_content ? i->d_content->getZoneRepresentation() : "") <<"'\n";
      cout<<"\n";
      cout<<"-\n";

    }
  }
  
  int releaseID=qd.d_assignedID;
  qids.erase(iter); // qd invalid now
  s_idmanager.releaseID(releaseID);
}


std::unique_ptr<Socket> s_socket = nullptr;

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
      MOADNSParser mdp(false, packet.c_str(), packet.length());
      if(!mdp.d_header.qr) {
        cout<<"Received a question from our reference nameserver!"<<endl;
        continue;
      }

      typedef qids_t::index<AssignedIDTag>::type qids_by_id_index_t;
      qids_by_id_index_t& idindex=qids.get<AssignedIDTag>();
      qids_by_id_index_t::const_iterator found=idindex.find(ntohs(mdp.d_header.id));
      if(found == idindex.end()) {
        if(!g_quiet)      
          cout<<"Received an answer ("<<mdp.d_qname<<") from reference nameserver with id "<<mdp.d_header.id<<" which we can't match to a question!"<<endl;
        s_weunmatched++;
        continue;
      }

      QuestionData qd=*found;    // we have to make a copy because we reinsert below      
      qd.d_newAnswers=mdp.d_answers;
      qd.d_newRcode=mdp.d_header.rcode;
      idindex.replace(found, qd);
      if(qd.d_origRcode!=-1) {
	qids_t::const_iterator iter= qids.project<0>(found);
	measureResultAndClean(iter);
      }
    }
    catch(const MOADNSException &mde)
    {
      s_wednserrors++;
    }
    catch(std::out_of_range &e)
    {
      s_wednserrors++;
    }
    catch(std::exception& e) 
    {
      s_wednserrors++;
    }
  }
}
catch(std::exception& e)
{
  cerr<<"Receiver function died: "<<e.what()<<endl;
  exit(1);
}
catch(...)
{
  cerr<<"Receiver function died with unknown exception"<<endl;
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

static void generateOptRR(const std::string& optRData, string& res)
{
  const uint8_t name = 0;
  dnsrecordheader dh;
  EDNS0Record edns0;
  edns0.extRCode = 0;
  edns0.version = 0;
  edns0.extFlags = 0;
  
  dh.d_type = htons(QType::OPT);
  dh.d_class = htons(1280);
  memcpy(&dh.d_ttl, &edns0, sizeof edns0);
  dh.d_clen = htons((uint16_t) optRData.length());
  res.assign((const char *) &name, sizeof name);
  res.append((const char *) &dh, sizeof dh);
  res.append(optRData.c_str(), optRData.length());
}

static void addECSOption(char* packet, const size_t packetSize, uint16_t* len, const ComboAddress& remote, int stamp)
{
  string EDNSRR;
  struct dnsheader* dh = (struct dnsheader*) packet;

  EDNSSubnetOpts eso;
  if(stamp < 0)
    eso.source = Netmask(remote);
  else {
    ComboAddress stamped(remote);
    *((char*)&stamped.sin4.sin_addr.s_addr)=stamp;
    eso.source = Netmask(stamped);
  }
  string optRData=makeEDNSSubnetOptsString(eso);
  string record;
  generateEDNSOption(EDNSOptionCode::ECS, optRData, record);
  generateOptRR(record, EDNSRR);


  uint16_t arcount = ntohs(dh->arcount);
  /* does it fit in the existing buffer? */
  if (packetSize > *len && (packetSize - *len) > EDNSRR.size()) {
    arcount++;
    dh->arcount = htons(arcount);
    memcpy(packet + *len, EDNSRR.c_str(), EDNSRR.size());
    *len += EDNSRR.size();
  }
}

static bool g_rdSelector;
static uint16_t g_pcapDnsPort;

static bool sendPacketFromPR(PcapPacketReader& pr, const ComboAddress& remote, int stamp)
{
  bool sent=false;
  if (pr.d_len <= sizeof(dnsheader)) {
    return sent;
  }
  if (pr.d_len > std::numeric_limits<uint16_t>::max()) {
    /* too large for an DNS UDP query, something is not right */
    return false;
  }
  dnsheader* dh=const_cast<dnsheader*>(reinterpret_cast<const dnsheader*>(pr.d_payload));
  if((ntohs(pr.d_udp->uh_dport)!=g_pcapDnsPort && ntohs(pr.d_udp->uh_sport)!=g_pcapDnsPort) || dh->rd != g_rdSelector)
    return sent;

  QuestionData qd;
  try {
    // yes, we send out ALWAYS. Even if we don't do anything with it later, 
    if(!dh->qr) { // this is to stress out the reference server with all the pain
      s_questions++;
      qd.d_assignedID = s_idmanager.getID();
      uint16_t tmp=dh->id;
      dh->id=htons(qd.d_assignedID);
      //      dh->rd=1; // useful to replay traffic to auths to a recursor
      uint16_t dlen = pr.d_len;

      if (stamp >= 0) {
        static_assert(sizeof(pr.d_buffer) >= 1500, "The size of the underlying buffer should be at least 1500 bytes");
        if (dlen > 1500) {
          /* the existing packet is larger than the maximum size we are willing to send, and it won't get better by adding ECS */
          return false;
        }
        addECSOption((char*)pr.d_payload, 1500, &dlen, pr.getSource(), stamp);
        pr.d_len=dlen;
      }

      s_socket->sendTo((const char*)pr.d_payload, dlen, remote);
      sent=true;
      dh->id=tmp;
    }
    MOADNSParser mdp(false, (const char*)pr.d_payload, pr.d_len);
    QuestionIdentifier qi=QuestionIdentifier::create(pr.getSource(), pr.getDest(), mdp);

    if(!mdp.d_header.qr) {

      if(qids.count(qi)) {
        if(!g_quiet)
          cout<<"Saw an exact duplicate question in PCAP "<<qi<< endl;
        s_duplicates++;
	s_idmanager.releaseID(qd.d_assignedID); // release = puts at back of pool
        return sent;
      }
      // new question - ID assigned above already
      qd.d_qi=qi;
      gettimeofday(&qd.d_resentTime,0);
      qids.insert(qd);
    }
    else {
      s_origanswers++;
      qids_t::const_iterator iter=qids.find(qi);      
      if(iter != qids.end()) {
        QuestionData eqd=*iter;
        eqd.d_origAnswers=mdp.d_answers;
        eqd.d_origRcode=mdp.d_header.rcode;
        
        if(!dh->ra) {
          s_norecursionavailable++;
          eqd.d_norecursionavailable=true;
        }
        qids.replace(iter, eqd);

        if(eqd.d_newRcode!=-1) {
          measureResultAndClean(iter);
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
  catch(const MOADNSException &mde)
  {
    if(!g_quiet)
      cerr<<"Error parsing packet: "<<mde.what()<<endl;
    s_idmanager.releaseID(qd.d_assignedID);  // not added to qids for cleanup
    s_origdnserrors++;
  }
  catch(std::exception &e)
  {
    if(!g_quiet)
      cerr<<"Error parsing packet: "<<e.what()<<endl;

    s_idmanager.releaseID(qd.d_assignedID);  // not added to qids for cleanup
    s_origdnserrors++;    
  }

  return sent;
}

void usage(po::options_description &desc) {
  cerr << "Usage: dnsreplay [OPTIONS] FILENAME [IP-ADDRESS] [PORT]"<<endl;
  cerr << desc << "\n";
}

int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("version", "show version number")
    ("packet-limit", po::value<uint32_t>()->default_value(0), "stop after this many packets")
    ("pcap-dns-port", po::value<uint16_t>()->default_value(53), "look at packets from or to this port in the PCAP (defaults to 53)")
    ("quiet", po::value<bool>()->default_value(true), "don't be too noisy")
    ("recursive", po::value<bool>()->default_value(true), "look at recursion desired packets, or not (defaults true)")
    ("speedup", po::value<float>()->default_value(1), "replay at this speedup")
    ("timeout-msec", po::value<uint32_t>()->default_value(500), "wait at least this many milliseconds for a reply")
    ("ecs-stamp", "Add original IP address to ECS in replay")
    ("ecs-mask", po::value<uint16_t>(), "Replace first octet of src IP address with this value in ECS")
    ("source-ip", po::value<string>()->default_value(""), "IP to send the replayed packet from")
    ("source-port", po::value<uint16_t>()->default_value(0), "Port to send the replayed packet from");

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
    usage(desc);
    return EXIT_SUCCESS;
  }

  if (g_vm.count("version")) {
    cerr<<"dnsreplay "<<VERSION<<endl;
    return EXIT_SUCCESS;
  }

  if(!g_vm.count("pcap-source")) {
    cerr<<"Fatal, need to specify at least a PCAP source file"<<endl;
    usage(desc);
    return EXIT_FAILURE;
  }

  uint32_t packetLimit = g_vm["packet-limit"].as<uint32_t>();

  g_rdSelector = g_vm["recursive"].as<bool>();
  g_pcapDnsPort = g_vm["pcap-dns-port"].as<uint16_t>();

  g_quiet = g_vm["quiet"].as<bool>();

  signal(SIGINT, pleaseQuitHandler);
  float speedup=g_vm["speedup"].as<float>();
  g_timeoutMsec=g_vm["timeout-msec"].as<uint32_t>();

  PcapPacketReader pr(g_vm["pcap-source"].as<string>());
  s_socket= make_unique<Socket>(AF_INET, SOCK_DGRAM);

  s_socket->setNonBlocking();

  if(g_vm.count("source-ip") && !g_vm["source-ip"].as<string>().empty())
    s_socket->bind(ComboAddress(g_vm["source-ip"].as<string>(), g_vm["source-port"].as<uint16_t>()));

  setSocketReceiveBuffer(s_socket->getHandle(), 2000000);
  setSocketSendBuffer(s_socket->getHandle(), 2000000);

  ComboAddress remote(g_vm["target-ip"].as<string>(), 
                    g_vm["target-port"].as<uint16_t>());

 int stamp = -1;
 if(g_vm.count("ecs-stamp") && g_vm.count("ecs-mask"))
   stamp=g_vm["ecs-mask"].as<uint16_t>();

  cerr<<"Replaying packets to: '"<<g_vm["target-ip"].as<string>()<<"', port "<<g_vm["target-port"].as<uint16_t>()<<endl;

  unsigned int once=0;
  struct timeval mental_time;
  mental_time.tv_sec=0; mental_time.tv_usec=0;

  if(!pr.getUDPPacket()) // we do this here so we error out more cleanly on no packets
    return 0;
  unsigned int count=0;
  bool first = true;
  for(;;) {
    if(g_pleaseQuit) {
      cerr<<"Interrupted from terminal"<<endl;
      break;
    }
    if(!((once++)%100)) 
      houseKeeping();
    
    struct timeval packet_ts;
    packet_ts.tv_sec = 0; 
    packet_ts.tv_usec = 0; 

    while(packet_ts < mental_time) {
      if(!first && !pr.getUDPPacket()) // otherwise we miss the first packet
        goto out;
      first=false;

      packet_ts.tv_sec = pr.d_pheader.ts.tv_sec;
      packet_ts.tv_usec = pr.d_pheader.ts.tv_usec;

      if(sendPacketFromPR(pr, remote, stamp))
        count++;
    } 
    if(packetLimit && count >= packetLimit) 
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
  emitFlightTimes();
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

