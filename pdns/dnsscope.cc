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
#define __FAVOR_BSD
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#if HAVE_BOOST_GE_148
#include "histog.hh"
#endif

#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsparser.hh"
#include "dnsname.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"
#include <boost/program_options.hpp>
#include <unordered_set>
#include <boost/logic/tribool.hpp>
#include "arguments.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"
#include "statnode.hh"

namespace po = boost::program_options;
po::variables_map g_vm;

ArgvMap& arg()
{	
  static ArgvMap theArg;
  return theArg;
}
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

unsigned int liveQuestions()
{
  unsigned int ret=0;
  for(statmap_t::value_type& val :  statmap) {
    if(!val.second.d_answercount)
      ret++;
    //    if(val.second.d_qcount > val.second.d_answercount)
    //      ret+= val.second.d_qcount - val.second.d_answercount;
  }
  return ret;
}

struct LiveCounts
{
  unsigned int questions;
  unsigned int answers;
  unsigned int outstanding;

  LiveCounts()
  {
    questions=answers=outstanding=0;
  }

  LiveCounts operator-(const LiveCounts& rhs)
  {
    LiveCounts ret;
    ret.questions = questions - rhs.questions;
    ret.answers = answers - rhs.answers;
    ret.outstanding = outstanding;
    return ret;
  }
};

void visitor(const StatNode* node, const StatNode::Stat& selfstat, const StatNode::Stat& childstat)
{
  // 20% servfails, >100 children, on average less than 2 copies of a query
  // >100 different subqueries
  double dups=1.0*childstat.queries/node->children.size();
  if(dups > 2.0)
    return;
  if(1.0*childstat.servfails / childstat.queries > 0.2 && node->children.size()>100) {
    cout<<node->fullname<<", servfails: "<<childstat.servfails<<", nxdomains: "<<childstat.nxdomains<<", remotes: "<<childstat.remotes.size()<<", children: "<<node->children.size()<<", childstat.queries: "<<childstat.queries;
    cout<<", dups2: "<<dups<<endl;
    for(const StatNode::Stat::remotes_t::value_type& rem :  childstat.remotes) {
      cout<<"source: "<<node->fullname<<"\t"<<rem.first.toString()<<"\t"<<rem.second<<endl;
    }
  }
}

const struct timeval operator-(const struct pdns_timeval& lhs, const struct pdns_timeval& rhs)
{
  struct timeval a{lhs.tv_sec, static_cast<suseconds_t>(lhs.tv_usec)}, b{rhs.tv_sec, static_cast<suseconds_t>(rhs.tv_usec)};
  return operator-(a,b);
}


int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("version", "print version number")
    ("rd", po::value<bool>(), "If set to true, only process RD packets, to false only non-RD, unset: both")
    ("ipv4", po::value<bool>()->default_value(true), "Process IPv4 packets")
    ("ipv6", po::value<bool>()->default_value(true), "Process IPv6 packets")
#if HAVE_BOOST_GE_148
    ("log-histogram", "Write a log-histogram to file 'log-histogram'")
    ("full-histogram", po::value<double>(), "Write a log-histogram to file 'full-histogram' with this millisecond bin size")
#endif
    ("filter-name,f", po::value<string>(), "Do statistics only for queries within this domain")
    ("load-stats,l", po::value<string>()->default_value(""), "if set, emit per-second load statistics (questions, answers, outstanding)")
    ("no-servfail-stats", "Don't include servfails in response time stats")
    ("servfail-tree", "Figure out subtrees that generate servfails")
    ("stats-dir", po::value<string>()->default_value("."), "Directory where statistics will be saved")
    ("write-failures,w", po::value<string>()->default_value(""), "if set, write weird packets to this PCAP file")
    ("verbose,v", "be verbose");
    
  hidden.add_options()
    ("files", po::value<vector<string> >(), "files");

  alloptions.add(desc).add(hidden); 

  po::positional_options_description p;
  p.add("files", -1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);
 
  vector<string> files;
  if(g_vm.count("files")) 
    files = g_vm["files"].as<vector<string> >(); 

  if(g_vm.count("version")) {
    cerr<<"dnsscope "<<VERSION<<endl;
    exit(0);
  }

  if(files.empty() || g_vm.count("help")) {
    cerr<<"Syntax: dnsscope filename.pcap [filenam2.pcap...]"<<endl;
    cout << desc << endl;
    exit(0);
  }

  DNSName filtername;
  if(g_vm.count("filter-name"))
    filtername = DNSName(g_vm["filter-name"].as<string>());
  uint32_t nameMismatch = 0;

  StatNode root;

  bool verbose = g_vm.count("verbose");

  bool haveRDFilter=0, rdFilter=0;
  if(g_vm.count("rd")) {
    rdFilter = g_vm["rd"].as<bool>();
    haveRDFilter=1;
    cout<<"Filtering on recursion desired="<<rdFilter<<endl;
  }
  else
    cout<<"Warning, looking at both RD and non-RD traffic!"<<endl;

  bool doIPv4 = g_vm["ipv4"].as<bool>();
  bool doIPv6 = g_vm["ipv6"].as<bool>();
  bool doServFailTree = g_vm.count("servfail-tree");
  bool noservfailstats = g_vm.count("no-servfail-stats");
  int dnserrors=0, parsefail=0;
  typedef map<uint32_t,uint32_t> cumul_t;
  cumul_t cumul;
  unsigned int untracked=0, errorresult=0, nonRDQueries=0, queries=0;
  unsigned int ipv4DNSPackets=0, ipv6DNSPackets=0, fragmented=0, rdNonRAAnswers=0;
  unsigned int answers=0, nonDNSIP=0, rdFilterMismatch=0;
  unsigned int dnssecOK=0, edns=0;
  unsigned int dnssecCD=0, dnssecAD=0;
  unsigned int reuses=0;
  typedef map<uint16_t,uint32_t> rcodes_t;
  rcodes_t rcodes;
  
  time_t lowestTime=2000000000, highestTime=0;
  time_t lastsec=0;
  LiveCounts lastcounts;
  std::unordered_set<ComboAddress, ComboAddress::addressOnlyHash> requestors, recipients, rdnonra;
  typedef vector<pair<time_t, LiveCounts> > pcounts_t;
  pcounts_t pcounts;
  OPTRecordContent::report();

  for(unsigned int fno=0; fno < files.size(); ++fno) {
    PcapPacketReader pr(files[fno]);
    std::unique_ptr<PcapPacketWriter> pw=nullptr;
    if(!g_vm["write-failures"].as<string>().empty())
      pw=std::unique_ptr<PcapPacketWriter>(new PcapPacketWriter(g_vm["write-failures"].as<string>(), pr));
 
    EDNSOpts edo;
    while(pr.getUDPPacket()) {

      if((ntohs(pr.d_udp->uh_dport)==5300 || ntohs(pr.d_udp->uh_sport)==5300 ||
	  ntohs(pr.d_udp->uh_dport)==53   || ntohs(pr.d_udp->uh_sport)==53) &&
	 pr.d_len > 12) {
	try {
	  if((pr.d_ip->ip_v == 4 && !doIPv4) || (pr.d_ip->ip_v == 6 && !doIPv6))
	    continue;
	  if(pr.d_ip->ip_v == 4) {
	    uint16_t frag = ntohs(pr.d_ip->ip_off);
	    if((frag & IP_MF) || (frag & IP_OFFMASK)) { // more fragments or IS a fragment
	      fragmented++;
	      continue;
	    }
	  }
	  uint16_t qtype;
	  DNSName qname((const char*)pr.d_payload, pr.d_len, 12, false, &qtype);
	  struct dnsheader header;
	  memcpy(&header, (struct dnsheader*)pr.d_payload, 12);

	  if(haveRDFilter && header.rd != rdFilter) {
	    rdFilterMismatch++;
	    continue;
	  }
          
          if(!filtername.empty() && !qname.isPartOf(filtername)) {
            nameMismatch++;
            continue;
          }
          
	  if(!header.qr) {
            uint16_t udpsize, z;
            if(getEDNSUDPPayloadSizeAndZ((const char*)pr.d_payload, pr.d_len, &udpsize, &z)) {
              edns++;
              if(z & EDNSOpts::DNSSECOK)
                dnssecOK++;
              if(header.cd)
                dnssecCD++;
              if(header.ad)
                dnssecAD++;
            }
          }

	  if(pr.d_ip->ip_v == 4) 
	    ++ipv4DNSPackets;
	  else
	    ++ipv6DNSPackets;
        
	  if(pr.d_pheader.ts.tv_sec != lastsec) {
	    LiveCounts lc;
	    if(lastsec) {
	      lc.questions = queries;
	      lc.answers = answers;
	      lc.outstanding = liveQuestions(); 

	      LiveCounts diff = lc - lastcounts;
	      pcounts.push_back(make_pair(pr.d_pheader.ts.tv_sec, diff));

	    }
	    lastsec = pr.d_pheader.ts.tv_sec;
	    lastcounts = lc;
	  }

	  lowestTime=min((time_t)lowestTime,  (time_t)pr.d_pheader.ts.tv_sec);
	  highestTime=max((time_t)highestTime, (time_t)pr.d_pheader.ts.tv_sec);

	  QuestionIdentifier qi=QuestionIdentifier::create(pr.getSource(), pr.getDest(), header, qname, qtype);

	  if(!header.qr) { // question
	    //	    cout<<"Query "<<qi<<endl;
	    if(!header.rd)
	      nonRDQueries++;
	    queries++;

	    ComboAddress rem = pr.getSource();
	    rem.sin4.sin_port=0;
	    requestors.insert(rem);	  

            QuestionData& qd=statmap[qi];
          
	    if(!qd.d_firstquestiontime.tv_sec)
	      qd.d_firstquestiontime=pr.d_pheader.ts;
	    else {
	      auto delta=makeFloat(pr.d_pheader.ts - qd.d_firstquestiontime);
	      //	      cout<<"Reuse of "<<qi<<", delta t="<<delta<<", count="<<qd.d_qcount<<endl;
	      if(delta > 2.0) {
		//		cout<<"Resetting old entry for "<<qi<<", too old"<<endl;
		qd.d_qcount=0;
		qd.d_answercount=0;
		qd.d_firstquestiontime=pr.d_pheader.ts;
	      }
	    }
	    if(qd.d_qcount++)
              reuses++;
	  }
	  else  {  // answer
	    //	    cout<<"Response "<<qi<<endl;
	    rcodes[header.rcode]++;
	    answers++;
	    if(header.rd && !header.ra) {
	      rdNonRAAnswers++;
	      rdnonra.insert(pr.getDest());
	    }
	  
	    if(header.ra) {
	      ComboAddress rem = pr.getDest();
	      rem.sin4.sin_port=0;
	      recipients.insert(rem);	  
	    }

	    QuestionData& qd=statmap[qi];
	    if(!qd.d_qcount) {
	      //	      cout<<"Untracked answer: "<<qi<<endl;
	      untracked++;
	    }

	    qd.d_answercount++;

	    if(qd.d_qcount) {
	      uint32_t usecs= (pr.d_pheader.ts.tv_sec - qd.d_firstquestiontime.tv_sec) * 1000000 +  
		(pr.d_pheader.ts.tv_usec - qd.d_firstquestiontime.tv_usec) ;

	      //	      cout<<"Usecs for "<<qi<<": "<<usecs<<endl;
              if(!noservfailstats || header.rcode != 2)
                cumul[usecs]++;
            
	      if(header.rcode != 0 && header.rcode!=3) 
		errorresult++;
	      ComboAddress rem = pr.getDest();
	      rem.sin4.sin_port=0;

	      if(doServFailTree)
		root.submit(qname, header.rcode, rem);
	    }

	    if(!qd.d_qcount || qd.d_qcount == qd.d_answercount) {
	      //	      cout<<"Clearing state for "<<qi<<endl<<endl;
	      statmap.erase(qi);
	    }
	    else {
	      //	      cout<<"State for qi remains open, qcount="<<qd.d_qcount<<", answercount="<<qd.d_answercount<<endl;
            }
	  }
	}
	catch(std::exception& e) {
	  if(verbose)
	    cout<<"error parsing packet: "<<e.what()<<endl;

	  if(pw)
	    pw->write();
	  parsefail++;
	  continue;
	}
      }
      else { // non-DNS ip
	nonDNSIP++;
      }
    }
    cout<<"PCAP contained "<<pr.d_correctpackets<<" correct packets, "<<pr.d_runts<<" runts, "<< pr.d_oversized<<" oversize, "<<pr.d_nonetheripudp<<" non-UDP.\n";

  }

  /*
  cout<<"Open when done: "<<endl;
  for(const auto& a : statmap) {
    cout<<a.first<<": qcount="<<a.second.d_qcount<<", answercount="<<a.second.d_answercount<<endl;
  }
  */
  
  cout<<"Timespan: "<<(highestTime-lowestTime)/3600.0<<" hours"<<endl;

  cout<<nonDNSIP<<" non-DNS UDP, "<<dnserrors<<" dns decoding errors, "<<parsefail<<" packets failed to parse"<<endl;
  cout<<"Ignored fragment packets: "<<fragmented<<endl;
  cout<<"Dropped DNS packets based on recursion-desired filter: "<<rdFilterMismatch<<endl;
  if(!filtername.empty())
    cout <<"Dropped DNS packets because not part of '"<<filtername<<"': "<<nameMismatch << endl;
  cout<<"DNS IPv4: "<<ipv4DNSPackets<<" packets, IPv6: "<<ipv6DNSPackets<<" packets"<<endl;
  cout<<"Questions: "<<queries<<", answers: "<<answers<<endl;
  cout<<"Reuses of same state entry: "<<reuses<<endl;
  unsigned int unanswered=0;


  //  ofstream openf("openf");
  for(statmap_t::const_iterator i=statmap.begin(); i!=statmap.end(); ++i) {
    if(!i->second.d_answercount) {
      unanswered++;
    }
    //openf<< i->first.d_source.toStringWithPort()<<' ' <<i->first.d_dest.toStringWithPort()<<' '<<i->first.d_id<<' '<<i->first.d_qname <<" " <<i->first.d_qtype<< " "<<i->second.d_qcount <<" " <<i->second.d_answercount<<endl;
  }

  cout<< boost::format("%d (%.02f%% of all) queries did not request recursion") % nonRDQueries % ((nonRDQueries*100.0)/queries) << endl;
  cout<< rdNonRAAnswers << " answers had recursion desired bit set, but recursion available=0 (for "<<rdnonra.size()<<" remotes)"<<endl;
  cout<<statmap.size()<<" queries went unanswered, of which "<< statmap.size()-unanswered<<" were answered on exact retransmit"<<endl;
  cout<<untracked<<" responses could not be matched to questions"<<endl;
  cout<<edns <<" questions requested EDNS processing, do=1: "<<dnssecOK<<", ad=1: "<<dnssecAD<<", cd=1: "<<dnssecCD<<endl;

  if(answers) {
    cout<<(boost::format("%1% %|25t|%2%") % "Rcode" % "Count\n");
    for(rcodes_t::const_iterator i=rcodes.begin(); i!=rcodes.end(); ++i)
      cout<<(boost::format("%s %|25t|%d %|35t|(%.1f%%)") % RCode::to_s(i->first) % i->second % (i->second*100.0/answers))<<endl;
  }

  uint32_t sum=0;
  //  ofstream stats("stats");
  uint32_t totpairs=0;
  double tottime=0;
  for(cumul_t::const_iterator i=cumul.begin(); i!=cumul.end(); ++i) {
    //    stats<<i->first<<"\t"<<(sum+=i->second)<<"\n";
    totpairs+=i->second;
    tottime+=i->first*i->second;
  }
  
  typedef map<uint32_t, bool> done_t;
  done_t done;
  for(auto a : {50, 100, 200, 300, 400, 800, 1000, 2000, 4000, 8000, 32000, 64000, 256000, 1024000, 2048000})
    done[a]=false;

  cout.setf(std::ios::fixed);
  cout.precision(4);
  sum=0;

#if HAVE_BOOST_GE_148
  if(g_vm.count("log-histogram")) {
    string fname = g_vm["stats-dir"].as<string>()+"/log-histogram";
    ofstream loglog(fname);
    if(!loglog)
      throw runtime_error("Unable to write statistics to "+fname);

    writeLogHistogramFile(cumul, loglog);
  }

  if(g_vm.count("full-histogram")) {
    string fname=g_vm["stats-dir"].as<string>()+"/full-histogram";
    ofstream loglog(fname);
    if(!loglog)
      throw runtime_error("Unable to write statistics to "+fname);
    writeFullHistogramFile(cumul, g_vm["full-histogram"].as<double>(), loglog);
  }
#endif

  
  sum=0;
  double lastperc=0, perc=0;
  uint64_t lastsum=0;

  for(cumul_t::const_iterator i=cumul.begin(); i!=cumul.end(); ++i) {
    for(done_t::iterator j=done.begin(); j!=done.end(); ++j) {
      if(!j->second && i->first > j->first) {
        j->second=true;

        perc=sum*100.0/totpairs;
        if(j->first < 1024)
          cout<< perc <<"% of questions answered within " << j->first << " usec (";
        else
          cout<< perc <<"% of questions answered within " << j->first/1000.0 << " msec (";
        
        cout<<perc-lastperc<<"%)\n";
        lastperc=sum*100.0/totpairs;
        lastsum=sum;
      }
    }
    sum+=i->second;
  }

  for(auto j = done.begin(); j != done.end(); ++j) {
    if(!j->second) {
      perc=sum*100.0/totpairs;
      if(j->first < 1024)
        cout<< perc <<"% of questions answered within " << j->first << " usec (";
      else
        cout<< perc <<"% of questions answered within " << j->first/1000.0 << " msec (";
      
      cout<<perc-lastperc<<"%)\n";
      lastperc=sum*100.0/totpairs;
      lastsum=sum;
      break;
    }
  }
  
  cout<< (totpairs-lastsum)<<" responses ("<<((totpairs-lastsum)*100.0/answers) <<"%) older than "<< (done.rbegin()->first/1000000.0) <<" seconds"<<endl;
  if(totpairs)
    cout<<"Average non-late response time: "<<tottime/totpairs<<" usec"<<endl;

  if(!g_vm["load-stats"].as<string>().empty()) {
    ofstream load(g_vm["load-stats"].as<string>().c_str());
    if(!load) 
      throw runtime_error("Error writing load statistics to "+g_vm["load-stats"].as<string>());
    for(pcounts_t::value_type& val :  pcounts) {
      load<<val.first<<'\t'<<val.second.questions<<'\t'<<val.second.answers<<'\t'<<val.second.outstanding<<'\n';  
    }
  }


  cout<<"Saw questions from "<<requestors.size()<<" distinct remotes, answers to "<<recipients.size()<<endl;
  ofstream remotes("remotes");
  for(const ComboAddress& rem :  requestors) {
    remotes<<rem.toString()<<'\n';
  }

  vector<ComboAddress> diff;
  set_difference(requestors.begin(), requestors.end(), recipients.begin(), recipients.end(), back_inserter(diff), ComboAddress::addressOnlyLessThan());
  cout<<"Saw "<<diff.size()<<" unique remotes asking questions, but not getting RA answers"<<endl;
  
  ofstream ignored("ignored");
  for(const ComboAddress& rem :  diff) {
    ignored<<rem.toString()<<'\n';
  }
  ofstream rdnonrafs("rdnonra");
  for(const ComboAddress& rem :  rdnonra) {
    rdnonrafs<<rem.toString()<<'\n';
  }

  if(doServFailTree) {
    StatNode::Stat node;
    root.visit(visitor, node);
  }

}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
