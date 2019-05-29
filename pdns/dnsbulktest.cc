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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/accumulators/accumulators.hpp>
#include <boost/array.hpp>
#include <boost/accumulators/statistics.hpp>
#include <boost/program_options.hpp>
#include "inflighter.cc"
#include <deque>
#include "namespaces.hh"
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"

using namespace boost::accumulators;
namespace po = boost::program_options;

po::variables_map g_vm;

StatBag S;

bool g_quiet=false;
bool g_envoutput=false;

struct DNSResult
{
  vector<ComboAddress> ips;
  int rcode;
  bool seenauthsoa;
};

struct TypedQuery
{
  TypedQuery(const string& name_, uint16_t type_) : name(name_), type(type_){}
  DNSName name;
  uint16_t type;
};

struct SendReceive
{
  typedef int Identifier;
  typedef DNSResult Answer; // ip 
  int d_socket;
  deque<uint16_t> d_idqueue;
    
  typedef accumulator_set<
        double
      , stats<boost::accumulators::tag::extended_p_square,
              boost::accumulators::tag::median(with_p_square_quantile),
              boost::accumulators::tag::mean(immediate)
              >
    > acc_t;
  acc_t* d_acc;
  
  boost::array<double, 11> d_probs;
  
  SendReceive(const std::string& remoteAddr, uint16_t port) : d_probs({{0.001,0.01, 0.025, 0.1, 0.25,0.5,0.75,0.9,0.975, 0.99,0.9999}})
  {
    d_acc = new acc_t(boost::accumulators::tag::extended_p_square::probabilities=d_probs);
    // 
    //d_acc = acc_t
    d_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int val=1;
    setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    
    ComboAddress remote(remoteAddr, port);
    connect(d_socket, (struct sockaddr*)&remote, remote.getSocklen());
    d_oks = d_errors = d_nodatas = d_nxdomains = d_unknowns = 0;
    d_receiveds = d_receiveerrors = d_senderrors = 0;
    for(unsigned int id =0 ; id < std::numeric_limits<uint16_t>::max(); ++id) 
      d_idqueue.push_back(id);
  }
  
  ~SendReceive()
  {
    close(d_socket);
  }
  
  Identifier send(TypedQuery& domain)
  {
    //cerr<<"Sending query for '"<<domain<<"'"<<endl;
    
    // send it, copy code from 'sdig'
    vector<uint8_t> packet;
  
    DNSPacketWriter pw(packet, domain.name, domain.type);

    if(d_idqueue.empty()) {
      cerr<<"Exhausted ids!"<<endl;
      exit(1);
    }    
    pw.getHeader()->id = d_idqueue.front();
    d_idqueue.pop_front();
    pw.getHeader()->rd = 1;
    pw.getHeader()->qr = 0;
    
    if(::send(d_socket, &*packet.begin(), packet.size(), 0) < 0)
      d_senderrors++;
    
    if(!g_quiet)
      cout<<"Sent out query for '"<<domain.name<<"' with id "<<pw.getHeader()->id<<endl;
    return pw.getHeader()->id;
  }
  
  bool receive(Identifier& id, DNSResult& dr)
  {
    if(waitForData(d_socket, 0, 500000) > 0) {
      char buf[512];
          
      int len = recv(d_socket, buf, sizeof(buf), 0);
      if(len < 0) {
        d_receiveerrors++;
        return 0;
      }
      else {
        d_receiveds++;
      }
      // parse packet, set 'id', fill out 'ip' 
      
      MOADNSParser mdp(false, string(buf, len));
      if(!g_quiet) {
        cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
        cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
        cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;
      }
      dr.rcode = mdp.d_header.rcode;
      for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
        if(i->first.d_place == 1 && i->first.d_type == mdp.d_qtype)
          dr.ips.push_back(ComboAddress(i->first.d_content->getZoneRepresentation()));
        if(i->first.d_place == 2 && i->first.d_type == QType::SOA) {
          dr.seenauthsoa = 1;
        }
        if(!g_quiet)
        {
          cout<<i->first.d_place-1<<"\t"<<i->first.d_name<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
          cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
        }
      }
      
      id = mdp.d_header.id;
      d_idqueue.push_back(id);
    
      return 1;
    }
    return 0;
  }
  
  void deliverTimeout(const Identifier& id)
  {
    if(!g_quiet) {
      cout<<"Timeout for id "<<id<<endl;
    }
    d_idqueue.push_back(id);
  }
  
  void deliverAnswer(TypedQuery& domain, const DNSResult& dr, unsigned int usec)
  {
    (*d_acc)(usec/1000.0);
//    if(usec > 1000000)
  //    cerr<<"Slow: "<<domain<<" ("<<usec/1000.0<<" msec)\n";
    if(!g_quiet) {
      cout<<domain.name<<"|"<<DNSRecordContent::NumberToType(domain.type)<<": ("<<usec/1000.0<<"msec) rcode: "<<dr.rcode;
      for(const ComboAddress& ca :  dr.ips) {
        cout<<", "<<ca.toString();
      }
      cout<<endl;
    }
    if(dr.rcode == RCode::NXDomain) {
      d_nxdomains++;
    }
    else if(dr.rcode) {
      d_errors++;
    }
    else if(dr.ips.empty() && dr.seenauthsoa) 
      d_nodatas++;
    else if(!dr.ips.empty())
      d_oks++;
    else {
      if(!g_quiet) cout<<"UNKNOWN!! ^^"<<endl;
      d_unknowns++;
    }
  }
  unsigned int d_errors, d_nxdomains, d_nodatas, d_oks, d_unknowns;
  unsigned int d_receiveds, d_receiveerrors, d_senderrors;
};

void usage(po::options_description &desc) {
  cerr << "Usage: dnsbulktest [OPTION].. IPADDRESS PORTNUMBER [LIMIT]"<<endl;
  cerr << desc << "\n";
}

int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("quiet,q", "be quiet about individual queries")
    ("type,t",  po::value<string>()->default_value("A"), "What type to query for")
    ("envoutput,e", "write report in shell environment format")
    ("version", "show the version number")
    ("www", po::value<bool>()->default_value(true), "duplicate all queries with an additional 'www.' in front")
  ;

  po::options_description alloptions;
  po::options_description hidden("hidden options");
  hidden.add_options()
    ("ip-address", po::value<string>(), "ip-address")
    ("portnumber", po::value<uint16_t>(), "portnumber")
    ("limit", po::value<uint32_t>()->default_value(0), "limit");

  alloptions.add(desc).add(hidden);
  po::positional_options_description p;
  p.add("ip-address", 1);
  p.add("portnumber", 1);
  p.add("limit", 1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);

  if (g_vm.count("help")) {
    usage(desc);
    return EXIT_SUCCESS;
  }

  if (g_vm.count("version")) {
    cerr<<"dnsbulktest "<<VERSION<<endl;
    return EXIT_SUCCESS;
  }

  if(!g_vm.count("portnumber")) {
    cerr<<"Fatal, need to specify ip-address and portnumber"<<endl;
    usage(desc);
    return EXIT_FAILURE;
  }

  bool doWww = g_vm["www"].as<bool>();
  g_quiet = g_vm.count("quiet") > 0;
  g_envoutput = g_vm.count("envoutput") > 0;
  uint16_t qtype;
  reportAllTypes();
  try {
    qtype = DNSRecordContent::TypeToNumber(g_vm["type"].as<string>());
  }
  catch(std::exception& e) {
    cerr << e.what() << endl;
    return EXIT_FAILURE;
  }

  SendReceive sr(g_vm["ip-address"].as<string>(), g_vm["portnumber"].as<uint16_t>());
  unsigned int limit = g_vm["limit"].as<unsigned int>();
    
  vector<TypedQuery> domains;
    
  Inflighter<vector<TypedQuery>, SendReceive> inflighter(domains, sr);
  inflighter.d_maxInFlight = 1000;
  inflighter.d_timeoutSeconds = 3;
  inflighter.d_burst = 100;
  string line;
  
  pair<string, string> split;
  string::size_type pos;
  while(stringfgets(stdin, line)) {
    if(limit && domains.size() >= limit)
      break;

    trim_right(line);
    if(line.empty() || line[0] == '#')
      continue;
    split=splitField(line,',');
    if (split.second.empty())
      split=splitField(line,'\t');
    if(split.second.find('.') == 0) // skip 'Hidden profile' in quantcast list.
      continue;
    pos=split.second.find('/');
    if(pos != string::npos) // alexa has whole urls in the list now.
      split.second.resize(pos);
    if(find_if(split.second.begin(), split.second.end(), isalpha) == split.second.end())
    {
      continue; // this was an IP address
    }
    domains.push_back(TypedQuery(split.second, qtype));
    if(doWww)
      domains.push_back(TypedQuery("www."+split.second, qtype));
  }
  cerr<<"Read "<<domains.size()<<" domains!"<<endl;
  random_shuffle(domains.begin(), domains.end());

  boost::format datafmt("%s %|20t|%+15s  %|40t|%s %|60t|%+15s\n");

  for(;;) {
    try {
      inflighter.run();
      break;
    }
    catch(std::exception& e) {
      cerr<<"Caught exception: "<<e.what()<<endl;
    }
  }

  cerr<< datafmt % "Sending" % "" % "Receiving" % "";
  cerr<< datafmt % "  Queued " % domains.size() % "  Received" % sr.d_receiveds;
  cerr<< datafmt % "  Error -/-" % sr.d_senderrors %  "  Timeouts" % inflighter.getTimeouts();
  cerr<< datafmt % " " % "" %  "  Unexpected" % inflighter.getUnexpecteds();
  
  cerr<< datafmt % " Sent" % (domains.size() - sr.d_senderrors) %  " Total" % (sr.d_receiveds + inflighter.getTimeouts() + inflighter.getUnexpecteds());
  
  cerr<<endl;  
  cerr<< datafmt % "DNS Status" % ""       % "" % "";
  cerr<< datafmt % "  OK" % sr.d_oks       % "" % "";
  cerr<< datafmt % "  Error" % sr.d_errors       % "" % "";  
  cerr<< datafmt % "  No Data" % sr.d_nodatas       % "" % "";  
  cerr<< datafmt % "  NXDOMAIN" % sr.d_nxdomains      % "" % "";
  cerr<< datafmt % "  Unknowns" % sr.d_unknowns      % "" % "";  
  cerr<< datafmt % "Answers" % (sr.d_oks      +      sr.d_errors      +      sr.d_nodatas      + sr.d_nxdomains           +      sr.d_unknowns) % "" % "";
  cerr<< datafmt % "  Timeouts " % (inflighter.getTimeouts()) % "" % "";
  cerr<< datafmt % "Total " % (sr.d_oks      +      sr.d_errors      +      sr.d_nodatas      + sr.d_nxdomains           +      sr.d_unknowns + inflighter.getTimeouts()) % "" % "";
  
  cerr<<"\n";
  cerr<< "Mean response time: "<<mean(*sr.d_acc) << " msec"<<", median: "<<median(*sr.d_acc)<< " msec\n";
  
  boost::format statfmt("Time < %6.03f msec %|30t|%6.03f%% cumulative\n");
  
  for (unsigned int i = 0; i < sr.d_probs.size(); ++i) {
        cerr << statfmt % extended_p_square(*sr.d_acc)[i] % (100*sr.d_probs[i]);
    }

  if(g_envoutput) {
    cout<<"DBT_QUEUED="<<domains.size()<<endl;
    cout<<"DBT_SENDERRORS="<<sr.d_senderrors<<endl;
    cout<<"DBT_RECEIVED="<<sr.d_receiveds<<endl;
    cout<<"DBT_NXDOMAINS="<<sr.d_nxdomains<<endl;
    cout<<"DBT_NODATAS="<<sr.d_nodatas<<endl;
    cout<<"DBT_UNKNOWNS="<<sr.d_unknowns<<endl;
    cout<<"DBT_OKS="<<sr.d_oks<<endl;
    cout<<"DBT_ERRORS="<<sr.d_errors<<endl;
    cout<<"DBT_TIMEOUTS="<<inflighter.getTimeouts()<<endl;
    cout<<"DBT_UNEXPECTEDS="<<inflighter.getUnexpecteds()<<endl;
    cout<<"DBT_OKPERCENTAGE="<<((float)sr.d_oks/domains.size()*100)<<endl;
    cout<<"DBT_OKPERCENTAGEINT="<<(int)((float)sr.d_oks/domains.size()*100)<<endl;
  }
}
catch(PDNSException& pe)
{
  cerr<<"Fatal error: "<<pe.reason<<endl;
  exit(EXIT_FAILURE);
}
