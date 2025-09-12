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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#if __clang_major__ >= 15
#pragma GCC diagnostic ignored "-Wdeprecated-copy-with-user-provided-copy"
#endif
#include <boost/accumulators/accumulators.hpp>
#include <boost/array.hpp>
#include <boost/accumulators/statistics.hpp>
#pragma GCC diagnostic pop
#include <boost/program_options.hpp>
#include "inflighter.cc"
#include <deque>
#include "namespaces.hh"
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "dns_random.hh"
#include "arguments.hh"

using namespace boost::accumulators;
namespace po = boost::program_options;

po::variables_map g_vm;

StatBag S;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

bool g_quiet=false;
bool g_envoutput=false;

struct DNSResult
{
  vector<ComboAddress> ips;
  int rcode{0};
  bool seenauthsoa{false};
};

struct TypedQuery
{
  TypedQuery(const string& name_, uint16_t type_) : name(name_), type(type_){}
  DNSName name;
  uint16_t type;
};

struct SendReceive
{
  using Identifier = int;
  using Answer = DNSResult; // ip
  Socket d_socket;
  std::deque<uint16_t> d_idqueue;

  using acc_t = accumulator_set<
        double
      , stats<boost::accumulators::tag::extended_p_square,
              boost::accumulators::tag::median(with_p_square_quantile),
              boost::accumulators::tag::mean(immediate)
              >
    >;
  unique_ptr<acc_t> d_acc;

  static constexpr std::array<double, 11> s_probs{{0.001,0.01, 0.025, 0.1, 0.25,0.5,0.75,0.9,0.975, 0.99,0.9999}};
  unsigned int d_errors{0};
  unsigned int d_nxdomains{0};
  unsigned int d_nodatas{0};
  unsigned int d_oks{0};
  unsigned int d_unknowns{0};
  unsigned int d_received{0};
  unsigned int d_receiveerrors{0};
  unsigned int d_senderrors{0};

  SendReceive(const std::string& remoteAddr, uint16_t port) :
    d_socket(AF_INET, SOCK_DGRAM),
    d_acc(make_unique<acc_t>(acc_t(boost::accumulators::tag::extended_p_square::probabilities=s_probs)))
  {
    d_socket.setReuseAddr();
    ComboAddress remote(remoteAddr, port);
    d_socket.connect(remote);
    for (unsigned int id =0 ; id < std::numeric_limits<uint16_t>::max(); ++id) {
      d_idqueue.push_back(id);
    }
  }

  Identifier send(TypedQuery& domain, int /*userdata*/)
  {
    //cerr<<"Sending query for '"<<domain<<"'"<<endl;

    // send it, copy code from 'sdig'
    vector<uint8_t> packet;

    DNSPacketWriter pw(packet, domain.name, domain.type);

    if (d_idqueue.empty()) {
      cerr<<"Exhausted ids!"<<endl;
      exit(1);
    }
    pw.getHeader()->id = d_idqueue.front();
    d_idqueue.pop_front();
    pw.getHeader()->rd = 1;
    pw.getHeader()->qr = 0;

    if (::send(d_socket.getHandle(), &*packet.begin(), packet.size(), 0) < 0) {
      d_senderrors++;
    }

    if (!g_quiet) {
      cout<<"Sent out query for '"<<domain.name<<"' with id "<<pw.getHeader()->id<<endl;
    }
    return pw.getHeader()->id;
  }

  bool receive(Identifier& iden, DNSResult& dnsResult, int /*userdata*/)
  {
    if (waitForData(d_socket.getHandle(), 0, 500) > 0) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init): no need to initialize the buffer
      std::array<char, 512> buf;

      auto len = recv(d_socket.getHandle(), buf.data(), buf.size(), 0);
      if (len < 0) {
        d_receiveerrors++;
        return false;
      }
      d_received++;
      // parse packet, set 'id', fill out 'ip'

      MOADNSParser mdp(false, string(buf.data(), static_cast<size_t>(len)));
      if (!g_quiet) {
        cout << "Reply to question for qname='" << mdp.d_qname << "', qtype=" << DNSRecordContent::NumberToType(mdp.d_qtype) << endl;
        cout << "Rcode: " << mdp.d_header.rcode << ", RD: " << mdp.d_header.rd << ", QR: " << mdp.d_header.qr;
        cout << ", TC: " << mdp.d_header.tc << ", AA: " << mdp.d_header.aa << ", opcode: " << mdp.d_header.opcode << endl;
      }
      dnsResult.rcode = mdp.d_header.rcode;
      for (auto i = mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
        if (i->d_place == 1 && i->d_type == mdp.d_qtype) {
          dnsResult.ips.emplace_back(i->getContent()->getZoneRepresentation());
        }
        if (i->d_place == 2 && i->d_type == QType::SOA) {
          dnsResult.seenauthsoa = true;
        }
        if (!g_quiet) {
          cout << i->d_place - 1 << "\t" << i->d_name << "\tIN\t" << DNSRecordContent::NumberToType(i->d_type);
          cout << "\t" << i->d_ttl << "\t" << i->getContent()->getZoneRepresentation() << "\n";
        }
      }

      iden = mdp.d_header.id;
      d_idqueue.push_back(iden);

      return true;
    }

    return false;
  }

  void deliverTimeout(const Identifier& id)
  {
    if(!g_quiet) {
      cout<<"Timeout for id "<<id<<endl;
    }
    d_idqueue.push_back(id);
  }

  void deliverAnswer(TypedQuery& domain, const DNSResult& dnsResult, unsigned int usec, int /*userdata*/)
  {
    (*d_acc)(usec / 1000.0);
    //  if(usec > 1000000)
    //    cerr<<"Slow: "<<domain<<" ("<<usec/1000.0<<" ms)\n";
    if (!g_quiet) {
      cout << domain.name << "|" << DNSRecordContent::NumberToType(domain.type) << ": (" << usec / 1000.0 << " ms) rcode: " << dnsResult.rcode;
      for (const ComboAddress& comboAddress : dnsResult.ips) {
        cout << ", " << comboAddress.toString();
      }
      cout << endl;
    }
    if (dnsResult.rcode == RCode::NXDomain) {
      d_nxdomains++;
    }
    else if (dnsResult.rcode != 0) {
      d_errors++;
    }
    else if (dnsResult.ips.empty() && dnsResult.seenauthsoa) {
      d_nodatas++;
    }
    else if (!dnsResult.ips.empty()) {
      d_oks++;
    }
    else {
      if (!g_quiet) {
        cout << "UNKNOWN!! ^^" << endl;
      }
      d_unknowns++;
    }
  }
};

static void usage(po::options_description &desc) {
  cerr << "Usage: dnsbulktest [OPTION].. IPADDRESS PORTNUMBER [LIMIT]"<<endl;
  cerr << desc << "\n";
}

int main(int argc, char** argv)
try
{
  ::arg().set("rng", "Specify random number generator to use. Valid values are auto,sodium,openssl,getrandom,arc4random,urandom.")="auto";
  ::arg().set("entropy-source", "If set, read entropy from this file")="/dev/urandom";

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

    boost::trim_right(line);
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
    if (std::none_of(split.second.begin(), split.second.end(), isalpha)) {
      continue; // this was an IP address
    }
    domains.push_back(TypedQuery(split.second, qtype));
    if(doWww)
      domains.push_back(TypedQuery("www."+split.second, qtype));
  }
  cerr<<"Read "<<domains.size()<<" domains!"<<endl;
  shuffle(domains.begin(), domains.end(), pdns::dns_random_engine());

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
  cerr<< datafmt % "  Queued " % domains.size() % "  Received" % sr.d_received;
  cerr<< datafmt % "  Error -/-" % sr.d_senderrors %  "  Timeouts" % inflighter.getTimeouts();
  cerr<< datafmt % " " % "" %  "  Unexpected" % inflighter.getUnexpecteds();

  cerr<< datafmt % " Sent" % (domains.size() - sr.d_senderrors) %  " Total" % (sr.d_received + inflighter.getTimeouts() + inflighter.getUnexpecteds());

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
  cerr<< "Mean response time: "<<mean(*sr.d_acc) << " ms"<<", median: "<<median(*sr.d_acc)<< " ms\n";

  boost::format statfmt("Time < %6.03f ms %|30t|%6.03f%% cumulative\n");

  for (unsigned int i = 0; i < SendReceive::s_probs.size(); ++i) {
    cerr << statfmt % extended_p_square(*sr.d_acc)[i] % (100*SendReceive::s_probs.at(i));
  }

  if (g_envoutput) {
    cout<<"DBT_QUEUED="<<domains.size()<<endl;
    cout<<"DBT_SENDERRORS="<<sr.d_senderrors<<endl;
    cout<<"DBT_RECEIVED="<<sr.d_received<<endl;
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
catch (const PDNSException& exp)
{
  cerr<<"Fatal error: "<<exp.reason<<endl;
  _exit(EXIT_FAILURE);
}
catch (const std::exception& exp) {
  cerr<<"Fatal error: "<<exp.what()<<endl;
  _exit(EXIT_FAILURE);
}
