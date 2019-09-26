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
#include <boost/accumulators/statistics/median.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/accumulators.hpp>

#include <boost/accumulators/statistics.hpp>

#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "threadname.hh"
#include <netinet/tcp.h>
#include <boost/array.hpp>
#include <boost/program_options.hpp>


StatBag S;
namespace po = boost::program_options;

po::variables_map g_vm;
bool g_verbose;
bool g_onlyTCP;
bool g_tcpNoDelay;
unsigned int g_timeoutMsec;
AtomicCounter g_networkErrors, g_otherErrors, g_OK, g_truncates, g_authAnswers, g_timeOuts;
ComboAddress g_dest;

unsigned int makeUsec(const struct timeval& tv)
{
  return 1000000*tv.tv_sec + tv.tv_usec;
}

/* On Linux, run echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle 
   to prevent running out of free TCP ports */

struct BenchQuery
{
  BenchQuery(const std::string& qname_, uint16_t qtype_) : qname(qname_), qtype(qtype_), udpUsec(0), tcpUsec(0), answerSecond(0) {}
  BenchQuery(): qtype(0), udpUsec(0), tcpUsec(0), answerSecond(0) {}
  DNSName qname;
  uint16_t qtype;
  uint32_t udpUsec, tcpUsec;
  time_t answerSecond;
};

void doQuery(BenchQuery* q)
try
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, q->qname, q->qtype);
  int res;
  string reply;

  struct timeval tv, now;
  gettimeofday(&tv, 0);

  if(!g_onlyTCP) {
    Socket udpsock(g_dest.sin4.sin_family, SOCK_DGRAM);
    
    udpsock.sendTo(string(packet.begin(), packet.end()), g_dest);
    ComboAddress origin;
    res = waitForData(udpsock.getHandle(), 0, 1000 * g_timeoutMsec);
    if(res < 0)
      throw NetworkError("Error waiting for response");
    if(!res) {
      g_timeOuts++;
      return;
    }

    udpsock.recvFrom(reply, origin);

    gettimeofday(&now, 0);
    q->udpUsec = makeUsec(now - tv);
    tv=now;

    MOADNSParser mdp(false, reply);
    if(!mdp.d_header.tc)
      return;
    g_truncates++;
  }

  Socket sock(g_dest.sin4.sin_family, SOCK_STREAM);
  int tmp=1;
  if(setsockopt(sock.getHandle(),SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) 
    throw runtime_error("Unable to set socket reuse: "+stringerror());
    
  if(g_tcpNoDelay && setsockopt(sock.getHandle(), IPPROTO_TCP, TCP_NODELAY,(char*)&tmp,sizeof tmp)<0) 
    throw runtime_error("Unable to set socket no delay: "+stringerror());

  sock.connect(g_dest);
  uint16_t len = htons(packet.size());
  string tcppacket((char*)& len, 2);
  tcppacket.append(packet.begin(), packet.end());

  sock.writen(tcppacket);

  res = waitForData(sock.getHandle(), 0, 1000 * g_timeoutMsec);
  if(res < 0)
    throw NetworkError("Error waiting for response");
  if(!res) {
    g_timeOuts++;
    return;
  }
  
  if(sock.read((char *) &len, 2) != 2)
    throw PDNSException("tcp read failed");
  
  len=ntohs(len);
  std::unique_ptr<char[]> creply(new char[len]);
  int n=0;
  int numread;
  while(n<len) {
    numread=sock.read(creply.get()+n, len-n);
    if(numread<0)
      throw PDNSException("tcp read failed");
    n+=numread;
  }
  
  reply=string(creply.get(), len);
  
  gettimeofday(&now, 0);
  q->tcpUsec = makeUsec(now - tv);
  q->answerSecond = now.tv_sec;

  MOADNSParser mdp(false, reply);
  //  cout<<"Had correct TCP/IP response, "<<mdp.d_answers.size()<<" answers, aabit="<<mdp.d_header.aa<<endl;
  if(mdp.d_header.aa)
    g_authAnswers++;
  g_OK++;
}
catch(NetworkError& ne)
{
  cerr<<"Network error: "<<ne.what()<<endl;
  g_networkErrors++;
}
catch(...)
{
  g_otherErrors++;
}

/* read queries from stdin, put in vector
   launch n worker threads, each picks a query using AtomicCounter
   If a worker reaches the end of its queue, it stops */

AtomicCounter g_pos;

vector<BenchQuery> g_queries;

static void* worker(void*)
{
  setThreadName("dnstcpb/worker");
  for(;;) {
    unsigned int pos = g_pos++; 
    if(pos >= g_queries.size())
      break;

    doQuery(&g_queries[pos]); // this is safe as long as nobody *inserts* to g_queries
  }
  return 0;
}

void usage(po::options_description &desc) {
  cerr<<"Syntax: dnstcpbench REMOTE [PORT] < QUERIES"<<endl;
  cerr<<"Where QUERIES is one query per line, format: qname qtype, just 1 space"<<endl;
  cerr<<desc<<endl;
}

int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("version", "print version number")
    ("verbose,v", "be verbose")
    ("udp-first,u", "try UDP first")
    ("file,f", po::value<string>(), "source file - if not specified, defaults to stdin")
    ("tcp-no-delay", po::value<bool>()->default_value(true), "use TCP_NODELAY socket option")
    ("timeout-msec", po::value<int>()->default_value(10), "wait for this amount of milliseconds for an answer")
    ("workers", po::value<int>()->default_value(100), "number of parallel workers");

  hidden.add_options()
    ("remote-host", po::value<string>(), "remote-host")
    ("remote-port", po::value<int>()->default_value(53), "remote-port");
  alloptions.add(desc).add(hidden); 

  po::positional_options_description p;
  p.add("remote-host", 1);
  p.add("remote-port", 1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);

  if(g_vm.count("version")) {
    cerr<<"dnstcpbench "<<VERSION<<endl;
    exit(EXIT_SUCCESS);
  }

  if(g_vm.count("help")) {
    usage(desc);
    exit(EXIT_SUCCESS);
  }
  g_tcpNoDelay = g_vm["tcp-no-delay"].as<bool>();

  g_onlyTCP = !g_vm.count("udp-first");
  g_verbose = g_vm.count("verbose");
  g_timeoutMsec = g_vm["timeout-msec"].as<int>();

  reportAllTypes();

  if(g_vm["remote-host"].empty()) {
    usage(desc);
    exit(EXIT_FAILURE);
  }

  g_dest = ComboAddress(g_vm["remote-host"].as<string>().c_str(), g_vm["remote-port"].as<int>());

  unsigned int numworkers=g_vm["workers"].as<int>();
  
  if(g_verbose) {
    cout<<"Sending queries to: "<<g_dest.toStringWithPort()<<endl;
    cout<<"Attempting UDP first: " << (g_onlyTCP ? "no" : "yes") <<endl;
    cout<<"Timeout: "<< g_timeoutMsec<<"msec"<<endl;
    cout << "Using TCP_NODELAY: "<<g_tcpNoDelay<<endl;
  }


  std::vector<pthread_t> workers(numworkers);

  FILE* fp;
  if(!g_vm.count("file"))
    fp=fdopen(0, "r");
  else {
    fp=fopen(g_vm["file"].as<string>().c_str(), "r");
    if(!fp)
      unixDie("Unable to open "+g_vm["file"].as<string>()+" for input");
  }
  pair<string, string> q;
  string line;
  while(stringfgets(fp, line)) {
    trim_right(line);
    q=splitField(line, ' ');
    g_queries.push_back(BenchQuery(q.first, DNSRecordContent::TypeToNumber(q.second)));
  }
  fclose(fp);
    
  for(unsigned int n = 0; n < numworkers; ++n) {
    pthread_create(&workers[n], 0, worker, 0);
  }
  for(unsigned int n = 0; n < numworkers; ++n) {
    void* status;
    pthread_join(workers[n], &status);
  }
  
  using namespace boost::accumulators;
  typedef accumulator_set<
    double
    , stats<boost::accumulators::tag::median(with_p_square_quantile),
      boost::accumulators::tag::mean(immediate)
    >
  > acc_t;

  acc_t udpspeeds, tcpspeeds, qps;
  
  typedef map<time_t, uint32_t> counts_t;
  counts_t counts;

  for(const BenchQuery& bq :  g_queries) {
    counts[bq.answerSecond]++;
    udpspeeds(bq.udpUsec);
    tcpspeeds(bq.tcpUsec);
  }

  for(const counts_t::value_type& val :  counts) {
    qps(val.second);
  }

  cout<<"Average qps: "<<mean(qps)<<", median qps: "<<median(qps)<<endl;
  cout<<"Average UDP latency: "<<mean(udpspeeds)<<"usec, median: "<<median(udpspeeds)<<"usec"<<endl;
  cout<<"Average TCP latency: "<<mean(tcpspeeds)<<"usec, median: "<<median(tcpspeeds)<<"usec"<<endl;

  cout<<"OK: "<<g_OK<<", network errors: "<<g_networkErrors<<", other errors: "<<g_otherErrors<<endl;
  cout<<"Timeouts: "<<g_timeOuts<<endl;
  cout<<"Truncateds: "<<g_truncates<<", auth answers: "<<g_authAnswers<<endl;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
