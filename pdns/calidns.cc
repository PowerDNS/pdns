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

#include <atomic>
#include <iostream>
#include <fstream>
#include <memory>
#include <poll.h>
#include <thread>

#include <boost/program_options.hpp>

#include "dns_random.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "misc.hh"
#include "sstuff.hh"
#include "statbag.hh"

using std::thread;
using std::unique_ptr;

StatBag S;

static std::atomic<unsigned int> g_recvcounter, g_recvbytes;
static volatile bool g_done;

namespace po = boost::program_options;
static po::variables_map g_vm;

static bool g_quiet;

static void* recvThread(const vector<std::unique_ptr<Socket>>* sockets)
{
  vector<pollfd> rfds, fds;
  for(const auto& s : *sockets) {
    struct pollfd pfd;
    pfd.fd = s->getHandle();
    pfd.events = POLLIN;
    pfd.revents = 0;
    rfds.push_back(pfd);
  }

  int err;

#if HAVE_RECVMMSG
  vector<struct mmsghdr> buf(100);
  for(auto& m : buf) {
    cmsgbuf_aligned *cbuf = new cmsgbuf_aligned;
    fillMSGHdr(&m.msg_hdr, new struct iovec, cbuf, sizeof(*cbuf), new char[1500], 1500, new ComboAddress("127.0.0.1"));
  }
#else
  struct msghdr buf;
  cmsgbuf_aligned *cbuf = new cmsgbuf_aligned;
  fillMSGHdr(&buf, new struct iovec, cbuf, sizeof(*cbuf), new char[1500], 1500, new ComboAddress("127.0.0.1"));
#endif

  while(!g_done) {
    fds=rfds;

    err = poll(&fds[0], fds.size(), -1);
    if (err < 0) {
      if (errno == EINTR)
        continue;
      unixDie("Unable to poll for new UDP events");
    }

    for(auto &pfd : fds) {
      if (pfd.revents & POLLIN) {
#if HAVE_RECVMMSG
        if ((err=recvmmsg(pfd.fd, &buf[0], buf.size(), MSG_WAITFORONE, 0)) < 0 ) {
          if(errno != EAGAIN)
            unixDie("recvmmsg");
          continue;
        }
        g_recvcounter+=err;
        for(int n=0; n < err; ++n)
          g_recvbytes += buf[n].msg_len;
#else
        if ((err = recvmsg(pfd.fd, &buf, 0)) < 0) {
          if (errno != EAGAIN)
            unixDie("recvmsg");
          continue;
        }
        g_recvcounter++;
        for (unsigned int i = 0; i < buf.msg_iovlen; i++)
          g_recvbytes += buf.msg_iov[i].iov_len;
#endif
      }
    }
  }
  return 0;
}

static void setSocketBuffer(int fd, int optname, uint32_t size)
{
  uint32_t psize=0;
  socklen_t len=sizeof(psize);
  
  if(!getsockopt(fd, SOL_SOCKET, optname, (char*)&psize, &len) && psize > size) {
    if (!g_quiet) {
      cerr<<"Not decreasing socket buffer size from "<<psize<<" to "<<size<<endl;
    }
    return; 
  }

  if (setsockopt(fd, SOL_SOCKET, optname, (char*)&size, sizeof(size)) < 0 ) {
    if (!g_quiet) {
      cerr<<"Warning: unable to raise socket buffer size to "<<size<<": "<<stringerror()<<endl;
    }
  }
}


static void setSocketReceiveBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_RCVBUF, size);
}

static void setSocketSendBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_SNDBUF, size);
}

static ComboAddress getRandomAddressFromRange(const Netmask& ecsRange)
{
  ComboAddress result = ecsRange.getMaskedNetwork();
  uint8_t bits = ecsRange.getBits();
  uint32_t mod = 1 << (32 - bits);
  result.sin4.sin_addr.s_addr = result.sin4.sin_addr.s_addr + ntohl(dns_random(mod));
  return result;
}

static void replaceEDNSClientSubnet(vector<uint8_t>* packet, const Netmask& ecsRange)
{
  /* the last 4 bytes of the packet are the IPv4 address */
  ComboAddress rnd = getRandomAddressFromRange(ecsRange);
  uint32_t addr = rnd.sin4.sin_addr.s_addr;

  const auto packetSize = packet->size();
  if (packetSize < sizeof(addr)) {
    return;
  }

  memcpy(&packet->at(packetSize - sizeof(addr)), &addr, sizeof(addr));
}

static void sendPackets(const vector<std::unique_ptr<Socket>>& sockets, const vector<vector<uint8_t>* >& packets, int qps, ComboAddress dest, const Netmask& ecsRange)
{
  unsigned int burst=100;
  const auto nsecPerBurst=1*(unsigned long)(burst*1000000000.0/qps);
  struct timespec nsec;
  nsec.tv_sec=0;
  nsec.tv_nsec=0;
  int count=0;
  unsigned int nBursts=0;
  DTime dt;
  dt.set();

  struct Unit {
    struct msghdr msgh;
    struct iovec iov;
    cmsgbuf_aligned cbuf;
  };
  vector<unique_ptr<Unit> > units;
  int ret;

  for(const auto& p : packets) {
    count++;

    Unit u;

    if (!ecsRange.empty()) {
      replaceEDNSClientSubnet(p, ecsRange);
    }

    fillMSGHdr(&u.msgh, &u.iov, nullptr, 0, (char*)&(*p)[0], p->size(), &dest);
    if((ret=sendmsg(sockets[count % sockets.size()]->getHandle(), 
		    &u.msgh, 0)))
      if(ret < 0)
	      unixDie("sendmsg");
    
    
    if(!(count%burst)) {
      nBursts++;
      // Calculate the time in nsec we need to sleep to the next burst.
      // If this is negative, it means that we are not achieving the requested
      // target rate, in which case we skip the sleep.
      int toSleep = nBursts*nsecPerBurst - 1000*dt.udiffNoReset();
      if (toSleep > 0) {
        nsec.tv_nsec = toSleep;
        nanosleep(&nsec, 0);
      }
    }
  }
}

static void usage(po::options_description &desc) {
  cerr<<"Syntax: calidns [OPTIONS] QUERY_FILE DESTINATION INITIAL_QPS HITRATE"<<endl;
  cerr<<desc<<endl;
}

/*
  New plan. Set cache hit percentage, which we achieve on a per second basis.
  So we start with 10000 qps for example, and for 90% cache hit ratio means
  we take 1000 unique queries and each send them 10 times.

  We then move the 1000 unique queries to the 'known' pool.

  For the next second, say 20000 qps, we know we are going to need 2000 new queries,
  so we take 2000 from the unknown pool. Then we need 18000 cache hits. We can get 1000 from 
  the known pool, leaving us down 17000. Or, we have 3000 in total now and we need 2000. We simply
  repeat the 3000 mix we have ~7 times. The 2000 can now go to the known pool too.

  For the next second, say 30000 qps, we'll need 3000 cache misses, which we get from 
  the unknown pool. To this we add 3000 queries from the known pool. Next up we repeat this batch 5
  times.

  In general the algorithm therefore is:

  1) Calculate number of cache misses required, get them from the unknown pool
  2) Move those to the known pool
  3) Fill up to amount of queries we need with random picks from the known pool

*/

int main(int argc, char** argv)
try
{
  po::options_description desc("Options");
  desc.add_options()
    ("help,h", "Show this helpful message")
    ("version", "Show the version number")
    ("ecs", po::value<string>(), "Add EDNS Client Subnet option to outgoing queries using random addresses from the specified range (IPv4 only)")
    ("ecs-from-file", "Read IP or subnet values from the query file and add them as EDNS Client Subnet options to outgoing queries")
    ("increment", po::value<float>()->default_value(1.1),  "Set the factor to increase the QPS load per run")
    ("maximum-qps", po::value<uint32_t>(), "Stop incrementing once this rate has been reached, to provide a stable load")
    ("minimum-success-rate", po::value<double>()->default_value(0), "Stop the test as soon as the success rate drops below this value, in percent")
    ("plot-file", po::value<string>(), "Write results to the specific file")
    ("quiet", "Whether to run quietly, outputting only the maximum QPS reached. This option is mostly useful when used with --minimum-success-rate")
    ("want-recursion", "Set the Recursion Desired flag on queries");
  po::options_description alloptions;
  po::options_description hidden("hidden options");
  hidden.add_options()
    ("query-file", po::value<string>(), "File with queries")
    ("destination", po::value<string>(), "Destination address")
    ("initial-qps", po::value<uint32_t>(), "Initial number of queries per second")
    ("hitrate", po::value<double>(), "Aim this percent cache hitrate");

  alloptions.add(desc).add(hidden);
  po::positional_options_description p;
  p.add("query-file", 1);
  p.add("destination", 1);
  p.add("initial-qps", 1);
  p.add("hitrate", 1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);

  if (g_vm.count("help")) {
    usage(desc);
    return EXIT_SUCCESS;
  }

  if (g_vm.count("version")) {
    cerr<<"calidns "<<VERSION<<endl;
    return EXIT_SUCCESS;
  }

  if (!(g_vm.count("query-file") && g_vm.count("destination") && g_vm.count("initial-qps") && g_vm.count("hitrate"))) {
    usage(desc);
    return EXIT_FAILURE;
  }

  float increment = 1.1;
  try {
    increment = g_vm["increment"].as<float>();
  }
  catch(...) {
  }

  bool wantRecursion = g_vm.count("want-recursion");
  bool useECSFromFile = g_vm.count("ecs-from-file");
  g_quiet = g_vm.count("quiet");

  double hitrate = g_vm["hitrate"].as<double>();
  if (hitrate > 100 || hitrate < 0) {
    cerr<<"hitrate must be between 0 and 100, not "<<hitrate<<endl;
    return EXIT_FAILURE;
  }
  hitrate /= 100;
  uint32_t qpsstart = g_vm["initial-qps"].as<uint32_t>();

  uint32_t maximumQps = std::numeric_limits<uint32_t>::max();
  if (g_vm.count("maximum-qps")) {
    maximumQps = g_vm["maximum-qps"].as<uint32_t>();
  }

  double minimumSuccessRate = g_vm["minimum-success-rate"].as<double>();
  if (minimumSuccessRate > 100.0 || minimumSuccessRate < 0.0) {
    cerr<<"Minimum success rate must be between 0 and 100, not "<<minimumSuccessRate<<endl;
    return EXIT_FAILURE;
  }

  Netmask ecsRange;
  if (g_vm.count("ecs")) {
    dns_random_init("0123456789abcdef");

    try {
      ecsRange = Netmask(g_vm["ecs"].as<string>());
      if (!ecsRange.empty()) {

        if (!ecsRange.isIpv4()) {
          cerr<<"Only IPv4 ranges are supported for ECS at the moment!"<<endl;
          return EXIT_FAILURE;
        }

        if (!g_quiet) {
          cout<<"Adding ECS option to outgoing queries with random addresses from the "<<ecsRange.toString()<<" range"<<endl;
        }
      }
    }
    catch (const NetmaskException& e) {
      cerr<<"Error while parsing the ECS netmask: "<<e.reason<<endl;
      return EXIT_FAILURE;
    }
  }

  struct sched_param param;
  param.sched_priority=99;

#if HAVE_SCHED_SETSCHEDULER
  if(sched_setscheduler(0, SCHED_FIFO, &param) < 0) {
    if (!g_quiet) {
      cerr<<"Unable to set SCHED_FIFO: "<<stringerror()<<endl;
    }
  }
#endif

  ifstream ifs(g_vm["query-file"].as<string>());
  string line;
  reportAllTypes();
  vector<std::shared_ptr<vector<uint8_t> > > unknown, known;
  std::vector<std::string> fields;
  fields.reserve(3);

  while(getline(ifs, line)) {
    vector<uint8_t> packet;
    DNSPacketWriter::optvect_t ednsOptions;
    boost::trim(line);
    if (line.empty() || line.at(0) == '#') {
      continue;
    }

    fields.clear();
    stringtok(fields, line, "\t ");
    if ((useECSFromFile && fields.size() < 3) || fields.size() < 2) {
      cerr<<"Skipping invalid line '"<<line<<", it does not contain enough values"<<endl;
      continue;
    }

    const std::string& qname = fields.at(0);
    const std::string& qtype = fields.at(1);
    std::string subnet;

    if (useECSFromFile) {
      subnet = fields.at(2);
    }

    DNSPacketWriter pw(packet, DNSName(qname), DNSRecordContent::TypeToNumber(qtype));
    pw.getHeader()->rd=wantRecursion;
    pw.getHeader()->id=dns_random_uint16();

    if(!subnet.empty() || !ecsRange.empty()) {
      EDNSSubnetOpts opt;
      opt.source = Netmask(subnet.empty() ? "0.0.0.0/32" : subnet);
      ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    }

    if(!ednsOptions.empty() || pw.getHeader()->id % 2) {
      pw.addOpt(1500, 0, EDNSOpts::DNSSECOK, ednsOptions);
      pw.commit();
    }
    unknown.emplace_back(std::make_shared<vector<uint8_t>>(packet));
  }
  random_shuffle(unknown.begin(), unknown.end());
  if (!g_quiet) {
    cout<<"Generated "<<unknown.size()<<" ready to use queries"<<endl;
  }
  
  vector<std::unique_ptr<Socket>> sockets;
  ComboAddress dest;
  try {
    dest = ComboAddress(g_vm["destination"].as<string>(), 53);
  }
  catch (PDNSException &e) {
    cerr<<e.reason<<endl;
    return EXIT_FAILURE;
  }
  for(int i=0; i < 24; ++i) {
    auto sock = make_unique<Socket>(dest.sin4.sin_family, SOCK_DGRAM);
    //    sock->connect(dest);
    setSocketSendBuffer(sock->getHandle(), 2000000);
    setSocketReceiveBuffer(sock->getHandle(), 2000000);
    sockets.push_back(std::move(sock));
  }
  new thread(recvThread, &sockets);
  uint32_t qps;

  ofstream plot;
  if (g_vm.count("plot-file")) {
    plot.open(g_vm["plot-file"].as<string>());
    if (!plot) {
      cerr<<"Error opening "<<g_vm["plot-file"].as<string>()<<" for writing: "<<stringerror()<<endl;
      return EXIT_FAILURE;
    }
  }

  double bestQPS = 0.0;
  double bestPerfectQPS = 0.0;

  for(qps=qpsstart;;) {
    double seconds=1;
    if (!g_quiet) {
      cout<<"Aiming at "<<qps<< "qps (RD="<<wantRecursion<<") for "<<seconds<<" seconds at cache hitrate "<<100.0*hitrate<<"%";
    }
    unsigned int misses=(1-hitrate)*qps*seconds;
    unsigned int total=qps*seconds;
    if (misses == 0) {
      misses = 1;
    }
    if (!g_quiet) {
      cout<<", need "<<misses<<" misses, "<<total<<" queries, have "<<unknown.size()<<" unknown left!"<<endl;
    }

    if (misses > unknown.size()) {
      cerr<<"Not enough queries remaining (need at least "<<misses<<" and got "<<unknown.size()<<", please add more to the query file), exiting."<<endl;
      return EXIT_FAILURE;
    }
    vector<vector<uint8_t>*> toSend;
    unsigned int n;
    for(n=0; n < misses; ++n) {
      auto ptr=unknown.back();
      unknown.pop_back();
      toSend.push_back(ptr.get());
      known.push_back(ptr);
    }
    for(;n < total; ++n) {
      toSend.push_back(known[dns_random(known.size())].get());
    }
    random_shuffle(toSend.begin(), toSend.end());
    g_recvcounter.store(0);
    g_recvbytes=0;
    DTime dt;
    dt.set();

    sendPackets(sockets, toSend, qps, dest, ecsRange);
    
    const auto udiff = dt.udiffNoReset();
    const auto realqps=toSend.size()/(udiff/1000000.0);
    if (!g_quiet) {
      cout<<"Achieved "<<realqps<<" qps over "<< udiff/1000000.0<<" seconds"<<endl;
    }
    
    usleep(50000);
    const auto received = g_recvcounter.load();
    const auto udiffReceived = dt.udiff();
    const auto realReceivedQPS = received/(udiffReceived/1000000.0);
    double perc=received*100.0/toSend.size();
     if (!g_quiet) {
       cout<<"Received "<<received<<" packets over "<< udiffReceived/1000000.0<<" seconds ("<<perc<<"%, adjusted received rate "<<realReceivedQPS<<" qps)"<<endl;
     }

    if (plot) {
      plot<<qps<<" "<<realqps<<" "<<perc<<" "<<received/(udiff/1000000.0)<<" " << 8*g_recvbytes.load()/(udiff/1000000.0)<<endl;
      plot.flush();
    }

    if (qps < maximumQps) {
      qps *= increment;
    }
    else {
      qps = maximumQps;
    }

    if (minimumSuccessRate > 0.0 && perc < minimumSuccessRate) {
      if (g_quiet) {
        cout<<bestQPS<<endl;
      }
      else {
        cout<<"The latest success rate ("<<perc<<") dropped below the minimum success rate of "<<minimumSuccessRate<<", stopping."<<endl;
        cout<<"The final rate reached before failing was "<<bestQPS<<" qps (best rate at 100% was "<<bestPerfectQPS<<" qps)"<<endl;
      }
      break;
    }

    bestQPS = std::max(bestQPS, realReceivedQPS);
    if (perc >= 100.0) {
      bestPerfectQPS = std::max(bestPerfectQPS, realReceivedQPS);
    }
  }

  if (plot) {
    plot.flush();
  }

  // t1.detach();
}
 catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
