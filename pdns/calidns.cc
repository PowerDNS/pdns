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
#include <iostream>
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include <thread>
#include <atomic>
#include "statbag.hh"
#include <fstream>
#include <poll.h>
#include <memory>
#include <boost/program_options.hpp>
using std::thread;
using std::unique_ptr;

StatBag S;

std::atomic<unsigned int> g_recvcounter, g_recvbytes;
volatile bool g_done;

namespace po = boost::program_options;
po::variables_map g_vm;

void* recvThread(const vector<Socket*>* sockets)
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

  vector<struct mmsghdr> buf(100);
  for(auto& m : buf) {
    fillMSGHdr(&m.msg_hdr, new struct iovec, new char[512], 512, new char[1500], 1500, new ComboAddress("127.0.0.1"));
  }

  while(!g_done) {
    fds=rfds;

    err = poll(&fds[0], fds.size(), -1);
    if(err < 0) {
      if(errno==EINTR)
	continue;
      unixDie("Unable to poll for new UDP events");
    }    
    
    for(auto &pfd : fds) {
      if(pfd.revents & POLLIN) {
	
	if((err=recvmmsg(pfd.fd, &buf[0], buf.size(), MSG_WAITFORONE, 0)) < 0 ) {
	  if(errno != EAGAIN)
	    cerr<<"recvfrom gave error, ignoring: "<<strerror(errno)<<endl;
	  unixDie("recvmmsg");
	  continue;
	}
	g_recvcounter+=err;
	for(int n=0; n < err; ++n)
	  g_recvbytes += buf[n].msg_len;
      }
    }
  }

  return 0;
}


void setSocketBuffer(int fd, int optname, uint32_t size)
{
  uint32_t psize=0;
  socklen_t len=sizeof(psize);
  
  if(!getsockopt(fd, SOL_SOCKET, optname, (char*)&psize, &len) && psize > size) {
    cerr<<"Not decreasing socket buffer size from "<<psize<<" to "<<size<<endl;
    return; 
  }

  if (setsockopt(fd, SOL_SOCKET, optname, (char*)&size, sizeof(size)) < 0 )
    cerr<<"Warning: unable to raise socket buffer size to "<<size<<": "<<strerror(errno)<<endl;
}


static void setSocketReceiveBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_RCVBUF, size);
}

static void setSocketSendBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_SNDBUF, size);
}

void sendPackets(const vector<Socket*>* sockets, const vector<vector<uint8_t>* >& packets, int qps, ComboAddress dest)
{
  unsigned int burst=100;
  struct timespec nsec;
  nsec.tv_sec=0;
  nsec.tv_nsec=1*(unsigned long)(burst*1000000000.0/qps);
  int count=0;

  struct Unit {
    struct msghdr msgh;
    struct iovec iov;
    char cbuf[256];
  };
  vector<unique_ptr<Unit> > units;
  int ret;

  for(const auto& p : packets) {
    count++;

    Unit u;

    fillMSGHdr(&u.msgh, &u.iov, u.cbuf, 0, (char*)&(*p)[0], p->size(), &dest);
    if((ret=sendmsg((*sockets)[count % sockets->size()]->getHandle(), 
		    &u.msgh, 0)))
      if(ret < 0)
	unixDie("sendmmsg");
    
    
    if(!(count%burst))
      nanosleep(&nsec, 0);
  }
}

void usage(po::options_description &desc) {
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
    ("increment", po::value<float>()->default_value(1.1),  "Set the factor to increase the QPS load per run")
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

  double hitrate = g_vm["hitrate"].as<double>();
  if (hitrate > 100 || hitrate < 0) {
    cerr<<"hitrate must be between 0 and 100, not "<<hitrate<<endl;
    return EXIT_FAILURE;
  }
  hitrate /= 100;
  uint32_t qpsstart = g_vm["initial-qps"].as<uint32_t>();

  struct sched_param param;
  param.sched_priority=99;

  if(sched_setscheduler(0, SCHED_FIFO, &param) < 0)
    cerr<<"Unable to set SCHED_FIFO: "<<strerror(errno)<<endl;

  ifstream ifs(g_vm["query-file"].as<string>());
  string line;
  reportAllTypes();
  vector<std::shared_ptr<vector<uint8_t> > > unknown, known;
  while(getline(ifs, line)) {
    vector<uint8_t> packet;
    boost::trim(line);
    const auto fields = splitField(line, ' ');
    DNSPacketWriter pw(packet, DNSName(fields.first), DNSRecordContent::TypeToNumber(fields.second));
    pw.getHeader()->rd=wantRecursion;
    pw.getHeader()->id=random();
    if(pw.getHeader()->id % 2) {
        pw.addOpt(1500, 0, EDNSOpts::DNSSECOK);
        pw.commit();
    }
    unknown.emplace_back(std::make_shared<vector<uint8_t>>(packet));
  }
  random_shuffle(unknown.begin(), unknown.end());
  cout<<"Generated "<<unknown.size()<<" ready to use queries"<<endl;
  
  vector<Socket*> sockets;
  ComboAddress dest;
  try {
    dest = ComboAddress(g_vm["destination"].as<string>(), 53);
  }
  catch (PDNSException &e) {
    cerr<<e.reason<<endl;
    return EXIT_FAILURE;
  }
  for(int i=0; i < 24; ++i) {
    Socket *sock = new Socket(dest.sin4.sin_family, SOCK_DGRAM);
    //    sock->connect(dest);
    setSocketSendBuffer(sock->getHandle(), 2000000);
    setSocketReceiveBuffer(sock->getHandle(), 2000000);
    sockets.push_back(sock);
  }
  new thread(recvThread, &sockets);
  int qps;

  ofstream plot("plot");
  for(qps=qpsstart;;qps *= increment) {
    double seconds=1;
    cout<<"Aiming at "<<qps<< "qps (RD="<<wantRecursion<<") for "<<seconds<<" seconds at cache hitrate "<<100.0*hitrate<<"%";
    unsigned int misses=(1-hitrate)*qps*seconds;
    unsigned int total=qps*seconds;
    if (misses == 0) {
      misses = 1;
    }
    cout<<", need "<<misses<<" misses, "<<total<<" queries, have "<<unknown.size()<<" unknown left!"<<endl;

    if (misses > unknown.size()) {
      cerr<<"Not enough queries remaining (need at least "<<misses<<" and got "<<unknown.size()<<", please add more to the query file), exiting."<<endl;
      exit(1);
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
      toSend.push_back(known[random()%known.size()].get());
    }
    random_shuffle(toSend.begin(), toSend.end());
    g_recvcounter.store(0);
    g_recvbytes=0;
    DTime dt;
    dt.set();

    sendPackets(&sockets, toSend, qps, dest);
    
    auto udiff = dt.udiff();
    auto realqps=toSend.size()/(udiff/1000000.0);
    cout<<"Achieved "<<realqps<<"qps"<< " over "<< udiff/1000000.0<<" seconds"<<endl;
    
    usleep(50000);
    double perc=g_recvcounter.load()*100.0/toSend.size();
    cout<<"Received "<<g_recvcounter.load()<<" packets ("<<perc<<"%)"<<endl;
    plot<<qps<<" "<<realqps<<" "<<perc<<" "<<g_recvcounter.load()/(udiff/1000000.0)<<" " << 8*g_recvbytes.load()/(udiff/1000000.0)<<endl;
    plot.flush();
  }
  plot.flush();
  // t1.detach();
}
 catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
}
