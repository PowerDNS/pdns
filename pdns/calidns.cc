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
using std::thread;
using std::unique_ptr;

StatBag S;

std::atomic<unsigned int> g_recvcounter;
volatile bool g_done;

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

    
    for(struct pollfd &pfd : fds) {
      if(pfd.revents & POLLIN) {
	
	if((err=recvmmsg(pfd.fd, &buf[0], buf.size(), MSG_WAITFORONE, 0)) < 0 ) {
	  if(errno != EAGAIN)
	    cerr<<"recvfrom gave error, ignoring: "<<strerror(errno)<<endl;
	  unixDie("recvmmsg");
	  continue;
	}
	g_recvcounter+=err;	
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

void sendThread(const vector<Socket*>* sockets, const vector<vector<uint8_t> >* packets, int qps, ComboAddress dest)
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

  for(const auto& p : *packets) {
    count++;

    Unit u;

    fillMSGHdr(&u.msgh, &u.iov, u.cbuf, 0, (char*)&p[0], p.size(), &dest);
    if((ret=sendmsg((*sockets)[count % sockets->size()]->getHandle(), 
		    &u.msgh, 0)))
      if(ret < 0)
	unixDie("sendmmsg");
    
    
    if(!(count%burst))
      nanosleep(&nsec, 0);
  }
}


// calidns queryfile destination qps

int main(int argc, char** argv)
try
{
  struct sched_param param;
  param.sched_priority=99;

  if(sched_setscheduler(0, SCHED_FIFO, &param) < 0)
    unixDie("setting scheduler");

  ifstream ifs(argv[1]);
  string line;
  reportAllTypes();
  vector<vector<uint8_t> > packets;
  while(getline(ifs, line)) {
    vector<uint8_t> packet;
    boost::trim(line);
    auto p = splitField(line, ' ');
    DNSPacketWriter pw(packet, DNSName(p.first), DNSRecordContent::TypeToNumber(p.second));
    packets.push_back(packet);
  }
  cout<<"Generated "<<packets.size()<<" queries"<<endl;
  random_shuffle(packets.begin(), packets.end());
  
  vector<Socket*> sockets;
  ComboAddress dest(argv[2]);  
  for(int i=0; i < 24; ++i) {
    Socket *sock = new Socket(AF_INET, SOCK_DGRAM);

    //    sock->connect(dest);
    setSocketSendBuffer(sock->getHandle(), 2000000);
    setSocketReceiveBuffer(sock->getHandle(), 2000000);
    sockets.push_back(sock);

  }
  new thread(recvThread, &sockets);
  int qps=atoi(argv[3]);

  ofstream plot("plot");
  for(qps=10000;;qps+=5000) {
    cout<<"Aiming at "<<qps<< "qps"<<endl;
    g_recvcounter.store(0);
    DTime dt;
    dt.set();

    sendThread(&sockets, &packets, qps, dest);
    
    auto udiff = dt.udiff();
    auto realqps=packets.size()/(udiff/1000000.0);
    cout<<"Achieved "<<realqps<<"qps"<< " over "<< udiff/1000000.0<<" seconds"<<endl;
    
    usleep(50000);
    double perc=g_recvcounter.load()*100.0/packets.size();
    cout<<"Received "<<g_recvcounter.load()<<" packets ("<<perc<<"%)"<<endl;
    plot<<qps<<" "<<realqps<<" "<<perc<<" "<<g_recvcounter.load()/(udiff/1000000.0)<<endl;
  }
  plot.flush();
  // t1.detach();
}
 catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
}
