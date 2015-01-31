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
using std::thread;

StatBag S;

std::atomic<unsigned int> g_recvcounter;
volatile bool g_done;

void* recvThread(Socket* s)
{
  char response[1500];
  while(!g_done) {
    try {
      s->read(response, sizeof(response));
      g_recvcounter++;
    }
    catch(...){}
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

void sendThread(const vector<Socket*>* sockets, const vector<vector<uint8_t> >* packets, int qps, bool even)
{

  int burst=20;
  struct timespec nsec;
  nsec.tv_sec=0;
  nsec.tv_nsec=(unsigned long)(burst*1000000000.0/qps);
  
  
  int count=0;

  for(const auto& p : *packets) {
    count++;
    if((count%2)==even)
      continue;

    (*sockets)[count % sockets->size()]->write((const char*)&p[0], p.size());
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
    DNSPacketWriter pw(packet, p.first, DNSRecordContent::TypeToNumber(p.second));
    packets.push_back(packet);
  }
  cout<<"Generated "<<packets.size()<<" queries"<<endl;
  random_shuffle(packets.begin(), packets.end());
  
  vector<Socket*> sockets;
  ComboAddress dest(argv[2]);  
  for(int i=0; i < 6; ++i) {
    Socket *sock = new Socket(AF_INET, SOCK_DGRAM);

    sock->connect(dest);
    setSocketSendBuffer(sock->getHandle(), 2000000);
    setSocketReceiveBuffer(sock->getHandle(), 2000000);
    sockets.push_back(sock);
    new thread(recvThread, sock);
  }

  int qps=atoi(argv[3]);

  ofstream plot("plot");
  for(qps=10000;;qps+=5000) {
    cout<<"Aiming at "<<qps<< "qps"<<endl;
    g_recvcounter.store(0);
    DTime dt;
    dt.set();

    thread t1(sendThread, &sockets, &packets, qps, 0);
    thread t2(sendThread, &sockets, &packets, qps, 1);

    t1.join();
    t2.join();
    
    auto udiff = dt.udiff();
    auto realqps=packets.size()/(udiff/1000000.0);
    cout<<"Achieved "<<realqps<<"qps"<< " over "<< udiff/1000000.0<<" seconds"<<endl;
    
    usleep(50000);
    double perc=g_recvcounter.load()*100.0/packets.size();
    cout<<"Received "<<g_recvcounter.load()<<" packets ("<<perc<<")"<<endl;
    plot<<qps<<" "<<realqps<<" "<<perc<<endl;
  }
  plot.flush();
  // t1.detach();
}
 catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
}
