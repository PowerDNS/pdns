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


// calidns queryfile destination qps

int main(int argc, char** argv)
try
{
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
  

  Socket sock(AF_INET, SOCK_DGRAM);
  ComboAddress dest(argv[2]);
  sock.connect(dest);
  setSocketSendBuffer(sock.getHandle(), 1000000);
  setSocketReceiveBuffer(sock.getHandle(), 1000000);


  thread t1(recvThread, &sock);

  int qps=atoi(argv[3]);
  cout<<"Calibration run, aiming at "<<qps<< "qps"<<endl;
  int burst=40;
  struct timespec nsec;
  nsec.tv_sec=0;
  nsec.tv_nsec=(unsigned long)(burst*1000000000.0/qps);

  DTime dt;
  dt.set();
  int count=0;
  for(const auto& p : packets) {
    sock.write((const char*)&p[0], p.size());
    if(!((count++)%burst))
       nanosleep(&nsec, 0);
  }
  auto udiff = dt.udiff();
  auto realqps=packets.size()/(udiff/1000000.0);
  cout<<"Achieved "<<realqps<<"qps"<< " over "<< udiff/1000000.0<<" seconds"<<endl;
  
  sleep(1);
  
  cout<<"Received "<<g_recvcounter.load()<<" packets"<<endl;
  t1.detach();
}
 catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
}
