#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "iputils.hh"
#include "sstuff.hh"
#include "statbag.hh"
#include <atomic>
#include <sys/mman.h>
#include <thread>
StatBag S;

std::atomic<uint64_t>* g_counter;

void printStatus()
{
  auto prev= g_counter->load();
  for(;;) {
    sleep(1);
    cout<<g_counter->load()-prev<<"\t"<<g_counter->load()<<endl;
    prev=g_counter->load();
  }
}

int main(int argc, char** argv)
try
{
  if(argc != 4) {
    cerr<<"Syntax: dumresp local-address local-port number-of-processes "<<endl;
    exit(EXIT_FAILURE);
  }


  auto ptr = mmap(NULL, sizeof(std::atomic<uint64_t>), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  g_counter = new(ptr) std::atomic<uint64_t>();
  
  int i=1;
  for(; i < atoi(argv[3]); ++i) {
    if(!fork())
      break;
  }
  if(i==1) {
    std::thread t(printStatus);
    t.detach();
  }
  
  ComboAddress local(argv[1], atoi(argv[2]));
  Socket s(local.sin4.sin_family, SOCK_DGRAM);  
#ifdef SO_REUSEPORT
  int one=1;
  if(setsockopt(s.getHandle(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
    unixDie("setsockopt for REUSEPORT");
#endif

  s.bind(local);
  cout<<"Bound to "<<local.toStringWithPort()<<endl;
  char buffer[1500];
  struct dnsheader* dh = (struct dnsheader*)buffer;
  int len;
  ComboAddress rem=local;
  socklen_t socklen = rem.getSocklen();
  for(;;) {
    len=recvfrom(s.getHandle(), buffer, sizeof(buffer), 0, (struct sockaddr*)&rem, &socklen);
    (*g_counter)++;
    if(len < 0)
      unixDie("recvfrom");

    if(dh->qr)
      continue;
    dh->qr=1;
    dh->ad=0;
    if(sendto(s.getHandle(), buffer, len, 0,  (struct sockaddr*)&rem, socklen) < 0)
      unixDie("sendto");

  }
}
catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  exit(EXIT_FAILURE);
}
