#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "iputils.hh"
#include "sstuff.hh"
#include "statbag.hh"

StatBag S;

int main(int argc, char** argv)
try
{
  if(argc != 4) {
    cerr<<"Syntax: dumresp local-address local-port number-of-threads "<<endl;
    exit(EXIT_FAILURE);
  }

  for(int i=1 ; i < atoi(argv[3]); ++i) {
    if(!fork())
      break;
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
