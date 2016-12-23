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

void usage() {
  cerr<<"Syntax: dumresp LOCAL-ADDRESS LOCAL-PORT NUMBER-OF-PROCESSES"<<endl;
}

int main(int argc, char** argv)
try
{
  for(int i = 1; i < argc; i++) {
    if((string) argv[i] == "--help"){
      usage();
      return(EXIT_SUCCESS);
    }

    if((string) argv[i] == "--version"){
      cerr<<"dumresp "<<VERSION<<endl;
      return(EXIT_SUCCESS);
    }
  }

  if(argc != 4) {
    usage();
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
