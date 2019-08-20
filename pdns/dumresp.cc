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

static std::atomic<uint64_t>* g_counter;

static void printStatus()
{
  auto prev= g_counter->load();
  for(;;) {
    sleep(1);
    cout<<g_counter->load()-prev<<"\t"<<g_counter->load()<<endl;
    prev=g_counter->load();
  }
}

static void usage() {
  cerr<<"Syntax: dumresp LOCAL-ADDRESS LOCAL-PORT NUMBER-OF-PROCESSES [tcp]"<<endl;
}

static void turnQueryIntoResponse(dnsheader* dh)
{
  (*g_counter)++;

  dh->qr=1;
  dh->ad=0;
}

static void tcpConnectionHandler(int sock)
try
{
  char buffer[1500];
  auto dh = reinterpret_cast<struct dnsheader*>(buffer);

  for (;;) {
    uint16_t len = 0;
    ssize_t got = read(sock, &len, sizeof(len));

    if (got == 0) {
      break;
    }

    if (got != sizeof(len))
      unixDie("read 1");

    len = ntohs(len);

    if (len < sizeof(dnsheader))
      unixDie("too small");

    if (len > sizeof(buffer))
      unixDie("too large");

    got = read(sock, buffer, len);
    if (got != len)
      unixDie("read 2: " + std::to_string(got) + " / " + std::to_string(len));

    if (dh->qr)
      continue;

    turnQueryIntoResponse(dh);

    uint16_t wirelen = htons(len);
    if (write(sock, &wirelen, sizeof(wirelen)) != sizeof(wirelen))
      unixDie("send 1");

    if (write(sock, buffer, len) < 0)
      unixDie("send 2");
  }

  close(sock);
}
catch(const std::exception& e) {
  cerr<<"TCP connection handler got an exception: "<<e.what()<<endl;
}

static void tcpAcceptor(const ComboAddress local)
{
  Socket tcpSocket(local.sin4.sin_family, SOCK_STREAM);
#ifdef SO_REUSEPORT
  int one=1;
  if(setsockopt(tcpSocket.getHandle(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
    unixDie("setsockopt for REUSEPORT");
#endif

  tcpSocket.bind(local);
  tcpSocket.listen(1024);

  ComboAddress rem("::1");
  auto socklen = rem.getSocklen();

  for (;;) {
    int sock = accept(tcpSocket.getHandle(), reinterpret_cast<struct sockaddr*>(&rem), &socklen);
    if (sock == -1) {
        continue;
    }

    std::thread connectionHandler(tcpConnectionHandler, sock);
    connectionHandler.detach();
  }
}

int main(int argc, char** argv)
try
{
  bool tcp = false;

  for(int i = 1; i < argc; i++) {
    if(std::string(argv[i]) == "--help"){
      usage();
      return(EXIT_SUCCESS);
    }

    if(std::string(argv[i]) == "--version"){
      cerr<<"dumresp "<<VERSION<<endl;
      return(EXIT_SUCCESS);
    }
  }

  if(argc == 5) {
    if (std::string(argv[4]) == "tcp") {
      tcp = true;
    }
    else {
      usage();
      exit(EXIT_FAILURE);
    }
  }
  else if(argc != 4) {
    usage();
    exit(EXIT_FAILURE);
  }

  auto ptr = mmap(nullptr, sizeof(std::atomic<uint64_t>), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  g_counter = new(ptr) std::atomic<uint64_t>();

  int numberOfListeners = atoi(argv[3]);
  ComboAddress local(argv[1], atoi(argv[2]));

  int i=1;
  for(; i < numberOfListeners; ++i) {
    if(!fork())
      break;
  }

  if (i==1) {
    std::thread t(printStatus);
    t.detach();

    if (tcp) {
      for (int j = 0; j < numberOfListeners; j++) {
        cout<<"Listening to TCP "<<local.toStringWithPort()<<endl;
        std::thread tcpAcceptorThread(tcpAcceptor, local);
        tcpAcceptorThread.detach();
      }
    }
  }

  Socket s(local.sin4.sin_family, SOCK_DGRAM);
#ifdef SO_REUSEPORT
  int one=1;
  if(setsockopt(s.getHandle(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
    unixDie("setsockopt for REUSEPORT");
#endif

  s.bind(local);
  cout<<"Bound to UDP "<<local.toStringWithPort()<<endl;

  ComboAddress rem = local;
  socklen_t socklen = rem.getSocklen();
  char buffer[1500];
  auto dh = reinterpret_cast<struct dnsheader*>(buffer);

  for(;;) {
    ssize_t len = recvfrom(s.getHandle(), buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&rem), &socklen);

    if(len < 0)
      unixDie("recvfrom");

    if (static_cast<size_t>(len) < sizeof(dnsheader))
      unixDie("too small " + std::to_string(len));

    if(dh->qr)
      continue;

    turnQueryIntoResponse(dh);

    if(sendto(s.getHandle(), buffer, len, 0,  reinterpret_cast<const struct sockaddr*>(&rem), socklen) < 0)
      unixDie("sendto");
  }
}
catch(const std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  exit(EXIT_FAILURE);
}
