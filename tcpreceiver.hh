/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef PDNS_TCPRECEIVER_HH
#define PDNS_TCPRECEIVER_HH

#include "dns.hh"
#include "iputils.hh"
#include "dnsbackend.hh"
#include "packethandler.hh"
#include <vector>

#ifndef WIN32
# include <sys/select.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <sys/stat.h>
# include <unistd.h>
# include <netdb.h>
# include <sys/uio.h>
# include <sys/select.h>
#endif // WIN32

using namespace std;

class TCPNameserver
{
public:
  TCPNameserver();
  ~TCPNameserver();
  void go();
private:

  static int sendDelPacket(DNSPacket *p, int outsock);
  static int readLength(int fd, struct sockaddr_in *remote);
  static void getQuestion(int fd, char *mesg, int pktlen, const struct sockaddr_in &remote);
  static int doAXFR(const string &target, DNSPacket *q, int outsock);
  static bool canDoAXFR(DNSPacket *q);
  static void *doConnection(void *data);
  static void *launcher(void *data);
  void thread(void);
  static pthread_mutex_t s_plock;
  static PacketHandler *s_P;
  pthread_t d_tid;
  static Semaphore *d_connectionroom_sem;
  static NetmaskGroup d_ng;

  vector<int>d_sockets;
  int d_highfd;
  fd_set d_rfds;
  static int s_timeout;
};

#endif /* PDNS_TCPRECEIVER_HH */
