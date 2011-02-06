/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef PDNS_TCPRECEIVER_HH
#define PDNS_TCPRECEIVER_HH

#include "dns.hh"
#include "iputils.hh"
#include "dnsbackend.hh"
#include "packethandler.hh"
#include <vector>
#include <boost/shared_ptr.hpp>
#include <poll.h>

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

#include "namespaces.hh"

class TCPNameserver
{
public:
  TCPNameserver();
  ~TCPNameserver();
  void go();
private:

  static void sendPacket(boost::shared_ptr<DNSPacket> p, int outsock);
  static int readLength(int fd, ComboAddress *remote);
  static void getQuestion(int fd, char *mesg, int pktlen, const ComboAddress& remote);
  static int doAXFR(const string &target, boost::shared_ptr<DNSPacket> q, int outsock);
  static bool canDoAXFR(boost::shared_ptr<DNSPacket> q);
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
  vector<struct pollfd> d_prfds;
  static int s_timeout;
};

#endif /* PDNS_TCPRECEIVER_HH */
