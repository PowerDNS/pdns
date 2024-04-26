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
#pragma once
#include "dns.hh"
#include "iputils.hh"
#include "dnsbackend.hh"
#include "packethandler.hh"
#include <vector>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/select.h>

#include "lock.hh"
#include "namespaces.hh"

class TCPNameserver
{
public:
  TCPNameserver();
  ~TCPNameserver();
  void go();
  unsigned int numTCPConnections();
private:

  static void sendPacket(std::unique_ptr<DNSPacket>& p, int outsock, bool last=true);
  static void getQuestion(int fd, char *mesg, int pktlen, const ComboAddress& remote, unsigned int totalTime);
  static int doAXFR(const DNSName &target, std::unique_ptr<DNSPacket>& q, int outsock);
  static int doIXFR(std::unique_ptr<DNSPacket>& q, int outsock);
  static bool canDoAXFR(std::unique_ptr<DNSPacket>& q, bool isAXFR, std::unique_ptr<PacketHandler>& packetHandler);
  static void doConnection(int fd);
  static void decrementClientCount(const ComboAddress& remote);
  void thread();
  static LockGuarded<std::map<ComboAddress,size_t,ComboAddress::addressOnlyLessThan>> s_clientsCount;
  static LockGuarded<std::unique_ptr<PacketHandler>> s_P;
  static std::unique_ptr<Semaphore> d_connectionroom_sem;
  static unsigned int d_maxTCPConnections;
  static NetmaskGroup d_ng;
  static size_t d_maxTransactionsPerConn;
  static size_t d_maxConnectionsPerClient;
  static unsigned int d_idleTimeout;
  static unsigned int d_maxConnectionDuration;

  vector<int>d_sockets;
  vector<struct pollfd> d_prfds;
};
