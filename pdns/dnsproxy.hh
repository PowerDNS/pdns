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
#ifndef PDNS_DNSPROXY
#define PDNS_DNSPROXY
#include <pthread.h>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dnspacket.hh"
#include "lock.hh"
#include "iputils.hh"

#include "namespaces.hh"

/**

how will this work.

This is a thread that just throws packets around. Should handle ~1000 packets/second.

Consists of a thread receiving packets back from the backend and retransmitting them to the original client.

Furthermore, it provides a member function that reports the packet to the connection tracker and actually sends it out. 

The sending happens from a source port that is determined by the constructor, but IS random. Furthermore, the ID is XOR-ed with a random value
to make sure outside parties can't spoof us.

To fix: how to remove the stale entries that will surely accumulate
*/

class DNSProxy
{
public:
  DNSProxy(const string &ip); //!< creates socket
  void go(); //!< launches the actual thread
  void onlyFrom(const string &ips); //!< Only these netmasks are allowed to recurse via us
  bool sendPacket(DNSPacket *p);    //!< send out a packet and make a conntrack entry to we can send back the answer

  void mainloop();                  //!< this is the main loop that receives reply packets and sends them out again
  static void *launchhelper(void *p)
  {
    static_cast<DNSProxy *>(p)->mainloop();
    return 0;
  }
  bool recurseFor(DNSPacket* p);
private:
  NetmaskGroup d_ng;
  int d_sock;
  unsigned int* d_resanswers;
  unsigned int* d_udpanswers;
  unsigned int* d_resquestions;
  pthread_mutex_t d_lock;
  uint16_t d_xor;
  int getID_locked();
  struct ConntrackEntry
  {
    uint16_t id;
    ComboAddress remote;
    int outsock;
    time_t created;
    string qname;
    uint16_t qtype;
  };

  typedef map<int,ConntrackEntry> map_t;
  map_t d_conntrack;
};

#endif
