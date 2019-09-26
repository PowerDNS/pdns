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
  ~DNSProxy(); //<! dtor for DNSProxy
  void go(); //!< launches the actual thread
  bool completePacket(std::unique_ptr<DNSPacket>& r, const DNSName& target,const DNSName& aname, const uint8_t scopeMask);

  void mainloop();                  //!< this is the main loop that receives reply packets and sends them out again
  static void *launchhelper(void *p)
  {
    static_cast<DNSProxy *>(p)->mainloop();
    return 0;
  }
  bool recurseFor(DNSPacket* p);
private:
  struct ConntrackEntry
  {
    time_t created;
    boost::optional<ComboAddress> anyLocal;
    DNSName qname;
    std::unique_ptr<DNSPacket> complete;
    DNSName aname;
    uint8_t anameScopeMask;
    ComboAddress remote;
    uint16_t id;
    uint16_t qtype;
    int outsock;
  };

  typedef map<int,ConntrackEntry> map_t;

  // Data
  ComboAddress d_remote;
  AtomicCounter* d_resanswers;
  AtomicCounter* d_udpanswers;
  AtomicCounter* d_resquestions;
  pthread_mutex_t d_lock;
  map_t d_conntrack;
  int d_sock;
  int getID_locked();
  uint16_t d_xor;
};

#endif
