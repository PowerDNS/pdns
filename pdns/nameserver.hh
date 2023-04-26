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
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>

#include "statbag.hh"
#include "namespaces.hh"
#include "dnspacket.hh"
#include "responsestats.hh"

/** This is the main class. It opens a socket on udp port 53 and waits for packets. Those packets can
    be retrieved with the receive() member function, which returns a DNSPacket.

    Some sample code in main():
    \code
    typedef Distributor<DNSPacket,DNSPacket,PacketHandler> DNSDistributor;
    DNSDistributor D(6); // the big dispatcher!

    pthread_t qtid, atid;
    N=new UDPNameserver;

    pthread_create(&qtid,0,qthread,static_cast<void *>(&D)); // receives packets
    pthread_create(&atid,0,athread,static_cast<void *>(&D)); // sends packets
    \endcode

    Code for qthread:
    \code
    void *qthread(void *p)
    {
      DNSDistributor *D=static_cast<DNSDistributor *>(p);

      DNSPacket *P;

      while((P=N->receive())) // receive a packet
      {
         D->question(P); // and give to the distributor, they will delete it
      }
      return 0;
    }

    \endcode

*/

#ifdef __linux__
#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif
#endif

extern std::vector<ComboAddress> g_localaddresses; // not static, our unit tests need to poke this

class PacketHandler; // Have to forward declare this

/*
 * We keep track of latency by storing the latency for each step in microseconds and the number of queries.
 * To get the average latency we can then divide the latency by the number of queries.
 * This might seem problematic, but in the uint64_t values we have available we can store 584000 years of latency.
 * So you'll probably restart your nameserver before it becomes a problem.
 */
struct NameserverLatencies
{
  uint64_t receiveLatency{0};
  uint64_t cacheLatency{0};
  uint64_t avgLatency{0};
  uint64_t sendLatency{0};
  uint64_t backendLatency{0};
  uint64_t queryCount{0};
};

class NameserverStats
{
public:
  NameserverStats(
    AtomicCounter& a_queryCounter,
    AtomicCounter& a_doQueryCounter,
    AtomicCounter& a_cookieQueryCounter,
    AtomicCounter& a_v4QueryCounter,
    AtomicCounter& a_v6QueryCounter,
    AtomicCounter& a_receiveLatencyCounter,
    AtomicCounter& a_cacheLatency,
    AtomicCounter& a_cacheLatencyCount,
    AtomicCounter& a_avgLatency,
    AtomicCounter& a_sendLatency,
    AtomicCounter& a_responseLatencyCount,
    AtomicCounter& a_backendLatency,
    AtomicCounter& a_backendLatencyCount) :
    queries(a_queryCounter),
    doQueries(a_doQueryCounter),
    cookieQueries(a_cookieQueryCounter),
    v4Queries(a_v4QueryCounter),
    v6Queries(a_v6QueryCounter),
    receiveLatency(a_receiveLatencyCounter),
    cacheLatency(a_cacheLatency),
    cacheLatencyCount(a_cacheLatencyCount),
    avgLatency(a_avgLatency),
    sendLatency(a_sendLatency),
    responseLatencyCount(a_responseLatencyCount),
    backendLatency(a_backendLatency),
    backendLatencyCount(a_backendLatencyCount)
  {
  }

  void countQuery(uint64_t latency, bool doSet, bool cookie, bool v4)
  {
    this->receiveLatency += (unsigned long)latency;
    this->queries++;

    if (doSet) {
      this->doQueries++;
    }

    if (cookie) {
      this->cookieQueries++;
    }

    if (v4) {
      this->v4Queries++;
    }
    else {
      this->v6Queries++;
    }
  }

  void logBackendLatency(uint64_t latency)
  {
    this->backendLatency += (unsigned long)latency;
    this->backendLatencyCount++;
  }

  void logResponseLatency(uint64_t netLatency, uint64_t totalLatency)
  {
    this->sendLatency += (unsigned long)netLatency;
    this->avgLatency += (unsigned long)totalLatency;
    this->responseLatencyCount++;
  }

  void logCacheLatency(uint64_t latency)
  {
    this->cacheLatency += (unsigned long)latency;
    this->cacheLatencyCount++;
  }

private:
  AtomicCounter& queries;
  AtomicCounter& doQueries;
  AtomicCounter& cookieQueries;
  AtomicCounter& v4Queries;
  AtomicCounter& v6Queries;
  AtomicCounter& receiveLatency;
  AtomicCounter& cacheLatency;
  AtomicCounter& cacheLatencyCount;
  AtomicCounter& avgLatency;
  AtomicCounter& sendLatency;
  AtomicCounter& responseLatencyCount;
  AtomicCounter& backendLatency;
  AtomicCounter& backendLatencyCount;
};

class Nameserver
{
public:
  Nameserver(NameserverStats a_stats, bool a_isUdpOrTcp, bool a_logDNSQueries) :
    stats(a_stats), isUdpOrTcp(a_isUdpOrTcp), logDNSQueries(a_logDNSQueries)
  {
  }
  virtual void run() = 0;

protected:
  NameserverStats stats;
  /**
   * This function is responsible for parsing a packet buffer into a DNSPacket
   * It will also update stats and receive latency information accordingly so the d_dt
   * in the DNSPacket should be set accordingly in the function before.
   * Buffer should have a static capacity equal to the max expected size
   * and be resized so size() matches the current packet size.
   * Socket, Remote and d_anylocal should also be set as well as handling the
   * PROXY protocol since that is protocol dependent.
   */
  bool parseQuery(DNSPacket& packet, std::string& buffer);
  bool tryCache(DNSPacket& question, DNSPacket& cached);
  std::unique_ptr<DNSPacket> processQuery(std::unique_ptr<PacketHandler>& packetHandler, DNSPacket& packet);

private:
  bool isUdpOrTcp;
  bool logDNSQueries;
};

class UDPBindAddress
{
public:
  UDPBindAddress(ComboAddress a_address, bool a_canReusePort, bool a_nonLocalBind, bool a_shouldFailOnNonExistent) :
    address(a_address), canReusePort(a_canReusePort), nonLocalBind(a_nonLocalBind), shouldFailOnNonExistent(a_shouldFailOnNonExistent)
  {
    this->mainSocket = -1;
  }
  int getSocket()
  {
#if defined(SO_REUSEPORT)
    if (!this->canReusePort && this->mainSocket != -1) {
#else
    if (this->mainSocket != -1) {
#endif
      return this->mainSocket;
    }

    int one = 1;

    int s;

    s = socket(this->address.sin4.sin_family, SOCK_DGRAM, 0);

    if (s < 0) {
      if (errno == EAFNOSUPPORT) {
        g_log << Logger::Error << "Binding " << this->address.toStringWithPort() << ": Address Family is not supported - skipping bind" << endl;
        return -1;
      }
      throw PDNSException("Unable to acquire a UDP socket: " + stringerror());
    }

    setCloseOnExec(s);

    if (IsAnyAddress(this->address)) {
      (void)setsockopt(s, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one));
      if (this->address.isIPv6()) {
        (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)); // if this fails, we report an error in tcpreceiver too
#ifdef IPV6_RECVPKTINFO
        (void)setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
#endif
      }
    }

    if (!setSocketTimestamps(s))
      g_log << Logger::Warning << "Unable to enable timestamp reporting for socket " << address.toStringWithPort() << endl;

    try {
      setSocketIgnorePMTU(s, this->address.sin4.sin_family);
    }
    catch (const std::exception& e) {
      g_log << Logger::Warning << "Failed to set IP_MTU_DISCOVER on UDP server socket: " << e.what() << endl;
    }

#if defined(SO_REUSEPORT)
    if (this->canReusePort) {
      if (!setReusePort(s)) {
        this->canReusePort = false;
      }
    }
#endif

    if (this->nonLocalBind)
      Utility::setBindAny(this->address.sin4.sin_family, s);

    if (::bind(s, (sockaddr*)&this->address, this->address.getSocklen()) < 0) {
      int err = errno;
      close(s);
      if (err == EADDRNOTAVAIL && !this->shouldFailOnNonExistent) {
        g_log << Logger::Error << "Address " << this->address << " does not exist on this server - skipping UDP bind" << endl;
        return -1;
      }
      else {
        g_log << Logger::Error << "Unable to bind UDP socket to '" + this->address.toStringWithPort() + "': " << stringerror(err) << endl;
        throw PDNSException("Unable to bind to UDP socket");
      }
    }
    this->mainSocket = s;
    g_log << Logger::Error << "UDP server bound to " << this->address.toStringWithPort() << endl;
    return s;
  }

private:
  ComboAddress address;
  bool canReusePort;
  int mainSocket;
  bool nonLocalBind;
  bool shouldFailOnNonExistent;
};

class UDPNameserver : Nameserver
{
public:
  UDPNameserver(NameserverStats stats, bool logDnsQueries, UDPBindAddress address); //!< Opens the socket
  virtual void run();

private:
  int listeningSocket;
  std::unique_ptr<PacketHandler> handler;

protected:
  void receiveAndProcessPacket(DNSPacket& question, DNSPacket& cached, std::string& buffer);
  virtual void handlePacket(DNSPacket& packet);
  void send(DNSPacket& packet);
};
/*
class DistributedUDPNameserver: UDPNameserver
{
public:
  DistributedUDPNameserver(std::string address, int port, bool shouldReusePort, DNSDistributor distributor);
  void run() override;
private:
  DNSDistributor distributor;
};*/

bool AddressIsUs(const ComboAddress& remote);
